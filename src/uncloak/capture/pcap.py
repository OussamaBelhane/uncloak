"""
PCAP/PCAPNG Telemetry Replay Harness for Uncloak.
Replays captured network packet streams, resolves DNS/SNI context, aggregates application bursts,
constructs Feature Schema v1 vectors, and renders tactical CLI or OCSF/NDJSON triage reports.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Generator, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Offline PCAP reading uses pure Python PcapReader and does not require live Npcap/libpcap
for _scapy_log in ("scapy", "scapy.runtime", "scapy.loading", "scapy.interactive"):
    logging.getLogger(_scapy_log).setLevel(logging.CRITICAL)

from scapy.layers.dns import DNS, DNSRR  # type: ignore[import-untyped]
from scapy.layers.inet import IP, TCP, UDP  # type: ignore[import-untyped]
from scapy.utils import PcapReader  # type: ignore[import-untyped]

from uncloak.capture.burst import BurstAggregator
from uncloak.core.models import FlowFeaturesV1
from uncloak.detection.model import C2Predictor
from uncloak.export.siem import EVENT_ID_C2_DETECTED, build_ocsf_detection_event


@dataclass
class PcapFlowAnalysis:
    """Complete Feature Schema v1 + C2Predictor scoring result for one replayed PCAP flow."""
    flow_key: str
    src_ip: str
    dst_ip: str
    dst_port: int
    resolved_domain: str
    total_packets: int
    total_bytes: int
    duration_sec: float
    features: FlowFeaturesV1
    prediction: dict[str, Any]


def _extract_tls_sni_ascii(payload: bytes) -> Optional[str]:
    """Lightweight parser extracting ASCII SNI extension hostname from TLS ClientHello payloads."""
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    # Scan for server_name extension (0x00 0x00) + name_type host_name (0x00)
    idx = payload.find(b"\x00\x00")
    while idx != -1 and idx + 9 < len(payload):
        if payload[idx + 6] == 0x00:
            name_len = int.from_bytes(payload[idx + 7:idx + 9], "big")
            if 4 <= name_len <= 128 and idx + 9 + name_len <= len(payload):
                candidate = payload[idx + 9:idx + 9 + name_len]
                try:
                    host = candidate.decode("ascii")
                    if "." in host and all(c.isalnum() or c in ".-_" for c in host):
                        return host
                except UnicodeDecodeError:
                    pass
        idx = payload.find(b"\x00\x00", idx + 2)
    return None


def analyze_pcap_detailed(
    pcap_path: str,
    min_bursts: int = 8,
    predictor: Optional[C2Predictor] = None,
) -> list[PcapFlowAnalysis]:
    """
    Replays an offline PCAP/PCAPNG file, tracks DNS/SNI resolutions per IP,
    aggregates TCP bursts (<200ms), extracts Feature Schema v1 vectors, and scores every qualifying flow.
    """
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    scorer = predictor or C2Predictor()
    dns_ip_to_domain: dict[str, str] = {}
    flow_sni: dict[str, str] = {}
    flow_aggregators: dict[str, BurstAggregator] = {}
    flow_meta: dict[str, dict[str, Any]] = {}

    with PcapReader(pcap_path) as pcap_reader:
        for pkt in pcap_reader:
            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            timestamp = float(pkt.time)

            # Capture DNS A-record resolutions from UDP/53 to set raw_ip_flag accurately
            if pkt.haslayer(UDP) and pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 1 and dns.ancount > 0 and dns.qd:
                    try:
                        qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                        for i in range(dns.ancount):
                            rr = dns.an[i]
                            if isinstance(rr, DNSRR) and rr.type == 1:
                                resolved_ip = str(rr.rdata)
                                if qname and resolved_ip:
                                    dns_ip_to_domain[resolved_ip] = qname
                    except Exception:
                        pass
                continue

            if not pkt.haslayer(TCP):
                continue

            tcp_layer = pkt[TCP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            raw_payload = bytes(tcp_layer.payload) if tcp_layer.payload else b""
            payload_len = len(raw_payload)

            # Canonical flow representation (client -> server service port)
            if src_port > dst_port:
                flow_key = f"{src_ip} -> {dst_ip}:{dst_port}"
                client_ip, server_ip, server_port = src_ip, dst_ip, dst_port
                is_outbound = True
            else:
                flow_key = f"{dst_ip} -> {src_ip}:{src_port}"
                client_ip, server_ip, server_port = dst_ip, src_ip, src_port
                is_outbound = False

            conn_id = f"{client_ip}:{src_port if is_outbound else dst_port}<->{server_ip}:{server_port}"

            if flow_key not in flow_aggregators:
                flow_aggregators[flow_key] = BurstAggregator()
                flow_meta[flow_key] = {
                    "src_ip": client_ip,
                    "dst_ip": server_ip,
                    "dst_port": server_port,
                    "first_ts": timestamp,
                    "last_ts": timestamp,
                    "packets": 0,
                    "bytes": 0,
                }

            meta = flow_meta[flow_key]
            meta["first_ts"] = min(meta["first_ts"], timestamp)
            meta["last_ts"] = max(meta["last_ts"], timestamp)
            meta["packets"] += 1
            meta["bytes"] += payload_len

            if is_outbound and payload_len > 40 and flow_key not in flow_sni:
                sni_host = _extract_tls_sni_ascii(raw_payload)
                if sni_host:
                    flow_sni[flow_key] = sni_host

            flow_aggregators[flow_key].ingest_packet(
                timestamp=timestamp,
                payload_bytes=payload_len,
                is_outbound=is_outbound,
                connection_id=conn_id,
            )

    results: list[PcapFlowAnalysis] = []
    for flow_key, aggregator in flow_aggregators.items():
        meta = flow_meta[flow_key]
        dst_ip = meta["dst_ip"]
        resolved_domain = flow_sni.get(flow_key) or dns_ip_to_domain.get(dst_ip, "")
        raw_ip_flag = 0 if resolved_domain else 1

        features = aggregator.extract_features(
            raw_ip_flag=raw_ip_flag,
            proc_signed=1,
            proc_path_class=0,
            min_bursts=min_bursts,
        )
        if not features:
            continue

        prediction = scorer.predict_v1(features, host_context_known=False)
        duration = max(0.0, meta["last_ts"] - meta["first_ts"])
        results.append(
            PcapFlowAnalysis(
                flow_key=flow_key,
                src_ip=meta["src_ip"],
                dst_ip=dst_ip,
                dst_port=meta["dst_port"],
                resolved_domain=resolved_domain,
                total_packets=meta["packets"],
                total_bytes=meta["bytes"],
                duration_sec=duration,
                features=features,
                prediction=prediction,
            )
        )

    results.sort(key=lambda item: item.prediction["threat_score"], reverse=True)
    return results


def analyze_pcap(
    pcap_path: str,
    min_bursts: int = 10,
) -> Generator[tuple[str, FlowFeaturesV1], None, None]:
    """
    Parses an offline PCAP/PCAPNG file, aggregates TCP application bursts per destination flow,
    and yields (flow_key, FlowFeaturesV1) for every session meeting the minimum burst threshold.
    """
    for item in analyze_pcap_detailed(pcap_path, min_bursts=min_bursts):
        yield item.flow_key, item.features


def _format_duration(seconds: float) -> str:
    mins = int(seconds // 60)
    secs = int(seconds % 60)
    if mins > 0:
        return f"{mins}m {secs:02d}s"
    return f"{secs}s"


def render_pcap_report(
    pcap_path: str,
    json_mode: bool = False,
    threshold: float = 0.75,
    min_bursts: int = 8,
    console: Optional[Console] = None,
) -> int:
    """
    Replays a PCAP file and renders either a high-impact Rich C2 Triage Table report
    or OCSF v1.1.0 NDJSON objects to stdout for CLI pipelines.
    """
    t0 = time.perf_counter()
    results = analyze_pcap_detailed(pcap_path, min_bursts=min_bursts)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    if json_mode:
        for item in results:
            pred = item.prediction
            ev = build_ocsf_detection_event(
                event_id=EVENT_ID_C2_DETECTED,
                hostname="OFFLINE-PCAP-REPLAY",
                src_ip=item.src_ip,
                src_port=0,
                dst_ip=item.dst_ip,
                dst_port=item.dst_port,
                pid=0,
                process_name="pcap_replay_stream",
                is_signed=True,
                threat_score=pred["threat_score"],
                severity_label=pred["confidence_level"],
                c2_framework=pred["c2_profile_hint"],
                mitre_technique=pred["mitre_technique"],
                features_v1=pred["feature_vector_v1"],
                reasons=pred["top_features"],
                containment_action=(
                    f"netsh advfirewall firewall add rule name='Uncloak_Block_{item.dst_ip}' "
                    f"dir=out action=block remoteip={item.dst_ip}"
                    if pred["threat_score"] >= threshold
                    else "Monitor Baseline"
                ),
            )
            ev["pcap_metadata"] = {
                "file": os.path.basename(pcap_path),
                "flow_key": item.flow_key,
                "resolved_domain": item.resolved_domain or None,
                "duration_sec": round(item.duration_sec, 2),
                "total_packets": item.total_packets,
                "total_bytes": item.total_bytes,
            }
            print(json.dumps(ev))
        return 0

    out_console = console or Console(color_system="truecolor")
    threats = [r for r in results if r.prediction["threat_score"] >= threshold]
    evaluating = [r for r in results if 0.48 <= r.prediction["threat_score"] < threshold]

    banner = Text()
    banner.append("UNCLOAK", style="bold #e5e7eb")
    banner.append(" // PCAP C2 THREAT HARNESS  |  ", style="#9ca3af")
    banner.append("CAPTURE: ", style="#6b7280")
    banner.append(os.path.basename(pcap_path), style="bold #93c5fd")
    banner.append("  |  ", style="#323846")
    banner.append("SCHEMA: ", style="#6b7280")
    banner.append("Feature Schema v1 (12-Dim)", style="#e5e7eb")
    banner.append("\n")
    banner.append("Flows Qualified (>=8 bursts): ", style="#9ca3af")
    banner.append(f"{len(results)}", style="bold #e5e7eb")
    banner.append("  |  ", style="#323846")
    banner.append("Confirmed C2 Beacons: ", style="#9ca3af")
    banner.append(f"{len(threats)}", style="bold #fca5a5" if threats else "#6ee7b7")
    banner.append("  |  ", style="#323846")
    banner.append("Watchlist: ", style="#9ca3af")
    banner.append(f"{len(evaluating)}", style="bold #fcd34d" if evaluating else "#9ca3af")
    banner.append("  |  ", style="#323846")
    banner.append(f"Scan Latency: {elapsed_ms:.1f} ms", style="bold #93c5fd")

    out_console.print(
        Panel(
            banner,
            title="[bold #e5e7eb] Mode 2 : PCAP Telemetry Replay Harness [/]",
            box=box.ROUNDED,
            style="on #101217",
            border_style="#262b38",
            padding=(0, 1),
        )
    )

    tbl = Table(
        box=box.ROUNDED,
        style="on #101217",
        border_style="#262b38",
        header_style="bold #9ca3af on #14171f",
        expand=True,
    )
    tbl.add_column("FLOW (SRC -> DST:PORT)", min_width=32, no_wrap=True)
    tbl.add_column("DNS / SNI CONTEXT", min_width=19, no_wrap=True)
    tbl.add_column("BURSTS", width=6, justify="right", no_wrap=True)
    tbl.add_column("IAT MED", width=7, justify="right", no_wrap=True)
    tbl.add_column("MAD", width=7, justify="right", no_wrap=True)
    tbl.add_column("IQR", width=7, justify="right", no_wrap=True)
    tbl.add_column("SKEW", width=7, justify="right", no_wrap=True)
    tbl.add_column("CONN/B", width=6, justify="right", no_wrap=True)
    tbl.add_column("DUR", width=7, justify="right", no_wrap=True)
    tbl.add_column("SCORE & VERDICT", width=18, justify="right", no_wrap=True)

    if not results:
        tbl.add_row("No qualifying TCP burst streams found", "-", "0", "-", "-", "-", "-", "-", "-", "BENIGN")
    else:
        for item in results:
            f = item.features
            pred = item.prediction
            score = pred["threat_score"]
            lvl = pred["confidence_level"]
            is_bad = score >= threshold
            is_eval = 0.48 <= score < threshold

            flow_style = "bold #fca5a5" if is_bad else ("bold #fcd34d" if is_eval else "#d1d5db")
            sni_text = Text(
                item.resolved_domain if item.resolved_domain else "Direct IP (No DNS)",
                style="bold #fca5a5" if (f.raw_ip_flag == 1 and is_bad) else ("#d1d5db" if item.resolved_domain else "#6b7280"),
            )
            mad_style = "bold #fca5a5" if f.iat_mad_ratio <= 0.18 else ("#fcd34d" if f.iat_mad_ratio <= 0.30 else "#9ca3af")

            verdict_txt = Text()
            if lvl == "CRITICAL":
                verdict_txt.append(f" {score * 100:.1f}% CRIT ", style="bold white on #b91c1c")
            elif lvl == "HIGH":
                verdict_txt.append(f" {score * 100:.1f}% HIGH ", style="bold black on #d97706")
            elif lvl == "EVALUATING":
                verdict_txt.append(f" {score * 100:.1f}% EVAL ", style="bold black on #eab308")
            else:
                verdict_txt.append(f"  {score * 100:.1f}% OK   ", style="#6b7280")

            row_bg = "on #160d10" if is_bad else ("on #161412" if is_eval else "on #101217")
            tbl.add_row(
                Text(item.flow_key, style=flow_style),
                sni_text,
                str(f.n_bursts),
                f"{f.iat_median:.2f}s",
                Text(f"{f.iat_mad_ratio:.3f}", style=mad_style),
                f"{f.iat_iqr_ratio:.3f}",
                f"{f.iat_bowley_skew:+.3f}",
                f"{f.conn_per_burst:.2f}",
                _format_duration(item.duration_sec),
                verdict_txt,
                style=row_bg,
            )

    out_console.print(tbl)

    if threats or evaluating:
        cards_grid = Table.grid(expand=True, padding=(0, 1))
        for _ in range(min(3, len(threats + evaluating))):
            cards_grid.add_column(ratio=1)

        card_panels = []
        for idx, item in enumerate((threats + evaluating)[:3], start=1):
            pred = item.prediction
            lvl = pred["confidence_level"]
            title_c = "#fca5a5" if lvl == "CRITICAL" else ("#fcd34d" if lvl == "HIGH" else "#fde047")
            border_c = "#7f1d1d" if lvl == "CRITICAL" else ("#92400e" if lvl == "HIGH" else "#713f12")

            profile_str = str(pred["c2_profile_hint"])[:36]
            flow_str = item.flow_key[:36]
            mitre_str = str(pred["mitre_technique"])[:36]
            f = item.features
            sig_str = f"MAD {f.iat_mad_ratio:.3f} | IQR {f.iat_iqr_ratio:.3f} | RawIP={f.raw_ip_flag}"[:36]
            wfp_str = f"EID 9001 -> block {item.dst_ip}"[:36]

            body = Text()
            body.append("Profile : ", style="#6b7280")
            body.append(f"{profile_str}\n", style="bold #e5e7eb")
            body.append("Flow    : ", style="#6b7280")
            body.append(f"{flow_str}\n", style="#93c5fd")
            body.append("MITRE   : ", style="#6b7280")
            body.append(f"{mitre_str}\n", style="#fcd34d")
            body.append("Signal  : ", style="#6b7280")
            body.append(f"{sig_str}\n", style="#fca5a5" if lvl != "EVALUATING" else "#fde047")
            body.append("SIEM/FW : ", style="#6b7280")
            body.append(wfp_str, style="#6ee7b7")

            card_panels.append(
                Panel(
                    body,
                    title=f"[bold {title_c}] Finding #{idx} : {lvl} ({pred['threat_score']*100:.1f}%) [/]",
                    box=box.ROUNDED,
                    style="on #0c0e13",
                    border_style=border_c,
                    padding=(0, 1),
                )
            )
        cards_grid.add_row(*card_panels)
        out_console.print(cards_grid)

    return 0
