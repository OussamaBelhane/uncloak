"""
Live Network Packet Capture & Flow Aggregation Engine for Uncloak.
Uses Npcap on Windows (or libpcap on POSIX) via BPF filtering to capture TCP flows,
extract JA4 TLS ClientHello fingerprints, and feed BurstAggregator in bounded RAM.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Optional

from uncloak.capture.burst import BurstAggregator
from uncloak.capture.ja4 import parse_tls_client_hello
from uncloak.core.models import FlowFeaturesV1

logger = logging.getLogger("uncloak.capture.live")

DEFAULT_OUTBOUND_BPF = (
    "tcp and not (dst net 10.0.0.0/8 or dst net 172.16.0.0/12 or dst net 192.168.0.0/16)"
)


def _discover_local_ips() -> set[str]:
    """Resolves primary local IPv4 addresses without generating DNS traffic."""
    ips = {"127.0.0.1"}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("10.255.255.255", 1))
            ips.add(str(sock.getsockname()[0]))
    except OSError:
        pass
    return ips


@dataclass
class LiveFlowState:
    """Tracks real-time burst aggregation and TLS fingerprint state for one flow."""

    flow_key: str
    local_ip: str
    dst_ip: str
    dst_port: int
    last_local_port: int
    aggregator: BurstAggregator
    ja4: Optional[str] = None
    sni: Optional[str] = None
    last_seen: float = 0.0


class LivePacketCapture:
    """Thread-safe live TCP capture engine with bounded memory flow tracking."""

    def __init__(
        self,
        bpf_filter: str = DEFAULT_OUTBOUND_BPF,
        local_ips: Optional[set[str]] = None,
        max_flows: int = 2048,
        burst_threshold_seconds: float = 0.200,
    ) -> None:
        if max_flows <= 0:
            raise ValueError("max_flows must be positive")
        self.bpf_filter = bpf_filter
        self.local_ips = set(local_ips) if local_ips is not None else _discover_local_ips()
        self.max_flows = int(max_flows)
        self.burst_threshold_seconds = float(burst_threshold_seconds)
        self._lock = threading.Lock()
        self._flows: OrderedDict[str, LiveFlowState] = OrderedDict()
        self._sniffer: Any = None
        self.packets_processed = 0

    def ingest_packet(
        self,
        timestamp: float,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        payload: bytes,
    ) -> Optional[str]:
        """Dissects a single TCP packet into bounded flow state and JA4 metadata."""
        if src_ip in self.local_ips:
            is_outbound = True
            local_ip, local_port = src_ip, int(src_port)
            remote_ip, remote_port = dst_ip, int(dst_port)
        elif dst_ip in self.local_ips:
            is_outbound = False
            local_ip, local_port = dst_ip, int(dst_port)
            remote_ip, remote_port = src_ip, int(src_port)
        else:
            is_outbound = True
            local_ip, local_port = src_ip, int(src_port)
            remote_ip, remote_port = dst_ip, int(dst_port)

        flow_key = f"{local_ip}->{remote_ip}:{remote_port}"
        conn_id = f"{local_ip}:{local_port}->{remote_ip}:{remote_port}"

        hello_info = None
        if is_outbound and len(payload) > 40:
            hello_info = parse_tls_client_hello(payload, transport="t")

        with self._lock:
            state = self._flows.get(flow_key)
            if state is None:
                state = LiveFlowState(
                    flow_key=flow_key,
                    local_ip=local_ip,
                    dst_ip=remote_ip,
                    dst_port=remote_port,
                    last_local_port=local_port,
                    aggregator=BurstAggregator(burst_threshold_seconds=self.burst_threshold_seconds),
                    last_seen=timestamp,
                )
                self._flows[flow_key] = state
                while len(self._flows) > self.max_flows:
                    self._flows.popitem(last=False)
            else:
                self._flows.move_to_end(flow_key)
                if is_outbound:
                    state.last_local_port = local_port
                state.last_seen = max(state.last_seen, timestamp)

            if hello_info is not None:
                if state.ja4 is None:
                    state.ja4 = hello_info.ja4
                if hello_info.sni and state.sni is None:
                    state.sni = hello_info.sni

            state.aggregator.ingest_packet(
                timestamp=timestamp,
                payload_bytes=len(payload),
                is_outbound=is_outbound,
                connection_id=conn_id,
            )
            self.packets_processed += 1
        return flow_key

    def ingest_scapy_packet(self, pkt: Any) -> Optional[str]:
        """Adapter converting a live Scapy IP/TCP packet into internal flow ingestion."""
        try:
            from scapy.layers.inet import IP, TCP  # type: ignore[import-untyped]
            from scapy.packet import Raw  # type: ignore[import-untyped]
        except ImportError:
            return None

        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return None

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        raw_payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        ts = float(getattr(pkt, "time", 0.0) or time.time())
        return self.ingest_packet(
            timestamp=ts,
            src_ip=str(ip_layer.src),
            src_port=int(tcp_layer.sport),
            dst_ip=str(ip_layer.dst),
            dst_port=int(tcp_layer.dport),
            payload=raw_payload,
        )

    def extract_ready_flows(
        self,
        min_bursts: int = 8,
        path_class: int = 0,
        is_signed: bool = False,
    ) -> list[tuple[LiveFlowState, FlowFeaturesV1]]:
        """Extracts FlowFeaturesV1 vectors for all flows meeting minimum burst count."""
        ready: list[tuple[LiveFlowState, FlowFeaturesV1]] = []
        with self._lock:
            for state in self._flows.values():
                features = state.aggregator.extract_features(
                    raw_ip_flag=0 if state.sni else 1,
                    proc_signed=1 if is_signed else 0,
                    proc_path_class=path_class,
                    min_bursts=min_bursts,
                )
                if features is not None:
                    ready.append((state, features))
        return ready

    def start(self, iface: Optional[str] = None) -> bool:
        """Starts asynchronous packet capture using Scapy AsyncSniffer."""
        if self._sniffer is not None:
            return True
        try:
            from scapy.sendrecv import AsyncSniffer  # type: ignore[import-untyped]
        except ImportError as exc:
            logger.error("Scapy is required for live capture: %s", exc)
            return False

        self._sniffer = AsyncSniffer(
            iface=iface,
            filter=self.bpf_filter,
            prn=self.ingest_scapy_packet,
            store=False,
        )
        self._sniffer.start()
        logger.info("Live packet capture started (iface=%s, filter=%s)", iface or "default", self.bpf_filter)
        return True

    def stop(self) -> None:
        """Stops asynchronous packet capture cleanly."""
        if self._sniffer is None:
            return
        try:
            self._sniffer.stop()
        except Exception:
            pass
        self._sniffer = None
