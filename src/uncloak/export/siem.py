"""
Native Enterprise SIEM Exporter for Uncloak.
Formats telemetry in OCSF v1.1.0 Network Activity (class_uid: 4001) NDJSON
and dispatches Windows Event Log entries (Event ID 9001 & Event ID 9002).
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger("uncloak.export")

EVENT_ID_C2_DETECTED = 9001
EVENT_ID_CONTAINMENT_EXECUTED = 9002


def build_ocsf_detection_event(
    *,
    event_id: int = EVENT_ID_C2_DETECTED,
    hostname: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    pid: int,
    process_name: str,
    process_path: str = "",
    process_guid: str = "",
    sha256: str = "",
    user_context: str = "NT AUTHORITY\\SYSTEM",
    is_signed: bool = False,
    threat_score: float = 0.0,
    severity_label: str = "CRITICAL",
    c2_framework: str = "Unknown C2 Beacon",
    mitre_technique: str = "T1071.001",
    features_v1: Optional[dict[str, Any]] = None,
    reasons: Optional[list[str]] = None,
    containment_action: Optional[str] = None,
) -> dict[str, Any]:
    """Builds an OCSF v1.1.0 Network Activity (class_uid 4001) JSON event record."""
    now_epoch = time.time()
    iso_ts = datetime.fromtimestamp(now_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    sev_map = {
        "CRITICAL": (5, "Critical"),
        "HIGH": (4, "High"),
        "EVALUATING": (3, "Medium"),
        "MEDIUM": (3, "Medium"),
        "HEALTHY": (1, "Informational"),
        "BENIGN": (1, "Informational"),
    }
    severity_id, severity_name = sev_map.get(severity_label.upper(), (4, "High"))

    is_containment = event_id == EVENT_ID_CONTAINMENT_EXECUTED
    activity_id = 5 if is_containment else 6  # 5=Refuse/Block, 6=Traffic/Detect
    activity_name = "Containment Enforced (SetTcpEntry + WFP)" if is_containment else "C2 Beacon Detected"

    return {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "Uncloak",
                "vendor_name": "Uncloak Security",
                "version": "0.2.0",
                "feature": {"name": "Statistical C2 Beacon & Kernel Socket Attribution"},
            },
            "log_provider": "Microsoft-Windows-Uncloak-Sensor",
            "event_code": f"EID-{event_id}",
            "windows_event_id": event_id,
            "logged_time": iso_ts,
        },
        "category_uid": 4,
        "category_name": "Network Activity",
        "class_uid": 4001,
        "class_name": "Network Activity",
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": 400100 + activity_id,
        "severity_id": severity_id,
        "severity": severity_name,
        "status": "Contained" if is_containment else "Alert",
        "time": int(now_epoch * 1000),
        "timestamp_utc": iso_ts,
        "message": (
            f"[{severity_name.upper()}] EID {event_id}: {c2_framework} on {hostname} "
            f"({process_name} PID {pid} -> {dst_ip}:{dst_port}, score={threat_score:.3f})"
        ),
        "device": {
            "hostname": hostname,
            "ip": src_ip,
            "os": {"name": "Windows", "type": "Server" if "SRV" in hostname else "Desktop"},
        },
        "src_endpoint": {"ip": src_ip, "port": src_port},
        "dst_endpoint": {"ip": dst_ip, "port": dst_port},
        "actor": {
            "user": {"name": user_context},
            "process": {
                "pid": pid,
                "name": process_name,
                "uid": process_guid,
                "cmd_line": "",
                "file": {
                    "path": process_path,
                    "hashes": [{"algorithm": "SHA-256", "value": sha256}] if sha256 else [],
                },
                "is_signed": is_signed,
            },
        },
        "attacks": [
            {
                "technique": {"uid": mitre_technique.split()[0], "name": mitre_technique},
                "tactic": {"name": "Command and Control"},
            }
        ],
        "uncloak_telemetry": {
            "threat_score": round(float(threat_score), 4),
            "c2_framework": c2_framework,
            "containment_action": containment_action or ("SetTcpEntry(DELETE_TCB) + netsh advfirewall" if is_containment else "Pending Analyst / SOAR"),
            "detection_reasons": reasons or [],
            "features_v1": features_v1 or {},
        },
    }


def emit_windows_event_log(
    event_id: int,
    level: str,
    message: str,
    source: str = "UncloakSensor",
) -> tuple[bool, str]:
    """
    Writes a structured security alert directly to the Windows Application Event Log
    using native eventcreate.exe (never shell=True). Falls back cleanly if unprivileged.
    """
    if sys.platform != "win32":
        return False, "Non-Windows platform (NDJSON sink active)"

    ev_type = "ERROR" if level.upper() in ("CRITICAL", "HIGH", "ERROR") else "WARNING"
    safe_msg = message.replace('"', "'").replace("\n", " ")[:900]
    safe_id = event_id if 1 <= int(event_id) <= 1000 else (901 if event_id == 9001 else 902)

    cmd = [
        "eventcreate",
        "/T", ev_type,
        "/ID", str(safe_id),
        "/L", "APPLICATION",
        "/SO", source,
        "/D", f"[Uncloak EID {event_id}] {safe_msg}",
    ]
    try:
        res = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            return True, f"WinEvent EID {event_id} Written"
        return False, "OCSF NDJSON Sink (WinEvent needs SYSTEM)"
    except Exception as exc:
        return False, "OCSF NDJSON Sink Active"


def append_ndjson_alert(event_dict: dict[str, Any], log_path: str = "uncloak_alerts.ndjson") -> str:
    """Appends one OCSF JSON object per line to an NDJSON file for Wazuh/Splunk/Elastic ingestion."""
    parent = os.path.dirname(os.path.abspath(log_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event_dict, separators=(",", ":")) + "\n")
    return os.path.abspath(log_path)


def render_service_console_preview(
    console: Console,
    events: list[dict[str, Any]],
    ndjson_path: str,
    win_ev_statuses: list[tuple[int, bool, str]],
) -> None:
    """Renders a crisp operational summary of Mode 1 (Headless Service & Enterprise SIEM Sink)."""
    banner = Text()
    banner.append("UNCLOAK HEADLESS ENTERPRISE SENSOR", style="bold #e5e7eb")
    banner.append("  |  ", style="#323846")
    banner.append("ZERO-UI WINDOWS DAEMON", style="bold #93c5fd")
    banner.append("  |  ", style="#323846")
    banner.append("NO LISTENING PORTS", style="#9ca3af")
    banner.append("\n")
    banner.append("SIEM Sinks: ", style="#9ca3af")
    banner.append("Windows Event Log (EID 9001 / 9002)", style="bold #fcd34d")
    banner.append("  +  ", style="#323846")
    banner.append(f"OCSF v1.1.0 NDJSON ({os.path.basename(ndjson_path)})", style="bold #93c5fd")

    console.print(
        Panel(
            banner,
            title="[bold #e5e7eb] Mode 1 : Headless Endpoint Service & SIEM Pipeline [/]",
            box=box.ROUNDED,
            style="on #101217",
            border_style="#262b38",
            padding=(0, 1),
        )
    )

    tbl = Table(
        title="ENTERPRISE SIEM TELEMETRY QUEUE (SPLUNK / WAZUH / SENTINEL READY)",
        box=box.ROUNDED,
        style="on #101217",
        border_style="#262b38",
        header_style="bold #9ca3af on #14171f",
        expand=True,
    )
    is_wide = console.width >= 120
    tbl.add_column("EID", width=6, min_width=6, no_wrap=True)
    tbl.add_column("SEV", width=9 if is_wide else 8, min_width=8, no_wrap=True)
    tbl.add_column("HOST :: PROCESS (PID)", min_width=28 if is_wide else 12, no_wrap=is_wide, ratio=None if is_wide else 2)
    tbl.add_column("5-TUPLE FLOW", min_width=36 if is_wide else 14, no_wrap=is_wide, ratio=None if is_wide else 2)
    tbl.add_column("MAD & SCORE", min_width=18 if is_wide else 11, no_wrap=is_wide, ratio=None if is_wide else 1)
    tbl.add_column("CONTAINMENT & EVENT SINK", ratio=1 if is_wide else 2)

    for idx, ev in enumerate(events):
        meta = ev.get("metadata", {})
        eid = meta.get("windows_event_id", 9001)
        sev = ev.get("severity", "Critical").upper()
        dev = ev.get("device", {})
        proc = ev.get("actor", {}).get("process", {})
        src = ev.get("src_endpoint", {})
        dst = ev.get("dst_endpoint", {})
        tel = ev.get("uncloak_telemetry", {})
        feats = tel.get("features_v1", {})

        eid_txt = Text(f" {eid} ", style="bold white on #b91c1c" if eid == 9001 else "bold #93c5fd on #1b202b")
        sev_txt = Text(sev, style="bold #fca5a5" if sev == "CRITICAL" else "bold #fcd34d")
        proc_txt = Text(f"{dev.get('hostname', 'HOST')} :: {proc.get('name', '?')} ({proc.get('pid', 0)})", style="bold #e5e7eb")
        flow_txt = Text(f"{src.get('ip')}:{src.get('port')} -> {dst.get('ip')}:{dst.get('port')}", style="#d1d5db")
        mad_val = feats.get("iat_mad_ratio", 0.0)
        score_val = tel.get("threat_score", 0.0) * 100.0
        stat_txt = Text(f"MAD {mad_val:.3f} | {score_val:.1f}%", style="bold #fca5a5")

        ev_status_msg = win_ev_statuses[idx][2] if idx < len(win_ev_statuses) else "OCSF NDJSON Sink"
        action_short = tel.get("containment_action", "")
        if len(action_short) > 40:
            action_short = action_short.split("(")[0].strip() if "SetTcpEntry" in action_short else action_short[:38]
        sink_txt = Text(f"{action_short} | {ev_status_msg}", style="#6ee7b7" if eid == 9002 else "#9ca3af")

        tbl.add_row(eid_txt, sev_txt, proc_txt, flow_txt, stat_txt, sink_txt)

    console.print(tbl)

    if events:
        ev0 = events[0]
        # Render compact OCSF v1.1.0 schema excerpt + raw single-line NDJSON stream preview
        compact_ocsf = {
            "metadata": {
                "version": ev0["metadata"]["version"],
                "log_provider": ev0["metadata"]["log_provider"],
                "windows_event_id": ev0["metadata"]["windows_event_id"],
                "logged_time": ev0["metadata"]["logged_time"],
            },
            "class_uid": ev0["class_uid"],
            "activity_name": ev0["activity_name"],
            "severity": ev0["severity"],
            "src_endpoint": ev0["src_endpoint"],
            "dst_endpoint": ev0["dst_endpoint"],
            "actor_process": {
                "pid": ev0["actor"]["process"]["pid"],
                "name": ev0["actor"]["process"]["name"],
                "uid": ev0["actor"]["process"]["uid"],
                "is_signed": ev0["actor"]["process"]["is_signed"],
            },
            "uncloak_telemetry": {
                "threat_score": ev0["uncloak_telemetry"]["threat_score"],
                "c2_framework": ev0["uncloak_telemetry"]["c2_framework"],
                "features_v1": ev0["uncloak_telemetry"]["features_v1"],
            },
        }
        ndjson_preview = Text()
        ndjson_preview.append(json.dumps(compact_ocsf, indent=2), style="#d1d5db")
        ndjson_preview.append("\n\nNDJSON Stream (Line 1 -> Splunk/Wazuh):\n", style="bold #93c5fd")
        ndjson_preview.append(json.dumps(ev0, separators=(",", ":"))[:144] + "...", style="#6b7280")
        console.print(
            Panel(
                ndjson_preview,
                title="[bold #e5e7eb] OCSF v1.1.0 Network Activity Payload (class_uid: 4001) [/]",
                box=box.ROUNDED,
                style="on #0c0e13",
                border_style="#262b38",
                padding=(0, 1),
            )
        )
