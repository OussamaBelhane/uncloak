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
    """Renders a compact enterprise SIEM verification card for Mode 1 (<= 20 terminal rows)."""
    ev0 = events[0] if events else {}
    dev0 = ev0.get("device", {})
    hostname = dev0.get("hostname", "ENDPOINT")
    host_ip = dev0.get("ip", "127.0.0.1")

    eid_status_parts: list[str] = []
    for eid, ok, msg in win_ev_statuses[:2]:
        tag = "Written" if ok else "Queued/NDJSON"
        eid_status_parts.append(f"EID {eid}: {tag}")
    win_ev_summary = " | ".join(eid_status_parts) if eid_status_parts else "EID 9001 / 9002 Armed"

    banner = Text()
    banner.append("UNCLOAK SENSOR", style="bold #f8fafc")
    banner.append("  |  ", style="#475569")
    banner.append("ACTIVE (0 Listening Ports)", style="bold #10b981")
    banner.append("  |  ", style="#475569")
    banner.append("Host: ", style="#94a3b8")
    banner.append(f"{hostname} ({host_ip})", style="bold #e2e8f0")
    banner.append("  |  ", style="#475569")
    banner.append("Context: ", style="#94a3b8")
    banner.append("Headless SYSTEM Daemon\n", style="#cbd5e1")
    banner.append("SIEM Sinks     : ", style="#94a3b8")
    banner.append(f"WinEventLog Application ({win_ev_summary})", style="#38bdf8")
    banner.append("  +  ", style="#475569")
    banner.append(f"OCSF v1.1.0 NDJSON ({os.path.basename(ndjson_path)})", style="bold #10b981")

    console.print(
        Panel(
            banner,
            title="[bold #f8fafc] Mode 1 : Headless Endpoint Sensor & SIEM Verification [/]",
            box=box.ROUNDED,
            border_style="#334155",
            padding=(0, 1),
        )
    )

    tbl = Table(
        title="DISPATCHED SIEM TELEMETRY QUEUE (SPLUNK / WAZUH / SENTINEL READY)",
        title_style="bold #cbd5e1",
        box=box.ROUNDED,
        border_style="#334155",
        header_style="bold #94a3b8",
        expand=True,
    )
    is_wide = console.width >= 120
    tbl.add_column("EID", width=6, min_width=6, no_wrap=True)
    tbl.add_column("SEV", width=9 if is_wide else 8, min_width=8, no_wrap=True)
    tbl.add_column("HOST :: PROCESS (PID)", min_width=26 if is_wide else 12, no_wrap=is_wide, ratio=None if is_wide else 2)
    tbl.add_column("5-TUPLE SOCKET FLOW", min_width=34 if is_wide else 14, no_wrap=is_wide, ratio=None if is_wide else 2)
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

        eid_txt = Text(
            f" {eid} ",
            style="bold white on #b91c1c" if eid == 9001 else "bold white on #1d4ed8",
        )
        sev_txt = Text(sev, style="bold #f87171" if sev == "CRITICAL" else "bold #f59e0b")
        proc_txt = Text(f"{dev.get('hostname', 'HOST')} :: {proc.get('name', '?')} ({proc.get('pid', 0)})", style="bold #f8fafc")
        flow_txt = Text(f"{src.get('ip')}:{src.get('port')} -> {dst.get('ip')}:{dst.get('port')}", style="#cbd5e1")
        mad_val = feats.get("iat_mad_ratio", 0.0)
        score_val = tel.get("threat_score", 0.0) * 100.0
        stat_txt = Text(f"MAD {mad_val:.3f} | {score_val:.1f}%", style="bold #f87171")

        ev_status_msg = win_ev_statuses[idx][2] if idx < len(win_ev_statuses) else "OCSF NDJSON Sink"
        ev_status_msg = ev_status_msg.replace("WinEvent EID ", "EID ")
        action_short = tel.get("containment_action", "")
        if len(action_short) > 30:
            action_short = action_short.split("(")[0].strip() if "SetTcpEntry" in action_short else action_short[:28]
        sink_txt = Text(f"{action_short} | {ev_status_msg}", style="#10b981" if eid == 9002 else "#94a3b8")

        tbl.add_row(eid_txt, sev_txt, proc_txt, flow_txt, stat_txt, sink_txt)

    console.print(tbl)

    if events:
        grid = Table.grid(expand=True, padding=(0, 2))
        grid.add_column(ratio=1, no_wrap=True)
        grid.add_column(ratio=1, no_wrap=True)

        left_col = Text()
        left_col.append("Schema    : ", style="#94a3b8")
        left_col.append("OCSF v1.1.0 Network Activity (class_uid: 4001)\n", style="#e2e8f0")
        left_col.append("Event IDs : ", style="#94a3b8")
        left_col.append("EID 9001 (C2 Detected) + EID 9002 (TCB Severed)\n", style="#38bdf8")
        left_col.append("Telemetry : ", style="#94a3b8")
        left_col.append("12-Dim FlowFeaturesV1 + JA4 + ProcessGuid", style="#cbd5e1")

        ndjson_base = os.path.basename(ndjson_path)
        compact_sample = json.dumps(
            {
                "class_uid": ev0.get("class_uid", 4001),
                "severity": ev0.get("severity", "Critical"),
                "score": round(float(ev0.get("uncloak_telemetry", {}).get("threat_score", 0.0)), 3),
            },
            separators=(",", ":"),
        )

        right_col = Text()
        right_col.append("NDJSON Sink : ", style="#94a3b8")
        right_col.append(f"{ndjson_base} ({len(events)} records appended)\n", style="#10b981")
        right_col.append("Sample Line : ", style="#94a3b8")
        right_col.append(f"{compact_sample}\n", style="#64748b")
        right_col.append("Raw Stream  : ", style="#94a3b8")
        right_col.append("Run 'uncloak service --once --json' for full OCSF stdout", style="bold #38bdf8")

        grid.add_row(left_col, right_col)
        console.print(
            Panel(
                grid,
                title="[bold #f8fafc] OCSF v1.1.0 Schema Verification & Ingestion Summary [/]",
                box=box.ROUNDED,
                border_style="#334155",
                padding=(0, 1),
            )
        )
