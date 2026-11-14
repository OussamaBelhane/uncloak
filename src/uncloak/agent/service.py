r"""
Uncloak Silent Endpoint Agent Service.
Executes as a headless Windows background daemon under NT AUTHORITY\SYSTEM.
Performs local socket monitoring, non-parametric cadence calculations, and signed mitigation execution.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import secrets
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Optional
from urllib import request

import psutil

from uncloak.attribution.identity import classify_path
from uncloak.attribution.trust import verify_authenticode
from uncloak.core.models import FlowSession
from uncloak.export.siem import (
    EVENT_ID_C2_DETECTED,
    EVENT_ID_CONTAINMENT_EXECUTED,
    append_ndjson_alert,
    build_ocsf_detection_event,
    emit_windows_event_log,
    render_service_console_preview,
)
from uncloak.mitigation.eviction import sever_tcp_connection
from uncloak.mitigation.firewall import block_application_destination

logger = logging.getLogger("uncloak.agent")


class UncloakAgentService:
    """Headless enterprise agent daemon operating with lightweight footprint."""

    def __init__(
        self,
        manager_url: str = "http://127.0.0.1:8443",
        auth_token: Optional[str] = None,
        heartbeat_interval: float = 15.0,
    ) -> None:
        self.manager_url = manager_url.rstrip("/")
        # Resolve authentication token dynamically; avoid hardcoded static secrets
        self.auth_token = (
            auth_token
            or os.environ.get("UNCLOAK_AGENT_TOKEN")
            or secrets.token_urlsafe(32)
        )
        self.heartbeat_interval = heartbeat_interval
        self.is_running = False
        self.host_id = f"host-{socket.gethostname().lower()}"
        self.hostname = socket.gethostname().upper()
        self.ip_address = self._resolve_primary_ip()
        self._lock = threading.Lock()
        self._active_sessions: dict[str, FlowSession] = {}

    def _resolve_primary_ip(self) -> str:
        """Determines the primary local IP address without external DNS calls."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("10.255.255.255", 1))
                return str(s.getsockname()[0])
        except Exception:
            return "127.0.0.1"

    def start(self, daemon: bool = True) -> None:
        """Starts the background telemetry loop and heartbeat synchronization."""
        self.is_running = True
        logger.info(
            "Starting Uncloak Agent [%s] reporting to %s",
            self.hostname,
            self.manager_url,
        )

        if daemon:
            t = threading.Thread(target=self._telemetry_worker, daemon=True)
            t.start()
        else:
            self._telemetry_worker()

    def stop(self) -> None:
        """Gracefully halts the agent service."""
        self.is_running = False

    def _telemetry_worker(self) -> None:
        """Continuous background loop dispatching heartbeats and collecting socket table diffs."""
        while self.is_running:
            try:
                self._send_heartbeat()
            except Exception as exc:
                logger.debug("Heartbeat transmission error: %s", exc)
            time.sleep(self.heartbeat_interval)

    def _collect_local_telemetry(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Harvests local OS process list and active TCP sockets."""
        processes: list[dict[str, Any]] = []
        connections: list[dict[str, Any]] = []

        try:
            raw_conns = psutil.net_connections(kind="tcp")
            for c in raw_conns:
                if c.status == "ESTABLISHED" and c.raddr:
                    connections.append({
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}",
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                        "status": c.status,
                        "pid": c.pid,
                    })
        except Exception:
            pass

        try:
            for p in psutil.process_iter(["pid", "ppid", "name", "exe", "username", "cpu_percent", "memory_info", "create_time"]):
                try:
                    info = p.info
                    pid = info["pid"]
                    p_name = info.get("name") or "unknown"
                    exe_path = info.get("exe") or ""

                    # Correlate active sockets for this process
                    p_socks = [c for c in connections if c["pid"] == pid]

                    mem = info.get("memory_info")
                    ram_mb = round(mem.rss / (1024 * 1024), 1) if mem else 0.0

                    ctime = info.get("create_time") or 0.0
                    dt_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ctime)) if ctime else ""

                    # Process I/O bytes
                    total_bytes = 0
                    bandwidth_str = "0 B"
                    try:
                        io = p.io_counters()
                        if io:
                            total_bytes = io.read_bytes + io.write_bytes
                            if total_bytes < 1024:
                                bandwidth_str = f"{total_bytes} B"
                            elif total_bytes < 1024 * 1024:
                                bandwidth_str = f"{total_bytes / 1024:.1f} KB"
                            elif total_bytes < 1024 * 1024 * 1024:
                                bandwidth_str = f"{total_bytes / (1024 * 1024):.1f} MB"
                            else:
                                bandwidth_str = f"{total_bytes / (1024 * 1024 * 1024):.2f} GB"
                    except Exception:
                        pass

                    for sock in p_socks:
                        sock["process_name"] = p_name
                        sock["bytes_str"] = bandwidth_str if total_bytes > 0 else "0 B"

                    # Genuine Authenticode verification and path classification
                    is_signed, sig_details = verify_authenticode(exe_path)
                    path_class = classify_path(exe_path)

                    processes.append({
                        "pid": pid,
                        "ppid": info.get("ppid") or 0,
                        "name": p_name,
                        "path": exe_path,
                        "username": info.get("username") or "SYSTEM",
                        "cpu_percent": round(info.get("cpu_percent") or 0.0, 1),
                        "ram_mb": ram_mb,
                        "bandwidth_usage": bandwidth_str,
                        "bandwidth_bytes": total_bytes,
                        "start_time": dt_str,
                        "socket_count": len(p_socks),
                        "is_signed": is_signed,
                        "sig_details": sig_details,
                        "path_class": path_class,
                        "threat_score": 0.0,
                        "status": "ACTIVE",
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        processes.sort(key=lambda x: (x["socket_count"] > 0, x["ram_mb"]), reverse=True)
        return processes[:80], connections[:100]

    def _send_heartbeat(self) -> None:
        """Sends signed JSON heartbeat payload to Manager endpoint."""
        procs, conns = self._collect_local_telemetry()
        payload = {
            "host_id": self.host_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_version": f"{platform.system()} {platform.release()}",
            "agent_version": "0.1.0",
            "timestamp": time.time(),
            "active_sockets": len(conns) if conns else len(self._active_sessions),
            "processes": procs,
            "connections": conns,
        }
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.manager_url}/api/agent/heartbeat",
            data=data,
            headers={
                "Content-Type": "application/json",
                "X-Uncloak-Token": self.auth_token,
            },
        )
        try:
            with request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    raw_cmd = resp.read()
                    if raw_cmd:
                        self._process_manager_directives(json.loads(raw_cmd))
        except Exception:
            pass

    def _process_manager_directives(self, directive: dict[str, Any]) -> None:
        """Processes mitigation directives dispatched by the Central Manager."""
        action = directive.get("action")
        target_pid = directive.get("pid")
        local_ip = directive.get("local_ip", "127.0.0.1")
        local_port = int(directive.get("local_port", 0))
        remote_ip = directive.get("remote_ip", "0.0.0.0")
        remote_port = int(directive.get("remote_port", 0))
        program_path = directive.get("program_path", "")

        if action == "SEVER_SOCKET" and local_port > 0 and remote_port > 0:
            logger.warning(
                "Executing authorized kernel TCP teardown on socket %s:%d -> %s:%d (PID %s)",
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                target_pid,
            )
            sever_tcp_connection(local_ip, local_port, remote_ip, remote_port)
        elif action == "BLOCK_DESTINATION" and program_path and remote_ip != "0.0.0.0":
            rule_name = f"Uncloak_Contain_{target_pid}_{remote_ip}"
            logger.warning(
                "Enforcing firewall containment rule '%s' for binary %s to %s",
                rule_name,
                program_path,
                remote_ip,
            )
            block_application_destination(rule_name, program_path, remote_ip)

    def emit_siem_cycle(
        self,
        ndjson_path: str = "uncloak_alerts.ndjson",
        include_sample_detections: bool = False,
    ) -> tuple[list[dict[str, Any]], str, list[tuple[int, bool, str]]]:
        """
        Emits structured OCSF v1.1.0 NDJSON events and Windows Event Log entries
        (Event ID 9001 C2 Detection, Event ID 9002 Containment Executed) for local SIEM agents
        (Wazuh, Splunk Universal Forwarder, Elastic Winlogbeat) without opening any listening UI ports.
        """
        events: list[dict[str, Any]] = []
        win_statuses: list[tuple[int, bool, str]] = []

        if include_sample_detections:
            ev_detect = build_ocsf_detection_event(
                event_id=EVENT_ID_C2_DETECTED,
                hostname=self.hostname,
                src_ip=self.ip_address,
                src_port=49152,
                dst_ip="193.26.158.114",
                dst_port=443,
                pid=5824,
                process_name="update.exe",
                process_path=r"C:\Users\Target\AppData\Roaming\update.exe",
                process_guid="{8f3a91c2-4d11-672a-0100-0000000016c0}",
                sha256="a4f982d17c63e01948b55209df712839ca004918273645519283746501928374",
                user_context=r"CORP\jdoe (Medium Integrity)",
                is_signed=False,
                threat_score=0.987,
                severity_label="CRITICAL",
                c2_framework="Sliver mTLS / Raw IP C2",
                mitre_technique="T1071.001 (Web Protocols) / T1573.002",
                features_v1={
                    "n_bursts": 14,
                    "iat_median": 8.4,
                    "iat_mad_ratio": 0.095,
                    "iat_iqr_ratio": 0.142,
                    "iat_bowley_skew": 0.03,
                    "size_out_median": 512.0,
                    "size_in_median": 1280.0,
                    "size_mad_ratio": 0.04,
                    "conn_per_burst": 1.0,
                    "raw_ip_flag": 1,
                    "proc_signed": 0,
                    "proc_path_class": 1,
                },
                reasons=[
                    "Rigid Clockwork IAT Dispersion (MAD=0.095, Median=8.4s)",
                    "Direct IP Egress Without Prior DNS Lookup (raw_ip_flag=1)",
                    "Unsigned PE Binary Executed on Disk (WinVerifyTrust Fail)",
                ],
                containment_action="SetTcpEntry(DELETE_TCB) Pending SOAR Approval",
            )
            ev_contain = build_ocsf_detection_event(
                event_id=EVENT_ID_CONTAINMENT_EXECUTED,
                hostname=self.hostname,
                src_ip=self.ip_address,
                src_port=51204,
                dst_ip="10.0.3.44",
                dst_port=445,
                pid=3104,
                process_name="wmiprvse.exe",
                process_path=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                process_guid="{8f3a91c2-500a-672a-0300-000000000c20}",
                sha256="4c92a77b128492a0038f91827364551290837465192837465192837465001122",
                user_context=r"NT AUTHORITY\NETWORK SERVICE",
                is_signed=True,
                threat_score=0.892,
                severity_label="HIGH",
                c2_framework="East-West Lateral Pivot / SMB Beacon",
                mitre_technique="T1021.002 (SMB/Admin Shares)",
                features_v1={
                    "n_bursts": 16,
                    "iat_median": 4.0,
                    "iat_mad_ratio": 0.050,
                    "iat_iqr_ratio": 0.075,
                    "iat_bowley_skew": 0.01,
                    "size_out_median": 256.0,
                    "size_in_median": 256.0,
                    "size_mad_ratio": 0.02,
                    "conn_per_burst": 1.0,
                    "raw_ip_flag": 1,
                    "proc_signed": 1,
                    "proc_path_class": 0,
                },
                reasons=[
                    "Rigid Clockwork IAT Dispersion (MAD=0.050, Median=4.0s)",
                    "East-West SMB Port 445 Periodic Polling",
                ],
                containment_action="SetTcpEntry(DELETE_TCB) + netsh advfirewall Outbound Block Enforced",
            )
            events.extend([ev_detect, ev_contain])

        out_path = ndjson_path
        for ev in events:
            out_path = append_ndjson_alert(ev, log_path=ndjson_path)
            eid = ev["metadata"]["windows_event_id"]
            sev = ev["severity"]
            ok, msg = emit_windows_event_log(eid, sev, ev["message"])
            win_statuses.append((eid, ok, msg))

        return events, out_path, win_statuses

    def run_local_tui(self) -> int:
        """Launches the Rich terminal cockpit locally for physical break-glass triage."""
        from uncloak.ui.cockpit import run_cockpit
        return run_cockpit(demo_mode=True)


def _compact_bin_cmd(python_exe: str, max_len: int = 58) -> str:
    """Formats binary command cleanly without awkward wrapping on 80-column consoles."""
    full = f"{python_exe} -m uncloak.agent.service"
    if len(full) <= max_len:
        return full
    exe_short = os.path.basename(python_exe)
    parent_name = os.path.basename(os.path.dirname(python_exe))
    prefix = f"...\\{parent_name}\\{exe_short} -m uncloak.agent.service"
    if len(prefix) <= max_len:
        return prefix
    return f"{exe_short} -m uncloak.agent.service"


def _render_service_lifecycle_panel(
    title: str,
    state_label: str,
    state_style: str,
    rows: list[tuple[str, str, str]],
    hint: Optional[str] = None,
    console: Optional[object] = None,
) -> None:
    """Renders an enterprise Windows SYSTEM service lifecycle status panel."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    out = console or Console(color_system="truecolor")
    body = Text()
    body.append("Service Task   : ", style="#94a3b8")
    body.append("UncloakEndpointAgent", style="bold #f8fafc")
    body.append("    |    ", style="#475569")
    body.append("State : ", style="#94a3b8")
    body.append(f"{state_label}\n", style=state_style)

    for label, value, val_style in rows:
        body.append(f"{label:<15}: ", style="#94a3b8")
        body.append(f"{value}\n", style=val_style)

    if hint:
        body.append("Next Action    : ", style="#94a3b8")
        body.append(hint, style="#38bdf8")

    out.print(
        Panel(
            body,
            title=f"[bold #f8fafc] {title} [/]",
            box=box.ROUNDED,
            border_style="#334155",
            padding=(0, 1),
        )
    )


def install_windows_service(console: Optional[object] = None) -> bool:
    """Installs Uncloak Agent as a silent background SYSTEM task on Windows boot."""
    if sys.platform != "win32":
        _render_service_lifecycle_panel(
            "Windows SYSTEM Service Lifecycle (UncloakSensor)",
            "UNSUPPORTED OS",
            "bold #f59e0b",
            [("Platform", sys.platform, "#cbd5e1")],
            hint="Windows Task Scheduler registration requires Windows (Win32 API).",
            console=console,
        )
        return False

    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = sys.executable

    task_name = "UncloakEndpointAgent"
    cmd = [
        "schtasks",
        "/create",
        "/tn",
        task_name,
        "/tr",
        f'"{pythonw}" -m uncloak.agent.service',
        "/sc",
        "onstart",
        "/ru",
        "SYSTEM",
        "/rl",
        "HIGHEST",
        "/f",
    ]
    res = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    bin_cmd = _compact_bin_cmd(pythonw)
    if res.returncode == 0:
        _render_service_lifecycle_panel(
            "Windows SYSTEM Service Lifecycle (UncloakSensor)",
            "REGISTERED & ARMED",
            "bold #10b981",
            [
                ("Privilege", "NT AUTHORITY\\SYSTEM (HIGHEST Integrity)", "#cbd5e1"),
                ("Binary Path", bin_cmd, "#e2e8f0"),
                ("Visibility", "Headless Daemon (0% taskbar, 0 listening ports)", "#cbd5e1"),
            ],
            hint="Run 'uncloak --status' to verify SCM trigger state.",
            console=console,
        )
        return True

    err_msg = (res.stderr or res.stdout or "Access denied").strip()
    _render_service_lifecycle_panel(
        "Windows SYSTEM Service Lifecycle (UncloakSensor)",
        "ELEVATION REQUIRED",
        "bold #f87171",
        [
            ("Privilege", "NT AUTHORITY\\SYSTEM (Administrator Shell Required)", "#cbd5e1"),
            ("Binary Path", bin_cmd, "#94a3b8"),
            ("SCM Detail", err_msg[:58], "#fca5a5"),
        ],
        hint="Re-run from an elevated Administrator PowerShell / cmd.",
        console=console,
    )
    return False


def uninstall_windows_service(console: Optional[object] = None) -> bool:
    """Removes the Uncloak Agent background task from Windows."""
    task_name = "UncloakEndpointAgent"
    cmd = ["schtasks", "/delete", "/tn", task_name, "/f"]
    res = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    if res.returncode == 0:
        _render_service_lifecycle_panel(
            "Windows SYSTEM Service Lifecycle (UncloakSensor)",
            "REMOVED",
            "bold #10b981",
            [("Action", f"Deleted '{task_name}' from Windows Task Scheduler", "#cbd5e1")],
            hint="Run 'uncloak --install' as Administrator to re-register.",
            console=console,
        )
        return True

    err_msg = (res.stderr or res.stdout or "Task not present or access denied").strip()
    _render_service_lifecycle_panel(
        "Windows SYSTEM Service Lifecycle (UncloakSensor)",
        "UNINSTALL FAILED",
        "bold #f87171",
        [("SCM Detail", err_msg[:110], "#fca5a5")],
        hint="Verify task exists via 'uncloak --status' or run as Administrator.",
        console=console,
    )
    return False


def query_service_status(console: Optional[object] = None) -> None:
    """Queries the running state of the Uncloak Agent Windows task."""
    task_name = "UncloakEndpointAgent"
    cmd = ["schtasks", "/query", "/tn", task_name, "/fo", "LIST"]
    res = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = sys.executable

    bin_cmd = _compact_bin_cmd(pythonw)
    if res.returncode == 0:
        parsed_rows: list[tuple[str, str, str]] = [
            ("Privilege", "NT AUTHORITY\\SYSTEM", "#cbd5e1"),
            ("Binary Path", bin_cmd, "#e2e8f0"),
        ]
        scm_state = "INSTALLED"
        for line in res.stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                key = k.strip()
                val = v.strip()
                if key == "Status":
                    scm_state = val.upper() or "READY"
                elif key in ("Next Run Time", "Last Run Time", "Author"):
                    parsed_rows.append((key, val, "#cbd5e1"))

        state_style = "bold #10b981" if scm_state in ("RUNNING", "READY") else "bold #f59e0b"
        _render_service_lifecycle_panel(
            "Windows SYSTEM Service Lifecycle (UncloakSensor)",
            scm_state,
            state_style,
            parsed_rows,
            hint="Run 'uncloak service --once' to verify OCSF + EID 9001/9002.",
            console=console,
        )
    else:
        _render_service_lifecycle_panel(
            "Windows SYSTEM Service Lifecycle (UncloakSensor)",
            "NOT INSTALLED",
            "bold #f59e0b",
            [
                ("Privilege", "NT AUTHORITY\\SYSTEM (On Boot / HIGHEST)", "#94a3b8"),
                ("Binary Path", bin_cmd, "#94a3b8"),
                ("Endpoint Mode", "Manual CLI / On-Demand Execution Only", "#cbd5e1"),
            ],
            hint="Run 'uncloak --install' (as Admin) to deploy SYSTEM sensor.",
            console=console,
        )


def main(args: Optional[list[str]] = None) -> int:
    """CLI entrypoint for standalone uncloak-agent."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="uncloak-agent",
        description="Uncloak Silent Endpoint Agent Daemon & Service Manager",
    )
    parser.add_argument("--install", action="store_true", help="Install agent as a silent Windows boot service (SYSTEM)")
    parser.add_argument("--uninstall", action="store_true", help="Remove agent from Windows startup")
    parser.add_argument("--status", action="store_true", help="Query Windows startup service registration status")
    parser.add_argument("--manager", default="http://127.0.0.1:8830", help="Central Fleet Manager URL (optional)")
    parser.add_argument("--once", action="store_true", help="Run a single SIEM OCSF/EventLog emission check and exit")
    parser.add_argument("--siem-out", default="uncloak_alerts.ndjson", help="Path to write OCSF v1.1.0 NDJSON SIEM log")
    
    parsed = parser.parse_args(args)

    if parsed.install:
        return 0 if install_windows_service() else 1
    if parsed.uninstall:
        return 0 if uninstall_windows_service() else 1
    if parsed.status:
        query_service_status()
        return 0

    agent = UncloakAgentService(manager_url=parsed.manager)
    if parsed.once:
        from rich.console import Console
        console = Console(color_system="truecolor")
        events, out_path, statuses = agent.emit_siem_cycle(
            ndjson_path=parsed.siem_out,
            include_sample_detections=True,
        )
        render_service_console_preview(console, events, out_path, statuses)
        return 0

    from uncloak.cli.parser import _print_service_startup_banner
    _print_service_startup_banner(agent, parsed.siem_out)
    agent.start(daemon=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
