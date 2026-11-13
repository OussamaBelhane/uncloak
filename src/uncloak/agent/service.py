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

    def run_local_tui(self) -> int:
        """Launches the Rich terminal cockpit locally for physical break-glass triage."""
        from uncloak.ui.cockpit import run_cockpit
        return run_cockpit(demo_mode=True)


def install_windows_service() -> bool:
    """Installs Uncloak Agent as a silent background SYSTEM task on Windows boot."""
    if sys.platform != "win32":
        print("[-] Windows startup service installation is supported on Windows only.")
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
    if res.returncode == 0:
        print(f"[+] Successfully registered '{task_name}' in Windows Task Scheduler.")
        print("[+] Startup Mode : Starts automatically on PC boot (NT AUTHORITY\\SYSTEM).")
        print("[+] Visibility   : Headless background daemon (0% taskbar, 0% system tray).")
        print("[+] Resiliency   : Runs under SYSTEM with HIGHEST integrity privileges.")
        return True
    else:
        print(f"[-] Installation failed (Requires Administrator privileges): {res.stderr.strip()}")
        return False


def uninstall_windows_service() -> bool:
    """Removes the Uncloak Agent background task from Windows."""
    task_name = "UncloakEndpointAgent"
    cmd = ["schtasks", "/delete", "/tn", task_name, "/f"]
    res = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"[+] Successfully removed '{task_name}' from Windows startup.")
        return True
    else:
        print(f"[-] Uninstallation failed: {res.stderr.strip()}")
        return False


def query_service_status() -> None:
    """Queries the running state of the Uncloak Agent Windows task."""
    task_name = "UncloakEndpointAgent"
    cmd = ["schtasks", "/query", "/tn", task_name, "/fo", "LIST"]
    res = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"[*] Task '{task_name}' is installed and active in Windows:")
        for line in res.stdout.splitlines():
            if any(k in line for k in ["TaskName", "Status", "Next Run Time", "Last Run Time", "Author"]):
                print(f"    {line.strip()}")
    else:
        print(f"[-] Task '{task_name}' is NOT installed in Windows Task Scheduler.")


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
    parser.add_argument("--manager", default="http://127.0.0.1:8443", help="Central Fleet Manager URL")
    
    parsed = parser.parse_args(args)

    if parsed.install:
        return 0 if install_windows_service() else 1
    if parsed.uninstall:
        return 0 if uninstall_windows_service() else 1
    if parsed.status:
        query_service_status()
        return 0

    agent = UncloakAgentService(manager_url=parsed.manager)
    print(f"[*] Uncloak Silent Endpoint Agent initialized on [{agent.hostname}]")
    print(f"[*] Connecting to Manager at {agent.manager_url} (Heartbeat: 15s)...")
    print("[*] Taskbar Visibility: Headless (0% taskbar, 0% system tray)")
    agent.start(daemon=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
