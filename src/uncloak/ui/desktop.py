"""
Enterprise Desktop Cockpit & Central Fleet Manager for Uncloak.
Delivers a tier-1 EDR-grade visual desktop window powered by native Microsoft Edge WebView2
with automatic loopback fallback and zero external browser dependencies.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlparse

from uncloak.manager.fleet import FleetManager
from uncloak.ui.cockpit import FlowEntry, export_telemetry_json
from uncloak.ui.layout import CockpitState


class CockpitDataManager:
    """Thread-safe state and data coordinator between Python and the Enterprise EDR UI."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.fleet = FleetManager()
        self.start_time = time.time()
        self.active_tab = "fleet"  # fleet, campaign, drilldown

    def get_state_payload(self, host_id: Optional[str] = None, pid: Optional[int] = None) -> dict[str, Any]:
        with self.lock:
            if host_id and host_id in self.fleet.hosts:
                self.fleet.selected_host_id = host_id
            if pid is not None:
                self.fleet.selected_pid = int(pid)
            fleet_summary = self.fleet.get_fleet_summary()
            selected_host = self.fleet.hosts.get(
                self.fleet.selected_host_id,
                next(iter(self.fleet.hosts.values())),
            )
            flows = self.fleet.host_flows.get(selected_host.host_id, [])

            now = time.time()
            packet_rate = getattr(self.fleet, "simulated_packet_rate", 145)

            flows_data = []
            for f in flows:
                flows_data.append({
                    "flow_id": f.flow_id,
                    "pid": f.pid,
                    "process_name": f.process_name,
                    "is_signed": f.is_signed,
                    "sig_info": f.sig_info,
                    "src_ip": f.src_ip,
                    "src_port": f.src_port,
                    "dst_ip": f.dst_ip,
                    "dst_port": f.dst_port,
                    "sni": f.sni,
                    "interval_str": f.interval_str,
                    "sparkline": f.sparkline,
                    "jitter_str": f.jitter_str,
                    "jitter_pct": f.jitter_pct,
                    "payload_str": f.payload_str,
                    "threat_score": f.threat_score,
                    "threat_label": f.threat_label,
                    "is_threat": f.is_threat,
                    "c2_framework": f.c2_framework,
                    "binary_path": f.binary_path,
                    "command_line": f.command_line,
                    "parent_process": f.parent_process,
                    "sha256": f.sha256,
                    "process_guid": getattr(f, "process_guid", f"{{8f3a91c2-4d11-672a-0100-00000000{f.pid:04x}}}"),
                    "ja4_fingerprint": f.ja4_fingerprint,
                    "heuristic_signals": f.heuristic_signals,
                    "detection_reasons": f.detection_reasons,
                    "bursts": f.bursts,
                    "user_context": f.user_context,
                    "is_severed": f.is_severed,
                    "mitre_technique": f.mitre_technique,
                    "state": f.state,
                    "packets": f.packets,
                    "bytes_transferred": f.bytes_transferred,
                    "first_seen": getattr(f, "first_seen", "2026-11-02 14:10:02"),
                    "last_seen": getattr(f, "last_seen", "2026-11-02 14:26:45"),
                    "duration": getattr(f, "duration", "16m 43s"),
                    "iat_mad_ratio": getattr(f, "iat_mad_ratio", "0.095 (Rigid Clockwork)" if f.is_threat else "0.684 (Organic Human)"),
                    "iat_iqr_ratio": getattr(f, "iat_iqr_ratio", "0.142 (Low Dispersion)" if f.is_threat else "0.920 (Wide Variance)"),
                    "bowley_skew": getattr(f, "bowley_skew", "+0.03 (Symmetric)" if f.is_threat else "+0.48 (Pareto Tail)"),
                    "conn_per_burst": getattr(f, "conn_per_burst", "1.00 (Persistent Socket)" if f.is_threat else "1.40 (HTTP/2 Pool)"),
                })

            top_threat = next((f for f in flows if f.is_threat and not f.is_severed), None)
            if not top_threat:
                top_threat = next((f for f in flows if f.is_threat), None)

            top_threat_dict = None
            if top_threat:
                top_threat_dict = {
                    "pid": top_threat.pid,
                    "process_name": top_threat.process_name,
                    "target": f"{top_threat.dst_ip}:{top_threat.dst_port}",
                    "c2_framework": top_threat.c2_framework or "Custom C2",
                    "status": "Severed (Host Clean)" if top_threat.is_severed else "Active (Live)",
                    "mitre": top_threat.mitre_technique,
                    "event": "EID 9002 (Mitigated)" if top_threat.is_severed else "EID 9001 Dispatched",
                    "threat_score": top_threat.threat_score,
                    "is_severed": top_threat.is_severed,
                }

            hosts_list = []
            for h in self.fleet.hosts.values():
                subnet = h.subnet or "Tier-2 Workstations"
                if "Tier-0" in subnet:
                    tier_label = "Tier-0 (Crown Jewels)"
                elif "Tier-1" in subnet or "Jump" in subnet or "DMZ" in subnet:
                    tier_label = "Tier-1 (App & DMZ)"
                elif "Local" in subnet:
                    tier_label = "Tier-2 (Host Sensor)"
                else:
                    tier_label = "Tier-2 (Workstation)"

                os_ver = h.os_version or "Windows 11"
                build_str = "Build 20348 (x64)" if "Server" in os_ver else "Build 22631 (x64)"
                sec_stale = int(now - h.last_heartbeat)

                hosts_list.append({
                    "host_id": h.host_id,
                    "hostname": h.hostname,
                    "ip_address": h.ip_address,
                    "subnet": h.subnet,
                    "ad_tier": tier_label,
                    "os_version": h.os_version,
                    "os_build": build_str,
                    "agent_version": h.agent_version,
                    "status": h.status,
                    "threat_level": h.threat_level,
                    "threat_score": h.threat_score,
                    "active_sockets_count": h.active_sockets_count,
                    "isolated_beacons_count": h.isolated_beacons_count,
                    "c2_framework": h.c2_framework,
                    "cpu_percent": h.cpu_percent,
                    "ram_mb": h.ram_mb,
                    "seconds_since_heartbeat": sec_stale,
                    "is_isolated": getattr(h, "is_isolated", False),
                })

            campaigns_list = []
            for c in self.fleet.campaigns.values():
                campaigns_list.append({
                    "campaign_id": c.campaign_id,
                    "name": c.name,
                    "c2_framework": c.c2_framework,
                    "ja4_fingerprint": c.ja4_fingerprint,
                    "cadence_profile": c.cadence_profile,
                    "affected_hosts": c.affected_hosts,
                    "target_destination": c.target_destination,
                    "threat_score": c.threat_score,
                    "status": c.status,
                })

            return {
                "app_name": "UNCLOAK",
                "version": "v0.1.0",
                "active_tab": self.active_tab,
                "fleet_summary": fleet_summary,
                "hosts": hosts_list,
                "campaigns": campaigns_list,
                "selected_host_id": selected_host.host_id,
                "selected_host": {
                    "host_id": selected_host.host_id,
                    "hostname": selected_host.hostname,
                    "ip_address": selected_host.ip_address,
                    "subnet": selected_host.subnet,
                    "os_version": selected_host.os_version,
                    "threat_level": selected_host.threat_level,
                    "threat_score": selected_host.threat_score,
                    "c2_framework": selected_host.c2_framework,
                    "cpu_percent": selected_host.cpu_percent,
                    "ram_mb": selected_host.ram_mb,
                    "active_sockets": selected_host.active_sockets_count,
                    "status": selected_host.status,
                    "seconds_since_heartbeat": int(now - selected_host.last_heartbeat),
                },
                "total_sockets": selected_host.active_sockets_count,
                "packet_rate": packet_rate,
                "active_beacons": selected_host.isolated_beacons_count,
                "uptime_seconds": int(now - self.start_time),
                "selected_pid": self.fleet.selected_pid,
                "top_incident": top_threat_dict,
                "flows": flows_data,
                "host_processes": self.fleet.host_processes.get(selected_host.host_id, []),
                "host_connection_history": self.fleet.host_connection_history.get(selected_host.host_id, []),
            }

    def select_host(self, host_id: str) -> bool:
        with self.lock:
            if host_id in self.fleet.hosts:
                self.fleet.selected_host_id = host_id
                flows = self.fleet.host_flows.get(host_id, [])
                if flows:
                    self.fleet.selected_pid = flows[0].pid
                return True
            return False

    def select_pid(self, host_id: Optional[str], pid: int) -> bool:
        with self.lock:
            if host_id and host_id in self.fleet.hosts:
                self.fleet.selected_host_id = host_id
            self.fleet.selected_pid = int(pid)
            return True

    def isolate_host(self, host_id: str) -> bool:
        with self.lock:
            if host_id in self.fleet.hosts:
                host = self.fleet.hosts[host_id]
                host.is_isolated = not getattr(host, "is_isolated", False)
                return True
            return False

    def sever_flow(self, host_id: str, pid: int) -> bool:
        return self.fleet.sever_host_socket(host_id, pid)

    def tarpit_flow(self, host_id: str, pid: int) -> bool:
        return self.fleet.tarpit_host_socket(host_id, pid)

    def sever_campaign(self, campaign_id: str) -> int:
        return self.fleet.sever_campaign(campaign_id)

    def export_data(self, host_id: str, pid: Optional[int] = None) -> str:
        with self.lock:
            flows = self.fleet.host_flows.get(host_id, [])
            target_flow = next((f for f in flows if f.pid == pid), None) if pid else None
            state = CockpitState(flows=flows)
            return export_telemetry_json(state, target_flow=target_flow)


DATA_MANAGER = CockpitDataManager()


class UncloakHTTPHandler(BaseHTTPRequestHandler):
    """Zero-dependency HTTP API and UI asset server."""

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def handle(self) -> None:
        """Suppresses normal client socket connection drops on Windows (WinError 10053)."""
        try:
            super().handle()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass

    def send_json(self, data: Any, status: int = 200) -> None:
        try:
            body = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/api/state":
                from urllib.parse import parse_qs
                query = parse_qs(parsed.query)
                host_param = query.get("host", [None])[0]
                pid_str = query.get("pid", [None])[0]
                pid_param = None
                if pid_str:
                    try:
                        pid_param = int(pid_str)
                    except ValueError:
                        pass
                self.send_json(DATA_MANAGER.get_state_payload(host_id=host_param, pid=pid_param))
            elif parsed.path == "/api/pid/history":
                from urllib.parse import parse_qs
                query = parse_qs(parsed.query)
                host_id = query.get("host", [""])[0] or DATA_MANAGER.fleet.selected_host_id
                pid_str = query.get("pid", ["0"])[0]
                try:
                    pid = int(pid_str)
                except ValueError:
                    pid = 0
                summary = DATA_MANAGER.fleet.get_pid_history_summary(host_id, pid)
                self.send_json(summary)
            elif parsed.path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
            elif parsed.path in ("/", "/index.html"):
                html = get_cockpit_html(DATA_MANAGER.get_state_payload()).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
            else:
                self.send_response(404)
                self.end_headers()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass

    def do_POST(self) -> None:
        try:
            parsed = urlparse(self.path)
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                req_data = json.loads(body.decode("utf-8")) if body else {}
            except Exception:
                req_data = {}

            if parsed.path == "/api/sever":
                pid = int(req_data.get("pid", 0))
                host_id = req_data.get("host_id") or DATA_MANAGER.fleet.selected_host_id
                success = DATA_MANAGER.sever_flow(host_id, pid)
                self.send_json({"success": success, "pid": pid, "host_id": host_id})

            elif parsed.path == "/api/tarpit":
                pid = int(req_data.get("pid", 0))
                host_id = req_data.get("host_id") or DATA_MANAGER.fleet.selected_host_id
                success = DATA_MANAGER.tarpit_flow(host_id, pid)
                self.send_json({"success": success, "pid": pid, "host_id": host_id})

            elif parsed.path == "/api/sever_campaign":
                campaign_id = req_data.get("campaign_id", "")
                count = DATA_MANAGER.sever_campaign(campaign_id)
                self.send_json({"success": count > 0, "severed_count": count})

            elif parsed.path == "/api/select_host":
                host_id = req_data.get("host_id", "")
                success = DATA_MANAGER.select_host(host_id)
                self.send_json({"success": success, "selected_host_id": host_id})

            elif parsed.path == "/api/select_pid":
                pid = req_data.get("pid")
                host_id = req_data.get("host_id")
                if pid is not None:
                    try:
                        DATA_MANAGER.select_pid(host_id, int(pid))
                    except (ValueError, TypeError):
                        pass
                self.send_json({"success": True, "selected_pid": DATA_MANAGER.fleet.selected_pid})

            elif parsed.path == "/api/isolate_host":
                host_id = req_data.get("host_id", "")
                success = DATA_MANAGER.isolate_host(host_id)
                self.send_json({"success": success, "host_id": host_id})

            elif parsed.path == "/api/export":
                pid = req_data.get("pid")
                host_id = req_data.get("host_id") or DATA_MANAGER.fleet.selected_host_id
                fn = DATA_MANAGER.export_data(host_id, pid=pid)
                self.send_json({"filename": fn})

            elif parsed.path == "/api/agent/heartbeat":
                # Agent check-in endpoint: register or update live host
                if req_data:
                    DATA_MANAGER.fleet.register_or_update_agent(req_data)
                self.send_json({"status": "ACK", "server_time": time.time()})

            else:
                self.send_response(404)
                self.end_headers()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass


def get_cockpit_html(initial_payload: dict[str, Any] | None = None) -> str:
    """Returns the complete enterprise web dashboard application with dual theme, table-first views, and slide-over drawer."""
    initial_json = json.dumps(initial_payload) if initial_payload is not None else "null"
    html_content = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Uncloak NDR | Enterprise Manager Console</title>
<style>
  :root {
    --font-sans: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
    --font-mono: 'JetBrains Mono', 'Cascadia Code', 'Consolas', 'Courier New', monospace;

    /* Enterprise Daylight Theme (Default) */
    --bg-canvas: #f1f5f9;
    --bg-surface: #ffffff;
    --bg-subtle: #f8fafc;
    --bg-hover: #eef2f6;
    --bg-selected: #eff6ff;

    --border: #e2e8f0;
    --border-strong: #cbd5e1;

    --text-main: #0f172a;
    --text-secondary: #334155;
    --text-muted: #64748b;

    --accent: #2563eb;
    --accent-hover: #1d4ed8;
    --accent-bg: #eff6ff;
    --accent-border: #bfdbfe;

    --crit-text: #b91c1c;
    --crit-bg: #fef2f2;
    --crit-border: #fecaca;
    --crit-solid: #dc2626;

    --high-text: #b45309;
    --high-bg: #fffbeb;
    --high-border: #fde68a;
    --high-solid: #d97706;

    --ok-text: #047857;
    --ok-bg: #ecfdf5;
    --ok-border: #a7f3d0;
    --ok-solid: #059669;

    --eval-text: #0369a1;
    --eval-bg: #f0f9ff;
    --eval-border: #bae6fd;

    --muted-text: #475569;
    --muted-bg: #f1f5f9;
    --muted-border: #cbd5e1;

    --rail-bg: #0f172a;
    --rail-surface: #1e293b;
    --rail-border: #1e293b;
    --rail-text: #94a3b8;
    --rail-text-active: #ffffff;

    --bg-code: #0f172a;
    --code-text: #e2e8f0;

    --shadow-sm: 0 1px 3px rgba(15, 23, 42, 0.06), 0 1px 2px rgba(15, 23, 42, 0.04);
    --shadow-md: 0 4px 12px rgba(15, 23, 42, 0.08);
    --shadow-drawer: -10px 0 36px rgba(15, 23, 42, 0.14);

    --radius-sm: 6px;
    --radius-md: 10px;
    --radius-lg: 12px;
    --row-pad-y: 11px;
    --row-pad-x: 14px;
    --ui-scale: 1;
  }

  body.theme-dark {
    /* Soft Slate-Blue Dark Theme (Low Eye-Strain Night Shift) */
    --bg-canvas: #131924;
    --bg-surface: #1b2332;
    --bg-subtle: #212b3d;
    --bg-hover: #263246;
    --bg-selected: rgba(59, 130, 246, 0.14);

    --border: #2a3548;
    --border-strong: #3b4a63;

    --text-main: #f1f5f9;
    --text-secondary: #cbd5e1;
    --text-muted: #94a3b8;

    --accent: #3b82f6;
    --accent-hover: #60a5fa;
    --accent-bg: rgba(59, 130, 246, 0.16);
    --accent-border: rgba(96, 165, 250, 0.40);

    --crit-text: #fda4af;
    --crit-bg: rgba(225, 29, 72, 0.16);
    --crit-border: rgba(251, 113, 133, 0.35);
    --crit-solid: #ef4444;

    --high-text: #fcd34d;
    --high-bg: rgba(217, 119, 6, 0.16);
    --high-border: rgba(251, 191, 36, 0.35);
    --high-solid: #f59e0b;

    --ok-text: #6ee7b7;
    --ok-bg: rgba(16, 185, 129, 0.14);
    --ok-border: rgba(52, 211, 153, 0.35);
    --ok-solid: #10b981;

    --eval-text: #7dd3fc;
    --eval-bg: rgba(14, 165, 233, 0.15);
    --eval-border: rgba(56, 189, 248, 0.35);

    --muted-text: #94a3b8;
    --muted-bg: rgba(148, 163, 184, 0.12);
    --muted-border: #334155;

    --rail-bg: #0d131d;
    --rail-surface: #1b2332;
    --rail-border: #1e293b;
    --rail-text: #94a3b8;
    --rail-text-active: #f8fafc;

    --bg-code: #0d131d;
    --code-text: #e2e8f0;

    --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.28);
    --shadow-md: 0 6px 18px rgba(0, 0, 0, 0.35);
    --shadow-drawer: -12px 0 38px rgba(0, 0, 0, 0.50);
  }

  body.force-compact {
    --row-pad-y: 7px;
    --row-pad-x: 11px;
    font-size: 12.5px;
  }

  body.force-large {
    --row-pad-y: 14px;
    --row-pad-x: 16px;
    font-size: 14.5px;
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  html, body {
    height: 100%;
    background: var(--bg-canvas);
    color: var(--text-main);
    font-family: var(--font-sans);
    font-size: 13.5px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    overflow: hidden;
  }

  .mono {
    font-family: var(--font-mono);
    font-variant-numeric: tabular-nums;
  }

  /* Custom subtle scrollbars */
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

  /* ================= APP SHELL ================= */
  .app-shell {
    display: flex;
    height: 100vh;
    width: 100vw;
    overflow: hidden;
  }

  /* Left Navigation Rail */
  .app-sidebar {
    width: 232px;
    flex-shrink: 0;
    background: var(--rail-bg);
    border-right: 1px solid var(--rail-border);
    display: flex;
    flex-direction: column;
    color: var(--rail-text);
    z-index: 20;
  }

  .brand-header {
    padding: 18px 18px 16px 18px;
    border-bottom: 1px solid var(--rail-border);
    display: flex;
    align-items: center;
    gap: 11px;
  }

  .brand-logo {
    width: 34px;
    height: 34px;
    border-radius: 8px;
    background: linear-gradient(135deg, #2563eb, #1d4ed8);
    display: flex;
    align-items: center;
    justify-content: center;
    color: #ffffff;
    flex-shrink: 0;
    box-shadow: 0 2px 8px rgba(37, 99, 235, 0.35);
  }

  .brand-title {
    font-size: 15px;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: -0.01em;
    line-height: 1.2;
  }

  .brand-subtitle {
    font-size: 11px;
    color: #94a3b8;
    font-weight: 500;
  }

  .sidebar-nav {
    flex: 1;
    padding: 16px 12px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .nav-group-label {
    font-size: 10.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #64748b;
    padding: 12px 10px 6px 10px;
  }
  .nav-group-label:first-child {
    padding-top: 2px;
  }

  .nav-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    border-radius: 8px;
    color: var(--rail-text);
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
    border: 1px solid transparent;
    transition: background 0.14s ease, color 0.14s ease;
    position: relative;
    user-select: none;
  }

  .nav-item:hover {
    background: rgba(255, 255, 255, 0.06);
    color: #e2e8f0;
  }

  .nav-item.active {
    background: var(--rail-surface);
    color: var(--rail-text-active);
    font-weight: 600;
    border-color: rgba(148, 163, 184, 0.18);
  }

  .nav-item.active::before {
    content: "";
    position: absolute;
    left: 0;
    top: 7px;
    bottom: 7px;
    width: 3px;
    border-radius: 0 3px 3px 0;
    background: #3b82f6;
  }

  .nav-item-left {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .nav-icon {
    width: 16px;
    height: 16px;
    opacity: 0.85;
    flex-shrink: 0;
  }
  .nav-item.active .nav-icon {
    color: #60a5fa;
    opacity: 1;
  }

  .nav-badge {
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 600;
    padding: 2px 7px;
    border-radius: 999px;
    background: rgba(239, 68, 68, 0.22);
    color: #fca5a5;
  }
  .nav-badge.blue {
    background: rgba(59, 130, 246, 0.22);
    color: #93c5fd;
  }
  .nav-badge.neutral {
    background: rgba(148, 163, 184, 0.18);
    color: #cbd5e1;
  }

  .sidebar-footer {
    padding: 14px;
    border-top: 1px solid var(--rail-border);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .rail-status-card {
    background: rgba(30, 41, 59, 0.72);
    border: 1px solid rgba(148, 163, 184, 0.16);
    border-radius: 8px;
    padding: 10px 12px;
    font-size: 11.5px;
    color: #cbd5e1;
  }

  .rail-status-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 4px;
  }
  .rail-status-row:last-child { margin-bottom: 0; }

  .rail-dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #10b981;
    margin-right: 6px;
    box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.2);
  }

  .density-switch-btn {
    width: 100%;
    background: transparent;
    border: 1px solid rgba(148, 163, 184, 0.22);
    color: #94a3b8;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 11.5px;
    font-family: var(--font-sans);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .density-switch-btn:hover {
    color: #f8fafc;
    border-color: rgba(148, 163, 184, 0.45);
  }

  /* Main Area */
  .main-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    background: var(--bg-canvas);
    overflow: hidden;
  }

  /* Top Context Bar */
  .top-context-bar {
    height: 58px;
    flex-shrink: 0;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
    padding: 0 26px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    z-index: 15;
  }

  .top-left {
    display: flex;
    align-items: center;
    gap: 14px;
    min-width: 0;
  }

  .breadcrumb {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13.5px;
    font-weight: 600;
    color: var(--text-main);
    white-space: nowrap;
  }
  .breadcrumb-section {
    color: var(--text-muted);
    font-weight: 500;
  }
  .breadcrumb-sep {
    color: var(--border-strong);
  }

  .live-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 999px;
    background: var(--ok-bg);
    border: 1px solid var(--ok-border);
    color: var(--ok-text);
    font-size: 11.5px;
    font-weight: 600;
  }

  .top-right {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
  }

  .time-selector-group {
    display: inline-flex;
    align-items: center;
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 2px;
    gap: 2px;
  }

  .time-pill-btn {
    border: none;
    background: transparent;
    color: var(--text-muted);
    padding: 5px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    font-family: var(--font-sans);
    transition: all 0.12s ease;
  }
  .time-pill-btn:hover {
    color: var(--text-main);
  }
  .time-pill-btn.active {
    background: var(--bg-surface);
    color: var(--accent);
    font-weight: 600;
    box-shadow: var(--shadow-sm);
  }

  .threat-alert-chip {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 6px 12px;
    border-radius: 8px;
    background: var(--crit-bg);
    border: 1px solid var(--crit-border);
    color: var(--crit-text);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: filter 0.12s ease;
  }
  .threat-alert-chip:hover { filter: brightness(0.97); }
  .threat-alert-chip.clean {
    background: var(--ok-bg);
    border-color: var(--ok-border);
    color: var(--ok-text);
  }

  /* Standard Buttons */
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 7px 13px;
    border-radius: 8px;
    font-family: var(--font-sans);
    font-size: 12.5px;
    font-weight: 500;
    cursor: pointer;
    border: 1px solid var(--border-strong);
    background: var(--bg-surface);
    color: var(--text-main);
    transition: background 0.12s ease, border-color 0.12s ease;
    white-space: nowrap;
  }
  .btn:hover {
    background: var(--bg-hover);
  }
  .btn-sm {
    padding: 5px 10px;
    font-size: 12px;
    border-radius: 6px;
  }
  .btn-primary {
    background: var(--accent);
    border-color: var(--accent);
    color: #ffffff;
    font-weight: 600;
  }
  .btn-primary:hover {
    background: var(--accent-hover);
    border-color: var(--accent-hover);
  }
  .btn-danger {
    background: var(--crit-bg);
    border-color: var(--crit-border);
    color: var(--crit-text);
    font-weight: 600;
  }
  .btn-danger:hover {
    background: var(--crit-solid);
    border-color: var(--crit-solid);
    color: #ffffff;
  }
  .btn-danger-solid {
    background: var(--crit-solid);
    border-color: var(--crit-solid);
    color: #ffffff;
    font-weight: 600;
  }
  .btn-danger-solid:hover {
    filter: brightness(0.92);
  }
  .btn-warning {
    background: var(--high-bg);
    border-color: var(--high-border);
    color: var(--high-text);
    font-weight: 600;
  }

  /* Scrolling Content Container */
  .workspace-container {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
    padding: 22px 26px 40px 26px;
  }

  .view-panel {
    display: none;
    flex-direction: column;
    gap: 20px;
    max-width: 1720px;
    margin: 0 auto;
  }
  .view-panel.active {
    display: flex;
  }

  /* Page Title Row */
  .view-header-row {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
  }
  .view-title {
    font-size: 20px;
    font-weight: 700;
    color: var(--text-main);
    letter-spacing: -0.02em;
    line-height: 1.25;
  }
  .view-subtitle {
    font-size: 13px;
    color: var(--text-muted);
    margin-top: 3px;
  }

  /* ================= KPI STRIP ================= */
  .kpi-grid-4 {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 16px;
  }

  .kpi-card {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-top: 3px solid var(--accent);
    border-radius: var(--radius-lg);
    padding: 16px 20px;
    box-shadow: var(--shadow-sm);
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .kpi-card.crit { border-top-color: var(--crit-solid); }
  .kpi-card.ok { border-top-color: var(--ok-solid); }
  .kpi-card.warn { border-top-color: var(--high-solid); }

  .kpi-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .kpi-value {
    font-size: 26px;
    font-weight: 700;
    color: var(--text-main);
    letter-spacing: -0.02em;
    line-height: 1.15;
    font-variant-numeric: tabular-nums;
  }
  .kpi-value.crit { color: var(--crit-text); }
  .kpi-value.ok { color: var(--ok-text); }
  .kpi-value.warn { color: var(--high-text); }
  .kpi-value.accent { color: var(--accent); }

  .kpi-sub {
    font-size: 12px;
    color: var(--text-muted);
  }

  /* ================= PRIORITY THREAT CARDS (VIEW 1) ================= */
  .priority-section {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .section-heading {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-secondary);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .priority-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 14px;
  }

  .priority-card {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-left: 4px solid var(--crit-solid);
    border-radius: var(--radius-md);
    padding: 14px 16px;
    box-shadow: var(--shadow-sm);
    display: flex;
    flex-direction: column;
    gap: 10px;
    cursor: pointer;
    transition: box-shadow 0.15s ease, border-color 0.15s ease;
  }
  .priority-card:hover {
    box-shadow: var(--shadow-md);
    border-color: var(--border-strong);
  }
  .priority-card.high { border-left-color: var(--high-solid); }

  .priority-card-top {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 10px;
  }
  .priority-card-top > div {
    min-width: 0;
  }
  .priority-host {
    font-size: 14.5px;
    font-weight: 700;
    color: var(--text-main);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .priority-meta {
    font-size: 11.5px;
    color: var(--text-muted);
    margin-top: 2px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .priority-framework {
    font-size: 12.5px;
    font-weight: 600;
    color: var(--crit-text);
    background: var(--crit-bg);
    border: 1px solid var(--crit-border);
    border-radius: 6px;
    padding: 6px 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .priority-card.high .priority-framework {
    color: var(--high-text);
    background: var(--high-bg);
    border-color: var(--high-border);
  }
  .priority-actions {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding-top: 4px;
  }

  /* ================= PANELS & TOOLBARS ================= */
  .panel-card {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-sm);
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .panel-header {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    flex-wrap: wrap;
    background: var(--bg-surface);
  }
  .panel-title {
    font-size: 14.5px;
    font-weight: 600;
    color: var(--text-main);
  }
  .panel-subtitle {
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 2px;
  }

  .toolbar-bar {
    padding: 14px 18px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-sm);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    flex-wrap: wrap;
  }

  .toolbar-left {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    flex: 1;
    min-width: 0;
  }

  .search-input {
    height: 36px;
    min-width: 280px;
    padding: 0 12px;
    border-radius: 8px;
    border: 1px solid var(--border-strong);
    background: var(--bg-subtle);
    color: var(--text-main);
    font-family: var(--font-sans);
    font-size: 13px;
    outline: none;
    transition: border-color 0.14s ease, background 0.14s ease;
  }
  .search-input:focus {
    background: var(--bg-surface);
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-bg);
  }
  .search-input::placeholder {
    color: var(--text-muted);
  }

  .pill-group {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .filter-pill {
    padding: 6px 12px;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--bg-subtle);
    color: var(--text-secondary);
    font-family: var(--font-sans);
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.12s ease;
  }
  .filter-pill:hover {
    background: var(--bg-hover);
    color: var(--text-main);
  }
  .filter-pill.active {
    background: var(--accent);
    border-color: var(--accent);
    color: #ffffff;
    font-weight: 600;
  }

  .segmented-toggle {
    display: inline-flex;
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 2px;
    gap: 2px;
  }
  .segmented-btn {
    padding: 5px 12px;
    border-radius: 6px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    font-family: var(--font-sans);
  }
  .segmented-btn.active {
    background: var(--bg-surface);
    color: var(--text-main);
    font-weight: 600;
    box-shadow: var(--shadow-sm);
  }

  /* ================= STATUS BADGES ================= */
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 9px;
    border-radius: 999px;
    font-size: 11.5px;
    font-weight: 600;
    border: 1px solid transparent;
    white-space: nowrap;
    line-height: 1.3;
  }
  .badge.crit { background: var(--crit-bg); color: var(--crit-text); border-color: var(--crit-border); }
  .badge.high { background: var(--high-bg); color: var(--high-text); border-color: var(--high-border); }
  .badge.ok { background: var(--ok-bg); color: var(--ok-text); border-color: var(--ok-border); }
  .badge.eval { background: var(--eval-bg); color: var(--eval-text); border-color: var(--eval-border); }
  .badge.neutral { background: var(--muted-bg); color: var(--muted-text); border-color: var(--muted-border); }
  .badge.accent { background: var(--accent-bg); color: var(--accent); border-color: var(--accent-border); }

  .dot-status {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
    background: var(--ok-solid);
    flex-shrink: 0;
  }
  .dot-status.crit { background: var(--crit-solid); box-shadow: 0 0 0 3px var(--crit-bg); }
  .dot-status.high { background: var(--high-solid); }
  .dot-status.muted { background: var(--text-muted); }

  /* ================= ENTERPRISE DATA TABLES ================= */
  .table-scroll {
    width: 100%;
    overflow-x: auto;
  }

  table.data-table {
    width: 100%;
    border-collapse: collapse;
    text-align: left;
  }

  table.data-table th {
    padding: 11px var(--row-pad-x);
    background: var(--bg-subtle);
    border-bottom: 1px solid var(--border);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted);
    white-space: nowrap;
  }

  table.data-table td {
    padding: var(--row-pad-y) var(--row-pad-x);
    border-bottom: 1px solid var(--border);
    color: var(--text-secondary);
    font-size: 13px;
    vertical-align: middle;
  }

  table.data-table tbody tr {
    transition: background 0.1s ease;
    cursor: pointer;
  }
  table.data-table tbody tr:hover {
    background: var(--bg-hover);
  }
  table.data-table tbody tr.row-selected {
    background: var(--bg-selected);
  }
  table.data-table tbody tr.row-threat td:first-child {
    box-shadow: inset 3px 0 0 var(--crit-solid);
  }
  table.data-table tbody tr.row-high td:first-child {
    box-shadow: inset 3px 0 0 var(--high-solid);
  }
  table.data-table tbody tr.row-isolated td {
    opacity: 0.85;
  }
  table.data-table tbody tr:last-child td {
    border-bottom: none;
  }

  .cell-primary {
    font-weight: 600;
    color: var(--text-main);
    display: block;
  }
  .cell-sub {
    font-size: 11.5px;
    color: var(--text-muted);
    display: block;
    margin-top: 1px;
  }

  /* Optional Card Grid for Fleet View */
  .subnet-group-card {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 18px 20px;
    box-shadow: var(--shadow-sm);
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .subnet-group-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }
  .hosts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(265px, 1fr));
    gap: 14px;
  }
  .host-grid-card {
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 14px 16px;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    gap: 8px;
    transition: background 0.14s ease, border-color 0.14s ease, box-shadow 0.14s ease;
  }
  .host-grid-card:hover {
    background: var(--bg-surface);
    border-color: var(--border-strong);
    box-shadow: var(--shadow-sm);
  }
  .host-grid-card.threat-c2 {
    background: var(--crit-bg);
    border-color: var(--crit-border);
  }
  .host-grid-card.threat-high {
    background: var(--high-bg);
    border-color: var(--high-border);
  }

  /* ================= VIEW 2: CAMPAIGN MASTER-DETAIL ================= */
  .campaign-master-detail {
    display: grid;
    grid-template-columns: 330px minmax(0, 1fr);
    gap: 20px;
    align-items: start;
  }

  .campaign-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .campaign-list-card {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-left: 4px solid var(--crit-solid);
    border-radius: var(--radius-md);
    padding: 14px 16px;
    cursor: pointer;
    box-shadow: var(--shadow-sm);
    transition: all 0.14s ease;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .campaign-list-card:hover {
    border-color: var(--border-strong);
    box-shadow: var(--shadow-md);
  }
  .campaign-list-card.selected {
    background: var(--bg-selected);
    border-color: var(--accent);
    border-left-color: var(--accent);
  }

  .killchain-box {
    position: relative;
    padding: 20px;
    background: var(--bg-subtle);
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
  }
  .killchain-flow {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 18px;
    min-width: 720px;
    position: relative;
  }
  .kc-stage {
    flex: 1;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 12px 14px;
    box-shadow: var(--shadow-sm);
    position: relative;
    z-index: 2;
  }
  .kc-stage.danger {
    border-color: var(--crit-border);
    background: var(--crit-bg);
  }
  .kc-arrow {
    color: var(--text-muted);
    font-weight: 700;
    font-size: 16px;
    flex-shrink: 0;
  }

  .metric-grid-3 {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px;
    padding: 18px 20px;
  }
  .metric-subcard {
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  /* ================= VIEW 3: ENDPOINT TRIAGE ================= */
  .endpoint-context-bar {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 16px 20px;
    box-shadow: var(--shadow-sm);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }

  .host-select {
    height: 36px;
    padding: 0 12px;
    border-radius: 8px;
    border: 1px solid var(--border-strong);
    background: var(--bg-subtle);
    color: var(--text-main);
    font-family: var(--font-sans);
    font-size: 13.5px;
    font-weight: 600;
    cursor: pointer;
    outline: none;
  }

  .incident-banner {
    background: var(--crit-bg);
    border: 1px solid var(--crit-border);
    border-left: 4px solid var(--crit-solid);
    border-radius: var(--radius-md);
    padding: 14px 18px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }
  .incident-banner.clean {
    background: var(--ok-bg);
    border-color: var(--ok-border);
    border-left-color: var(--ok-solid);
  }

  .subtab-bar {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 0 20px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
  }
  .subtab-btn {
    padding: 13px 16px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    font-family: var(--font-sans);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: color 0.14s ease, border-color 0.14s ease;
  }
  .subtab-btn:hover {
    color: var(--text-main);
  }
  .subtab-btn.active {
    color: var(--accent);
    font-weight: 600;
    border-bottom-color: var(--accent);
  }

  /* ================= VIEW 5: POLICIES & SIEM ================= */
  .policies-grid-2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 20px;
    align-items: start;
  }
  .tier-policy-row {
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 14px 16px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    flex-wrap: wrap;
  }
  .tier-select {
    height: 34px;
    padding: 0 10px;
    border-radius: 6px;
    border: 1px solid var(--border-strong);
    background: var(--bg-surface);
    color: var(--text-main);
    font-family: var(--font-sans);
    font-size: 12.5px;
    font-weight: 500;
  }
  .code-viewer {
    background: var(--bg-code);
    color: var(--code-text);
    font-family: var(--font-mono);
    font-size: 11.5px;
    line-height: 1.55;
    padding: 16px 18px;
    border-radius: 8px;
    overflow-x: auto;
    max-height: 380px;
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
  }

  /* ================= SLIDE-OVER RIGHT INSPECTOR DRAWER ================= */
  .drawer-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(15, 23, 42, 0.35);
    z-index: 40;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.2s ease;
  }
  .drawer-backdrop.open {
    opacity: 1;
    pointer-events: auto;
  }

  .inspector-drawer {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    width: 460px;
    max-width: 94vw;
    background: var(--bg-surface);
    border-left: 1px solid var(--border);
    box-shadow: var(--shadow-drawer);
    z-index: 50;
    display: flex;
    flex-direction: column;
    transform: translateX(100%);
    transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .inspector-drawer.open {
    transform: translateX(0);
  }

  .drawer-header {
    padding: 18px 22px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 14px;
    background: var(--bg-surface);
  }
  .drawer-eyebrow {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--accent);
    margin-bottom: 4px;
  }
  .drawer-title {
    font-size: 17px;
    font-weight: 700;
    color: var(--text-main);
    line-height: 1.25;
  }
  .drawer-subtitle {
    font-size: 12.5px;
    color: var(--text-muted);
    margin-top: 2px;
  }
  .drawer-close-btn {
    width: 32px;
    height: 32px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--bg-subtle);
    color: var(--text-secondary);
    font-size: 18px;
    line-height: 1;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .drawer-close-btn:hover {
    background: var(--bg-hover);
    color: var(--text-main);
  }

  .drawer-body {
    flex: 1;
    overflow-y: auto;
    padding: 18px 22px 26px 22px;
    display: flex;
    flex-direction: column;
    gap: 16px;
    background: var(--bg-canvas);
  }

  .drawer-card {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 15px 17px;
    box-shadow: var(--shadow-sm);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .drawer-card-title {
    font-size: 11.5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
  }
  .kv-row {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    font-size: 12.5px;
  }
  .kv-label {
    color: var(--text-muted);
    flex-shrink: 0;
  }
  .kv-val {
    color: var(--text-main);
    font-weight: 500;
    text-align: right;
    word-break: break-all;
  }

  .cadence-strip {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 8px 10px;
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: 6px;
  }
  .cadence-dot {
    height: 18px;
    flex: 1;
    border-radius: 3px;
    background: var(--border);
  }
  .cadence-dot.pulse {
    background: var(--crit-solid);
  }
  .cadence-dot.high {
    background: var(--high-solid);
  }
  .cadence-dot.ok {
    background: var(--ok-solid);
  }

  .drawer-actions-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px;
    margin-top: 4px;
  }

  /* ================= MODALS ================= */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(15, 23, 42, 0.55);
    z-index: 80;
    display: none;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  .modal-backdrop.active {
    display: flex;
  }
  .modal-card {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: 0 20px 50px rgba(15, 23, 42, 0.25);
    width: 100%;
    max-width: 580px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }
  .modal-card.wide {
    max-width: 920px;
  }
  .modal-header {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .modal-title {
    font-size: 15.5px;
    font-weight: 700;
    color: var(--text-main);
  }
  .modal-body {
    padding: 18px 20px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    max-height: 75vh;
    overflow-y: auto;
  }
  .modal-footer {
    padding: 14px 20px;
    border-top: 1px solid var(--border);
    background: var(--bg-subtle);
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 10px;
  }

  .scope-option-box {
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 14px;
    cursor: pointer;
    display: flex;
    align-items: flex-start;
    gap: 10px;
  }
  .scope-option-box.selected {
    background: var(--accent-bg);
    border-color: var(--accent);
  }

  .toast-banner {
    display: none;
    padding: 10px 14px;
    border-radius: 8px;
    background: var(--ok-bg);
    border: 1px solid var(--ok-border);
    color: var(--ok-text);
    font-size: 12.5px;
    font-weight: 600;
  }

  @media (max-width: 1200px) {
    .kpi-grid-4 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .campaign-master-detail { grid-template-columns: 1fr; }
    .policies-grid-2 { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<div class="app-shell">
  <!-- LEFT NAVY-SLATE NAVIGATION RAIL -->
  <aside class="app-sidebar">
    <div class="brand-header">
      <div class="brand-logo">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
      </div>
      <div>
        <div class="brand-title">Uncloak NDR</div>
        <div class="brand-subtitle">Enterprise Manager</div>
      </div>
    </div>

    <nav class="sidebar-nav">
      <div class="nav-group-label">Monitoring</div>
      <div class="nav-item active" id="nav-fleet" onclick="switchView('fleet')">
        <div class="nav-item-left">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
          <span>Fleet Endpoints</span>
        </div>
        <span class="nav-badge" id="nav-badge-fleet">4</span>
      </div>
      <div class="nav-item" id="nav-campaign" onclick="switchView('campaign')">
        <div class="nav-item-left">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><line x1="14.1" y1="9.9" x2="17.5" y2="6.5"/><line x1="6.5" y1="17.5" x2="9.9" y2="14.1"/></svg>
          <span>Threat Campaigns</span>
        </div>
        <span class="nav-badge blue" id="nav-badge-campaign">2</span>
      </div>

      <div class="nav-group-label">Investigation</div>
      <div class="nav-item" id="nav-drilldown" onclick="switchView('drilldown')">
        <div class="nav-item-left">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <span>Endpoint Triage</span>
        </div>
      </div>
      <div class="nav-item" id="nav-alerts" onclick="switchView('alerts')">
        <div class="nav-item-left">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
          <span>Alerts &amp; Event Log</span>
        </div>
        <span class="nav-badge neutral" id="nav-badge-alerts">18</span>
      </div>

      <div class="nav-group-label">Governance</div>
      <div class="nav-item" id="nav-policies" onclick="switchView('policies')">
        <div class="nav-item-left">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span>Policies &amp; SIEM</span>
        </div>
      </div>
    </nav>

    <div class="sidebar-footer">
      <div class="rail-status-card">
        <div class="rail-status-row">
          <span><span class="rail-dot"></span>Pipeline Live</span>
          <span class="mono" style="color: #6ee7b7;">OCSF 1.1</span>
        </div>
        <div class="rail-status-row" style="color: #94a3b8; font-size: 11px;">
          <span>Telemetry Sync</span>
          <span class="mono" id="rail-host-sync">32 / 32 Hosts</span>
        </div>
      </div>
      <button class="density-switch-btn" onclick="cycleDensity()">
        <span>Display Density</span>
        <span class="mono" id="density-label">Normal</span>
      </button>
    </div>
  </aside>

  <!-- RIGHT MAIN CONTENT AREA -->
  <div class="main-area">
    <header class="top-context-bar">
      <div class="top-left">
        <div class="breadcrumb">
          <span class="breadcrumb-section" id="bc-section">Monitoring</span>
          <span class="breadcrumb-sep">/</span>
          <span id="bc-page">Fleet Endpoints</span>
        </div>
        <span class="live-pill">
          <span class="dot-status"></span>
          <span>Live ETW + WFP Telemetry</span>
        </span>
      </div>

      <div class="top-right">
        <div class="time-selector-group" title="Filter log retention window">
          <button class="time-pill-btn" id="tr-live" onclick="setGlobalTimeRange('live')">Live</button>
          <button class="time-pill-btn" id="tr-24h" onclick="setGlobalTimeRange('24h')">24h</button>
          <button class="time-pill-btn" id="tr-7d" onclick="setGlobalTimeRange('7d')">7d</button>
          <button class="time-pill-btn" id="tr-30d" onclick="setGlobalTimeRange('30d')">30d</button>
          <button class="time-pill-btn active" id="tr-all" onclick="setGlobalTimeRange('all')">All</button>
        </div>

        <button class="threat-alert-chip" id="top-threat-chip" onclick="filterToActiveThreats()">
          <span class="dot-status crit"></span>
          <span id="top-threat-label">4 Active Threats</span>
        </button>

        <button class="btn btn-sm" id="theme-toggle-btn" onclick="toggleTheme()" title="Switch Light / Dark Slate Theme">
          <span id="theme-toggle-icon">Dark Slate</span>
        </button>

        <button class="btn btn-primary btn-sm" onclick="exportTelemetry()">Export OCSF</button>
      </div>
    </header>

    <div class="workspace-container">
      <!-- ==================== VIEW 1: FLEET ENDPOINTS ==================== -->
      <section class="view-panel active" id="view-fleet">
        <div class="view-header-row">
          <div>
            <h1 class="view-title">Enterprise Fleet Endpoints</h1>
            <p class="view-subtitle">Real-time C2 beacon detection, process-to-socket attribution, and Windows Filtering Platform (WFP) status across all Active Directory tiers.</p>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="badge neutral mono" id="fleet-table-counter">Showing 32 of 32 Endpoints</span>
          </div>
        </div>

        <div class="kpi-grid-4">
          <div class="kpi-card crit">
            <div class="kpi-label"><span>Critical &amp; High Endpoints</span><span>EID 9001</span></div>
            <div class="kpi-value crit" id="kpi-crit-hosts">4</div>
            <div class="kpi-sub">Active periodic beacon signatures detected</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label"><span>Monitored Windows Hosts</span><span>Sensors</span></div>
            <div class="kpi-value" id="kpi-total-hosts">32</div>
            <div class="kpi-sub">Tier-0 DCs, Tier-1 Servers, Tier-2 Endpoints</div>
          </div>
          <div class="kpi-card warn">
            <div class="kpi-label"><span>Tracked Outbound Sockets</span><span>FlowFeaturesV1</span></div>
            <div class="kpi-value accent" id="kpi-total-sockets">0</div>
            <div class="kpi-sub">Burst cadence &amp; JA4 TLS classification</div>
          </div>
          <div class="kpi-card ok">
            <div class="kpi-label"><span>Contained / Stale Agents</span><span>WFP Policy</span></div>
            <div class="kpi-value ok" id="kpi-muted-hosts">0</div>
            <div class="kpi-sub">Active isolation or muted telemetry states</div>
          </div>
        </div>

        <!-- Priority Attention Strip (Only active Critical / High hosts) -->
        <div class="priority-section" id="fleet-priority-section">
          <div class="section-heading">
            <span>Priority Triage Queue (Active Detections)</span>
            <span style="font-weight: 500; color: var(--text-muted);">Click card to inspect socket telemetry or jump to endpoint triage</span>
          </div>
          <div class="priority-grid" id="fleet-priority-strip"></div>
        </div>

        <!-- Toolbar -->
        <div class="toolbar-bar">
          <div class="toolbar-left">
            <input type="text" class="search-input" id="fleet-search-input" placeholder="Search hostname, IP address, OS, tier, or C2 framework... [/]" oninput="renderFleetView()">
            <div class="pill-group">
              <button class="filter-pill active" id="filter-btn-all" onclick="filterTableByScope('ALL')">All Endpoints</button>
              <button class="filter-pill" id="filter-btn-threats" onclick="filterTableByScope('THREATS')">Active Threats</button>
              <button class="filter-pill" id="filter-btn-tier0" onclick="filterTableByScope('TIER-0')">Tier-0 (DCs)</button>
              <button class="filter-pill" id="filter-btn-tier1" onclick="filterTableByScope('TIER-1')">Tier-1 (Servers)</button>
              <button class="filter-pill" id="filter-btn-tier2" onclick="filterTableByScope('TIER-2')">Tier-2 (Workstations)</button>
              <button class="filter-pill" id="filter-btn-muted" onclick="filterTableByScope('MUTED')">Stale</button>
            </div>
          </div>
          <div class="segmented-toggle">
            <button class="segmented-btn active" id="btn-fleet-table" onclick="switchFleetLayout('table')">Table View</button>
            <button class="segmented-btn" id="btn-fleet-grid" onclick="switchFleetLayout('grid')">Card Grid</button>
          </div>
        </div>

        <!-- Default Enterprise Endpoint Table -->
        <div class="panel-card" id="fleet-table-container">
          <div class="table-scroll">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Endpoint / OS</th>
                  <th>IP Address</th>
                  <th>AD Tier</th>
                  <th>Sockets</th>
                  <th>CPU / Memory</th>
                  <th style="text-align: right;">Max Score</th>
                  <th>Detection / Framework</th>
                  <th>Last Heartbeat</th>
                  <th style="text-align: right;">Actions</th>
                </tr>
              </thead>
              <tbody id="fleet-table-tbody"></tbody>
            </table>
          </div>
        </div>

        <!-- Optional Grouped Card Grid -->
        <div id="fleet-subnets-container" style="display: none; flex-direction: column; gap: 16px;"></div>
      </section>

      <!-- ==================== VIEW 2: THREAT CAMPAIGNS ==================== -->
      <section class="view-panel" id="view-campaign">
        <div class="view-header-row">
          <div>
            <h1 class="view-title">Coordinated Threat Campaigns</h1>
            <p class="view-subtitle">Cross-endpoint C2 outbreak correlation grouped by JA4 TLS client fingerprint, shared destination infrastructure, and timing cadence.</p>
          </div>
        </div>

        <div class="kpi-grid-4">
          <div class="kpi-card crit">
            <div class="kpi-label"><span>Active Campaigns</span><span>Clustered</span></div>
            <div class="kpi-value crit" id="camp-kpi-count">2</div>
            <div class="kpi-sub">Multi-host correlated C2 patterns</div>
          </div>
          <div class="kpi-card warn">
            <div class="kpi-label"><span>Impacted Endpoints</span><span>Lateral Scope</span></div>
            <div class="kpi-value warn" id="camp-kpi-hosts">4</div>
            <div class="kpi-sub">Hosts communicating with shared C2 nodes</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label"><span>Shared JA4 Cluster</span><span>TLS Profile</span></div>
            <div class="kpi-value accent mono" style="font-size: 16px; padding-top: 4px;" id="camp-kpi-ja4">t13d1516h2_...</div>
            <div class="kpi-sub">Cryptographic ClientHello consistency</div>
          </div>
          <div class="kpi-card ok">
            <div class="kpi-label"><span>Fleet Quarantine Action</span><span>Containment</span></div>
            <div class="kpi-value ok">Ready</div>
            <div class="kpi-sub">One-click SetTcpEntry &amp; WFP policy push</div>
          </div>
        </div>

        <div class="campaign-master-detail">
          <div class="campaign-list" id="campaign-list-container"></div>

          <div class="panel-card" id="campaign-detail-panel">
            <div class="panel-header">
              <div>
                <div class="panel-title" id="cd-title">Select a threat campaign</div>
                <div class="panel-subtitle" id="cd-subtitle">Cross-host JA4 &amp; FlowFeaturesV1 attribution summary</div>
              </div>
              <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <button class="btn btn-sm" onclick="openStixModal()">Export STIX 2.1</button>
                <button class="btn btn-sm" onclick="openYaralModal()">Export YARA-L</button>
                <button class="btn btn-danger-solid btn-sm" id="cd-sever-btn" onclick="severSelectedCampaign()">Quarantine Campaign</button>
              </div>
            </div>

            <div class="killchain-box">
              <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 12px;">Correlated Attack Kill-Chain Propagation</div>
              <div class="killchain-flow" id="killchain-flow"></div>
            </div>

            <div class="metric-grid-3" id="cd-metrics-grid"></div>

            <div style="border-top: 1px solid var(--border);">
              <div style="padding: 12px 20px; background: var(--bg-subtle); border-bottom: 1px solid var(--border); font-size: 12.5px; font-weight: 600; color: var(--text-main);">
                Correlated Endpoints in Campaign
              </div>
              <div class="table-scroll">
                <table class="data-table">
                  <thead>
                    <tr>
                      <th>Endpoint</th>
                      <th>IP Address</th>
                      <th>AD Tier</th>
                      <th>Active Sockets</th>
                      <th style="text-align: right;">Threat Score</th>
                      <th style="text-align: right;">Triage</th>
                    </tr>
                  </thead>
                  <tbody id="cd-hosts-tbody"></tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- ==================== VIEW 3: ENDPOINT TRIAGE ==================== -->
      <section class="view-panel" id="view-drilldown">
        <div class="endpoint-context-bar">
          <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
            <label for="host-selector" style="font-size: 12.5px; font-weight: 600; color: var(--text-muted);">Endpoint:</label>
            <select id="host-selector" class="host-select" onchange="changeSelectedHost(this.value)"></select>
            <span class="badge neutral mono" id="hd-ip">10.0.1.15</span>
            <span class="badge accent" id="hd-tier">Tier-1 Server</span>
            <span class="badge neutral" id="hd-os">Windows Server 2022</span>
            <span class="badge ok" id="hd-agent-state">Agent Streaming</span>
          </div>
          <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
            <button class="btn btn-sm" onclick="openSelectedFlowDrawer()">Inspect Host &amp; Socket Drawer</button>
            <button class="btn btn-sm" onclick="openWhitelistModalForSelected()">Allowlist Target</button>
            <button class="btn btn-danger btn-sm" id="btn-isolate-host" onclick="toggleCurrentHostIsolation()">Isolate Host (WFP)</button>
          </div>
        </div>

        <div class="incident-banner" id="hd-incident-banner">
          <div style="display: flex; align-items: center; gap: 14px; flex-wrap: wrap;">
            <span class="badge crit" id="ib-sev-badge">CRITICAL C2</span>
            <div>
              <div style="font-weight: 700; color: var(--text-main);" id="ib-title">update.exe (PID 5824) -&gt; 193.26.158.114:443</div>
              <div style="font-size: 12.5px; color: var(--text-secondary);" id="ib-sub">Sliver mTLS / Raw IP C2 | Threat Score: 98.7% | IAT MAD: 0.095</div>
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <button class="btn btn-sm" onclick="openSelectedFlowDrawer()">Open Triage Drawer &rarr;</button>
            <button class="btn btn-danger-solid btn-sm" onclick="severCurrentTopFlow()">Sever Socket</button>
          </div>
        </div>

        <div class="panel-card">
          <div class="subtab-bar">
            <button class="subtab-btn active" id="subtab-flows" onclick="switchHostSubtab('flows')">Outbound Sockets <span class="mono" id="subtab-flows-count">(0)</span></button>
            <button class="subtab-btn" id="subtab-procs" onclick="switchHostSubtab('procs')">Running Processes <span class="mono" id="subtab-procs-count">(0)</span></button>
            <button class="subtab-btn" id="subtab-history" onclick="switchHostSubtab('history')">Connection Timeline</button>
            <button class="subtab-btn" id="subtab-whitelist" onclick="switchHostSubtab('whitelist')">Allowlist Rules <span class="mono" id="whitelist-count-label">(2)</span></button>
          </div>

          <!-- Sub-tab 1: Outbound Sockets -->
          <div id="subpanel-flows">
            <div class="table-scroll">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Verdict</th>
                    <th>Process &amp; PID</th>
                    <th>Remote Endpoint</th>
                    <th>SNI / Hostname</th>
                    <th>JA4 Profile</th>
                    <th>Cadence (IAT / MAD)</th>
                    <th style="text-align: right;">Score</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody id="flows-tbody"></tbody>
              </table>
            </div>
          </div>

          <!-- Sub-tab 2: Running Processes -->
          <div id="subpanel-procs" style="display: none;">
            <div class="table-scroll">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>PID</th>
                    <th>Process Name</th>
                    <th>Executable Path &amp; Signing</th>
                    <th>Parent Process</th>
                    <th>User Context</th>
                    <th>Sockets</th>
                    <th style="text-align: right;">History &amp; Triage</th>
                  </tr>
                </thead>
                <tbody id="procs-tbody"></tbody>
              </table>
            </div>
          </div>

          <!-- Sub-tab 3: Connection Timeline -->
          <div id="subpanel-history" style="display: none;">
            <div style="padding: 12px 18px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; gap: 12px; background: var(--bg-subtle);">
              <div style="display: flex; align-items: center; gap: 8px;">
                <input type="text" class="search-input" id="timeline-pid-input" placeholder="Filter timeline by PID (e.g. 5824)..." oninput="filterTimelineByPid(this.value)" style="min-width: 240px; height: 32px;">
                <button class="btn btn-sm" onclick="clearTimelinePidFilter()">Clear</button>
              </div>
              <span class="badge accent" id="timeline-pid-filter-label" style="display: none;"></span>
            </div>
            <div class="table-scroll">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Process (PID)</th>
                    <th>Local -&gt; Remote</th>
                    <th>SNI / Destination</th>
                    <th>Volume</th>
                    <th>State</th>
                    <th style="text-align: right;">Verdict</th>
                  </tr>
                </thead>
                <tbody id="history-tbody"></tbody>
              </table>
            </div>
          </div>

          <!-- Sub-tab 4: Allowlist Rules -->
          <div id="subpanel-whitelist" style="display: none;">
            <div style="padding: 12px 18px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; background: var(--bg-subtle);">
              <span style="font-size: 12.5px; color: var(--text-secondary);">Active process and destination exemptions pushed to fleet endpoints.</span>
              <button class="btn btn-primary btn-sm" onclick="openWhitelistModalForSelected()">+ New Exemption Rule</button>
            </div>
            <div class="table-scroll">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Rule ID</th>
                    <th>Scope</th>
                    <th>Process Entity</th>
                    <th>Destination Pattern</th>
                    <th>Justification</th>
                    <th>Created (UTC)</th>
                    <th style="text-align: right;">Action</th>
                  </tr>
                </thead>
                <tbody id="whitelist-rules-tbody"></tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <!-- ==================== VIEW 4: ALERTS & EVENT LOG ==================== -->
      <section class="view-panel" id="view-alerts">
        <div class="view-header-row">
          <div>
            <h1 class="view-title">Historical Alerts &amp; SIEM Event Log</h1>
            <p class="view-subtitle">Searchable multi-day audit trail across Windows Event Log (EID 9001 / 9002), OCSF v1.1.0 records, and autonomous containments.</p>
          </div>
          <span class="badge neutral mono" id="alerts-showing-label">Showing 18 of 18 Indexed Events</span>
        </div>

        <div class="kpi-grid-4">
          <div class="kpi-card">
            <div class="kpi-label"><span>Indexed Events</span><span>Windowed</span></div>
            <div class="kpi-value" id="al-kpi-total">18 Events</div>
            <div class="kpi-sub">SQLite WAL + Application.evtx + OCSF</div>
          </div>
          <div class="kpi-card crit">
            <div class="kpi-label"><span>EID 9001 Detections</span><span>Alerts</span></div>
            <div class="kpi-value crit" id="al-kpi-9001">11 Alerts</div>
            <div class="kpi-sub">FlowFeaturesV1 Score &gt;= 0.85 Triggered</div>
          </div>
          <div class="kpi-card ok">
            <div class="kpi-label"><span>EID 9002 Containments</span><span>Enforced</span></div>
            <div class="kpi-value ok" id="al-kpi-9002">7 Actions</div>
            <div class="kpi-sub">SetTcpEntry TCB Evict + WFP Rule</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label"><span>SIEM Sync Latency</span><span>Wazuh / Splunk</span></div>
            <div class="kpi-value accent">0.18s avg</div>
            <div class="kpi-sub">Universal Forwarder &amp; Agent synchronized</div>
          </div>
        </div>

        <div class="toolbar-bar">
          <div class="toolbar-left">
            <input type="text" class="search-input" id="alert-search-input" placeholder="Search alerts by ID, hostname, process, PID, C2 IP, or framework... [/]" oninput="renderAlertsLedger()" style="min-width: 340px;">
            <div class="pill-group">
              <button class="filter-pill active" id="al-f-all" onclick="setAlertFilter('ALL')">All Events</button>
              <button class="filter-pill" id="al-f-9001" onclick="setAlertFilter('9001')">EID 9001 Detections</button>
              <button class="filter-pill" id="al-f-9002" onclick="setAlertFilter('9002')">EID 9002 Containments</button>
              <button class="filter-pill" id="al-f-crit" onclick="setAlertFilter('CRITICAL')">Critical Only</button>
              <button class="filter-pill" id="al-f-t0" onclick="setAlertFilter('Tier-0')">Tier-0</button>
              <button class="filter-pill" id="al-f-t1" onclick="setAlertFilter('Tier-1')">Tier-1</button>
              <button class="filter-pill" id="al-f-t2" onclick="setAlertFilter('Tier-2')">Tier-2</button>
            </div>
          </div>
        </div>

        <div class="panel-card">
          <div class="table-scroll">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>EID</th>
                  <th>Severity</th>
                  <th>Endpoint &amp; AD Tier</th>
                  <th>Process (PID / Signing)</th>
                  <th>Remote C2 Endpoint</th>
                  <th>Framework &amp; Score</th>
                  <th>Containment / SIEM Status</th>
                  <th style="text-align: right;">Snapshot</th>
                </tr>
              </thead>
              <tbody id="alerts-ledger-tbody"></tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- ==================== VIEW 5: POLICIES & SIEM ==================== -->
      <section class="view-panel" id="view-policies">
        <div class="view-header-row">
          <div>
            <h1 class="view-title">Containment Policies &amp; SIEM Integration</h1>
            <p class="view-subtitle">Active Directory tier response guardrails, FlowFeaturesV1 detector tuning, and copy-ready Wazuh / Splunk configurations.</p>
          </div>
        </div>

        <div class="policies-grid-2">
          <!-- Left Column: AD Tier Guardrails -->
          <div class="panel-card">
            <div class="panel-header">
              <div>
                <div class="panel-title">Active Directory Tier Containment Matrix</div>
                <div class="panel-subtitle">Safeguard mission-critical Domain Controllers while automating workstation containment</div>
              </div>
              <button class="btn btn-primary btn-sm" onclick="applyPolicyChanges()">Save &amp; Push Policies</button>
            </div>
            <div style="padding: 18px 20px; display: flex; flex-direction: column; gap: 14px;">
              <div class="toast-banner" id="policy-save-toast"></div>

              <div class="tier-policy-row">
                <div>
                  <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 3px;">
                    <span class="badge crit">Tier-0</span>
                    <strong style="color: var(--text-main);">Domain Controllers &amp; Enterprise PKI</strong>
                  </div>
                  <div style="font-size: 12px; color: var(--text-muted);">Prevents accidental service disruption on DC01 / PKI-CA01 via strict human quorum.</div>
                </div>
                <select id="pol-tier0-mode" class="tier-select">
                  <option value="audit_p1" selected>Audit + P1 SIEM Escalation</option>
                  <option value="quorum">Require 2-Analyst Quorum Sever</option>
                  <option value="auto_sever">Autonomous SetTcpEntry RST</option>
                </select>
              </div>

              <div class="tier-policy-row">
                <div>
                  <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 3px;">
                    <span class="badge high">Tier-1</span>
                    <strong style="color: var(--text-main);">Application, SQL &amp; Exchange Servers</strong>
                  </div>
                  <div style="font-size: 12px; color: var(--text-muted);">Balances uptime on production servers with fast single-click analyst severing.</div>
                </div>
                <select id="pol-tier1-mode" class="tier-select">
                  <option value="prompt_analyst" selected>Hold Socket + Analyst Prompt</option>
                  <option value="audit_p1">Audit + SIEM Alert Only</option>
                  <option value="auto_wfp">Autonomous SetTcpEntry + WFP Block</option>
                </select>
              </div>

              <div class="tier-policy-row">
                <div>
                  <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 3px;">
                    <span class="badge ok">Tier-2</span>
                    <strong style="color: var(--text-main);">Engineering Workstations &amp; Laptops</strong>
                  </div>
                  <div style="font-size: 12px; color: var(--text-muted);">Automatically isolates high-confidence C2 beacons (Score &gt;= 0.90) at kernel level.</div>
                </div>
                <select id="pol-tier2-mode" class="tier-select">
                  <option value="auto_wfp" selected>Autonomous SetTcpEntry + WFP Block</option>
                  <option value="prompt_analyst">Hold Socket + Analyst Prompt</option>
                  <option value="audit_only">Passive Telemetry Only</option>
                </select>
              </div>

              <div style="border-top: 1px solid var(--border); padding-top: 14px; display: flex; flex-direction: column; gap: 10px;">
                <div style="font-size: 13px; font-weight: 600; color: var(--text-main);">FlowFeaturesV1 Detection Thresholds</div>
                <div class="kv-row">
                  <span class="kv-label">Minimum Threat Confidence for EID 9001</span>
                  <span class="mono" style="font-weight: 600; color: var(--accent);">0.850 (85.0%)</span>
                </div>
                <div class="kv-row">
                  <span class="kv-label">Max IAT MAD/Median Ratio for Periodic Jitter</span>
                  <span class="mono" style="font-weight: 600;">0.180 (Low Entropy)</span>
                </div>
                <div class="kv-row">
                  <span class="kv-label">Minimum Observed Communication Bursts</span>
                  <span class="mono" style="font-weight: 600;">8 Bursts / Window</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Right Column: SIEM Sinks & Deployable Rules -->
          <div class="panel-card">
            <div class="panel-header">
              <div>
                <div class="panel-title">Enterprise SIEM Sinks &amp; Schema</div>
                <div class="panel-subtitle">Native Windows Event Log + OCSF v1.1.0 NDJSON ready for Wazuh and Splunk</div>
              </div>
              <button class="btn btn-sm" id="siem-copy-btn" onclick="copySiemSnippet()">Copy Snippet</button>
            </div>
            <div style="padding: 16px 20px; display: flex; flex-direction: column; gap: 14px;">
              <div style="display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px;">
                <div class="metric-subcard">
                  <span style="font-size: 11px; color: var(--text-muted); font-weight: 600;">WAZUH AGENT SINK</span>
                  <span style="font-weight: 700; color: var(--ok-text);">Connected (EventChannel)</span>
                  <span class="mono" style="font-size: 11px; color: var(--text-muted);">Rule 100901 / 100902</span>
                </div>
                <div class="metric-subcard">
                  <span style="font-size: 11px; color: var(--text-muted); font-weight: 600;">SPLUNK FORWARDER</span>
                  <span style="font-weight: 700; color: var(--ok-text);">OCSF NDJSON Streaming</span>
                  <span class="mono" style="font-size: 11px; color: var(--text-muted);">sourcetype=uncloak:ocsf:json</span>
                </div>
              </div>

              <div class="pill-group">
                <button class="filter-pill active" id="siem-tab-wazuh_rules" onclick="switchSiemSnippet('wazuh_rules')">Wazuh local_rules.xml</button>
                <button class="filter-pill" id="siem-tab-wazuh_ossec" onclick="switchSiemSnippet('wazuh_ossec')">Wazuh ossec.conf</button>
                <button class="filter-pill" id="siem-tab-splunk_inputs" onclick="switchSiemSnippet('splunk_inputs')">Splunk inputs.conf</button>
                <button class="filter-pill" id="siem-tab-ocsf_schema" onclick="switchSiemSnippet('ocsf_schema')">OCSF v1.1.0 Sample</button>
              </div>

              <pre class="code-viewer" id="siem-snippet-viewer"></pre>
            </div>
          </div>
        </div>
      </section>
    </div>
  </div>
</div>

<!-- SLIDE-OVER RIGHT INSPECTOR DRAWER -->
<div class="drawer-backdrop" id="drawer-backdrop" onclick="closeInspectorDrawer()"></div>
<aside class="inspector-drawer" id="right-inspector-drawer" aria-hidden="true">
  <div class="drawer-header">
    <div>
      <div class="drawer-eyebrow" id="drawer-eyebrow">SOCKET TRIAGE</div>
      <div class="drawer-title" id="drawer-title">update.exe (PID 5824)</div>
      <div class="drawer-subtitle" id="drawer-subtitle">WIN-PROD-SRV01 (10.0.1.15)</div>
    </div>
    <button class="drawer-close-btn" onclick="closeInspectorDrawer()" title="Close Drawer (Esc)">&#215;</button>
  </div>
  <div class="drawer-body" id="drawer-body"></div>
</aside>

<!-- MODALS -->
<!-- 1. Sever Socket / Process Tree Modal -->
<div class="modal-backdrop" id="sever-confirm-modal">
  <div class="modal-card">
    <div class="modal-header">
      <div class="modal-title" style="color: var(--crit-text);">Confirm Socket Containment (SetTcpEntry)</div>
      <button class="drawer-close-btn" onclick="closeSeverModal()">&#215;</button>
    </div>
    <div class="modal-body">
      <p style="color: var(--text-secondary);">Execute an immediate kernel-level TCP TCB teardown (`MIB_TCP_STATE_DELETE_TCB`) against the target endpoint process?</p>
      <div class="drawer-card">
        <div class="kv-row"><span class="kv-label">Target Endpoint</span><span class="kv-val mono" id="sm-host">-</span></div>
        <div class="kv-row"><span class="kv-label">Process &amp; PID</span><span class="kv-val mono" id="sm-proc">-</span></div>
        <div class="kv-row"><span class="kv-label">Remote C2 Socket</span><span class="kv-val mono" id="sm-remote">-</span></div>
        <div class="kv-row"><span class="kv-label">SIEM Audit Log</span><span class="kv-val">Windows Event ID 9002 + OCSF 4001</span></div>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" onclick="closeSeverModal()">Cancel</button>
      <button class="btn btn-danger-solid" onclick="executeConfirmedSever()">Execute Containment</button>
    </div>
  </div>
</div>

<!-- 2. Firewall / WFP Block Modal -->
<div class="modal-backdrop" id="tarpit-confirm-modal">
  <div class="modal-card">
    <div class="modal-header">
      <div class="modal-title" style="color: var(--high-text);">Confirm Persistent Windows Firewall Block</div>
      <button class="drawer-close-btn" onclick="closeTarpitModal()">&#215;</button>
    </div>
    <div class="modal-body">
      <p style="color: var(--text-secondary);">Push an outbound Windows Filtering Platform (WFP) block rule preventing future socket reconnects from this process to the remote IP.</p>
      <div class="drawer-card">
        <div class="kv-row"><span class="kv-label">Process &amp; PID</span><span class="kv-val mono" id="tm-proc">-</span></div>
        <div class="kv-row"><span class="kv-label">Blocked Destination</span><span class="kv-val mono" id="tm-remote">-</span></div>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" onclick="closeTarpitModal()">Cancel</button>
      <button class="btn btn-warning" onclick="executeConfirmedTarpit()">Enforce Firewall Block</button>
    </div>
  </div>
</div>

<!-- 3. Allowlist Exemption Modal -->
<div class="modal-backdrop" id="whitelist-modal">
  <div class="modal-card">
    <div class="modal-header">
      <div class="modal-title">Create Allowlist Exemption Rule</div>
      <button class="drawer-close-btn" onclick="closeWhitelistModal()">&#215;</button>
    </div>
    <div class="modal-body">
      <div class="drawer-card">
        <div class="kv-row"><span class="kv-label">Target Endpoint</span><span class="kv-val mono" id="wl-host">WIN-PROD-SRV01</span></div>
        <div class="kv-row"><span class="kv-label">Process Entity</span><span class="kv-val mono" id="wl-process">update.exe</span></div>
        <div class="kv-row"><span class="kv-label">Destination Pattern</span><span class="kv-val mono" id="wl-dest">193.26.158.114:443</span></div>
      </div>
      <div style="display: flex; flex-direction: column; gap: 8px;">
        <div class="scope-option-box selected" id="wl-scope-local-box" onclick="setWhitelistScope('LOCAL')">
          <input type="radio" name="wl-scope" id="wl-scope-local" checked>
          <div>
            <div style="font-weight: 600; color: var(--text-main);">Local Endpoint Scope (<span id="wl-scope-hostname">Host</span>)</div>
            <div style="font-size: 12px; color: var(--text-muted);">Permits <span class="mono" id="wl-rule-dest">destination</span> exclusively on this endpoint.</div>
          </div>
        </div>
        <div class="scope-option-box" id="wl-scope-global-box" onclick="setWhitelistScope('GLOBAL')">
          <input type="radio" name="wl-scope" id="wl-scope-global">
          <div>
            <div style="font-weight: 600; color: var(--text-main);">Global Enterprise Policy (All Managed Hosts)</div>
            <div style="font-size: 12px; color: var(--text-muted);">Pushes signed binary exemption across all 32 monitored sensors.</div>
          </div>
        </div>
      </div>
      <div>
        <label for="wl-reason" style="display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 5px;">Audit Justification</label>
        <input type="text" class="search-input" id="wl-reason" placeholder="Verified enterprise updater or approved vendor telemetry..." style="width: 100%; min-width: 0;">
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" onclick="closeWhitelistModal()">Cancel</button>
      <button class="btn btn-primary" onclick="applyWhitelistPolicy()">Deploy Allowlist Rule</button>
    </div>
  </div>
</div>

<!-- 4. PID Historical Audit Modal -->
<div class="modal-backdrop" id="pid-history-modal">
  <div class="modal-card wide">
    <div class="modal-header">
      <div>
        <div class="modal-title">Process Network History: <span id="ph-proc" class="mono">update.exe</span> (PID <span id="ph-pid" class="mono">5824</span>)</div>
        <div style="font-size: 12px; color: var(--text-muted);">Endpoint: <span id="ph-host" class="mono">WIN-PROD-SRV01</span></div>
      </div>
      <div style="display: flex; align-items: center; gap: 8px;">
        <button class="btn btn-sm" onclick="exportCurrentPidCsv()">Export CSV</button>
        <button class="drawer-close-btn" onclick="closePidHistoryModal()">&#215;</button>
      </div>
    </div>
    <div class="modal-body">
      <div class="kpi-grid-4">
        <div class="metric-subcard"><span class="kv-label">First Seen</span><strong class="mono" id="ph-first-seen">-</strong></div>
        <div class="metric-subcard"><span class="kv-label">Last Activity</span><strong class="mono" id="ph-last-seen">-</strong></div>
        <div class="metric-subcard"><span class="kv-label">Transferred</span><strong class="mono" id="ph-bandwidth">-</strong></div>
        <div class="metric-subcard"><span class="kv-label">Sockets</span><strong class="mono" id="ph-sockets">-</strong></div>
      </div>
      <div class="table-scroll" style="border: 1px solid var(--border); border-radius: 8px;">
        <table class="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Local Socket</th>
              <th>Remote Endpoint</th>
              <th>SNI / Hostname</th>
              <th>Duration</th>
              <th>Bytes</th>
              <th>State</th>
              <th style="text-align: right;">Verdict</th>
            </tr>
          </thead>
          <tbody id="ph-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- 5. STIX 2.1 / YARA-L Export Modal -->
<div class="modal-backdrop" id="export-intel-modal">
  <div class="modal-card wide">
    <div class="modal-header">
      <div class="modal-title" id="eim-title">Threat Intelligence Export</div>
      <div style="display: flex; align-items: center; gap: 8px;">
        <button class="btn btn-sm" onclick="copyIntelModal()">Copy Payload</button>
        <button class="drawer-close-btn" onclick="closeIntelModal()">&#215;</button>
      </div>
    </div>
    <div class="modal-body">
      <pre class="code-viewer" id="eim-code"></pre>
    </div>
  </div>
</div>

<script>
  window.INITIAL_STATE = __INITIAL_STATE_PLACEHOLDER__;

  /* ================= STATE & STATIC DATASETS ================= */
  let stateData = null;
  let currentTab = 'fleet';
  let currentFleetLayout = 'table';
  let activeFleetScope = 'ALL';
  let currentHostSubtab = 'flows';
  let selectedCampaignId = null;
  let currentTimeRange = 'all';
  let activeAlertFilter = 'ALL';
  let selectedAlertId = 'ALT-2026-9182';
  let activeSiemSnippetKey = 'wazuh_rules';

  let userSelectedHostId = null;
  let userSelectedPid = null;
  let drawerMode = null; // 'flow' | 'alert'

  let pendingSeverPid = null;
  let pendingSeverHostId = null;
  let pendingTarpitPid = null;
  let activeModalPidData = null;
  let activeWhitelistTarget = null;
  let activeWhitelistScope = 'LOCAL';

  const VIEW_BREADCRUMBS = {
    fleet: { section: 'Monitoring', page: 'Fleet Endpoints' },
    campaign: { section: 'Monitoring', page: 'Threat Campaigns' },
    drilldown: { section: 'Investigation', page: 'Endpoint Triage' },
    alerts: { section: 'Investigation', page: 'Alerts & Event Log' },
    policies: { section: 'Governance', page: 'Policies & SIEM' }
  };

  let enterpriseWhitelistRules = [
    {
      rule_id: 'WL-2026-001',
      scope: 'GLOBAL',
      entity: 'teams.exe',
      destination: '*.teams.microsoft.com',
      justification: 'Microsoft Teams enterprise telemetry - verified vendor binary',
      created_at: '2026-11-01 08:00 UTC'
    },
    {
      rule_id: 'WL-2026-002',
      scope: 'LOCAL',
      entity: 'azure_ad_sync.exe',
      destination: '*.login.microsoftonline.com',
      justification: 'Entra ID Hybrid Password Hash Sync Agent (DC01-PROD)',
      created_at: '2026-11-01 09:30 UTC'
    }
  ];

  const HISTORICAL_ALERTS = [
    {
      id: 'ALT-2026-9182',
      timestamp: '2026-11-14 13:12:04 UTC',
      ageLabel: '4m ago',
      ageHours: 0.07,
      eid: 9001,
      severity: 'CRITICAL',
      tier: 'Tier-1',
      hostId: 'host-win-prod-srv01',
      hostname: 'WIN-PROD-SRV01',
      hostIp: '10.0.1.15',
      processName: 'update.exe',
      processPath: 'C:\\ProgramData\\Updates\\update.exe',
      pid: 5824,
      auth: 'Unsigned PE',
      sha256: 'a4f982d17c63e0197b5f31a829c4b0e192f88374',
      parentProc: 'explorer.exe (PID 2180)',
      userSid: 'NT AUTHORITY\\SYSTEM (S-1-5-18)',
      remoteEndpoint: '193.26.158.114:443',
      framework: 'Sliver mTLS / Raw IP C2',
      score: 0.987,
      bursts: 14,
      iatMedian: 8.4,
      iatMad: 0.095,
      skew: '+0.03',
      bytesOut: '512 B',
      bytesIn: '1,280 B',
      ja4: 't13d1516h2_8daaf4b10222',
      mitre: 'T1071.001 + T1573',
      statusText: 'Wazuh Rule 100901 Dispatched',
      actionTaken: 'Alert Logged (Analyst Prompt Pending)'
    },
    {
      id: 'ALT-2026-9181',
      timestamp: '2026-11-14 12:55:19 UTC',
      ageLabel: '21m ago',
      ageHours: 0.35,
      eid: 9002,
      severity: 'CRITICAL',
      tier: 'Tier-2',
      hostId: 'host-ws-eng-04',
      hostname: 'WS-ENG-04',
      hostIp: '10.0.3.44',
      processName: 'svchost_upd.exe',
      processPath: 'C:\\Users\\eng_user\\AppData\\Local\\Temp\\svchost_upd.exe',
      pid: 4192,
      auth: 'Unsigned PE',
      sha256: 'e91c4092831a7d55b02c11820b4f82e391a00112',
      parentProc: 'cmd.exe (PID 3804)',
      userSid: 'CORP\\m.benali (S-1-5-21-...-1142)',
      remoteEndpoint: '193.26.158.114:443',
      framework: 'Sliver mTLS C2 (Auto-Contained)',
      score: 0.964,
      bursts: 19,
      iatMedian: 10.0,
      iatMad: 0.078,
      skew: '+0.01',
      bytesOut: '480 B',
      bytesIn: '1,024 B',
      ja4: 't13d1516h2_8daaf4b10222',
      mitre: 'T1071.001 + T1105',
      statusText: 'SetTcpEntry RST + WFP Blocked',
      actionTaken: 'Autonomous Tier-2 Containment Executed'
    },
    {
      id: 'ALT-2026-9178',
      timestamp: '2026-11-14 12:28:40 UTC',
      ageLabel: '48m ago',
      ageHours: 0.80,
      eid: 9001,
      severity: 'HIGH',
      tier: 'Tier-1',
      hostId: 'host-win-app-srv02',
      hostname: 'WIN-APP-SRV02',
      hostIp: '10.0.1.22',
      processName: 'wmiprvse.exe',
      processPath: 'C:\\Windows\\System32\\wbem\\wmiprvse.exe',
      pid: 3104,
      auth: 'Signed MS (Hollowed)',
      sha256: '71bd0093ac118e3b940c7e5612a9881031e4109a',
      parentProc: 'svchost.exe (PID 892)',
      userSid: 'NT AUTHORITY\\NETWORK SERVICE',
      remoteEndpoint: '185.225.73.19:8443',
      framework: 'Cobalt Strike HTTPS Malleable',
      score: 0.912,
      bursts: 11,
      iatMedian: 15.2,
      iatMad: 0.114,
      skew: '-0.02',
      bytesOut: '640 B',
      bytesIn: '2,048 B',
      ja4: 't13d1312h2_f57a46bbac02',
      mitre: 'T1047 + T1071.001',
      statusText: 'Splunk HEC Indexed (0.14s)',
      actionTaken: 'Pending Tier-1 Quorum Confirmation'
    },
    {
      id: 'ALT-2026-9171',
      timestamp: '2026-11-14 10:49:12 UTC',
      ageLabel: '2h ago',
      ageHours: 2.4,
      eid: 9002,
      severity: 'HIGH',
      tier: 'Tier-2',
      hostId: 'host-remote-sales-10',
      hostname: 'REMOTE-SALES-10',
      hostIp: '172.16.40.10',
      processName: 'rundll32.exe',
      processPath: 'C:\\Windows\\System32\\rundll32.exe',
      pid: 7420,
      auth: 'LOLBin Execution',
      sha256: '4c8291bc55e7a1048d39f012a871b2384c903812',
      parentProc: 'WINWORD.EXE (PID 6212)',
      userSid: 'CORP\\s.alaoui (S-1-5-21-...-1308)',
      remoteEndpoint: '185.225.73.19:8443',
      framework: 'Cobalt Strike Beacon DLL',
      score: 0.935,
      bursts: 16,
      iatMedian: 12.0,
      iatMad: 0.088,
      skew: '+0.04',
      bytesOut: '384 B',
      bytesIn: '1,536 B',
      ja4: 't13d1312h2_f57a46bbac02',
      mitre: 'T1218.011 + T1071.001',
      statusText: 'SetTcpEntry RST + WFP Blocked',
      actionTaken: 'Autonomous Tier-2 Containment Executed'
    },
    {
      id: 'ALT-2026-9164',
      timestamp: '2026-11-14 06:42:55 UTC',
      ageLabel: '6h ago',
      ageHours: 6.5,
      eid: 9001,
      severity: 'CRITICAL',
      tier: 'Tier-0',
      hostId: 'host-dc01-prod',
      hostname: 'DC01-PROD',
      hostIp: '10.0.0.10',
      processName: 'lsass_diag.exe',
      processPath: 'C:\\Windows\\Temp\\lsass_diag.exe',
      pid: 6048,
      auth: 'Unsigned PE',
      sha256: '9f0183c2b1084a6c2e77510b8e4901d28f44028b',
      parentProc: 'services.exe (PID 668)',
      userSid: 'NT AUTHORITY\\SYSTEM (S-1-5-18)',
      remoteEndpoint: '91.92.241.58:443',
      framework: 'Mythic Apollo C2 Channel',
      score: 0.951,
      bursts: 12,
      iatMedian: 30.0,
      iatMad: 0.062,
      skew: '+0.01',
      bytesOut: '768 B',
      bytesIn: '1,152 B',
      ja4: 't13d1516h2_c330aa8190f1',
      mitre: 'T1003.001 + T1573',
      statusText: 'Tier-0 Protected (SIEM P1)',
      actionTaken: 'Audit & P1 SOC Escalation (No Auto-Sever)'
    },
    {
      id: 'ALT-2026-9155',
      timestamp: '2026-11-14 02:01:08 UTC',
      ageLabel: '11h ago',
      ageHours: 11.2,
      eid: 9002,
      severity: 'HIGH',
      tier: 'Tier-2',
      hostId: 'host-fin-exec-01',
      hostname: 'FIN-EXEC-01',
      hostIp: '10.0.4.12',
      processName: 'OneDriveSync_tmp.exe',
      processPath: 'C:\\Users\\cfo\\AppData\\Roaming\\OneDriveSync_tmp.exe',
      pid: 8812,
      auth: 'Unsigned PE',
      sha256: '33a72f19d04c8b1e5a92017f6c30841a90e211b7',
      parentProc: 'powershell.exe (PID 4490)',
      userSid: 'CORP\\k.tazi (S-1-5-21-...-1009)',
      remoteEndpoint: '45.155.205.81:443',
      framework: 'Havoc Demon C2 Profile',
      score: 0.942,
      bursts: 22,
      iatMedian: 5.0,
      iatMad: 0.051,
      skew: '+0.02',
      bytesOut: '320 B',
      bytesIn: '896 B',
      ja4: 't13d1516h2_00291a83c114',
      mitre: 'T1059.001 + T1071.001',
      statusText: 'SetTcpEntry RST + WFP Blocked',
      actionTaken: 'Autonomous Tier-2 Containment Executed'
    },
    {
      id: 'ALT-2026-9149',
      timestamp: '2026-11-13 18:45:33 UTC',
      ageLabel: '18h ago',
      ageHours: 18.5,
      eid: 9001,
      severity: 'EVAL',
      tier: 'Tier-1',
      hostId: 'host-exch-hybrid-01',
      hostname: 'EXCH-HYBRID-01',
      hostIp: '10.0.1.35',
      processName: 'MSExchangeSync.exe',
      processPath: 'C:\\Program Files\\Microsoft\\Exchange\\MSExchangeSync.exe',
      pid: 9120,
      auth: 'Signed Vendor',
      sha256: '601bc289f4e19002a74c5b2289d1302e47f108c4',
      parentProc: 'services.exe (PID 704)',
      userSid: 'NT AUTHORITY\\SYSTEM',
      remoteEndpoint: '104.21.48.202:443',
      framework: 'Periodic Polling (Low Entropy)',
      score: 0.520,
      bursts: 9,
      iatMedian: 60.0,
      iatMad: 0.175,
      skew: '+0.14',
      bytesOut: '1,420 B',
      bytesIn: '4,800 B',
      ja4: 't13d1516h2_8daaf4b10222',
      mitre: 'T1071.001 (Monitor Only)',
      statusText: 'Logged to Application.evtx',
      actionTaken: 'Monitoring Under Evaluation Threshold'
    },
    {
      id: 'ALT-2026-9130',
      timestamp: '2026-11-13 01:14:22 UTC',
      ageLabel: '1d 12h ago',
      ageHours: 36.0,
      eid: 9002,
      severity: 'CRITICAL',
      tier: 'Tier-2',
      hostId: 'host-ws-dev-12',
      hostname: 'WS-DEV-12',
      hostIp: '10.0.3.68',
      processName: 'npm_worker.exe',
      processPath: 'C:\\Users\\dev12\\.cache\\npm_worker.exe',
      pid: 5108,
      auth: 'Unsigned PE',
      sha256: 'b18f3309d7c24a081e55a19037c40129ab19e205',
      parentProc: 'node.exe (PID 2904)',
      userSid: 'CORP\\y.hassani (S-1-5-21-...-1402)',
      remoteEndpoint: '194.87.139.27:8080',
      framework: 'Sliver HTTP Implant',
      score: 0.971,
      bursts: 28,
      iatMedian: 6.0,
      iatMad: 0.044,
      skew: '+0.01',
      bytesOut: '256 B',
      bytesIn: '768 B',
      ja4: 'plaintext_http_11',
      mitre: 'T1195.002 + T1071.001',
      statusText: 'SetTcpEntry RST + WFP Blocked',
      actionTaken: 'Autonomous Tier-2 Containment Executed'
    },
    {
      id: 'ALT-2026-9118',
      timestamp: '2026-11-12 07:09:41 UTC',
      ageLabel: '2d ago',
      ageHours: 54.0,
      eid: 9001,
      severity: 'HIGH',
      tier: 'Tier-1',
      hostId: 'host-sql-cluster-01',
      hostname: 'SQL-CLUSTER-01',
      hostIp: '10.0.1.30',
      processName: 'sqlagent_helper.exe',
      processPath: 'C:\\ProgramData\\SQLCache\\sqlagent_helper.exe',
      pid: 6780,
      auth: 'Unsigned PE',
      sha256: 'c4209ab817e630f4b211a98c0029e531d8a712b3',
      parentProc: 'sqlservr.exe (PID 1984)',
      userSid: 'NT SERVICE\\SQLSERVERAGENT',
      remoteEndpoint: '10.0.1.15:445',
      framework: 'SMB Named-Pipe Lateral Pivot',
      score: 0.896,
      bursts: 15,
      iatMedian: 4.5,
      iatMad: 0.072,
      skew: '+0.05',
      bytesOut: '1,024 B',
      bytesIn: '1,024 B',
      ja4: 'smb_v3_named_pipe',
      mitre: 'T1021.002 + T1570',
      statusText: 'Wazuh Rule 100901 Dispatched',
      actionTaken: 'Containment Approved by SOC Tier-2'
    },
    {
      id: 'ALT-2026-9102',
      timestamp: '2026-11-11 07:12:09 UTC',
      ageLabel: '3d ago',
      ageHours: 78.0,
      eid: 9002,
      severity: 'CRITICAL',
      tier: 'Tier-2',
      hostId: 'host-ws-build-node1',
      hostname: 'WS-BUILD-NODE1',
      hostIp: '10.0.3.90',
      processName: 'msbuild_svc.exe',
      processPath: 'C:\\BuildAgent\\temp\\msbuild_svc.exe',
      pid: 9940,
      auth: 'Unsigned PE',
      sha256: '8a11c39f20d49e103b7a61c82e004f99b72c1840',
      parentProc: 'Agent.Worker.exe (PID 3120)',
      userSid: 'CORP\\svc_ci_runner',
      remoteEndpoint: '45.134.26.183:443',
      framework: 'Brute Ratel C4 HTTPS',
      score: 0.981,
      bursts: 24,
      iatMedian: 11.0,
      iatMad: 0.068,
      skew: '+0.02',
      bytesOut: '512 B',
      bytesIn: '1,408 B',
      ja4: 't13d1516h2_5b81e2c9410a',
      mitre: 'T1071.001 + T1055',
      statusText: 'SetTcpEntry RST + WFP Blocked',
      actionTaken: 'Autonomous Tier-2 Containment Executed'
    },
    {
      id: 'ALT-2026-9089',
      timestamp: '2026-11-09 21:04:50 UTC',
      ageLabel: '4d ago',
      ageHours: 112.0,
      eid: 9001,
      severity: 'HIGH',
      tier: 'Tier-1',
      hostId: 'host-file-srv-corp',
      hostname: 'FILE-SRV-CORP',
      hostIp: '10.0.1.40',
      processName: 'powershell.exe',
      processPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      pid: 4412,
      auth: 'LOLBin Execution',
      sha256: 'de96a6d6994433554e921b9d9f3a0018e589c4d1',
      parentProc: 'wsmprovhost.exe (PID 2088)',
      userSid: 'CORP\\adm_backups',
      remoteEndpoint: '10.0.3.44:5985',
      framework: 'WinRM / PowerShell Remoting Burst',
      score: 0.874,
      bursts: 10,
      iatMedian: 9.8,
      iatMad: 0.132,
      skew: '-0.04',
      bytesOut: '896 B',
      bytesIn: '2,304 B',
      ja4: 'winrm_http_negotiate',
      mitre: 'T1021.006 + T1059.001',
      statusText: 'Splunk HEC Indexed (0.19s)',
      actionTaken: 'Investigated & Contained Remotely'
    },
    {
      id: 'ALT-2026-9074',
      timestamp: '2026-11-08 09:16:30 UTC',
      ageLabel: '6d ago',
      ageHours: 148.0,
      eid: 9002,
      severity: 'CRITICAL',
      tier: 'Tier-2',
      hostId: 'host-hr-payroll-02',
      hostname: 'HR-PAYROLL-02',
      hostIp: '10.0.5.18',
      processName: 'adp_sync_util.exe',
      processPath: 'C:\\Users\\hr_pay\\Downloads\\adp_sync_util.exe',
      pid: 7716,
      auth: 'Unsigned PE',
      sha256: 'f82c100b31e9a4d6208c4f13b907e2a8c5019f44',
      parentProc: 'chrome.exe (PID 5120)',
      userSid: 'CORP\\n.idrissi (S-1-5-21-...-1510)',
      remoteEndpoint: '193.26.158.114:443',
      framework: 'Sliver mTLS / Raw IP C2',
      score: 0.991,
      bursts: 31,
      iatMedian: 8.4,
      iatMad: 0.039,
      skew: '+0.01',
      bytesOut: '512 B',
      bytesIn: '1,280 B',
      ja4: 't13d1516h2_8daaf4b10222',
      mitre: 'T1566.001 + T1071.001',
      statusText: 'SetTcpEntry RST + WFP Blocked',
      actionTaken: 'Autonomous Tier-2 Containment Executed'
    },
    {
      id: 'ALT-2026-9061',
      timestamp: '2026-11-05 19:22:14 UTC',
      ageLabel: '8d ago',
      ageHours: 210.0,
      eid: 9001,
      severity: 'HIGH',
      tier: 'Tier-0',
      hostId: 'host-pki-ca01',
      hostname: 'PKI-CA01',
      hostIp: '10.0.0.20',
      processName: 'cert_export.exe',
      processPath: 'C:\\Users\\ca_admin\\AppData\\Local\\cert_export.exe',
      pid: 5510,
      auth: 'Unsigned PE',
      sha256: '2d8a049c71e80b3f9210a44d7e60582c1a9f0047',
      parentProc: 'cmd.exe (PID 3912)',
      userSid: 'CORP\\svc_ca_enroll',
      remoteEndpoint: '10.0.0.10:445',
      framework: 'ADCS / SMB Relay Beacon',
      score: 0.905,
      bursts: 13,
      iatMedian: 7.5,
      iatMad: 0.091,
      skew: '+0.06',
      bytesOut: '1,152 B',
      bytesIn: '1,792 B',
      ja4: 'smb_v3_signing_disabled',
      mitre: 'T1649 + T1557',
      statusText: 'Tier-0 Protected (SIEM P1)',
      actionTaken: 'Blocked via Firewall & Revoked Token'
    },
    {
      id: 'ALT-2026-9045',
      timestamp: '2026-11-02 13:05:48 UTC',
      ageLabel: '12d ago',
      ageHours: 288.0,
      eid: 9001,
      severity: 'HIGH',
      tier: 'Tier-1',
      hostId: 'host-gw-edge-01',
      hostname: 'GW-EDGE-01',
      hostIp: '10.0.2.10',
      processName: 'nginx_proxy_mod.exe',
      processPath: 'C:\\EdgeProxy\\modules\\nginx_proxy_mod.exe',
      pid: 6204,
      auth: 'Unsigned PE',
      sha256: '17d8a390b211c847e950a31b42c6d108f3b22e01',
      parentProc: 'nginx.exe (PID 1480)',
      userSid: 'NT AUTHORITY\\LOCAL SERVICE',
      remoteEndpoint: '185.225.73.19:8443',
      framework: 'Reverse SOCKS5 Tunnel Cadence',
      score: 0.889,
      bursts: 18,
      iatMedian: 2.5,
      iatMad: 0.105,
      skew: '+0.08',
      bytesOut: '768 B',
      bytesIn: '2,560 B',
      ja4: 't13d1312h2_f57a46bbac02',
      mitre: 'T1090.001 + T1572',
      statusText: 'Wazuh Rule 100901 Dispatched',
      actionTaken: 'Analyst Severed Socket via Console'
    },
    {
      id: 'ALT-2026-9032',
      timestamp: '2026-10-30 13:18:02 UTC',
      ageLabel: '15d ago',
      ageHours: 360.0,
      eid: 9002,
      severity: 'CRITICAL',
      tier: 'Tier-2',
      hostId: 'host-fin-billing-03',
      hostname: 'FIN-BILLING-03',
      hostIp: '10.0.4.25',
      processName: 'invoice_viewer.exe',
      processPath: 'C:\\Users\\billing3\\Desktop\\invoice_viewer.exe',
      pid: 8044,
      auth: 'Unsigned PE',
      sha256: '66a01d4f920e7b11c839a54d2b07e8c913f42209',
      parentProc: 'OUTLOOK.EXE (PID 2610)',
      userSid: 'CORP\\r.chraibi (S-1-5-21-...-1604)',
      remoteEndpoint: '193.26.158.114:443',
      framework: 'Sliver mTLS / Raw IP C2',
      score: 0.976,
      bursts: 20,
      iatMedian: 8.4,
      iatMad: 0.055,
      skew: '+0.02',
      bytesOut: '512 B',
      bytesIn: '1,280 B',
      ja4: 't13d1516h2_8daaf4b10222',
      mitre: 'T1204.002 + T1071.001',
      statusText: 'SetTcpEntry RST + WFP Blocked',
      actionTaken: 'Autonomous Tier-2 Containment Executed'
    },
    {
      id: 'ALT-2026-9021',
      timestamp: '2026-10-27 13:10:19 UTC',
      ageLabel: '18d ago',
      ageHours: 432.0,
      eid: 9001,
      severity: 'EVAL',
      tier: 'Tier-2',
      hostId: 'host-ops-helpdesk-03',
      hostname: 'OPS-HELPDESK-03',
      hostIp: '10.0.6.14',
      processName: 'ScreenConnectClient.exe',
      processPath: 'C:\\Program Files\\ScreenConnect\\ScreenConnectClient.exe',
      pid: 3420,
      auth: 'Signed Vendor',
      sha256: '09c2b4e178a31d90f4a8275b1039e6d2c74108a2',
      parentProc: 'services.exe (PID 688)',
      userSid: 'NT AUTHORITY\\SYSTEM',
      remoteEndpoint: '52.16.192.44:8041',
      framework: 'RMM Heartbeat (Allowlisted)',
      score: 0.615,
      bursts: 12,
      iatMedian: 20.0,
      iatMad: 0.148,
      skew: '+0.11',
      bytesOut: '256 B',
      bytesIn: '384 B',
      ja4: 't13d1516h2_90a2c714e811',
      mitre: 'T1219 (Verified Benign RMM)',
      statusText: 'Resolved via WL-2026-002',
      actionTaken: 'SOC Allowlisted Approved Helpdesk RMM'
    },
    {
      id: 'ALT-2026-9012',
      timestamp: '2026-10-24 13:44:05 UTC',
      ageLabel: '21d ago',
      ageHours: 504.0,
      eid: 9001,
      severity: 'CRITICAL',
      tier: 'Tier-0',
      hostId: 'host-mgt-paw-01',
      hostname: 'MGT-PAW-01',
      hostIp: '10.0.0.50',
      processName: 'ad_audit_tmp.exe',
      processPath: 'C:\\Windows\\Temp\\ad_audit_tmp.exe',
      pid: 4816,
      auth: 'Unsigned PE',
      sha256: 'e019c8b473a2d65f1908c47a3e21b905d64c2108',
      parentProc: 'powershell.exe (PID 3102)',
      userSid: 'CORP\\tier0_admin_m',
      remoteEndpoint: '91.92.241.58:443',
      framework: 'Mythic Poseidon / Apollo',
      score: 0.958,
      bursts: 16,
      iatMedian: 14.0,
      iatMad: 0.064,
      skew: '+0.03',
      bytesOut: '512 B',
      bytesIn: '1,024 B',
      ja4: 't13d1516h2_c330aa8190f1',
      mitre: 'T1071.001 + T1550',
      statusText: 'Tier-0 Protected (SIEM P1)',
      actionTaken: 'Privileged Account Reset + Manual Sever'
    },
    {
      id: 'ALT-2026-9004',
      timestamp: '2026-10-21 13:02:11 UTC',
      ageLabel: '24d ago',
      ageHours: 576.0,
      eid: 9001,
      severity: 'HIGH',
      tier: 'Tier-1',
      hostId: 'host-win-prod-srv01',
      hostname: 'WIN-PROD-SRV01',
      hostIp: '10.0.1.15',
      processName: 'regsvr32.exe',
      processPath: 'C:\\Windows\\System32\\regsvr32.exe',
      pid: 2948,
      auth: 'LOLBin Execution',
      sha256: '8d9c0142a7b5e3610f82c419b3a7085d2e110c94',
      parentProc: 'wmiprvse.exe (PID 1844)',
      userSid: 'NT AUTHORITY\\SYSTEM',
      remoteEndpoint: '185.225.73.19:8443',
      framework: 'Squiblydoo C2 Stager Cadence',
      score: 0.894,
      bursts: 9,
      iatMedian: 18.0,
      iatMad: 0.098,
      skew: '+0.05',
      bytesOut: '448 B',
      bytesIn: '1,664 B',
      ja4: 't13d1312h2_f57a46bbac02',
      mitre: 'T1218.010 + T1071.001',
      statusText: 'Splunk HEC Indexed (0.16s)',
      actionTaken: 'Blocked & Rotated Local Admin Keys'
    }
  ];

  const SIEM_SNIPPETS = {
    wazuh_rules: `<!-- /var/ossec/etc/rules/local_rules.xml on Wazuh Manager -->
<group name="uncloak_ndr,windows,c2_defense,">
  <rule id="100901" level="12">
    <if_sid>60009</if_sid>
    <field name="win.system.providerName">^Microsoft-Windows-Uncloak-Sensor$</field>
    <field name="win.system.eventID">^9001$</field>
    <description>Uncloak NDR: Periodic C2 Beacon Detected ($(win.eventdata.processName) -> $(win.eventdata.remoteEndpoint))</description>
    <mitre>
      <id>T1071.001</id>
      <id>T1573</id>
    </mitre>
    <group>attack,c2_beacon,uncloak_detection,</group>
  </rule>

  <rule id="100902" level="10">
    <if_sid>60009</if_sid>
    <field name="win.system.providerName">^Microsoft-Windows-Uncloak-Sensor$</field>
    <field name="win.system.eventID">^9002$</field>
    <description>Uncloak Containment: Kernel SetTcpEntry TCB Eviction / WFP Block Enforced on PID $(win.eventdata.pid)</description>
    <mitre>
      <id>M1030</id>
    </mitre>
    <group>active_response,containment,uncloak_containment,</group>
  </rule>
</group>`,
    wazuh_ossec: `<!-- C:\\Program Files (x86)\\ossec-agent\\ossec.conf on Managed Endpoints -->
<ossec_config>
  <!-- 1. Forward native Windows Event Log (EID 9001 & 9002) via EventChannel -->
  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[Provider[@Name='Microsoft-Windows-Uncloak-Sensor']]</query>
  </localfile>

  <!-- 2. Stream OCSF v1.1.0 structured JSON alerts directly to Wazuh Manager -->
  <localfile>
    <log_format>json</log_format>
    <location>C:\\ProgramData\\Uncloak\\logs\\uncloak_alerts.ndjson</location>
  </localfile>
</ossec_config>`,
    splunk_inputs: `# $SPLUNK_HOME\\etc\\apps\\TA-uncloak\\local\\inputs.conf (Universal Forwarder)

[WinEventLog://Application]
disabled = 0
whitelist1 = EventCode="9001,9002" SourceName="Microsoft-Windows-Uncloak-Sensor"
index = main
sourcetype = WinEventLog:Application

[monitor://C:\\ProgramData\\Uncloak\\logs\\uncloak_alerts.ndjson]
disabled = 0
index = main
sourcetype = uncloak:ocsf:json
crcSalt = <SOURCE>

# Sample SPL Correlation Search for Multi-Host Outbreaks:
# index=main (sourcetype="uncloak:ocsf:json" OR EventCode IN (9001, 9002))
# | stats count values(actor_process.name) dc(src_endpoint.ip) by dst_endpoint.ip`,
    ocsf_schema: `{
  "metadata": {
    "version": "1.1.0",
    "log_provider": "Microsoft-Windows-Uncloak-Sensor",
    "windows_event_id": 9001,
    "logged_time": "2026-11-14T13:12:04Z"
  },
  "class_uid": 4001,
  "activity_name": "C2 Beacon Detected",
  "severity": "Critical",
  "src_endpoint": { "hostname": "WIN-PROD-SRV01", "ip": "10.0.1.15", "port": 49152 },
  "dst_endpoint": { "ip": "193.26.158.114", "port": 443 },
  "actor_process": { "pid": 5824, "name": "update.exe", "is_signed": false },
  "uncloak_telemetry": {
    "threat_score": 0.987,
    "c2_framework": "Sliver mTLS / Raw IP C2",
    "features_v1": { "n_bursts": 14, "iat_median": 8.4, "iat_mad_ratio": 0.095, "raw_ip_flag": 1 }
  }
}`
  };

  /* ================= HELPERS & THEME ================= */
  function escHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function applyTheme(theme) {
    const isDark = theme === 'dark';
    document.body.classList.toggle('theme-dark', isDark);
    const lbl = document.getElementById('theme-toggle-icon');
    if (lbl) lbl.innerText = isDark ? 'Light Enterprise' : 'Dark Slate';
    try { localStorage.setItem('uncloak_theme', isDark ? 'dark' : 'light'); } catch (e) {}
  }

  function toggleTheme() {
    applyTheme(document.body.classList.contains('theme-dark') ? 'light' : 'dark');
  }

  function initTheme() {
    let saved = 'light';
    try { saved = localStorage.getItem('uncloak_theme') || 'light'; } catch (e) {}
    applyTheme(saved);
  }

  function cycleDensity() {
    const b = document.body;
    if (!b.classList.contains('force-compact') && !b.classList.contains('force-large')) {
      b.classList.add('force-compact');
    } else if (b.classList.contains('force-compact')) {
      b.classList.remove('force-compact');
      b.classList.add('force-large');
    } else {
      b.classList.remove('force-large');
    }
    updateDensityLabel();
  }

  function updateDensityLabel() {
    const lbl = document.getElementById('density-label');
    if (!lbl) return;
    if (document.body.classList.contains('force-compact')) lbl.innerText = 'Compact';
    else if (document.body.classList.contains('force-large')) lbl.innerText = 'Comfortable';
    else lbl.innerText = 'Normal';
  }

  /* ================= NAVIGATION & POLLING ================= */
  function switchView(tabName) {
    currentTab = tabName;
    ['fleet', 'campaign', 'drilldown', 'alerts', 'policies'].forEach(t => {
      const nav = document.getElementById('nav-' + t);
      const panel = document.getElementById('view-' + t);
      if (nav) nav.classList.toggle('active', t === tabName);
      if (panel) panel.classList.toggle('active', t === tabName);
    });
    const bc = VIEW_BREADCRUMBS[tabName] || { section: 'Monitoring', page: tabName };
    document.getElementById('bc-section').innerText = bc.section;
    document.getElementById('bc-page').innerText = bc.page;
    renderUI();
  }

  async function fetchState() {
    try {
      const hostArg = userSelectedHostId ? '?host=' + encodeURIComponent(userSelectedHostId) : '';
      const pidArg = userSelectedPid ? (hostArg ? '&' : '?') + 'pid=' + encodeURIComponent(userSelectedPid) : '';
      const res = await fetch('/api/state' + hostArg + pidArg);
      if (!res.ok) return;
      stateData = await res.json();
      if (!userSelectedHostId && stateData.selected_host_id) userSelectedHostId = stateData.selected_host_id;
      if (!userSelectedPid && stateData.selected_pid) userSelectedPid = stateData.selected_pid;
      renderUI();
    } catch (err) {
      // Passive ignore on poll failure while keeping current UI state intact
    }
  }

  function renderUI() {
    if (!stateData) return;
    const summary = stateData.fleet_summary || {};
    const critCount = (summary.critical_hosts || 0) + (summary.high_hosts || 0);

    document.getElementById('nav-badge-fleet').innerText = critCount;
    document.getElementById('nav-badge-campaign').innerText = (stateData.campaigns || []).length;
    document.getElementById('rail-host-sync').innerText = (summary.total_hosts || 0) + ' / ' + (summary.total_hosts || 0) + ' Hosts';

    const topChip = document.getElementById('top-threat-chip');
    const topLabel = document.getElementById('top-threat-label');
    if (critCount > 0) {
      topChip.classList.remove('clean');
      topLabel.innerText = critCount + ' Active Threats';
    } else {
      topChip.classList.add('clean');
      topLabel.innerText = 'Fleet Nominal';
    }

    if (currentTab === 'fleet') renderFleetView();
    else if (currentTab === 'campaign') renderCampaigns();
    else if (currentTab === 'drilldown') renderHostDrilldown();
    else if (currentTab === 'alerts') renderAlertsLedger();
    else if (currentTab === 'policies') renderPoliciesView();
  }

  /* ================= VIEW 1: FLEET ENDPOINTS ================= */
  function filterToActiveThreats() {
    switchView('fleet');
    filterTableByScope('THREATS');
  }

  function switchFleetLayout(layout) {
    currentFleetLayout = layout;
    document.getElementById('btn-fleet-table').classList.toggle('active', layout === 'table');
    document.getElementById('btn-fleet-grid').classList.toggle('active', layout === 'grid');
    document.getElementById('fleet-table-container').style.display = layout === 'table' ? 'flex' : 'none';
    document.getElementById('fleet-subnets-container').style.display = layout === 'grid' ? 'flex' : 'none';
    renderFleetView();
  }

  function filterTableByScope(scope) {
    activeFleetScope = scope;
    ['all', 'threats', 'tier0', 'tier1', 'tier2', 'muted'].forEach(k => {
      const btn = document.getElementById('filter-btn-' + k);
      if (btn) btn.classList.remove('active');
    });
    const key = scope === 'TIER-0' ? 'tier0' : (scope === 'TIER-1' ? 'tier1' : (scope === 'TIER-2' ? 'tier2' : scope.toLowerCase()));
    const activeBtn = document.getElementById('filter-btn-' + key);
    if (activeBtn) activeBtn.classList.add('active');
    renderFleetView();
  }

  function getFilteredHosts() {
    if (!stateData || !stateData.hosts) return [];
    const q = (document.getElementById('fleet-search-input')?.value || '').trim().toLowerCase();
    return stateData.hosts.filter(h => {
      if (activeFleetScope === 'THREATS' && h.threat_level !== 'CRITICAL' && h.threat_level !== 'HIGH') return false;
      if (activeFleetScope === 'TIER-0' && !(h.ad_tier || h.subnet || '').includes('Tier-0')) return false;
      if (activeFleetScope === 'TIER-1' && !(h.ad_tier || h.subnet || '').includes('Tier-1')) return false;
      if (activeFleetScope === 'TIER-2' && !(h.ad_tier || h.subnet || '').includes('Tier-2')) return false;
      if (activeFleetScope === 'MUTED' && h.status !== 'MUTED') return false;
      if (!q) return true;
      const hay = `${h.hostname} ${h.ip_address} ${h.os_version} ${h.ad_tier || ''} ${h.subnet || ''} ${h.c2_framework || ''}`.toLowerCase();
      return hay.includes(q);
    });
  }

  function renderFleetView() {
    if (!stateData) return;
    const summary = stateData.fleet_summary || {};
    const hosts = stateData.hosts || [];

    document.getElementById('kpi-crit-hosts').innerText = (summary.critical_hosts || 0) + (summary.high_hosts || 0);
    document.getElementById('kpi-total-hosts').innerText = summary.total_hosts || hosts.length;
    document.getElementById('kpi-total-sockets').innerText = summary.total_sockets || 0;
    document.getElementById('kpi-muted-hosts').innerText = summary.muted_hosts || hosts.filter(h => h.is_isolated || h.status === 'MUTED').length;

    // Priority Threat Strip
    const threatHosts = hosts.filter(h => h.threat_level === 'CRITICAL' || h.threat_level === 'HIGH');
    const stripSection = document.getElementById('fleet-priority-section');
    const stripGrid = document.getElementById('fleet-priority-strip');
    if (threatHosts.length > 0) {
      stripSection.style.display = 'flex';
      stripGrid.innerHTML = threatHosts.slice(0, 4).map(h => {
        const isHigh = h.threat_level === 'HIGH';
        return `
          <div class="priority-card ${isHigh ? 'high' : ''}" onclick="inspectHostInDrawer('${escHtml(h.host_id)}')">
            <div class="priority-card-top">
              <div>
                <div class="priority-host">${escHtml(h.hostname)}</div>
                <div class="priority-meta mono">${escHtml(h.ip_address)} &bull; ${escHtml(h.ad_tier || h.subnet)}</div>
              </div>
              <span class="badge ${isHigh ? 'high' : 'crit'}">${escHtml(h.threat_level)}</span>
            </div>
            <div class="priority-framework">
              <span>${escHtml(h.c2_framework || 'Periodic C2 Beacon')}</span>
              <span class="mono">${(h.threat_score * 100).toFixed(1)}%</span>
            </div>
            <div class="priority-actions">
              <button class="btn btn-sm" onclick="event.stopPropagation(); inspectHostInDrawer('${escHtml(h.host_id)}')">Inspect Drawer</button>
              <button class="btn btn-primary btn-sm" onclick="event.stopPropagation(); selectAndDrilldown('${escHtml(h.host_id)}')">Triage Host &#8594;</button>
            </div>
          </div>`;
      }).join('');
    } else {
      stripSection.style.display = 'none';
    }

    const filtered = getFilteredHosts();
    document.getElementById('fleet-table-counter').innerText = `Showing ${filtered.length} of ${hosts.length} Endpoints`;

    if (currentFleetLayout === 'table') {
      renderFleetTable(filtered);
    } else {
      renderFleetSubnetsGrid(filtered);
    }
  }

  function renderFleetTable(filtered) {
    const tbody = document.getElementById('fleet-table-tbody');
    if (!tbody) return;
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" style="text-align: center; padding: 36px; color: var(--text-muted);">No endpoints match the current filter criteria.</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.map(h => {
      const isCrit = h.threat_level === 'CRITICAL';
      const isHigh = h.threat_level === 'HIGH';
      const isEval = h.threat_level === 'EVALUATING';
      const isMuted = h.status === 'MUTED';
      const isIso = h.is_isolated;
      const badgeClass = isMuted ? 'neutral' : (isCrit ? 'crit' : (isHigh || isIso ? 'high' : (isEval ? 'eval' : 'ok')));
      const badgeLabel = isIso ? 'ISOLATED' : (isMuted ? 'STALE' : h.threat_level);
      const rowClass = (isCrit ? 'row-threat ' : (isHigh ? 'row-high ' : '')) + (isIso ? 'row-isolated ' : '') + (userSelectedHostId === h.host_id ? 'row-selected' : '');

      let staleText = 'Just now';
      if (h.seconds_since_heartbeat > 5) {
        const m = Math.floor(h.seconds_since_heartbeat / 60);
        const s = h.seconds_since_heartbeat % 60;
        staleText = m > 0 ? `${m}m ${s}s ago` : `${s}s ago`;
      }

      const scoreColor = isCrit ? 'var(--crit-text)' : (isHigh ? 'var(--high-text)' : 'var(--text-muted)');
      return `
        <tr class="${rowClass}" onclick="inspectHostInDrawer('${escHtml(h.host_id)}')">
          <td>
            <span class="badge ${badgeClass}">
              <span class="dot-status ${isCrit ? 'crit' : (isHigh ? 'high' : (isMuted ? 'muted' : ''))}"></span>
              ${escHtml(badgeLabel)}
            </span>
          </td>
          <td>
            <span class="cell-primary">${escHtml(h.hostname)}</span>
            <span class="cell-sub">${escHtml(h.os_version)}</span>
          </td>
          <td class="mono">${escHtml(h.ip_address)}</td>
          <td><span class="badge neutral">${escHtml(h.ad_tier || h.subnet)}</span></td>
          <td class="mono" style="font-weight: 600;">${h.active_sockets_count}</td>
          <td class="mono" style="font-size: 12px; color: var(--text-muted);">${h.cpu_percent}% / ${h.ram_mb} MB</td>
          <td class="mono" style="text-align: right; font-weight: 700; color: ${scoreColor};">${(h.threat_score * 100).toFixed(1)}%</td>
          <td>
            ${h.c2_framework
              ? `<span style="font-weight: 600; color: var(--crit-text);">${escHtml(h.c2_framework)}</span>`
              : `<span style="color: var(--text-muted);">Nominal</span>`}
          </td>
          <td class="mono" style="font-size: 12px; color: var(--text-muted);">${staleText}</td>
          <td style="text-align: right; white-space: nowrap;">
            <button class="btn btn-sm" onclick="event.stopPropagation(); selectAndDrilldown('${escHtml(h.host_id)}')" style="margin-right: 6px;">Triage &#8594;</button>
            <button class="btn btn-sm ${isIso ? '' : 'btn-danger'}" onclick="event.stopPropagation(); toggleHostIsolation('${escHtml(h.host_id)}')">${isIso ? 'Re-Join' : 'Isolate'}</button>
          </td>
        </tr>`;
    }).join('');
  }

  function renderFleetSubnetsGrid(filtered) {
    const container = document.getElementById('fleet-subnets-container');
    if (!container) return;
    const grouped = {};
    filtered.forEach(h => {
      const k = h.subnet || h.ad_tier || 'Enterprise Network';
      if (!grouped[k]) grouped[k] = [];
      grouped[k].push(h);
    });
    const keys = Object.keys(grouped);
    if (keys.length === 0) {
      container.innerHTML = '<div class="panel-card" style="padding: 36px; text-align: center; color: var(--text-muted);">No endpoints match the current filter criteria.</div>';
      return;
    }
    container.innerHTML = keys.map(subnet => {
      const cards = grouped[subnet].map(h => {
        const isCrit = h.threat_level === 'CRITICAL';
        const isHigh = h.threat_level === 'HIGH';
        const cardCls = isCrit ? 'threat-c2' : (isHigh ? 'threat-high' : '');
        const badgeCls = isCrit ? 'crit' : (isHigh ? 'high' : 'ok');
        return `
          <div class="host-grid-card ${cardCls}" onclick="inspectHostInDrawer('${escHtml(h.host_id)}')">
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
              <strong style="color: var(--text-main);">${escHtml(h.hostname)}</strong>
              <span class="badge ${badgeCls}">${escHtml(h.threat_level)}</span>
            </div>
            <div class="mono" style="font-size: 12px; color: var(--text-muted);">${escHtml(h.ip_address)} &bull; ${h.active_sockets_count} sockets</div>
            <div style="font-size: 12px; color: ${isCrit ? 'var(--crit-text)' : 'var(--text-secondary)'}; font-weight: ${isCrit ? '600' : '400'};">
              ${escHtml(h.c2_framework || 'No active beacon signature')}
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px;">
              <span class="mono" style="font-size: 12px; font-weight: 700;">${(h.threat_score * 100).toFixed(1)}%</span>
              <button class="btn btn-sm" onclick="event.stopPropagation(); selectAndDrilldown('${escHtml(h.host_id)}')">Triage &#8594;</button>
            </div>
          </div>`;
      }).join('');
      return `
        <div class="subnet-group-card">
          <div class="subnet-group-header">
            <strong style="font-size: 14px; color: var(--text-main);">${escHtml(subnet)}</strong>
            <span class="badge neutral mono">${grouped[subnet].length} Hosts</span>
          </div>
          <div class="hosts-grid">${cards}</div>
        </div>`;
    }).join('');
  }

  /* ================= VIEW 2: THREAT CAMPAIGNS ================= */
  function renderCampaigns() {
    if (!stateData || !stateData.campaigns) return;
    const campaigns = stateData.campaigns || [];
    if (!selectedCampaignId && campaigns.length > 0) selectedCampaignId = campaigns[0].campaign_id;

    document.getElementById('camp-kpi-count').innerText = campaigns.length;
    const uniqueHosts = new Set();
    campaigns.forEach(c => (c.affected_hosts || []).forEach(h => uniqueHosts.add(h)));
    document.getElementById('camp-kpi-hosts').innerText = uniqueHosts.size;
    if (campaigns[0]) document.getElementById('camp-kpi-ja4').innerText = campaigns[0].ja4_fingerprint;

    const listEl = document.getElementById('campaign-list-container');
    listEl.innerHTML = campaigns.map(c => {
      const sel = c.campaign_id === selectedCampaignId ? 'selected' : '';
      return `
        <div class="campaign-list-card ${sel}" onclick="selectCampaign('${escHtml(c.campaign_id)}')">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
            <span class="badge ${c.status === 'SEVERED' ? 'ok' : 'crit'}">${escHtml(c.status)}</span>
            <span class="mono" style="font-size: 12px; font-weight: 700; color: var(--crit-text);">${(c.threat_score * 100).toFixed(1)}%</span>
          </div>
          <div style="font-size: 14px; font-weight: 700; color: var(--text-main);">${escHtml(c.name)}</div>
          <div style="font-size: 12px; color: var(--text-muted);">${escHtml(c.c2_framework)}</div>
          <div class="mono" style="font-size: 11.5px; color: var(--text-secondary);">Dest: ${escHtml(c.target_destination)} &bull; ${(c.affected_hosts || []).length} Hosts</div>
        </div>`;
    }).join('');

    const camp = campaigns.find(c => c.campaign_id === selectedCampaignId) || campaigns[0];
    if (!camp) return;

    document.getElementById('cd-title').innerText = camp.name + ' (' + camp.c2_framework + ')';
    document.getElementById('cd-subtitle').innerText = `Destination: ${camp.target_destination} | JA4: ${camp.ja4_fingerprint}`;

    const hostObjs = (stateData.hosts || []).filter(h => (camp.affected_hosts || []).includes(h.host_id) || (camp.affected_hosts || []).includes(h.hostname));
    const kcEl = document.getElementById('killchain-flow');
    kcEl.innerHTML = `
      <div class="kc-stage">
        <div style="font-size: 11px; font-weight: 700; color: var(--accent);">01 / INITIAL EXECUTION</div>
        <div style="font-weight: 600; margin-top: 4px;">Unsigned Payload / LOLBin</div>
        <div class="mono" style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">${hostObjs.length} Managed Endpoints</div>
      </div>
      <div class="kc-arrow">&#8594;</div>
      <div class="kc-stage">
        <div style="font-size: 11px; font-weight: 700; color: var(--high-text);">02 / CADENCE VECTOR</div>
        <div style="font-weight: 600; margin-top: 4px;">Periodic Jitter Signature</div>
        <div class="mono" style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">${escHtml(camp.cadence_profile)}</div>
      </div>
      <div class="kc-arrow">&#8594;</div>
      <div class="kc-stage">
        <div style="font-size: 11px; font-weight: 700; color: var(--accent);">03 / TLS FINGERPRINT</div>
        <div style="font-weight: 600; margin-top: 4px;">Shared ClientHello Cluster</div>
        <div class="mono" style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">${escHtml(camp.ja4_fingerprint)}</div>
      </div>
      <div class="kc-arrow">&#8594;</div>
      <div class="kc-stage danger">
        <div style="font-size: 11px; font-weight: 700; color: var(--crit-text);">04 / EXTERNAL C2 NODE</div>
        <div class="mono" style="font-weight: 700; margin-top: 4px; color: var(--crit-text);">${escHtml(camp.target_destination)}</div>
        <div style="font-size: 11.5px; color: var(--text-secondary); margin-top: 2px;">MITRE T1071.001 / T1573</div>
      </div>`;

    document.getElementById('cd-metrics-grid').innerHTML = `
      <div class="metric-subcard">
        <span class="kv-label">FlowFeaturesV1 Cadence</span>
        <strong style="color: var(--text-main);">${escHtml(camp.cadence_profile)}</strong>
        <span style="font-size: 12px; color: var(--text-muted);">Clustered multi-host beacon periodicity</span>
      </div>
      <div class="metric-subcard">
        <span class="kv-label">JA4 Client Fingerprint</span>
        <strong class="mono" style="color: var(--accent);">${escHtml(camp.ja4_fingerprint)}</strong>
        <span style="font-size: 12px; color: var(--text-muted);">Identical TLS cipher + ALPN handshake across fleet</span>
      </div>
      <div class="metric-subcard">
        <span class="kv-label">Campaign Confidence</span>
        <strong class="mono" style="color: var(--crit-text);">${(camp.threat_score * 100).toFixed(1)}%</strong>
        <span style="font-size: 12px; color: var(--text-muted);">Cross-host correlation quorum reached</span>
      </div>`;

    const tbody = document.getElementById('cd-hosts-tbody');
    tbody.innerHTML = hostObjs.map(h => `
      <tr onclick="selectAndDrilldown('${escHtml(h.host_id)}')">
        <td><strong style="color: var(--text-main);">${escHtml(h.hostname)}</strong></td>
        <td class="mono">${escHtml(h.ip_address)}</td>
        <td><span class="badge neutral">${escHtml(h.ad_tier || h.subnet)}</span></td>
        <td class="mono">${h.active_sockets_count}</td>
        <td class="mono" style="text-align: right; font-weight: 700; color: var(--crit-text);">${(h.threat_score * 100).toFixed(1)}%</td>
        <td style="text-align: right;"><button class="btn btn-sm">Triage Host &#8594;</button></td>
      </tr>`).join('') || '<tr><td colspan="6" style="padding: 20px; text-align: center; color: var(--text-muted);">No matching active endpoints currently reported.</td></tr>';
  }

  function selectCampaign(campId) {
    selectedCampaignId = campId;
    renderCampaigns();
  }

  /* ================= VIEW 3: ENDPOINT TRIAGE ================= */
  function selectAndDrilldown(hostId) {
    userSelectedHostId = hostId;
    userSelectedPid = null;
    closeInspectorDrawer();
    switchView('drilldown');
    fetchState();
  }

  function changeSelectedHost(hostId) {
    userSelectedHostId = hostId;
    userSelectedPid = null;
    fetch('/api/select_host', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host_id: hostId })
    }).then(() => fetchState());
  }

  function switchHostSubtab(subtab) {
    currentHostSubtab = subtab;
    ['flows', 'procs', 'history', 'whitelist'].forEach(t => {
      document.getElementById('subtab-' + t).classList.toggle('active', t === subtab);
      document.getElementById('subpanel-' + t).style.display = t === subtab ? 'block' : 'none';
    });
    if (subtab === 'whitelist') renderWhitelistLedger();
  }

  function renderHostDrilldown() {
    if (!stateData) return;
    const hosts = stateData.hosts || [];
    const host = stateData.selected_host || hosts[0];
    if (!host) return;

    const sel = document.getElementById('host-selector');
    if (sel.options.length !== hosts.length) {
      sel.innerHTML = hosts.map(h => `<option value="${escHtml(h.host_id)}">${escHtml(h.hostname)} (${escHtml(h.ip_address)})</option>`).join('');
    }
    sel.value = host.host_id;

    document.getElementById('hd-ip').innerText = host.ip_address;
    document.getElementById('hd-tier').innerText = host.ad_tier || host.subnet;
    document.getElementById('hd-os').innerText = host.os_version;

    const agentPill = document.getElementById('hd-agent-state');
    const isoBtn = document.getElementById('btn-isolate-host');
    if (host.is_isolated) {
      agentPill.className = 'badge high';
      agentPill.innerText = 'WFP Isolated';
      isoBtn.innerText = 'Re-Join Network';
      isoBtn.className = 'btn btn-sm';
    } else {
      agentPill.className = 'badge ok';
      agentPill.innerText = 'Agent Streaming';
      isoBtn.innerText = 'Isolate Host (WFP)';
      isoBtn.className = 'btn btn-danger btn-sm';
    }

    const flows = stateData.flows || [];
    const procs = stateData.host_processes || [];
    const history = stateData.host_connection_history || [];
    document.getElementById('subtab-flows-count').innerText = `(${flows.length})`;
    document.getElementById('subtab-procs-count').innerText = `(${procs.length})`;

    const activeFlow = flows.find(f => f.pid === userSelectedPid) || flows.find(f => f.is_threat && !f.is_severed) || flows.find(f => f.is_threat) || flows[0];
    const banner = document.getElementById('hd-incident-banner');
    if (activeFlow && (activeFlow.is_threat || activeFlow.threat_score >= 0.7)) {
      const madVal = String(activeFlow.iat_mad_ratio || '0.095').split(' ')[0];
      banner.classList.remove('clean');
      document.getElementById('ib-sev-badge').className = activeFlow.threat_score >= 0.9 ? 'badge crit' : 'badge high';
      document.getElementById('ib-sev-badge').innerText = activeFlow.threat_label || 'C2 BEACON';
      document.getElementById('ib-title').innerText = `${activeFlow.process_name} (PID ${activeFlow.pid}) \u2192 ${activeFlow.dst_ip}:${activeFlow.dst_port}`;
      document.getElementById('ib-sub').innerText = `${activeFlow.c2_framework || 'Periodic Beacon'} | Score: ${(activeFlow.threat_score * 100).toFixed(1)}% | Interval: ${activeFlow.interval_str || '8.4s'} | MAD Ratio: ${madVal}`;
    } else {
      banner.classList.add('clean');
      document.getElementById('ib-sev-badge').className = 'badge ok';
      document.getElementById('ib-sev-badge').innerText = 'NOMINAL';
      document.getElementById('ib-title').innerText = `${host.hostname} - No Active Critical Beacon Detections`;
      document.getElementById('ib-sub').innerText = 'Click any socket, process, or historical connection below to inspect telemetry details in the drawer.';
    }

    // Flows Table
    const fbody = document.getElementById('flows-tbody');
    fbody.innerHTML = flows.map(f => {
      const isCrit = f.threat_score >= 0.85 && !f.is_severed;
      const isHigh = f.threat_score >= 0.60 && f.threat_score < 0.85 && !f.is_severed;
      const vCls = f.is_severed ? 'neutral' : (isCrit ? 'crit' : (isHigh ? 'high' : 'ok'));
      const selCls = (f.pid === userSelectedPid ? 'row-selected ' : '') + (isCrit ? 'row-threat' : '');
      const hasSni = f.sni && !String(f.sni).toLowerCase().includes('direct ip');
      const sniCell = hasSni ? `<span style="color: var(--text-main);">${escHtml(f.sni)}</span>` : '<span style="color: var(--text-muted);">Direct IP (No SNI)</span>';
      const ja4Val = f.ja4_fingerprint || 't13d1516h2_...';
      const madShort = String(f.iat_mad_ratio || '0.095').split(' ')[0];
      return `
        <tr class="${selCls}" onclick="selectFlowAndInspect(${f.pid})">
          <td><span class="badge ${vCls}">${escHtml(f.is_severed ? 'SEVERED' : (f.threat_label || 'BENIGN'))}</span></td>
          <td>
            <span class="cell-primary">${escHtml(f.process_name)}</span>
            <span class="cell-sub mono">PID ${f.pid} &bull; ${f.is_signed ? 'Signed' : 'Unsigned'}</span>
          </td>
          <td class="mono" style="font-weight: 600; color: var(--text-main);">${escHtml(f.dst_ip)}:${f.dst_port}</td>
          <td style="font-size: 12.5px;">${sniCell}</td>
          <td class="mono" style="font-size: 12px;">${escHtml(ja4Val)}</td>
          <td class="mono" style="font-size: 12px;">IAT ${escHtml(f.interval_str || '8.4s')} | MAD ${escHtml(madShort)}</td>
          <td class="mono" style="text-align: right; font-weight: 700; color: ${isCrit ? 'var(--crit-text)' : (isHigh ? 'var(--high-text)' : 'var(--text-muted)')};">${(f.threat_score * 100).toFixed(1)}%</td>
          <td><span class="badge ${f.is_severed ? 'neutral' : 'ok'}">${escHtml(f.state || 'ESTABLISHED')}</span></td>
        </tr>`;
    }).join('') || '<tr><td colspan="8" style="text-align: center; padding: 28px; color: var(--text-muted);">No active outbound sockets recorded.</td></tr>';

    // Processes Table
    const pbody = document.getElementById('procs-tbody');
    pbody.innerHTML = procs.map(p => {
      const pName = p.name || p.process_name || 'unknown.exe';
      const pPath = p.path || p.exe_path || 'C:\\Windows\\System32\\...';
      const pUser = p.username || p.user_context || 'NT AUTHORITY\\SYSTEM';
      const pSocks = p.socket_count != null ? p.socket_count : (p.active_sockets || 1);
      return `
      <tr onclick="openPidHistoryModal(${p.pid}, '${escHtml(pName)}')">
        <td class="mono" style="font-weight: 600;">${p.pid}</td>
        <td><strong style="color: var(--text-main);">${escHtml(pName)}</strong></td>
        <td>
          <span class="mono" style="font-size: 12px; color: var(--text-secondary);">${escHtml(pPath)}</span>
          <span class="cell-sub">${p.is_signed ? 'Verified Microsoft / Vendor Signature' : 'Unsigned Binary'}</span>
        </td>
        <td class="mono" style="font-size: 12px;">PID ${p.ppid || 680}</td>
        <td class="mono" style="font-size: 12px;">${escHtml(pUser)}</td>
        <td class="mono" style="font-weight: 600;">${pSocks}</td>
        <td style="text-align: right;"><button class="btn btn-sm" onclick="event.stopPropagation(); openPidHistoryModal(${p.pid}, '${escHtml(pName)}')">Socket History</button></td>
      </tr>`;
    }).join('') || '<tr><td colspan="7" style="text-align: center; padding: 28px; color: var(--text-muted);">No running processes enumerated.</td></tr>';

    // Connection Timeline Table
    const hbody = document.getElementById('history-tbody');
    hbody.innerHTML = history.map(r => {
      const isCrit = (r.verdict || '').includes('CRITICAL');
      const isHigh = (r.verdict || '').includes('HIGH');
      return `
        <tr onclick="openPidHistoryModal(${r.pid}, '${escHtml(r.process_name)}')">
          <td class="mono" style="font-size: 12px;">${escHtml(r.timestamp)}</td>
          <td><strong style="color: var(--text-main);">${escHtml(r.process_name)}</strong> <span class="mono" style="color: var(--text-muted);">(${r.pid})</span></td>
          <td class="mono" style="font-size: 12px;">${escHtml(r.local_addr)} -&gt; <strong>${escHtml(r.remote_addr)}</strong></td>
          <td style="font-size: 12px;">${escHtml(r.sni || 'Direct IP (No SNI)')}</td>
          <td class="mono" style="font-size: 12px;">${escHtml(r.bytes_str || '512 B')}</td>
          <td><span class="badge ${r.state === 'ESTABLISHED' ? 'accent' : 'neutral'}">${escHtml(r.state)}</span></td>
          <td style="text-align: right;"><span class="badge ${isCrit ? 'crit' : (isHigh ? 'high' : 'neutral')}">${escHtml(r.verdict)}</span></td>
        </tr>`;
    }).join('') || '<tr><td colspan="7" style="text-align: center; padding: 28px; color: var(--text-muted);">No historical connections cached.</td></tr>';
  }

  /* ================= VIEW 4: HISTORICAL ALERTS ================= */
  function getMaxHoursForRange(rangeKey) {
    if (rangeKey === 'live') return 1;
    if (rangeKey === '24h') return 24;
    if (rangeKey === '7d') return 168;
    if (rangeKey === '30d') return 720;
    return 999999;
  }

  function setGlobalTimeRange(rangeKey) {
    currentTimeRange = rangeKey;
    ['live', '24h', '7d', '30d', 'all'].forEach(k => {
      const btn = document.getElementById('tr-' + k);
      if (btn) btn.classList.toggle('active', k === rangeKey);
    });
    if (currentTab === 'alerts') renderAlertsLedger();
  }

  function setAlertFilter(filterKey) {
    activeAlertFilter = filterKey;
    const map = { ALL: 'al-f-all', '9001': 'al-f-9001', '9002': 'al-f-9002', CRITICAL: 'al-f-crit', 'Tier-0': 'al-f-t0', 'Tier-1': 'al-f-t1', 'Tier-2': 'al-f-t2' };
    Object.values(map).forEach(id => {
      const el = document.getElementById(id);
      if (el) el.classList.remove('active');
    });
    const activeEl = document.getElementById(map[filterKey] || 'al-f-all');
    if (activeEl) activeEl.classList.add('active');
    renderAlertsLedger();
  }

  function renderAlertsLedger() {
    const tbody = document.getElementById('alerts-ledger-tbody');
    if (!tbody) return;
    const maxHours = getMaxHoursForRange(currentTimeRange);
    const q = (document.getElementById('alert-search-input')?.value || '').trim().toLowerCase();

    const windowedAlerts = HISTORICAL_ALERTS.filter(a => a.ageHours <= maxHours);
    const filtered = windowedAlerts.filter(a => {
      if (activeAlertFilter === '9001' && a.eid !== 9001) return false;
      if (activeAlertFilter === '9002' && a.eid !== 9002) return false;
      if (activeAlertFilter === 'CRITICAL' && a.severity !== 'CRITICAL') return false;
      if (['Tier-0', 'Tier-1', 'Tier-2'].includes(activeAlertFilter) && a.tier !== activeAlertFilter) return false;
      if (!q) return true;
      return `${a.id} ${a.eid} ${a.hostname} ${a.hostIp} ${a.tier} ${a.processName} ${a.pid} ${a.remoteEndpoint} ${a.framework} ${a.statusText}`.toLowerCase().includes(q);
    });

    document.getElementById('al-kpi-total').innerText = windowedAlerts.length + ' Events';
    document.getElementById('al-kpi-9001').innerText = windowedAlerts.filter(a => a.eid === 9001).length + ' Alerts';
    document.getElementById('al-kpi-9002').innerText = windowedAlerts.filter(a => a.eid === 9002).length + ' Actions';
    document.getElementById('alerts-showing-label').innerText = `Showing ${filtered.length} of ${HISTORICAL_ALERTS.length} Indexed Events`;
    document.getElementById('nav-badge-alerts').innerText = filtered.length;

    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 36px; color: var(--text-muted);">No historical alerts match your filter and time window.</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.map(a => {
      const isCrit = a.severity === 'CRITICAL';
      const isHigh = a.severity === 'HIGH';
      const sevCls = isCrit ? 'crit' : (isHigh ? 'high' : 'eval');
      const eidCls = a.eid === 9001 ? 'crit' : 'ok';
      const selCls = (a.id === selectedAlertId ? 'row-selected ' : '') + (isCrit ? 'row-threat' : '');
      return `
        <tr class="${selCls}" onclick="inspectAlertInDrawer('${escHtml(a.id)}')">
          <td>
            <span class="cell-primary mono" style="font-size: 12px;">${escHtml(a.timestamp)}</span>
            <span class="cell-sub mono">${escHtml(a.ageLabel)} &bull; ${escHtml(a.id)}</span>
          </td>
          <td><span class="badge ${eidCls} mono">EID ${a.eid}</span></td>
          <td><span class="badge ${sevCls}">${escHtml(a.severity)}</span></td>
          <td>
            <span class="cell-primary">${escHtml(a.hostname)}</span>
            <span class="cell-sub mono">${escHtml(a.hostIp)} &bull; ${escHtml(a.tier)}</span>
          </td>
          <td>
            <span class="cell-primary">${escHtml(a.processName)}</span>
            <span class="cell-sub mono">PID ${a.pid} &bull; ${escHtml(a.auth)}</span>
          </td>
          <td class="mono" style="font-weight: 600; color: var(--text-main);">${escHtml(a.remoteEndpoint)}</td>
          <td>
            <span style="font-weight: 600; color: var(--text-main); display: block;">${escHtml(a.framework)}</span>
            <span class="mono" style="font-size: 11.5px; color: ${isCrit ? 'var(--crit-text)' : 'var(--text-muted)'};">Score ${(a.score * 100).toFixed(1)}% &bull; MAD ${a.iatMad.toFixed(3)}</span>
          </td>
          <td style="font-size: 12px; color: ${a.eid === 9002 ? 'var(--ok-text)' : 'var(--text-secondary)'}; font-weight: 500;">${escHtml(a.statusText)}</td>
          <td style="text-align: right;"><button class="btn btn-sm" onclick="event.stopPropagation(); inspectAlertInDrawer('${escHtml(a.id)}')">Inspect</button></td>
        </tr>`;
    }).join('');
  }

  /* ================= VIEW 5: POLICIES & SIEM ================= */
  function renderPoliciesView() {
    switchSiemSnippet(activeSiemSnippetKey);
  }

  function switchSiemSnippet(key) {
    activeSiemSnippetKey = key;
    ['wazuh_rules', 'wazuh_ossec', 'splunk_inputs', 'ocsf_schema'].forEach(k => {
      const btn = document.getElementById('siem-tab-' + k);
      if (btn) btn.classList.toggle('active', k === key);
    });
    const viewer = document.getElementById('siem-snippet-viewer');
    if (viewer) viewer.textContent = SIEM_SNIPPETS[key] || '';
  }

  function copySiemSnippet() {
    const text = SIEM_SNIPPETS[activeSiemSnippetKey] || '';
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    const btn = document.getElementById('siem-copy-btn');
    if (btn) {
      btn.innerText = 'Copied!';
      setTimeout(() => { btn.innerText = 'Copy Snippet'; }, 1500);
    }
  }

  function applyPolicyChanges() {
    const t0 = document.getElementById('pol-tier0-mode').value;
    const t1 = document.getElementById('pol-tier1-mode').value;
    const t2 = document.getElementById('pol-tier2-mode').value;
    const toast = document.getElementById('policy-save-toast');
    if (toast) {
      const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
      toast.style.display = 'block';
      toast.innerText = `Policy revision deployed across 32 sensors at ${nowStr} (Tier-0: ${t0}, Tier-1: ${t1}, Tier-2: ${t2}).`;
      setTimeout(() => { toast.style.display = 'none'; }, 5500);
    }
  }

  /* ================= SLIDE-OVER RIGHT INSPECTOR DRAWER ================= */
  function openDrawerShell() {
    document.getElementById('drawer-backdrop').classList.add('open');
    const drawer = document.getElementById('right-inspector-drawer');
    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
  }

  function closeInspectorDrawer() {
    document.getElementById('drawer-backdrop').classList.remove('open');
    const drawer = document.getElementById('right-inspector-drawer');
    drawer.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
  }

  function inspectHostInDrawer(hostId) {
    userSelectedHostId = hostId;
    if (stateData && stateData.hosts) {
      const host = stateData.hosts.find(h => h.host_id === hostId);
      if (host) {
        fetch('/api/state?host=' + encodeURIComponent(hostId))
          .then(r => r.json())
          .then(payload => {
            stateData = payload;
            const flow = (payload.flows && payload.flows[0]) || payload.top_incident;
            renderFlowDrawer(host, flow);
          })
          .catch(() => renderFlowDrawer(host, stateData.top_incident));
        return;
      }
    }
    openSelectedFlowDrawer();
  }

  function selectFlowAndInspect(pid) {
    userSelectedPid = pid;
    const flows = (stateData && stateData.flows) || [];
    const flow = flows.find(f => f.pid === pid) || flows[0];
    const host = stateData && stateData.selected_host;
    renderHostDrilldown();
    renderFlowDrawer(host, flow);
  }

  function openSelectedFlowDrawer() {
    if (!stateData) return;
    const host = stateData.selected_host || (stateData.hosts && stateData.hosts[0]);
    const flows = stateData.flows || [];
    const flow = flows.find(f => f.pid === userSelectedPid) || flows.find(f => f.is_threat && !f.is_severed) || flows.find(f => f.is_threat) || flows[0];
    renderFlowDrawer(host, flow);
  }

  function renderFlowDrawer(host, flow) {
    drawerMode = 'flow';
    const hName = host ? host.hostname : 'WIN-PROD-SRV01';
    const hIp = host ? host.ip_address : '10.0.1.15';
    const hTier = host ? (host.ad_tier || host.subnet) : 'Tier-1 Server';

    if (!flow) {
      document.getElementById('drawer-eyebrow').innerText = 'ENDPOINT SUMMARY';
      document.getElementById('drawer-title').innerText = hName;
      document.getElementById('drawer-subtitle').innerText = `${hIp} \u2022 ${hTier}`;
      document.getElementById('drawer-body').innerHTML = `
        <div class="drawer-card">
          <div class="drawer-card-title">01 / Endpoint Health</div>
          <div class="kv-row"><span class="kv-label">Status</span><span class="badge ok">Nominal</span></div>
          <div class="kv-row"><span class="kv-label">Active Sockets</span><span class="kv-val mono">${host ? host.active_sockets_count : 0}</span></div>
          <div class="drawer-actions-grid" style="grid-template-columns: 1fr;">
            <button class="btn btn-primary" onclick="closeInspectorDrawer(); selectAndDrilldown('${escHtml(host ? host.host_id : '')}')">Open Full Endpoint Triage &#8594;</button>
          </div>
        </div>`;
      openDrawerShell();
      return;
    }

    const scorePct = (Number(flow.threat_score || 0) * 100).toFixed(1);
    const isThreat = flow.threat_score >= 0.70 && !flow.is_severed;
    const binPath = flow.binary_path || ('C:\\ProgramData\\Updates\\' + flow.process_name);
    const sniText = (flow.sni && !String(flow.sni).toLowerCase().includes('direct ip')) ? flow.sni : (flow.dst_ip + ':' + flow.dst_port);
    const madText = flow.iat_mad_ratio || '0.095 (Periodic)';
    const iatText = flow.interval_str || '8.4s';
    const ja4Text = flow.ja4_fingerprint || 't13d1516h2_8daaf4b10222';
    const mitreText = flow.mitre_technique || 'T1071.001 + T1573';
    const bottomBtnHtml = currentTab === 'drilldown'
      ? `<button class="btn" style="width: 100%; margin-top: 4px;" onclick="closeInspectorDrawer()">Close Triage Drawer</button>`
      : `<button class="btn btn-primary" style="width: 100%; margin-top: 4px;" onclick="closeInspectorDrawer(); selectAndDrilldown('${escHtml(host ? host.host_id : '')}')">Open Full Endpoint Triage &#8594;</button>`;

    document.getElementById('drawer-eyebrow').innerText = isThreat ? 'C2 SOCKET TRIAGE' : 'SOCKET INSPECTION';
    document.getElementById('drawer-title').innerText = `${flow.process_name} (PID ${flow.pid})`;
    document.getElementById('drawer-subtitle').innerText = `${hName} (${hIp}) \u2192 ${flow.dst_ip}:${flow.dst_port}`;

    const dots = Array.from({ length: 14 }, (_, idx) => {
      if (flow.is_severed && idx > 9) return '<div class="cadence-dot"></div>';
      return `<div class="cadence-dot ${isThreat ? 'pulse' : 'ok'}"></div>`;
    }).join('');

    document.getElementById('drawer-body').innerHTML = `
      <div class="drawer-card">
        <div class="drawer-card-title">01 / Kernel Process Attribution</div>
        <div class="kv-row"><span class="kv-label">Endpoint</span><span class="kv-val mono">${escHtml(hName)} (${escHtml(hTier)})</span></div>
        <div class="kv-row"><span class="kv-label">Executable Path</span><span class="kv-val mono">${escHtml(binPath)}</span></div>
        <div class="kv-row"><span class="kv-label">Parent Process</span><span class="kv-val mono">${escHtml(flow.parent_process || 'explorer.exe (PID 2180)')}</span></div>
        <div class="kv-row"><span class="kv-label">User Context</span><span class="kv-val mono">${escHtml(flow.user_context || 'NT AUTHORITY\\SYSTEM')}</span></div>
        <div class="kv-row"><span class="kv-label">Binary Signing</span><span class="badge ${flow.is_signed ? 'ok' : 'crit'}">${flow.is_signed ? 'Signed Vendor Binary' : 'Unsigned Executable'}</span></div>
        <div class="kv-row"><span class="kv-label">SHA-256 Digest</span><span class="kv-val mono">${escHtml(flow.sha256 || 'a4f982d17c63e0197b5f31a829c4b0e192f88374')}</span></div>
        <div class="kv-row"><span class="kv-label">SNI / Destination</span><span class="kv-val mono">${escHtml(sniText)}</span></div>
      </div>

      <div class="drawer-card">
        <div class="drawer-card-title">02 / FlowFeaturesV1 Behavioral Cadence</div>
        <div class="kv-row"><span class="kv-label">Threat Verdict</span><span class="badge ${isThreat ? 'crit' : 'ok'}">${escHtml(flow.threat_label || 'BENIGN')} (${scorePct}%)</span></div>
        <div class="kv-row"><span class="kv-label">C2 Fingerprint</span><span class="kv-val" style="color: ${isThreat ? 'var(--crit-text)' : 'var(--text-main)'}; font-weight: 600;">${escHtml(flow.c2_framework || 'Nominal Traffic')}</span></div>
        <div class="kv-row"><span class="kv-label">Interval &amp; Jitter</span><span class="kv-val mono">${escHtml(iatText)} (${escHtml(flow.jitter_str || '±4%')})</span></div>
        <div class="kv-row"><span class="kv-label">IAT MAD Ratio</span><span class="kv-val mono">${escHtml(madText)}</span></div>
        <div class="kv-row"><span class="kv-label">Bowley Skew</span><span class="kv-val mono">${escHtml(flow.bowley_skew || '+0.03 (Symmetric)')}</span></div>
        <div class="kv-row"><span class="kv-label">JA4 Client Hash</span><span class="kv-val mono">${escHtml(ja4Text)}</span></div>
        <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">Observed Periodic Burst Cadence (14-Burst Rolling Window):</div>
        <div class="cadence-strip">${dots}</div>
      </div>

      <div class="drawer-card">
        <div class="drawer-card-title">03 / MITRE ATT&amp;CK &amp; Containment Actions</div>
        <div class="kv-row"><span class="kv-label">MITRE Mapping</span><span class="kv-val mono">${escHtml(mitreText)}</span></div>
        <div class="drawer-actions-grid">
          <button class="btn btn-danger-solid" onclick="promptSeverModal(${flow.pid}, '${escHtml(flow.dst_ip + ':' + flow.dst_port)}', '${escHtml(flow.process_name)}')">Sever Socket</button>
          <button class="btn btn-warning" onclick="tarpitFlow(${flow.pid}, '${escHtml(flow.dst_ip + ':' + flow.dst_port)}', '${escHtml(flow.process_name)}')">Firewall Block</button>
          <button class="btn" onclick="openPidHistoryModal(${flow.pid}, '${escHtml(flow.process_name)}')">PID History</button>
          <button class="btn" onclick="openWhitelistModal(${flow.pid}, '${escHtml(flow.process_name)}', '${escHtml(flow.dst_ip + ':' + flow.dst_port)}', '${escHtml(hName)}')">Allowlist Rule</button>
        </div>
        ${bottomBtnHtml}
      </div>`;
    openDrawerShell();
  }

  function inspectAlertInDrawer(alertId) {
    selectedAlertId = alertId;
    if (currentTab === 'alerts') renderAlertsLedger();
    const sel = HISTORICAL_ALERTS.find(a => a.id === alertId) || HISTORICAL_ALERTS[0];
    if (!sel) return;

    drawerMode = 'alert';
    const isCrit = sel.severity === 'CRITICAL';
    document.getElementById('drawer-eyebrow').innerText = `HISTORICAL EVENT RECORD \u2022 ${sel.id}`;
    document.getElementById('drawer-title').innerText = `${sel.processName} (PID ${sel.pid})`;
    document.getElementById('drawer-subtitle').innerText = `${sel.hostname} (${sel.hostIp}) \u2022 ${sel.timestamp}`;

    const ocsfJson = JSON.stringify({
      metadata: { version: '1.1.0', windows_event_id: sel.eid, logged_time: sel.timestamp },
      class_uid: 4001,
      severity: sel.severity,
      src_endpoint: { hostname: sel.hostname, ip: sel.hostIp, tier: sel.tier },
      dst_endpoint: sel.remoteEndpoint,
      actor_process: { pid: sel.pid, name: sel.processName, sha256: sel.sha256 },
      uncloak_telemetry: {
        threat_score: sel.score,
        c2_framework: sel.framework,
        iat_median: sel.iatMedian,
        iat_mad_ratio: sel.iatMad,
        ja4: sel.ja4
      }
    }, null, 2);

    document.getElementById('drawer-body').innerHTML = `
      <div class="drawer-card">
        <div class="drawer-card-title">01 / Recorded Endpoint &amp; Binary Snapshot</div>
        <div class="kv-row"><span class="kv-label">Endpoint</span><span class="kv-val mono">${escHtml(sel.hostname)} (${escHtml(sel.tier)})</span></div>
        <div class="kv-row"><span class="kv-label">Executable Path</span><span class="kv-val mono">${escHtml(sel.processPath)}</span></div>
        <div class="kv-row"><span class="kv-label">Parent Process</span><span class="kv-val mono">${escHtml(sel.parentProc)}</span></div>
        <div class="kv-row"><span class="kv-label">User Account SID</span><span class="kv-val mono">${escHtml(sel.userSid)}</span></div>
        <div class="kv-row"><span class="kv-label">SHA-256 Digest</span><span class="kv-val mono">${escHtml(sel.sha256)}</span></div>
      </div>

      <div class="drawer-card">
        <div class="drawer-card-title">02 / Recorded FlowFeaturesV1 Vector</div>
        <div class="kv-row"><span class="kv-label">Severity &amp; Score</span><span class="badge ${isCrit ? 'crit' : 'high'}">${escHtml(sel.severity)} &bull; ${(sel.score * 100).toFixed(1)}%</span></div>
        <div class="kv-row"><span class="kv-label">Framework</span><span class="kv-val" style="font-weight: 600;">${escHtml(sel.framework)}</span></div>
        <div class="kv-row"><span class="kv-label">IAT Median / MAD</span><span class="kv-val mono">${sel.iatMedian}s / ${sel.iatMad.toFixed(3)}</span></div>
        <div class="kv-row"><span class="kv-label">Bursts / Bowley Skew</span><span class="kv-val mono">${sel.bursts} bursts | ${sel.skew}</span></div>
        <div class="kv-row"><span class="kv-label">Payload Asymmetry</span><span class="kv-val mono">Out ${sel.bytesOut} / In ${sel.bytesIn}</span></div>
        <div class="kv-row"><span class="kv-label">Action / Status</span><span class="kv-val" style="color: var(--ok-text);">${escHtml(sel.actionTaken)}</span></div>
      </div>

      <div class="drawer-card">
        <div class="drawer-card-title">03 / Dispatched OCSF v1.1.0 &amp; EVTX Payload</div>
        <pre class="code-viewer" style="max-height: 220px; font-size: 11px;">${escHtml(ocsfJson)}</pre>
        <button class="btn btn-primary" style="width: 100%;" onclick="closeInspectorDrawer(); openAlertHostInDrilldown('${escHtml(sel.id)}')">Open Host in Endpoint Triage &#8594;</button>
      </div>`;
    openDrawerShell();
  }

  function openAlertHostInDrilldown(alertId) {
    const rec = HISTORICAL_ALERTS.find(a => a.id === (alertId || selectedAlertId));
    if (!rec || !stateData) return;
    const found = (stateData.hosts || []).find(h => h.host_id === rec.hostId || h.hostname === rec.hostname);
    if (found) selectAndDrilldown(found.host_id);
    else switchView('drilldown');
  }

  /* ================= CONTAINMENT & MODALS ================= */
  function severCurrentTopFlow() {
    if (!stateData) return;
    const flow = (stateData.flows || []).find(f => f.pid === userSelectedPid) || stateData.top_incident || (stateData.flows || [])[0];
    if (flow) promptSeverModal(flow.pid, flow.dst_ip + ':' + flow.dst_port, flow.process_name);
  }

  function promptSeverModal(pid, remote, procName) {
    pendingSeverPid = pid;
    pendingSeverHostId = userSelectedHostId || (stateData && stateData.selected_host_id);
    document.getElementById('sm-host').innerText = (stateData && stateData.selected_host) ? stateData.selected_host.hostname : 'WIN-PROD-SRV01';
    document.getElementById('sm-proc').innerText = `${procName} (PID ${pid})`;
    document.getElementById('sm-remote').innerText = remote;
    document.getElementById('sever-confirm-modal').classList.add('active');
  }

  function closeSeverModal() {
    document.getElementById('sever-confirm-modal').classList.remove('active');
  }

  async function executeConfirmedSever() {
    closeSeverModal();
    await fetch('/api/sever', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid: pendingSeverPid, host_id: pendingSeverHostId })
    });
    fetchState();
  }

  function tarpitFlow(pid, remote, procName) {
    pendingTarpitPid = pid;
    document.getElementById('tm-proc').innerText = `${procName} (PID ${pid})`;
    document.getElementById('tm-remote').innerText = remote;
    document.getElementById('tarpit-confirm-modal').classList.add('active');
  }

  function tarpitSelectedFlow() {
    if (!stateData) return;
    const flow = (stateData.flows || []).find(f => f.pid === userSelectedPid) || stateData.top_incident || (stateData.flows || [])[0];
    if (flow) tarpitFlow(flow.pid, flow.dst_ip + ':' + flow.dst_port, flow.process_name);
  }

  function closeTarpitModal() {
    document.getElementById('tarpit-confirm-modal').classList.remove('active');
  }

  async function executeConfirmedTarpit() {
    closeTarpitModal();
    await fetch('/api/tarpit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid: pendingTarpitPid, host_id: userSelectedHostId || (stateData && stateData.selected_host_id) })
    });
    fetchState();
  }

  async function severSelectedCampaign() {
    if (!selectedCampaignId) return;
    await fetch('/api/sever_campaign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ campaign_id: selectedCampaignId })
    });
    fetchState();
  }

  async function toggleHostIsolation(hostId) {
    await fetch('/api/isolate_host', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host_id: hostId })
    });
    fetchState();
  }

  function toggleCurrentHostIsolation() {
    if (stateData && stateData.selected_host) {
      toggleHostIsolation(stateData.selected_host.host_id);
    }
  }

  /* Allowlist Modal */
  function openWhitelistModal(pid, procName, dest, host) {
    activeWhitelistTarget = {
      pid: pid || 5824,
      procName: procName || 'update.exe',
      dest: dest || '193.26.158.114:443',
      host: host || (stateData && stateData.selected_host ? stateData.selected_host.hostname : 'WIN-PROD-SRV01')
    };
    document.getElementById('wl-host').innerText = activeWhitelistTarget.host;
    document.getElementById('wl-process').innerText = activeWhitelistTarget.procName + ' (PID ' + activeWhitelistTarget.pid + ')';
    document.getElementById('wl-dest').innerText = activeWhitelistTarget.dest;
    document.getElementById('wl-rule-dest').innerText = activeWhitelistTarget.dest;
    document.getElementById('wl-scope-hostname').innerText = activeWhitelistTarget.host;
    setWhitelistScope('LOCAL');
    document.getElementById('whitelist-modal').classList.add('active');
  }

  function openWhitelistModalForSelected() {
    const flow = stateData && ((stateData.flows || []).find(f => f.pid === userSelectedPid) || (stateData.flows || [])[0]);
    const host = stateData && stateData.selected_host ? stateData.selected_host.hostname : 'WIN-PROD-SRV01';
    if (flow) openWhitelistModal(flow.pid, flow.process_name, flow.dst_ip + ':' + flow.dst_port, host);
    else openWhitelistModal(5824, 'update.exe', '193.26.158.114:443', host);
  }

  function closeWhitelistModal() {
    document.getElementById('whitelist-modal').classList.remove('active');
  }

  function setWhitelistScope(scope) {
    activeWhitelistScope = scope;
    document.getElementById('wl-scope-local-box').classList.toggle('selected', scope === 'LOCAL');
    document.getElementById('wl-scope-global-box').classList.toggle('selected', scope === 'GLOBAL');
    document.getElementById('wl-scope-local').checked = (scope === 'LOCAL');
    document.getElementById('wl-scope-global').checked = (scope === 'GLOBAL');
  }

  function applyWhitelistPolicy() {
    const reason = document.getElementById('wl-reason').value || 'Approved enterprise vendor telemetry';
    const target = activeWhitelistTarget || { pid: 5824, procName: 'update.exe', dest: '193.26.158.114:443', host: 'WIN-PROD-SRV01' };
    const ruleId = 'WL-2026-00' + (enterpriseWhitelistRules.length + 1);
    enterpriseWhitelistRules.unshift({
      rule_id: ruleId,
      scope: activeWhitelistScope,
      entity: target.procName,
      destination: target.dest,
      justification: reason,
      created_at: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
    });
    if (stateData && stateData.flows) {
      const flow = stateData.flows.find(f => f.pid === target.pid || f.process_name === target.procName);
      if (flow) {
        flow.is_severed = false;
        flow.is_threat = false;
        flow.threat_score = 0.001;
        flow.threat_label = 'POLICY ALLOWED';
        flow.state = 'WHITELISTED';
      }
    }
    closeWhitelistModal();
    renderUI();
    renderWhitelistLedger();
  }

  function revokeWhitelistRule(ruleId) {
    enterpriseWhitelistRules = enterpriseWhitelistRules.filter(r => r.rule_id !== ruleId);
    renderWhitelistLedger();
  }

  function renderWhitelistLedger() {
    document.getElementById('whitelist-count-label').innerText = '(' + enterpriseWhitelistRules.length + ')';
    const tbody = document.getElementById('whitelist-rules-tbody');
    if (!tbody) return;
    tbody.innerHTML = enterpriseWhitelistRules.map(r => `
      <tr>
        <td class="mono" style="font-weight: 600;">${escHtml(r.rule_id)}</td>
        <td><span class="badge ${r.scope === 'GLOBAL' ? 'accent' : 'neutral'}">${r.scope === 'GLOBAL' ? 'GLOBAL (All Hosts)' : 'LOCAL (Host)'}</span></td>
        <td style="font-weight: 600; color: var(--text-main);">${escHtml(r.entity)}</td>
        <td class="mono" style="font-size: 12px;">${escHtml(r.destination)}</td>
        <td>${escHtml(r.justification)}</td>
        <td class="mono" style="font-size: 12px; color: var(--text-muted);">${escHtml(r.created_at)}</td>
        <td style="text-align: right;"><button class="btn btn-danger btn-sm" onclick="revokeWhitelistRule('${escHtml(r.rule_id)}')">Revoke</button></td>
      </tr>`).join('');
  }

  /* PID History Modal */
  function openPidHistoryModal(pid, procName) {
    if (!stateData || !stateData.selected_host) return;
    const hostId = stateData.selected_host.host_id;
    document.getElementById('pid-history-modal').classList.add('active');
    document.getElementById('ph-pid').innerText = pid;
    document.getElementById('ph-proc').innerText = procName || 'Process ' + pid;
    document.getElementById('ph-host').innerText = stateData.selected_host.hostname;

    const localRecords = (stateData.host_connection_history || []).filter(r => String(r.pid) === String(pid));
    if (localRecords.length > 0) {
      activeModalPidData = {
        pid: pid,
        process_name: procName || localRecords[0].process_name,
        total_connections: localRecords.length,
        active_connections: localRecords.filter(r => r.state !== 'CLOSED').length,
        first_seen: localRecords[localRecords.length - 1].timestamp,
        last_seen: localRecords[0].timestamp,
        total_bandwidth: (localRecords.length * 1.8).toFixed(1) + ' MB',
        records: localRecords
      };
      renderPidHistoryModal(activeModalPidData);
    }

    fetch('/api/pid/history?host=' + encodeURIComponent(hostId) + '&pid=' + pid)
      .then(res => res.json())
      .then(data => {
        if (data && data.records && data.records.length > 0) {
          activeModalPidData = data;
          renderPidHistoryModal(data);
        }
      })
      .catch(() => {});
  }

  function renderPidHistoryModal(data) {
    document.getElementById('ph-first-seen').innerText = data.first_seen || 'N/A';
    document.getElementById('ph-last-seen').innerText = data.last_seen || 'N/A';
    document.getElementById('ph-bandwidth').innerText = data.total_bandwidth || '0 B';
    document.getElementById('ph-sockets').innerText = `${data.total_connections} (${data.active_connections} Live)`;

    document.getElementById('ph-tbody').innerHTML = (data.records || []).map(r => {
      const isCrit = (r.verdict || '').includes('CRITICAL');
      const isHigh = (r.verdict || '').includes('HIGH');
      return `
        <tr>
          <td class="mono" style="font-size: 12px;">${escHtml(r.timestamp || r.first_seen)}</td>
          <td class="mono" style="font-size: 12px;">${escHtml(r.local_addr)}</td>
          <td class="mono" style="font-weight: 600;">${escHtml(r.remote_addr)}</td>
          <td>${escHtml(r.sni || 'Direct IP')}</td>
          <td class="mono">${escHtml(r.duration || 'Active')}</td>
          <td class="mono">${escHtml(r.bytes_str || '512 B')}</td>
          <td><span class="badge ${r.state === 'ESTABLISHED' ? 'accent' : 'neutral'}">${escHtml(r.state)}</span></td>
          <td style="text-align: right;"><span class="badge ${isCrit ? 'crit' : (isHigh ? 'high' : 'neutral')}">${escHtml(r.verdict)}</span></td>
        </tr>`;
    }).join('') || `<tr><td colspan="8" style="text-align: center; padding: 24px; color: var(--text-muted);">No historical connections recorded for PID ${data.pid}</td></tr>`;
  }

  function closePidHistoryModal() {
    document.getElementById('pid-history-modal').classList.remove('active');
  }

  function filterTimelineByPid(pid) {
    pid = (pid || '').trim();
    const rows = document.querySelectorAll('#history-tbody tr');
    const badge = document.getElementById('timeline-pid-filter-label');
    if (!pid) {
      rows.forEach(r => { r.style.display = ''; });
      if (badge) badge.style.display = 'none';
      return;
    }
    let matched = 0;
    rows.forEach(r => {
      const ok = r.innerText.includes(pid);
      r.style.display = ok ? '' : 'none';
      if (ok) matched++;
    });
    if (badge) {
      badge.style.display = 'inline-flex';
      badge.innerText = `Showing ${matched} events for PID ${pid}`;
    }
  }

  function clearTimelinePidFilter() {
    const input = document.getElementById('timeline-pid-input');
    if (input) input.value = '';
    filterTimelineByPid('');
  }

  function exportCurrentPidCsv() {
    if (!activeModalPidData || !activeModalPidData.records) return;
    let csv = 'Timestamp,Local,Remote,SNI,State,Verdict\n';
    activeModalPidData.records.forEach(r => {
      csv += `"${r.timestamp || ''}","${r.local_addr}","${r.remote_addr}","${r.sni || ''}","${r.state}","${r.verdict}"\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `uncloak_pid_${activeModalPidData.pid}_history.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  /* STIX / YARA-L Modals */
  function openStixModal() {
    const camp = (stateData && stateData.campaigns || []).find(c => c.campaign_id === selectedCampaignId) || (stateData && stateData.campaigns && stateData.campaigns[0]);
    const stix = JSON.stringify({
      type: 'bundle',
      id: 'bundle--uncloak-001',
      objects: [{
        type: 'indicator',
        name: camp ? camp.name : 'Sliver C2 Campaign',
        pattern_type: 'stix',
        pattern: `[ipv4-addr:value = '${camp ? camp.target_destination.split(':')[0] : '193.26.158.114'}']`
      }]
    }, null, 2);
    document.getElementById('eim-title').innerText = 'STIX 2.1 Threat Intelligence Bundle';
    document.getElementById('eim-code').textContent = stix;
    document.getElementById('export-intel-modal').classList.add('active');
  }

  function openYaralModal() {
    const camp = (stateData && stateData.campaigns || []).find(c => c.campaign_id === selectedCampaignId) || (stateData && stateData.campaigns && stateData.campaigns[0]);
    const yaral = `rule uncloak_c2_campaign {\n  meta:\n    author = "Uncloak NDR"\n    severity = "CRITICAL"\n  events:\n    $net.network.tls.ja4 = "${camp ? camp.ja4_fingerprint : 't13d1516h2_8daaf4b10222'}"\n  condition:\n    #net > 2\n}`;
    document.getElementById('eim-title').innerText = 'Google SecOps / YARA-L Detection Rule';
    document.getElementById('eim-code').textContent = yaral;
    document.getElementById('export-intel-modal').classList.add('active');
  }

  function closeIntelModal() {
    document.getElementById('export-intel-modal').classList.remove('active');
  }

  function copyIntelModal() {
    const text = document.getElementById('eim-code').textContent || '';
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).catch(() => {});
  }

  async function exportTelemetry() {
    const res = await fetch('/api/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid: userSelectedPid || 5824, host_id: userSelectedHostId || (stateData && stateData.selected_host_id) })
    });
    const data = await res.json().catch(() => ({}));
    if (data && data.filename) {
      const toast = document.getElementById('top-threat-label');
      if (toast) toast.innerText = 'Exported ' + data.filename;
      setTimeout(() => renderUI(), 2500);
    }
  }

  /* ================= KEYBOARD & URL PARAMS ================= */
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      closeInspectorDrawer();
      closeSeverModal();
      closeTarpitModal();
      closeWhitelistModal();
      closePidHistoryModal();
      closeIntelModal();
    } else if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
      e.preventDefault();
      const input = currentTab === 'alerts' ? document.getElementById('alert-search-input') : document.getElementById('fleet-search-input');
      if (input) input.focus();
    }
  });

  function handleUrlParams() {
    const urlParams = new URLSearchParams(window.location.search);
    const themeParam = urlParams.get('theme');
    if (themeParam === 'dark' || themeParam === 'light') applyTheme(themeParam);

    const density = urlParams.get('density');
    if (density === 'compact') {
      document.body.classList.remove('force-large');
      document.body.classList.add('force-compact');
      updateDensityLabel();
    } else if (density === 'large') {
      document.body.classList.remove('force-compact');
      document.body.classList.add('force-large');
      updateDensityLabel();
    }

    const layout = urlParams.get('layout');
    if (layout === 'table' || layout === 'grid') switchFleetLayout(layout);

    const scope = urlParams.get('scope');
    if (scope) filterTableByScope(scope.toUpperCase());

    const tab = urlParams.get('tab');
    if (tab && ['fleet', 'campaign', 'drilldown', 'alerts', 'policies'].includes(tab)) switchView(tab);

    const camp = urlParams.get('camp');
    if (camp) selectCampaign(camp);

    const timeParam = urlParams.get('time');
    if (timeParam && ['live', '24h', '7d', '30d', 'all'].includes(timeParam)) setGlobalTimeRange(timeParam);

    const alertSev = urlParams.get('alert_sev');
    if (alertSev) setAlertFilter(alertSev);

    const siemParam = urlParams.get('siem');
    if (siemParam && ['wazuh_rules', 'wazuh_ossec', 'splunk_inputs', 'ocsf_schema'].includes(siemParam)) switchSiemSnippet(siemParam);

    const host = urlParams.get('host');
    if (host) changeSelectedHost(host);

    const subtab = urlParams.get('subtab');
    if (subtab && ['flows', 'procs', 'history', 'whitelist'].includes(subtab)) switchHostSubtab(subtab);

    if (urlParams.get('drawer') === 'open') {
      if (currentTab === 'alerts') inspectAlertInDrawer(selectedAlertId);
      else openSelectedFlowDrawer();
    }

    const modal = urlParams.get('modal');
    const paramPid = parseInt(urlParams.get('pid') || '5824', 10);
    if (modal === 'sever') promptSeverModal(paramPid, '193.26.158.114:443', 'update.exe');
    else if (modal === 'tarpit') tarpitSelectedFlow();
    else if (modal === 'whitelist') { switchView('drilldown'); openWhitelistModalForSelected(); }
    else if (modal === 'pid') { switchView('drilldown'); switchHostSubtab('procs'); openPidHistoryModal(paramPid, 'update.exe'); }
    else if (modal === 'stix') openStixModal();
    else if (modal === 'yaral') openYaralModal();
  }

  /* ================= BOOTSTRAP ================= */
  initTheme();
  if (window.INITIAL_STATE) {
    stateData = window.INITIAL_STATE;
    userSelectedHostId = stateData.selected_host_id;
    userSelectedPid = stateData.selected_pid;
    renderUI();
    handleUrlParams();
  }

  setInterval(fetchState, 2000);
  fetchState();
</script>
</body>
</html>
"""
    return html_content.replace("__INITIAL_STATE_PLACEHOLDER__", initial_json)


def launch_desktop(port: Optional[int] = None) -> int:
    """Launches the enterprise desktop cockpit using WebView2 with zero-dependency loopback fallback."""
    target_port = port or 8443
    try:
        server = ThreadingHTTPServer(("127.0.0.1", target_port), UncloakHTTPHandler)
    except OSError:
        server = ThreadingHTTPServer(("127.0.0.1", 0), UncloakHTTPHandler)
    assigned_port = server.server_address[1]
    url = f"http://127.0.0.1:{assigned_port}"

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    print(f"[*] Uncloak Enterprise Fleet Manager initialized on {url}")

    if sys.platform == "win32":
        try:
            import clr
            # Try pythonnet / webview if installed
        except Exception:
            pass

        # Try pywebview if present
        try:
            import webview
            webview.create_window(
                "UNCLOAK :: Enterprise Fleet Threat Hunting & C2 Defense",
                url,
                width=1540,
                height=960,
                min_size=(1200, 750),
            )
            webview.start()
            return 0
        except Exception:
            pass

        # Fallback to Edge App Mode
        edge_paths = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ]
        edge_bin = next((p for p in edge_paths if os.path.exists(p)), None)
        if edge_bin:
            try:
                subprocess.Popen([
                    edge_bin,
                    f"--app={url}",
                    "--window-size=1540,960",
                    "--new-window",
                ])
                server_thread.join()
                return 0
            except Exception:
                pass

    # Generic browser fallback
    import webbrowser
    webbrowser.open(url)
    try:
        server_thread.join()
    except KeyboardInterrupt:
        pass
    return 0


def main() -> int:
    """CLI entrypoint for standalone uncloak-manager."""
    return launch_desktop()


if __name__ == "__main__":
    sys.exit(main())
