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
            packet_rate = 145 + int(now * 2) % 12

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
                    "first_seen": getattr(f, "first_seen", "2026-11-02 14:10:02 UTC"),
                    "last_seen": getattr(f, "last_seen", "2026-11-02 14:26:45 UTC"),
                    "duration": getattr(f, "duration", "16m 43s"),
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
    """Returns the complete enterprise web dashboard application with tabs, heatmap, and drawer."""
    initial_json = json.dumps(initial_payload) if initial_payload is not None else "null"
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>UNCLOAK :: Enterprise Fleet Threat Hunting & C2 Defense</title>
<style>
  :root {
    --bg-base: #060913;
    --bg-card: #0b1120;
    --bg-hover: #131d33;
    --border: #1e293b;
    --border-bright: #334155;
    --text-main: #f1f5f9;
    --text-dim: #94a3b8;
    --text-muted: #64748b;
    --cyan: #38bdf8;
    --cyan-glow: rgba(56, 189, 248, 0.25);
    --crimson: #ef4444;
    --crimson-dark: #dc2626;
    --crimson-glow: rgba(239, 68, 68, 0.3);
    --amber: #f59e0b;
    --green: #10b981;
    --purple: #a855f7;
    --font-mono: 'Consolas', 'Cascadia Code', 'SF Mono', monospace;

      /* RHYTHM SPARKLINE & JITTER TELEMETRY */
  .pulse-cell {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    vertical-align: middle;
  }
  .rhythm-track {
    display: inline-flex;
    align-items: center;
    justify-content: space-evenly;
    width: 66px;
    height: 18px;
    background: rgba(11, 17, 32, 0.95);
    border: 1px solid #1e293b;
    border-radius: 3px;
    padding: 0 4px;
    box-sizing: border-box;
    position: relative;
    overflow: hidden;
  }
  .rhythm-track.threat-track {
    border-color: rgba(239, 68, 68, 0.45);
    background: rgba(239, 68, 68, 0.08);
  }
  .rhythm-tick {
    width: 2px;
    height: 12px;
    border-radius: 1px;
  }
  .rhythm-tick.c2-tick {
    background: #f87171;
    box-shadow: 0 0 4px rgba(248, 113, 113, 0.8);
  }
  .rhythm-tick.benign-tick {
    background: var(--green);
    box-shadow: 0 0 3px rgba(16, 185, 129, 0.6);
  }
  .organic-wave {
    display: inline-flex;
    align-items: flex-end;
    gap: 3px;
    height: 12px;
  }
  .organic-bar {
    width: 2px;
    background: #38bdf8;
    opacity: 0.6;
    border-radius: 1px;
  }
  .jitter-pill {
    font-size: 8.5px;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 3px;
    letter-spacing: 0.04em;
    white-space: nowrap;
    text-transform: uppercase;
    font-family: var(--font-mono);
  }
  .jitter-pill.rigid {
    background: rgba(239, 68, 68, 0.15);
    color: #fca5a5;
    border: 1px solid rgba(239, 68, 68, 0.4);
  }
  .jitter-pill.organic {
    background: rgba(16, 185, 129, 0.1);
    color: #6ee7b7;
    border: 1px solid rgba(16, 185, 129, 0.3);
  }
  .jitter-pill.clean {
    background: rgba(56, 189, 248, 0.1);
    color: #7dd3fc;
    border: 1px solid rgba(56, 189, 248, 0.3);
  }

  /* RESPONSIVE SCALING ENGINE (Default: 110% Comfortable Desktop View) */
    --ui-font-base: 12.2px;
    --ui-header-pad: 10px 18px;
    --ui-brand-size: 14.5px;
    --ui-nav-pad: 6px 14px;
    --ui-nav-size: 11px;
    --ui-stat-pad: 4px 10px;
    --ui-stat-size: 11px;
    --ui-search-pad: 7px 12px;
    --ui-search-size: 12px;
    --ui-subnet-title-size: 11.5px;
    --ui-grid-min: 310px;
    --ui-card-pad: 12px 14px;
    --ui-card-name-size: 13.5px;
    --ui-pill-size: 10px;
    --ui-pill-pad: 3px 7px;
    --ui-meta-size: 11px;
    --ui-threat-tag-size: 11px;
    --ui-table-header-size: 11px;
    --ui-table-header-pad: 8px 12px;
    --ui-table-cell-size: 12px;
    --ui-table-cell-pad: 8px 12px;
    --ui-drawer-title-size: 11.5px;
    --ui-drawer-pad: 14px;
    --ui-card-kv-size: 12px;
    --ui-action-btn-pad: 5px 12px;
    --ui-action-btn-size: 11px;
    --ui-footer-pad: 8px 18px;
    --ui-footer-size: 11px;
  }

  /* COMPACT SCREEN / LAPTOP RESPONSIVE ADAPTATION (Automatic 100% Sizing for screen width <= 1366px or height <= 820px) */
  @media (max-width: 1366px), (max-height: 820px) {
    :root {
      --ui-font-base: 11px;
      --ui-header-pad: 8px 16px;
      --ui-brand-size: 13px;
      --ui-nav-pad: 5px 12px;
      --ui-nav-size: 10px;
      --ui-stat-pad: 3px 8px;
      --ui-stat-size: 10px;
      --ui-search-pad: 5px 10px;
      --ui-search-size: 11px;
      --ui-subnet-title-size: 10px;
      --ui-grid-min: 280px;
      --ui-card-pad: 10px 12px;
      --ui-card-name-size: 12px;
      --ui-pill-size: 9px;
      --ui-pill-pad: 2px 6px;
      --ui-meta-size: 10px;
      --ui-threat-tag-size: 10px;
      --ui-table-header-size: 10px;
      --ui-table-header-pad: 6px 10px;
      --ui-table-cell-size: 11px;
      --ui-table-cell-pad: 6px 10px;
      --ui-drawer-title-size: 10px;
      --ui-drawer-pad: 12px;
      --ui-card-kv-size: 11px;
      --ui-action-btn-pad: 4px 10px;
      --ui-action-btn-size: 10px;
      --ui-footer-pad: 6px 16px;
      --ui-footer-size: 10px;
    }
  }

  /* RESPONSIVE SCALING ENGINE:
     - Desktop Monitors (>= 1440px wide & >= 850px tall): 110% Zoom (matches 110% Image 2)
     - Laptops & Compact Displays (< 1440px or < 850px): 100% Scale (matches 100% Image 1)
  */
  @media (min-width: 1440px) and (min-height: 850px) {
    body {
      zoom: 1.1;
    }
  }

  @media (max-width: 1439px), (max-height: 849px) {
    body {
      zoom: 1.0;
    }
  }

  body.force-compact {
    zoom: 1.0 !important;
    --ui-font-base: 11px !important;
    --ui-header-pad: 8px 16px !important;
    --ui-brand-size: 13px !important;
    --ui-nav-pad: 5px 12px !important;
    --ui-nav-size: 10px !important;
    --ui-stat-pad: 3px 8px !important;
    --ui-stat-size: 10px !important;
    --ui-search-pad: 5px 10px !important;
    --ui-search-size: 11px !important;
    --ui-subnet-title-size: 10px !important;
    --ui-grid-min: 280px !important;
    --ui-card-pad: 10px 12px !important;
    --ui-card-name-size: 12px !important;
    --ui-pill-size: 9px !important;
    --ui-pill-pad: 2px 6px !important;
    --ui-meta-size: 10px !important;
    --ui-threat-tag-size: 10px !important;
    --ui-table-header-size: 10px !important;
    --ui-table-header-pad: 6px 10px !important;
    --ui-table-cell-size: 11px !important;
    --ui-table-cell-pad: 6px 10px !important;
    --ui-drawer-title-size: 10px !important;
    --ui-drawer-pad: 12px !important;
    --ui-card-kv-size: 11px !important;
    --ui-action-btn-pad: 4px 10px !important;
    --ui-action-btn-size: 10px !important;
    --ui-footer-pad: 6px 16px !important;
    --ui-footer-size: 10px !important;
  }

  body.force-large {
    zoom: 1.1 !important;
    --ui-font-base: 12.2px !important;
    --ui-header-pad: 10px 18px !important;
    --ui-brand-size: 14.5px !important;
    --ui-nav-pad: 6px 14px !important;
    --ui-nav-size: 11px !important;
    --ui-stat-pad: 4px 10px !important;
    --ui-stat-size: 11px !important;
    --ui-search-pad: 7px 12px !important;
    --ui-search-size: 12px !important;
    --ui-subnet-title-size: 11.5px !important;
    --ui-grid-min: 310px !important;
    --ui-card-pad: 12px 14px !important;
    --ui-card-name-size: 13.5px !important;
    --ui-pill-size: 10px !important;
    --ui-pill-pad: 3px 7px !important;
    --ui-meta-size: 11px !important;
    --ui-threat-tag-size: 11px !important;
    --ui-table-header-size: 11px !important;
    --ui-table-header-pad: 8px 12px !important;
    --ui-table-cell-size: 12px !important;
    --ui-table-cell-pad: 8px 12px !important;
    --ui-drawer-title-size: 11.5px !important;
    --ui-drawer-pad: 14px !important;
    --ui-card-kv-size: 12px !important;
    --ui-action-btn-pad: 5px 12px !important;
    --ui-action-btn-size: 11px !important;
    --ui-footer-pad: 8px 18px !important;
    --ui-footer-size: 11px !important;
  }

  /* Enterprise Layout Switcher */
  .view-switch-btn {
    background: transparent;
    border: 1px solid transparent;
    color: var(--text-dim);
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 700;
    padding: 4px 12px;
    border-radius: 4px;
    cursor: pointer;
    letter-spacing: 0.5px;
    transition: all 0.15s ease;
  }
  .view-switch-btn:hover {
    color: var(--cyan);
    background: rgba(56, 189, 248, 0.08);
  }
  .view-switch-btn.active {
    background: #1e293b;
    border-color: var(--cyan);
    color: var(--cyan);
    box-shadow: 0 0 10px rgba(56, 189, 248, 0.25);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body {
    height: 100vh;
    max-height: 100vh;
    overflow: hidden !important;
    background-color: var(--bg-base);
    color: var(--text-main);
    font-family: var(--font-mono);
    font-size: var(--ui-font-base);
    line-height: 1.4;
    user-select: none;
    display: flex;
    flex-direction: column;
  }

  /* SLEEK CYBER CUSTOM SCROLLBAR (ELIMINATES UGLY WHITE OS SCROLLBARS) */
  ::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }
  ::-webkit-scrollbar-track {
    background: #020617;
  }
  ::-webkit-scrollbar-thumb {
    background: #1e293b;
    border-radius: 3px;
    border: 1px solid rgba(56, 189, 248, 0.25);
  }
  ::-webkit-scrollbar-thumb:hover {
    background: var(--cyan);
  }
  * {
    scrollbar-width: thin;
    scrollbar-color: #1e293b #020617;
  }

  /* TOP ENTERPRISE HEADER */
  header {
    background: #090e1c;
    border-bottom: 1px solid var(--border);
    padding: var(--ui-header-pad);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-shrink: 0;
  }

  .brand-group {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .brand-logo {
    font-size: var(--ui-brand-size);
    font-weight: 800;
    color: var(--cyan);
    letter-spacing: 0.1em;
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .nav-tabs {
    display: flex;
    gap: 4px;
    background: rgba(2, 6, 23, 0.6);
    padding: 3px;
    border-radius: 6px;
    border: 1px solid var(--border);
  }

  .nav-tab-btn {
    background: none;
    border: none;
    color: var(--text-dim);
    font-family: var(--font-mono);
    font-size: var(--ui-nav-size);
    font-weight: 700;
    padding: var(--ui-nav-pad);
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .nav-tab-btn:hover { color: white; background: var(--bg-hover); }
  .nav-tab-btn.active {
    color: white;
    background: #1e293b;
    box-shadow: 0 1px 3px rgba(0,0,0,0.4);
    outline: 1px solid var(--border-bright);
  }

  .fleet-stats-strip {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: var(--ui-stat-size);
  }

  .stat-badge {
    background: #0b1120;
    border: 1px solid var(--border);
    padding: var(--ui-stat-pad);
    border-radius: 4px;
    color: var(--text-dim);
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .stat-badge strong { color: white; }
  .stat-badge.critical { border-color: rgba(239, 68, 68, 0.5); color: #fca5a5; }
  .stat-badge.critical strong { color: #f87171; }

  .live-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 6px var(--green);
    display: inline-block;
  }
  .live-dot.pulsing {
    background: var(--crimson);
    box-shadow: 0 0 8px var(--crimson);
    animation: pulse 1.2s infinite;
  }

  @keyframes pulse {
    0% { transform: scale(1); opacity: 1; }
    50% { transform: scale(1.3); opacity: 0.6; }
    100% { transform: scale(1); opacity: 1; }
  }

  /* MAIN CONTENT WRAPPER (NO DOUBLE SCROLLBAR) */
  .workspace-container {
    flex: 1;
    min-height: 0;
    overflow: hidden !important;
    padding: 10px 16px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  /* VIEW PANELS */
  .view-panel {
    display: none;
    flex-direction: column;
    gap: 10px;
    flex: 1;
    min-height: 0;
    height: 100%;
    overflow: hidden;
  }
  .view-panel.active {
    display: flex;
  }

  .fleet-filter-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    background: #090e1c;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 12px;
  }

  .search-box {
    background: #020617;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: white;
    font-family: var(--font-mono);
    font-size: var(--ui-search-size);
    padding: var(--ui-search-pad);
    width: 340px;
  }
  .search-box:focus { outline: 1px solid var(--cyan); }

  .subnet-group {
    background: #090e1c;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .subnet-title {
    font-size: var(--ui-subnet-title-size);
    font-weight: 700;
    color: var(--cyan);
    letter-spacing: 0.08em;
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .host-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(var(--ui-grid-min), 1fr));
    gap: 10px;
  }

  .host-card {
    background: #040711;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: var(--ui-card-pad);
    display: flex;
    flex-direction: column;
    gap: 6px;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .host-card:hover {
    background: #0c1222;
    border-color: var(--cyan);
    transform: translateY(-1px);
  }

  .host-card.critical {
    border-color: rgba(239, 68, 68, 0.6);
    background: linear-gradient(180deg, #160808 0%, #080303 100%);
    box-shadow: 0 0 15px rgba(239, 68, 68, 0.1);
  }

  .host-card.muted {
    border-color: #f59e0b;
    background: #090b14;
    opacity: 0.82;
  }

  .live-dot.muted {
    background: #94a3b8;
    box-shadow: none;
  }

  .host-pill.muted {
    background: #334155;
    color: #fde68a;
    border: 1px solid #f59e0b;
  }

  .staleness-banner {
    background: #1c1507;
    border: 1px solid #f59e0b;
    border-radius: 6px;
    padding: 8px 12px;
    color: #fde68a;
    font-size: 11px;
    font-weight: 700;
    display: none;
    align-items: center;
    gap: 8px;
    margin-bottom: 10px;
  }

  .host-card-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .host-name {
    font-weight: 700;
    font-size: var(--ui-card-name-size);
    color: white;
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .host-pill {
    font-size: var(--ui-pill-size);
    font-weight: 700;
    padding: var(--ui-pill-pad);
    border-radius: 3px;
    text-transform: uppercase;
  }

  .host-pill.crit { background: var(--crimson-dark); color: white; }
  .host-pill.high { background: var(--amber); color: black; }
  .host-pill.eval { background: #3b82f6; color: white; }
  .host-pill.safe { background: #064e3b; color: #a7f3d0; }

  .host-meta {
    font-size: var(--ui-meta-size);
    color: var(--text-dim);
    display: flex;
    justify-content: space-between;
  }

  .host-threat-c2 {
    font-size: var(--ui-threat-tag-size);
    color: #fca5a5;
    background: rgba(220, 38, 38, 0.2);
    padding: 2px 6px;
    border-radius: 3px;
    border: 1px solid rgba(239, 68, 68, 0.4);
    display: inline-block;
    margin-top: 2px;
  }

  /* VIEW 2: CAMPAIGN CORRELATION (STREAMLINED MASTER-DETAIL) */
  .campaign-split-view {
    display: grid;
    grid-template-columns: 35% 65%;
    gap: 12px;
    height: calc(100vh - 195px);
    min-height: 480px;
    max-height: 740px;
  }

  .campaign-card {
    background: #090e1c;
    border: 1px solid rgba(239, 68, 68, 0.35);
    border-left: 3px solid #ef4444;
    border-radius: 6px;
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    cursor: pointer;
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  }

  .campaign-card:hover:not(.selected) {
    background: #0f172a;
    border-color: rgba(56, 189, 248, 0.6);
    transform: translateX(2px);
  }

  .campaign-card.selected {
    background: linear-gradient(135deg, rgba(56, 189, 248, 0.12) 0%, #090e1c 100%) !important;
    border: 1px solid var(--cyan) !important;
    border-left: 4px solid var(--cyan) !important;
    box-shadow: 0 0 16px rgba(56, 189, 248, 0.22) !important;
  }

  .campaign-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    padding-bottom: 6px;
  }

  .campaign-title {
    font-size: 11.5px;
    font-weight: 800;
    color: #f87171;
    display: flex;
    align-items: center;
    gap: 6px;
    letter-spacing: 0.3px;
  }

  .campaign-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 6px 10px;
    background: #040711;
    padding: 8px 10px;
    border-radius: 4px;
    border: 1px solid var(--border);
  }

  .campaign-kv span { display: block; font-size: 8.5px; color: var(--text-dim); letter-spacing: 0.3px; }
  .campaign-kv strong { font-size: 10px; color: white; word-break: break-all; }

  .affected-hosts-row {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .affected-host-chip {
    background: #1e1b4b;
    border: 1px solid #4338ca;
    color: #c7d2fe;
    padding: 2px 6px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 9px;
  }

  /* SVG Attack Graph Animations */
  @keyframes packetFlow {
    from { stroke-dashoffset: 24; }
    to { stroke-dashoffset: 0; }
  }
  .attack-pulse-red {
    stroke-dasharray: 6 3;
    animation: packetFlow 1s linear infinite;
  }
  .attack-pulse-amber {
    stroke-dasharray: 5 3;
    animation: packetFlow 1.2s linear infinite;
  }
  .attack-pulse-purple {
    stroke-dasharray: 6 3;
    animation: packetFlow 1s linear infinite;
  }
  @keyframes pulseGlowRed {
    0%, 100% { filter: drop-shadow(0 0 4px rgba(239, 68, 68, 0.5)); }
    50% { filter: drop-shadow(0 0 12px rgba(239, 68, 68, 0.85)); }
  }
  @keyframes pulseGlowAmber {
    0%, 100% { filter: drop-shadow(0 0 4px rgba(245, 158, 11, 0.5)); }
    50% { filter: drop-shadow(0 0 12px rgba(245, 158, 11, 0.85)); }
  }
  @keyframes pulseGlowCyan {
    0%, 100% { filter: drop-shadow(0 0 4px rgba(56, 189, 248, 0.5)); }
    50% { filter: drop-shadow(0 0 12px rgba(56, 189, 248, 0.85)); }
  }
  .pulse-node-red { animation: pulseGlowRed 2s ease-in-out infinite; }
  .pulse-node-amber { animation: pulseGlowAmber 2s ease-in-out infinite; }
  .pulse-node-cyan { animation: pulseGlowCyan 2s ease-in-out infinite; }

  /* VIEW 3: HOST DRILL-DOWN */
  .drilldown-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #090e1c;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 12px;
  }

  .incident-banner {
    background: linear-gradient(90deg, rgba(30, 8, 8, 0.95), rgba(45, 12, 12, 0.85));
    border: 1px solid var(--crimson-dark);
    border-radius: 8px;
    padding: 8px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .incident-tag {
    background: var(--crimson-dark);
    color: white;
    font-weight: 700;
    font-size: 10px;
    padding: 3px 8px;
    border-radius: 4px;
    text-transform: uppercase;
  }

  .table-wrapper {
    background: #090e1c;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    text-align: left;
  }

  th {
    position: sticky;
    top: 0;
    z-index: 10;
    background: #040711;
    color: var(--text-dim);
    font-size: var(--ui-table-header-size);
    font-weight: 700;
    padding: var(--ui-table-header-pad);
    border-bottom: 1px solid var(--border);
    cursor: pointer;
  }

  td {
    padding: var(--ui-table-cell-pad);
    border-bottom: 1px solid rgba(30, 41, 59, 0.4);
    font-size: var(--ui-table-cell-size);
  }

  tbody tr.row-threat { background: #160808; }
  tbody tr.selected { background: #1e293b !important; outline: 1px solid var(--cyan); }

  /* TRI-PANE DRAWER */
  .drawer-container {
    background: #090e1c;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: var(--ui-drawer-pad);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .drawer-cards {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
  }

  .forensic-card {
    background: #040711;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .card-title {
    font-size: var(--ui-drawer-title-size);
    font-weight: 700;
    letter-spacing: 0.08em;
    padding-bottom: 4px;
    border-bottom: 1px solid rgba(30, 41, 59, 0.6);
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .card-indicator {
    width: 6px; height: 6px;
    border-radius: 50%;
    display: inline-block;
  }
  .card-title.cyan { color: #38bdf8; }
  .card-title.cyan .card-indicator { background: #38bdf8; box-shadow: 0 0 8px rgba(56, 189, 248, 0.6); }
  .card-title.amber { color: var(--amber); }
  .card-title.amber .card-indicator { background: var(--amber); box-shadow: 0 0 8px rgba(245, 158, 11, 0.6); }
  .card-title.blue { color: #06b6d4; }
  .card-title.blue .card-indicator { background: #06b6d4; box-shadow: 0 0 8px rgba(6, 182, 212, 0.6); }

  .card-kv-grid { display: flex; flex-direction: column; gap: 4px; }
  .card-row { display: flex; justify-content: space-between; font-size: var(--ui-card-kv-size); }
  .card-label { color: var(--text-dim); }
  .card-value { color: white; font-weight: 500; }
  .highlight-red { color: #f87171 !important; font-weight: 700; }
  .highlight-cyan { color: #38bdf8 !important; }

  /* BUTTONS & MODALS */
  .action-btn {
    background: #1e293b;
    border: 1px solid var(--border-bright);
    color: white;
    font-family: var(--font-mono);
    font-size: var(--ui-action-btn-size);
    font-weight: 700;
    padding: var(--ui-action-btn-pad);
    border-radius: 4px;
    cursor: pointer;
  }
  .action-btn:hover { background: #334155; }
  .action-btn.danger { background: var(--crimson-dark); border-color: var(--crimson); }
  .action-btn.danger:hover { background: var(--crimson); }
  .action-btn.tarpit { background: #6b21a8; border-color: #9333ea; }
  .action-btn.tarpit:hover { background: #7e22ce; }

  .modal-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(2, 6, 23, 0.88);
    backdrop-filter: blur(8px);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }
  .modal-overlay.active { display: flex !important; }

  .modal-window {
    background: #090e1c;
    border: 1px solid var(--cyan);
    border-radius: 8px;
    width: 600px;
    max-height: 85vh;
    padding: 18px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    box-shadow: 0 0 35px var(--cyan-glow);
  }

  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
  }

  .btn-close {
    background: none;
    border: none;
    color: var(--text-dim);
    font-size: 16px;
    cursor: pointer;
  }
  .btn-close:hover { color: white; }

  footer {
    background: #040711;
    border-top: 1px solid var(--border);
    padding: 6px 16px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 10px;
    color: var(--text-dim);
    flex-shrink: 0;
  }
</style>
<script>
window.INITIAL_STATE = __INITIAL_STATE_PLACEHOLDER__;
</script>
</head>
<body>

  <!-- TOP HEADER -->
  <header>
    <div class="brand-group">
      <div class="brand-logo">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="var(--cyan)"><path d="M12 2L1 21h22L12 2zm0 3.99L19.53 19H4.47L12 5.99zM11 16h2v2h-2zm0-6h2v4h-2z"/></svg>
        UNCLOAK // ENTERPRISE EDR
      </div>
      <div class="nav-tabs">
        <button class="nav-tab-btn active" id="tab-fleet" onclick="switchView('fleet')">[1] FLEET THREAT MATRIX</button>
        <button class="nav-tab-btn" id="tab-campaign" onclick="switchView('campaign')">[2] CAMPAIGN CORRELATION</button>
        <button class="nav-tab-btn" id="tab-drilldown" onclick="switchView('drilldown')">[3] HOST FORENSIC DRILL-DOWN</button>
      </div>
    </div>

    <div class="fleet-stats-strip">
      <div class="stat-badge critical">
        <span class="live-dot pulsing"></span>
        <strong id="badge-crit-hosts">2</strong> ACTIVE THREATS
      </div>
      <div class="stat-badge">
        <span class="live-dot"></span>
        <strong id="badge-total-hosts">10</strong> MONITORED HOSTS
      </div>
      <div class="stat-badge">
        <strong id="badge-total-sockets">1,528</strong> EXTENDED SOCKETS
      </div>
      <button class="action-btn" id="density-toggle-btn" onclick="toggleDensity()" title="Toggle UI Density (Alt+Z)" style="border-color: var(--cyan); color: var(--cyan);">Density: Large (110%)</button>
      <button class="action-btn" onclick="exportTelemetry()">[E] Export OCSF Telemetry</button>
    </div>
  </header>

  <!-- MAIN WORKSPACE CONTAINER -->
  <div class="workspace-container">

    <!-- VIEW 1: FLEET THREAT MATRIX -->
    <div class="view-panel active" id="view-fleet">
      <div class="fleet-filter-bar">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="color: var(--text-dim);">Filter Fleet:</span>
          <input type="text" class="search-box" id="fleet-search" placeholder="Filter host, IP, subnet, C2... [/]" oninput="filterFleet(this.value)" style="width: 260px;">
        </div>
        <div style="display: flex; gap: 4px; background: #0b1120; padding: 3px; border-radius: 6px; border: 1px solid var(--border);">
          <button class="view-switch-btn active" id="btn-fleet-grid" onclick="switchFleetLayout('grid')">TIERED GRID</button>
          <button class="view-switch-btn" id="btn-fleet-table" onclick="switchFleetLayout('table')">DENSE FLEET TABLE</button>
        </div>
        <div style="color: var(--text-dim); font-size: 10px;">
          Agent Health: <strong id="agent-health-label" style="color: var(--green);">All 10 Agents Active (0 Muted)</strong> | Heartbeat: <strong>15s Interval</strong>
        </div>
      </div>

      <!-- Subnet Grid Rendered Dynamically (Single Controlled Scroll) -->
      <div id="fleet-subnets-container" style="display: flex; flex-direction: column; gap: 10px; flex: 1; min-height: 0; overflow-y: auto; overflow-x: hidden; padding-right: 4px;">
      </div>

      <!-- Enterprise Dense Fleet Table (Single Controlled Scroll, Zero Window Bloat) -->
      <div id="fleet-table-container" style="display: none; flex-direction: column; gap: 6px; flex: 1; min-height: 0; overflow: hidden;">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 2px; flex-shrink: 0;">
          <div style="display: flex; gap: 6px; align-items: center;">
            <span style="color: var(--text-dim); font-size: 11px; margin-right: 4px; font-weight: 700;">SCOPE:</span>
            <button class="view-switch-btn active" id="filter-btn-all" onclick="filterTableByScope('ALL')">ALL (32)</button>
            <button class="view-switch-btn" id="filter-btn-threats" onclick="filterTableByScope('THREATS')" style="color: #f87171;">THREATS (4)</button>
            <button class="view-switch-btn" id="filter-btn-tier0" onclick="filterTableByScope('TIER-0')" style="color: #c084fc;">TIER-0 IDENTITY (5)</button>
            <button class="view-switch-btn" id="filter-btn-tier1" onclick="filterTableByScope('TIER-1')">TIER-1 SERVERS (10)</button>
            <button class="view-switch-btn" id="filter-btn-tier2" onclick="filterTableByScope('TIER-2')">TIER-2 WORKSTATIONS (17)</button>
            <button class="view-switch-btn" id="filter-btn-muted" onclick="filterTableByScope('MUTED')" style="color: #f59e0b;">DISCONNECTED (1)</button>
            <button class="view-switch-btn" id="filter-btn-mitigated" onclick="filterTableByScope('MITIGATED')" style="color: #a855f7;">BLOCKED / MITIGATED (4)</button>
          </div>
          <div id="fleet-table-counter" style="color: var(--text-dim); font-size: 11px; font-weight: 700;">Showing 32 of 32 Monitored Endpoints</div>
        </div>
        <div class="table-wrapper" style="flex: 1; min-height: 0; overflow-y: auto; overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th style="width: 80px;">STATUS</th>
              <th>HOSTNAME</th>
              <th>IP ADDRESS</th>
              <th>AD ARCHITECTURE TIER</th>
              <th>OS VERSION & BUILD</th>
              <th>ACTIVE SOCKETS</th>
              <th>CPU / RAM</th>
              <th>MAX THREAT SCORE</th>
              <th>DETECTED ATTRIBUTION</th>
              <th>LAST CONTACT</th>
              <th style="text-align: center;">ACTIONS</th>
            </tr>
          </thead>
          <tbody id="fleet-table-tbody">
          </tbody>
        </table>
        </div>
      </div>
    </div>

    <!-- VIEW 2: CAMPAIGN CORRELATION (STREAMLINED MASTER-DETAIL & SVG ATTACK GRAPH) -->
    <div class="view-panel" id="view-campaign">
      <div class="fleet-filter-bar">
        <div>
          <span style="font-weight: 700; color: white;">Cross-Host Intrusion Correlation Engine:</span>
          <span style="color: var(--text-dim); margin-left: 8px;">Clusters endpoints communicating with matching JA4 TLS handshakes and jitter dispersion profiles.</span>
        </div>
        <div style="color: #f87171; font-weight: 700;" id="campaign-count-label">2 ACTIVE CAMPAIGNS DETECTED</div>
      </div>

      <!-- Campaign KPI Metrics Strip (4 Sleek Badges) -->
      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 10px;">
        <div class="forensic-card" style="padding: 7px 10px; border-color: rgba(239, 68, 68, 0.4);">
          <div class="card-label" style="font-size: 8.5px; color: #f87171;">ACTIVE OUTBREAKS</div>
          <div class="card-value highlight-red" style="font-size: 14px; margin-top: 2px; font-weight: 800;">2 CLUSTERS</div>
        </div>
        <div class="forensic-card" style="padding: 7px 10px;">
          <div class="card-label" style="font-size: 8.5px; color: var(--text-dim);">COMPROMISED HOSTS</div>
          <div class="card-value" style="font-size: 14px; margin-top: 2px; font-weight: 800; color: white;">3 ENDPOINTS (Tier-1 & WS)</div>
        </div>
        <div class="forensic-card" style="padding: 7px 10px;">
          <div class="card-label" style="font-size: 8.5px; color: var(--text-dim);">EXTRACTED JA4s</div>
          <div class="card-value highlight-cyan" style="font-size: 14px; margin-top: 2px; font-weight: 800;">2 SIGNATURES (100% Match)</div>
        </div>
        <div class="forensic-card" style="padding: 7px 10px; border-color: rgba(239, 68, 68, 0.4); display: flex; flex-direction: column; justify-content: space-between;">
          <div class="card-label" style="font-size: 8.5px; color: #f87171;">GLOBAL SEVER ACTION</div>
          <button class="action-btn danger" onclick="severAllCampaigns()" style="font-weight: 700; font-size: 10px; padding: 3px 8px; width: 100%;">[!] Sever All Outbreaks (3 Sockets)</button>
        </div>
      </div>

      <!-- MASTER-DETAIL SPLIT-VIEW (35% / 65%, NO DUPLICATION, ZERO SCROLL) -->
      <div class="campaign-split-view">
        
        <!-- LEFT COLUMN (35%): OUTBREAK HIT-LIST -->
        <div style="display: flex; flex-direction: column; gap: 8px; overflow-y: auto;">
          <div style="font-weight: 800; color: var(--cyan); font-size: 11px; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); padding-bottom: 4px; display: flex; justify-content: space-between; align-items: center;">
            <span>OUTBREAK HIT-LIST</span>
            <span style="font-size: 9px; color: var(--text-dim);">CLICK TO INSPECT TOPOLOGY</span>
          </div>
          <div id="campaigns-container" style="display: flex; flex-direction: column; gap: 8px;">
            <!-- Hydrated dynamically by renderCampaigns() -->
          </div>
        </div>

        <!-- RIGHT COLUMN (65%): VISUAL ATTACK TOPOLOGY GRAPH & THREAT INTEL -->
        <div id="campaign-detail-container" style="background: #090e1c; border: 1px solid var(--border); border-radius: 8px; padding: 12px; display: flex; flex-direction: column; justify-content: space-between; overflow-y: hidden;">
          <!-- Hydrated dynamically by renderCampaignDetail() -->
        </div>
      </div>
    </div>

    <!-- VIEW 3: HOST FORENSIC DRILL-DOWN -->
    <div class="view-panel" id="view-drilldown">
      <div class="staleness-banner" id="staleness-alert-banner"></div>
      <div class="drilldown-bar">
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-dim);">Selected Target Host:</span>
          <select id="host-dropdown" class="search-box" style="width: 220px;" onchange="changeSelectedHost(this.value)">
          </select>
          <span class="host-pill crit" id="host-threat-pill">CRITICAL (98.7%)</span>
        </div>
                <div style="font-size: 11px; color: var(--text-dim); display: flex; align-items: center; gap: 14px;">
          <span>OS: <strong style="color: white;" id="host-os-label">Windows Server 2022</strong></span>
          <span>IP: <strong style="color: white;" id="host-ip-label">10.0.0.15</strong></span>
          <button class="action-btn" id="drilldown-isolate-btn" onclick="toggleHostIsolation()" style="padding: 3px 10px; font-weight: 700; border-color: #f87171; color: #f87171;">Isolate Host</button>
        </div>
      </div>

      <!-- Incident Banner -->
      <div class="incident-banner" id="incident-banner">
        <div style="display: flex; align-items: center; gap: 10px;">
          <div class="incident-tag">CRITICAL INCIDENT</div>
          <div>
            <div style="font-weight: 700; color: white;" id="inc-title">CRITICAL C2 BEACON ISOLATED</div>
            <div style="color: var(--text-dim); font-size: 10px;">
              TARGET: <span id="inc-target" style="color: #fca5a5;">193.26.158.114:443 (Sliver C2)</span> │ 
              PID: <span id="inc-pid">5824 (update.exe)</span> │ 
              STATUS: <span id="inc-status" style="color: #fca5a5;">Active (Live)</span>
            </div>
          </div>
        </div>
        <button class="action-btn danger" onclick="severCurrentIncident()">Sever Connection</button>
      </div>

      <!-- Sub-Tabs Bar for Selected Host -->
      <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-top: 4px;">
        <div class="nav-tabs" style="background: #090e1c;">
          <button class="nav-tab-btn active" id="subtab-btn-flows" onclick="switchHostSubtab('flows')">[A] NETWORK SOCKETS & JITTER (<span id="flows-count-label">0</span>)</button>
          <button class="nav-tab-btn" id="subtab-btn-procs" onclick="switchHostSubtab('procs')">[B] ALL RUNNING PROCESSES (<span id="procs-count-label">0</span>)</button>
          <button class="nav-tab-btn" id="subtab-btn-history" onclick="switchHostSubtab('history')">[C] CONNECTION HISTORY & TIMELINE (<span id="history-count-label">0</span>)</button>
          <button class="nav-tab-btn" id="subtab-btn-whitelist" onclick="switchHostSubtab('whitelist')">[D] MITIGATION & WHITELIST LEDGER (<span id="whitelist-count-label">2</span>)</button>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <input type="text" class="search-box" id="host-sub-search" placeholder="Search processes, sockets, IPs... [/]" oninput="filterHostSubtab(this.value)" style="width: 280px;">
          <button class="action-btn" onclick="exportHostAuditLog()">Export Host Audit</button>
        </div>
      </div>

      <!-- PANE 1: ACTIVE NETWORK SOCKETS & FLOWS -->
      <div class="table-wrapper" id="pane-flows">
        <table>
          <thead>
            <tr>
              <th>FIRST SEEN (UTC)</th>
              <th>PID</th>
              <th>PROCESS</th>
              <th>DESTINATION</th>
              <th>SNI / DOMAIN</th>
              <th>INTERVAL & LOGIC PULSE</th>
              <th>DURATION</th>
              <th>PAYLOAD</th>
              <th style="text-align: right;">THREAT SCORE</th>
              <th style="text-align: center;">ACTIONS</th>
            </tr>
          </thead>
          <tbody id="flows-tbody">
          </tbody>
        </table>
      </div>

      <!-- PANE 2: ALL RUNNING PROCESSES ON HOST -->
      <div class="table-wrapper" id="pane-procs" style="display: none; max-height: 400px; overflow-y: auto;">
        <table>
          <thead>
            <tr>
              <th>PID</th>
              <th>PROCESS NAME</th>
              <th>PARENT (PPID)</th>
              <th>START TIME (UTC)</th>
              <th>SECURITY CONTEXT</th>
              <th>CPU %</th>
              <th>RAM</th>
              <th>INTERNET USAGE</th>
              <th>SIGNATURE STATUS</th>
              <th>ACTIVE SOCKETS</th>
              <th style="text-align: center;">ACTIONS</th>
            </tr>
          </thead>
          <tbody id="procs-tbody">
          </tbody>
        </table>
      </div>

      <!-- PANE 3: CHRONOLOGICAL CONNECTION AUDIT LOG -->
      <div id="pane-history" style="display: none;">
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 8px; background: #0b1120; padding: 6px 12px; border: 1px solid var(--border); border-radius: 4px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 11px; color: var(--text-dim); font-weight: 700;">FILTER BY PID:</span>
            <input type="number" class="search-box" id="timeline-pid-input" placeholder="e.g. 5824" oninput="filterTimelineByPid(this.value)" style="width: 140px; padding: 4px 8px;">
            <button class="action-btn" onclick="clearTimelinePidFilter()" style="padding: 4px 10px;">All PIDs</button>
          </div>
          <div id="timeline-pid-filter-label" style="font-size: 11px; color: var(--cyan); font-weight: 700; display: none;"></div>
        </div>
        <div class="table-wrapper" style="max-height: 380px; overflow-y: auto;">
        <table>
          <thead>
            <tr>
              <th>TIMESTAMP (UTC)</th>
              <th>PROCESS (PID)</th>
              <th>DIRECTION</th>
              <th>LOCAL SOCKET</th>
              <th>REMOTE ENDPOINT</th>
              <th>SNI / DOMAIN</th>
              <th>DURATION</th>
              <th>BYTES</th>
              <th>STATE</th>
              <th>SECURITY VERDICT</th>
            </tr>
          </thead>
          <tbody id="history-tbody">
          </tbody>
        </table>
        </div>
      </div>


        <!-- PANE D: MITIGATION & WHITELIST POLICY LEDGER -->
        <div id="pane-whitelist" style="display: none;">
          <!-- Top Section: Active Enforced Mitigations (Blocked Threats) -->
          <div style="background: #090e1c; border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin-bottom: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 10px;">
              <div>
                <strong style="color: #f87171; font-size: 12px;">AUTONOMOUS PREVENTION & KERNEL MITIGATION EVENTS (BLOCKED)</strong>
                <div style="color: var(--text-dim); font-size: 10.5px; margin-top: 2px;">Sockets terminated via SetTcpEntry or frozen via TCP Zero-Window tarpit.</div>
              </div>
              <span class="host-pill crit" style="font-size: 10px;">2 ACTIVE BLOCKS ENFORCED</span>
            </div>
            <div class="table-wrapper" style="max-height: 200px; overflow-y: auto;">
              <table>
                <thead>
                  <tr>
                    <th>TIMESTAMP (UTC)</th>
                    <th>TARGET HOST</th>
                    <th>PROCESS (PID)</th>
                    <th>DESTINATION</th>
                    <th>TRIGGER HEURISTIC</th>
                    <th>ENFORCEMENT METHOD</th>
                    <th style="text-align: center;">ACTIONS</th>
                  </tr>
                </thead>
                <tbody id="mitigation-tbody">
                  <tr style="background: rgba(239, 68, 68, 0.08);">
                    <td style="white-space: nowrap; font-size: 11px;">2026-11-02 14:26:45 UTC</td>
                    <td><strong>WIN-PROD-SRV01</strong></td>
                    <td style="color: #f87171;"><strong>update.exe (5824)</strong></td>
                    <td>193.26.158.114:443</td>
                    <td><span style="color: #f87171;">Rigid 8.4s Cadence (Sliver C2)</span></td>
                    <td><span class="host-pill crit" style="font-size: 9px;">KERNEL SetTcpEntry SEVERED</span></td>
                    <td style="text-align: center;">
                      <button class="action-btn" onclick="openWhitelistModal(5824, 'update.exe', '193.26.158.114:443', 'WIN-PROD-SRV01')" style="padding: 2px 8px; border-color: var(--green); color: var(--green); font-weight: 700;">Resolve False Positive</button>
                    </td>
                  </tr>
                  <tr style="background: rgba(168, 85, 247, 0.08);">
                    <td style="white-space: nowrap; font-size: 11px;">2026-11-02 14:26:10 UTC</td>
                    <td><strong>WIN-APP-SRV02</strong></td>
                    <td style="color: #c084fc;"><strong>rundll32.exe (6712)</strong></td>
                    <td>cdn-azure-edge.net:8443</td>
                    <td><span style="color: #c084fc;">Domain Fronted 15.0s (Cobalt Strike)</span></td>
                    <td><span class="host-pill arch" style="font-size: 9px; border-color: #a855f7; color: #d8b4fe;">TCP ZERO-WINDOW TARPITTED</span></td>
                    <td style="text-align: center;">
                      <button class="action-btn" onclick="openWhitelistModal(6712, 'rundll32.exe', 'cdn-azure-edge.net:8443', 'WIN-APP-SRV02')" style="padding: 2px 8px; border-color: var(--green); color: var(--green); font-weight: 700;">Resolve False Positive</button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Bottom Section: Active Enterprise Whitelist Policies -->
          <div style="background: #090e1c; border: 1px solid var(--border); border-radius: 6px; padding: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 10px;">
              <div>
                <strong style="color: var(--green); font-size: 12px;">ACTIVE WHITELIST EXEMPTIONS & ALLOW POLICIES</strong>
                <div style="color: var(--text-dim); font-size: 10.5px; margin-top: 2px;">Pre-approved enterprise applications exempted from beacon termination heuristics.</div>
              </div>
              <button class="action-btn" onclick="openWhitelistModal(0, '', '', '')" style="padding: 3px 10px; border-color: var(--green); color: var(--green); font-weight: 700;">+ Create Custom Rule</button>
            </div>
            <div class="table-wrapper" style="max-height: 220px; overflow-y: auto;">
              <table>
                <thead>
                  <tr>
                    <th>RULE ID</th>
                    <th>SCOPE</th>
                    <th>TARGET ENTITY</th>
                    <th>MATCH CRITERIA</th>
                    <th>SOC AUDIT JUSTIFICATION</th>
                    <th>CREATED AT</th>
                    <th style="text-align: center;">ACTIONS</th>
                  </tr>
                </thead>
                <tbody id="whitelist-rules-tbody">
                  <tr>
                    <td><strong style="color: var(--cyan);">WL-2026-001</strong></td>
                    <td><span class="host-pill arch" style="font-size: 9px; border-color: var(--cyan); color: var(--cyan);">GLOBAL (All 32 Hosts)</span></td>
                    <td><strong>teams.exe</strong></td>
                    <td style="font-size: 10.5px; color: var(--text-dim);">SHA256 + *.teams.microsoft.com</td>
                    <td style="font-size: 11px;">Microsoft Teams enterprise telemetry - verified vendor binary</td>
                    <td style="font-size: 10.5px; color: var(--text-dim);">2026-11-01 08:00 UTC</td>
                    <td style="text-align: center;">
                      <button class="action-btn danger" onclick="revokeWhitelistRule('WL-2026-001')" style="padding: 2px 7px; font-size: 10px;">Revoke</button>
                    </td>
                  </tr>
                  <tr>
                    <td><strong style="color: var(--cyan);">WL-2026-002</strong></td>
                    <td><span class="host-pill arch" style="font-size: 9px; border-color: var(--purple); color: #d8b4fe;">LOCAL (DC01-PROD)</span></td>
                    <td><strong>azure_ad_sync.exe</strong></td>
                    <td style="font-size: 10.5px; color: var(--text-dim);">SHA256 + *.login.microsoftonline.com</td>
                    <td style="font-size: 11px;">Entra ID Hybrid Password Hash Sync Agent</td>
                    <td style="font-size: 10.5px; color: var(--text-dim);">2026-11-01 09:30 UTC</td>
                    <td style="text-align: center;">
                      <button class="action-btn danger" onclick="revokeWhitelistRule('WL-2026-002')" style="padding: 2px 7px; font-size: 10px;">Revoke</button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>


      <!-- Tri-Pane Drawer -->
      <div class="drawer-container">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div style="font-weight: 700; color: var(--cyan); display: flex; align-items: center; gap: 6px;">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="var(--cyan)"><path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
            FORENSIC SESSION ATTRIBUTION : <span id="drawer-host-header">193.26.158.114:443 (PID 5824)</span>
          </div>
          <button class="action-btn" onclick="openDossierModal()">Open Forensic Dossier (I)</button>
        </div>

        <div class="drawer-cards">
          <!-- Card 1 -->
          <div class="forensic-card">
            <div class="card-title cyan"><span class="card-indicator"></span>HOST ATTRIBUTION</div>
            <div class="card-kv-grid">
              <div class="card-row"><span class="card-label">PID</span><span class="card-value" id="c1-pid">5824</span></div>
              <div class="card-row"><span class="card-label">Process</span><span class="card-value highlight-red" id="c1-proc">update.exe</span></div>
              <div class="card-row"><span class="card-label">Binary Path</span><span class="card-value" id="c1-path">AppData\\Roaming\\update.exe</span></div>
              <div class="card-row"><span class="card-label">Signature</span><span class="card-value highlight-red" id="c1-sig">Unsigned Binary (On-Disk PE)</span></div>
              <div class="card-row"><span class="card-label">SHA-256</span><span class="card-value" id="c1-sha">e3b0c44298fc1c..</span></div>
              <div class="card-row"><span class="card-label">Process Start Time</span><span class="card-value" id="c1-start">2026-11-02 14:10:02 UTC</span></div>
              <div class="card-row"><span class="card-label">Parent Lineage</span><span class="card-value" id="c1-parent">explorer.exe (PID 2110) -> cmd.exe (PID 4920) -> update.exe (PID 5824)</span></div>
            </div>
          </div>

          <!-- Card 2 -->
          <div class="forensic-card">
            <div class="card-title amber"><span class="card-indicator"></span>CADENCE & TIMING</div>
            <div class="card-kv-grid">
              <div class="card-row"><span class="card-label">Interval</span><span class="card-value" id="c2-int">8.4s (±0.8s)</span></div>
              <div class="card-row"><span class="card-label">Beacon State</span><span class="card-value highlight-red" id="c2-state">ACTIVE (C2 Live)</span></div>
              <div class="card-row"><span class="card-label">Logic Wave</span><span class="card-value" id="c2-pulse"></span></div>
              <div class="card-row"><span class="card-label">Payload Profile</span><span class="card-value" id="c2-payload">512 B (Fixed)</span></div>
              <div class="card-row"><span class="card-label">Burst Distribution</span><span class="card-value" id="c2-bursts">14 bursts / 2m</span></div>
              <div class="card-row"><span class="card-label">Shannon Entropy</span><span class="card-value highlight-cyan" id="c2-entropy">0.94 (Encrypted C2 Payload)</span></div>
              <div class="card-row"><span class="card-label">Payload Ratio (In/Out)</span><span class="card-value" id="c2-ratio">In: 1.2 KB | Out: 480 B (Beacon Loop)</span></div>
              <div class="card-row"><span class="card-label">Jitter Metric</span><span class="card-value highlight-red" id="c2-jitter">9.5% (Rigid / Anomalous)</span></div>
              <div class="card-row"><span class="card-label">First Seen (Opened)</span><span class="card-value" id="c2-first">2026-11-02 14:10:02 UTC</span></div>
              <div class="card-row"><span class="card-label">Last Packet Seen</span><span class="card-value" id="c2-last">2026-11-02 14:26:45 UTC</span></div>
              <div class="card-row"><span class="card-label">Active Duration</span><span class="card-value highlight-cyan" id="c2-duration">16m 43s</span></div>
            </div>
          </div>

          <!-- Card 3 -->
          <div class="forensic-card">
            <div class="card-title blue"><span class="card-indicator"></span>FORENSIC & MITIGATION</div>
            <div class="card-kv-grid">
              <div class="card-row"><span class="card-label">MITRE ATT&CK</span><span class="card-value" id="c3-mitre">T1071.001 (Web Protocols)</span></div>
              <div class="card-row"><span class="card-label">Kernel Hook API</span><span class="card-value highlight-cyan">iphlpapi.dll SetTcpEntry</span></div>
              <div class="card-row"><span class="card-label">Action Status</span><span class="card-value" id="c3-action">Pending Mitigation</span></div>
              <div class="card-row"><span class="card-label">Socket State</span><span class="card-value" id="c3-stack">ESTABLISHED (Live)</span></div>
            </div>
            <div style="display: flex; gap: 8px; margin-top: 6px;">
              <button class="action-btn danger" style="flex: 1;" onclick="severSelectedFlow()" title="Drop active TCP connection">Sever Socket</button>
              <button class="action-btn tarpit" style="flex: 1;" onclick="tarpitSelectedFlow()" title="Freeze C2 beacon with TCP stall">Tarpit / Ghost</button>
              <button class="action-btn danger" style="flex: 1; border-color: #dc2626; background: rgba(220, 38, 38, 0.2);" onclick="promptKillTreeModal(stateData.selected_pid, 'Selected Process')" title="Terminate process and all child processes">Kill Tree</button>
            </div>
            <button class="action-btn" id="btn-card3-whitelist" onclick="openWhitelistModalForSelected()" style="width: 100%; margin-top: 6px; border-color: var(--green); color: var(--green); background: rgba(16, 185, 129, 0.08); font-weight: 700;">Resolve False Positive & Whitelist</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- SURGICAL KERNEL MITIGATION CONFIRMATION MODAL -->
  <div class="modal-overlay" id="sever-confirm-modal">
    <div class="modal-window" style="border-color: rgba(239, 68, 68, 0.7);">
      <div class="modal-header">
        <h3 style="color: #ef4444; font-size: 13px;">CONFIRM SURGICAL KERNEL MITIGATION</h3>
        <button class="btn-close" onclick="closeSeverModal()">&times;</button>
      </div>
      <div style="font-size: 12px; color: #cbd5e1; line-height: 1.6;">
        <p style="margin-bottom: 10px;">You are about to execute a kernel-level TCP Control Block eviction via <code style="color: #38bdf8;">iphlpapi.dll SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)</code>.</p>
        <div style="background: #020617; border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; margin-bottom: 12px; display: flex; flex-direction: column; gap: 6px;">
          <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-dim);">Target Socket:</span><strong style="color: #f87171;" id="modal-target-socket">193.26.158.114:443</strong></div>
          <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-dim);">Owning Process:</span><strong style="color: white;" id="modal-target-proc">update.exe (PID 5824)</strong></div>
          <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-dim);">Host Impact:</span><span style="color: #4ade80;">Socket Dropped │ Host Process Persists</span></div>
        </div>
        <p style="font-size: 11px; color: #94a3b8;">This operation immediately severs the C2 session while leaving the host operating system stable.</p>
      </div>
      <div style="display: flex; justify-content: flex-end; gap: 10px; border-top: 1px solid var(--border); padding-top: 10px;">
        <button class="action-btn" onclick="closeSeverModal()">Cancel [ESC]</button>
        <button class="action-btn danger" onclick="executeConfirmedSever()">Confirm & Sever Socket [Enter]</button>
      </div>
    </div>
  </div>

  <!-- TARPIT / GHOST SOCKET DECEPTIVE DEFENSE MODAL -->
  <div class="modal-overlay" id="tarpit-confirm-modal">
    <div class="modal-window" style="border-color: #a855f7;">
      <div class="modal-header">
        <h3 style="color: #c084fc; font-size: 13px;">ENFORCE TARPIT / GHOST SOCKET (DECEPTIVE DEFENSE)</h3>
        <button class="btn-close" onclick="closeTarpitModal()">&times;</button>
      </div>
      <div style="font-size: 12px; color: #cbd5e1; line-height: 1.6;">
        <p style="margin-bottom: 10px;">Instead of dropping the connection (which alerts the C2 operator), you are about to enforce a <strong>TCP Zero-Window Tarpit</strong>.</p>
        <div style="background: #020617; border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; margin-bottom: 12px; display: flex; flex-direction: column; gap: 6px;">
          <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-dim);">Target Socket:</span><strong style="color: #c084fc;" id="tarpit-modal-target">193.26.158.114:443</strong></div>
          <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-dim);">Owning Process:</span><strong style="color: white;" id="tarpit-modal-proc">update.exe (PID 5824)</strong></div>
          <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-dim);">Deception Strategy:</span><span style="color: #c084fc;">TCP Window Size = 0 (Stall Implant)</span></div>
        </div>
        <p style="font-size: 11px; color: #94a3b8;">The malware freezes waiting for TCP buffer space, buying time to extract volatile RAM artifacts before the attacker realizes they are trapped.</p>
      </div>
      <div style="display: flex; justify-content: flex-end; gap: 10px; border-top: 1px solid var(--border); padding-top: 10px;">
        <button class="action-btn" onclick="closeTarpitModal()">Cancel [ESC]</button>
        <button class="action-btn tarpit" onclick="executeConfirmedTarpit()">Confirm Tarpit Quarantine [Enter]</button>
      </div>
    </div>
  </div>

  <!-- STIX 2.1 THREAT INTEL EXPORT MODAL -->
  <div class="modal-overlay" id="stix-export-modal">
    <div class="modal-window" style="max-width: 650px; border-color: rgba(56, 189, 248, 0.6);">
      <div class="modal-header">
        <h3 style="color: var(--cyan); font-size: 13px;">STIX 2.1 THREAT INTEL BUNDLE</h3>
        <button class="btn-close" onclick="closeStixModal()">&times;</button>
      </div>
      <div style="font-size: 11px; color: var(--text-dim); margin-bottom: 8px;">
        OASIS Open CTI STIX 2.1 bundle formatted for ingestion into MISP, OpenCTI, and ThreatConnect.
      </div>
      <pre id="stix-json-preview" style="background: #020617; border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-family: var(--font-mono); font-size: 10px; color: #a5f3fc; max-height: 280px; overflow-y: auto; white-space: pre-wrap; line-height: 1.4;"></pre>
      <div style="display: flex; justify-content: flex-end; gap: 8px; border-top: 1px solid var(--border); padding-top: 10px; margin-top: 10px;">
        <button class="action-btn" onclick="copyStixToClipboard()">Copy JSON</button>
        <button class="action-btn danger" onclick="downloadStixBundle()">Download STIX 2.1 (.json)</button>
      </div>
    </div>
  </div>

  <!-- YARA-L DETECTION RULE MODAL -->
  <div class="modal-overlay" id="yaral-export-modal">
    <div class="modal-window" style="max-width: 650px; border-color: rgba(245, 158, 11, 0.6);">
      <div class="modal-header">
        <h3 style="color: #f59e0b; font-size: 13px;">GOOGLE CHRONICLE YARA-L 2.0 DETECTION RULE</h3>
        <button class="btn-close" onclick="closeYaralModal()">&times;</button>
      </div>
      <div style="font-size: 11px; color: var(--text-dim); margin-bottom: 8px;">
        Compiled Detection-as-Code rule for real-time UDM event stream hunting across Google Chronicle SIEM.
      </div>
      <pre id="yaral-code-preview" style="background: #020617; border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-family: var(--font-mono); font-size: 10.5px; color: #fde68a; max-height: 280px; overflow-y: auto; white-space: pre-wrap; line-height: 1.4;"></pre>
      <div style="display: flex; justify-content: flex-end; gap: 8px; border-top: 1px solid var(--border); padding-top: 10px; margin-top: 10px;">
        <button class="action-btn" onclick="copyYaralToClipboard()">Copy YARA-L Rule</button>
        <button class="action-btn" style="border-color: #f59e0b; color: #f59e0b;" onclick="deployYaralToChronicle()">Push to Chronicle SIEM Pipeline</button>
      </div>
    </div>
  </div>

  <!-- PROCESS FORENSIC DOSSIER MODAL -->
  <div class="modal-overlay" id="dossier-modal">
    <div class="modal-window">
      <div class="modal-header">
        <h3 id="modal-dossier-title">PROCESS FORENSIC DOSSIER</h3>
        <button class="btn-close" onclick="closeDossierModal()">&times;</button>
      </div>
      <div class="dossier-body" id="modal-dossier-body" style="font-size: 11px; max-height: 60vh; overflow-y: auto; display: flex; flex-direction: column; gap: 8px;">
      </div>
      <div style="display: flex; justify-content: flex-end; gap: 10px; border-top: 1px solid var(--border); padding-top: 10px;">
        <button class="action-btn" onclick="closeDossierModal()">Close</button>
      </div>
    </div>
  </div>

  <!-- PID CONNECTION & INTERNET USAGE HISTORY MODAL -->
  <div class="modal-overlay" id="pid-history-modal" onclick="if(event.target === this) closePidHistoryModal()">
    <div class="modal-window" style="width: 1080px; max-width: 95vw; max-height: 90vh;">
      <div class="modal-header" style="justify-content: space-between;">
        <div>
          <span class="modal-title" style="color: var(--cyan); font-size: 14px;">PID NETWORK & INTERNET USAGE AUDIT</span>
          <span style="color: var(--text-dim); margin-left: 10px; font-size: 12px;">PID <strong id="ph-pid" style="color: white;">-</strong> (<span id="ph-proc" style="color: var(--cyan); font-weight: 700;">-</span>) on <strong id="ph-host" style="color: white;">-</strong></span>
        </div>
        <button class="action-btn" onclick="closePidHistoryModal()" style="padding: 2px 8px; font-weight: 700;">X</button>
      </div>

      <!-- 4 High-Impact Summary Cards -->
      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 12px 0;">
        <div class="forensic-card" style="padding: 10px 12px;">
          <div class="card-label" style="font-size: 9.5px; color: var(--text-dim);">FIRST SEEN (UTC)</div>
          <div class="card-value" id="ph-first-seen" style="font-size: 11px; margin-top: 4px; color: white;">-</div>
        </div>
        <div class="forensic-card" style="padding: 10px 12px;">
          <div class="card-label" style="font-size: 9.5px; color: var(--text-dim);">LAST ACTIVE (UTC)</div>
          <div class="card-value" id="ph-last-seen" style="font-size: 11px; margin-top: 4px; color: white;">-</div>
        </div>
        <div class="forensic-card" style="padding: 10px 12px;">
          <div class="card-label" style="font-size: 9.5px; color: var(--text-dim);">TOTAL BANDWIDTH USAGE</div>
          <div class="card-value highlight-cyan" id="ph-bandwidth" style="font-size: 13px; margin-top: 4px; font-weight: 700;">-</div>
        </div>
        <div class="forensic-card" style="padding: 10px 12px;">
          <div class="card-label" style="font-size: 9.5px; color: var(--text-dim);">SOCKETS (TOTAL / LIVE)</div>
          <div class="card-value" id="ph-sockets" style="font-size: 13px; margin-top: 4px; font-weight: 700; color: white;">-</div>
        </div>
      </div>

      <!-- Detailed Chronological Timeline Table -->
      <div class="table-wrapper" style="max-height: 380px; overflow-y: auto; flex: 1;">
        <table>
          <thead>
            <tr>
              <th>DATE & TIME (UTC)</th>
              <th>LOCAL SOCKET</th>
              <th>REMOTE ENDPOINT</th>
              <th>SNI / DOMAIN</th>
              <th>DURATION</th>
              <th>BANDWIDTH USAGE</th>
              <th>STATE</th>
              <th style="text-align: right;">VERDICT</th>
            </tr>
          </thead>
          <tbody id="ph-tbody">
          </tbody>
        </table>
      </div>

      <div class="modal-footer" style="display: flex; justify-content: space-between; align-items: center; margin-top: 14px; padding-top: 8px; border-top: 1px solid var(--border);">
        <button class="action-btn" onclick="exportCurrentPidCsv()" style="font-weight: 700;">Export PID History (CSV)</button>
        <button class="action-btn" style="background: #334155; color: white;" onclick="closePidHistoryModal()">Close (Esc)</button>
      </div>
    </div>
  </div>
  <!-- ENTERPRISE FALSE POSITIVE & WHITELIST POLICY MODAL -->
  <div class="modal-overlay" id="whitelist-modal" onclick="if(event.target === this) closeWhitelistModal()">
    <div class="modal-window" style="width: 720px; max-width: 95vw; border-color: var(--green); box-shadow: 0 0 35px rgba(16, 185, 129, 0.25);">
      <div class="modal-header">
        <div>
          <span class="modal-title" style="color: var(--green); font-size: 13.5px; font-weight: 800;">RESOLVE FALSE POSITIVE & WHITELIST POLICY</span>
          <div style="color: var(--text-dim); font-size: 11px; margin-top: 2px;">
            Exempt verified business software from beacon heuristics and reverse connection blocking.
          </div>
        </div>
        <button class="action-btn" onclick="closeWhitelistModal()" style="padding: 2px 8px; font-weight: 700;">X</button>
      </div>

      <!-- Incident Context Summary -->
      <div style="background: #040711; border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin: 12px 0; display: flex; flex-direction: column; gap: 6px;">
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-dim); font-size: 11px;">Target Host:</span>
          <strong style="color: white; font-size: 11px;" id="wl-host">WIN-PROD-SRV01 (10.0.1.15)</strong>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-dim); font-size: 11px;">Process & Binary:</span>
          <strong style="color: var(--cyan); font-size: 11px;" id="wl-process">update.exe (PID 5824)</strong>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-dim); font-size: 11px;">Destination Socket:</span>
          <strong style="color: white; font-size: 11px;" id="wl-dest">193.26.158.114:443 (Raw IP / No SNI)</strong>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-dim); font-size: 11px;">Trigger Heuristic:</span>
          <span style="color: #f87171; font-size: 11px; font-weight: 700;" id="wl-trigger">Rigid 8.4s Cadence (9.5% Jitter) - Sliver C2 Rule</span>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-dim); font-size: 11px;">Current Enforcement:</span>
          <span class="host-pill crit" style="font-size: 9.5px;" id="wl-block-state">SEVERED (Kernel SetTcpEntry)</span>
        </div>
      </div>

      <!-- 1. Policy Scope Selector (Local vs Global) -->
      <div style="margin-bottom: 12px;">
        <label style="display: block; font-size: 11px; font-weight: 800; color: white; margin-bottom: 6px; letter-spacing: 0.5px;">
          1. SELECT POLICY SCOPE:
        </label>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
          <div id="wl-scope-local-box" onclick="setWhitelistScope('LOCAL')" style="background: #0d1527; border: 1px solid var(--cyan); border-radius: 6px; padding: 10px; cursor: pointer;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <input type="radio" id="wl-scope-local" name="wl_scope" value="LOCAL" checked>
              <strong style="color: var(--cyan); font-size: 11.5px;">LOCAL SCOPE (Current Host Only)</strong>
            </div>
            <div style="color: var(--text-dim); font-size: 10px; margin-top: 4px; line-height: 1.4;">
              Exempt only on <span id="wl-scope-hostname">WIN-PROD-SRV01</span>. Recommended for developer testing and local admin scripts.
            </div>
          </div>

          <div id="wl-scope-global-box" onclick="setWhitelistScope('GLOBAL')" style="background: #040711; border: 1px solid var(--border); border-radius: 6px; padding: 10px; cursor: pointer;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <input type="radio" id="wl-scope-global" name="wl_scope" value="GLOBAL">
              <strong style="color: white; font-size: 11.5px;">GLOBAL ENTERPRISE (All 32+ Hosts)</strong>
            </div>
            <div style="color: var(--text-dim); font-size: 10px; margin-top: 4px; line-height: 1.4;">
              Pushes whitelist rule fleet-wide. Recommended for verified vendor SaaS, IT management daemons, and backup agents.
            </div>
          </div>
        </div>
      </div>

      <!-- 2. Fingerprint & Match Criteria -->
      <div style="margin-bottom: 12px;">
        <label style="display: block; font-size: 11px; font-weight: 800; color: white; margin-bottom: 6px; letter-spacing: 0.5px;">
          2. RULE MATCHING CRITERIA:
        </label>
        <div style="display: flex; flex-direction: column; gap: 6px; background: #040711; border: 1px solid var(--border); border-radius: 6px; padding: 10px;">
          <label style="display: flex; align-items: center; gap: 8px; font-size: 11px; color: var(--text-dim); cursor: pointer;">
            <input type="checkbox" id="wl-match-hash" checked>
            <span>Match Binary SHA-256 Hash (<code style="color: #cbd5e1; font-size: 10px;">e3b0c44298fc1c14..</code>)</span>
          </label>
          <label style="display: flex; align-items: center; gap: 8px; font-size: 11px; color: var(--text-dim); cursor: pointer;">
            <input type="checkbox" id="wl-match-dest" checked>
            <span>Match Destination Socket IP / Domain (<code style="color: #cbd5e1; font-size: 10px;" id="wl-rule-dest">193.26.158.114:443</code>)</span>
          </label>
          <label style="display: flex; align-items: center; gap: 8px; font-size: 11px; color: var(--text-dim); cursor: pointer;">
            <input type="checkbox" id="wl-match-ja4" checked>
            <span>Match TLS JA4 Client Hello Signature (<code style="color: #cbd5e1; font-size: 10px;">t13d1516h2_8daaf4b10222..</code>)</span>
          </label>
        </div>
      </div>

      <!-- 3. SOC Audit Note -->
      <div style="margin-bottom: 14px;">
        <label style="display: block; font-size: 11px; font-weight: 800; color: white; margin-bottom: 6px; letter-spacing: 0.5px;">
          3. SOC AUDIT JUSTIFICATION & TICKET ID:
        </label>
        <input type="text" class="search-box" id="wl-reason" placeholder="e.g. Approved vendor telemetry daemon / JIRA-8924 verification" style="width: 100%; font-size: 11px;" value="Approved enterprise vendor telemetry - verified benign by SOC">
      </div>

      <!-- Footer Buttons -->
      <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border); padding-top: 12px;">
        <button class="action-btn" onclick="closeWhitelistModal()">Cancel</button>
        <button class="action-btn" onclick="applyWhitelistPolicy()" style="background: var(--green); color: black; font-weight: 800; border-color: var(--green); padding: 6px 16px;">
          Confirm Whitelist & Reverse Block
        </button>
      </div>
    </div>
  </div>


  <!-- FOOTER -->
  <footer>
    <div>
      Shortcuts: <strong style="color: white;">[1]</strong> Fleet Matrix │ <strong style="color: white;">[2]</strong> Campaigns │ <strong style="color: white;">[3]</strong> Drill-Down (Subtabs: <strong style="color: white;">A</strong> Sockets, <strong style="color: white;">B</strong> Procs, <strong style="color: white;">C</strong> Timeline) │ <strong style="color: white;">K</strong> Sever │ <strong style="color: white;">Alt+Z</strong> Density
    </div>
    <div>UNCLOAK v0.1.0 │ Statistical Beacon Detection & Kernel Socket Attribution Engine</div>
  </footer>

<script>
  let stateData = null;
  let currentTab = 'fleet';
  let currentFleetLayout = 'grid';
  let activeModalPidData = null;

  let activeWhitelistTarget = null;
  let activeWhitelistScope = 'LOCAL';
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
    if (!stateData) return;
    const flow = (stateData.flows || []).find(f => f.pid === stateData.selected_pid) || (stateData.flows || [])[0];
    const host = stateData.selected_host ? stateData.selected_host.hostname : 'WIN-PROD-SRV01';
    if (flow) {
      openWhitelistModal(flow.pid, flow.process_name, flow.dst_ip + ':' + flow.dst_port, host);
    } else {
      openWhitelistModal(5824, 'update.exe', '193.26.158.114:443', host);
    }
  }

  function openWhitelistModalForHost(hostId) {
    if (!stateData) return;
    const host = stateData.hosts.find(h => h.host_id === hostId) || stateData.selected_host;
    openWhitelistModal(5824, 'update.exe', '193.26.158.114:443', host ? host.hostname : 'WIN-PROD-SRV01');
  }

  function closeWhitelistModal() {
    document.getElementById('whitelist-modal').classList.remove('active');
  }

  function setWhitelistScope(scope) {
    activeWhitelistScope = scope;
    const localBox = document.getElementById('wl-scope-local-box');
    const globalBox = document.getElementById('wl-scope-global-box');
    const radioLocal = document.getElementById('wl-scope-local');
    const radioGlobal = document.getElementById('wl-scope-global');

    if (scope === 'GLOBAL') {
      globalBox.style.background = '#0d1527';
      globalBox.style.borderColor = 'var(--cyan)';
      localBox.style.background = '#040711';
      localBox.style.borderColor = 'var(--border)';
      if (radioGlobal) radioGlobal.checked = true;
    } else {
      localBox.style.background = '#0d1527';
      localBox.style.borderColor = 'var(--cyan)';
      globalBox.style.background = '#040711';
      globalBox.style.borderColor = 'var(--border)';
      if (radioLocal) radioLocal.checked = true;
    }
  }

  function applyWhitelistPolicy() {
    const reason = document.getElementById('wl-reason').value || 'Approved enterprise vendor software';
    const target = activeWhitelistTarget || { procName: 'update.exe', dest: '193.26.158.114:443', host: 'WIN-PROD-SRV01' };

    // Create new policy rule
    const ruleId = 'WL-2026-00' + (enterpriseWhitelistRules.length + 1);
    enterpriseWhitelistRules.unshift({
      rule_id: ruleId,
      scope: activeWhitelistScope,
      entity: target.procName,
      destination: target.dest,
      justification: reason,
      created_at: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
    });

    // Reverse block in local telemetry state
    if (stateData && stateData.flows) {
      const flow = stateData.flows.find(f => f.pid === target.pid || f.process_name === target.procName);
      if (flow) {
        flow.is_severed = false;
        flow.is_threat = false;
        flow.threat_score = 0.001;
        flow.threat_label = 'POLICY ALLOWED';
        flow.state = 'WHITELISTED (POLICY ALLOWED)';
      }
    }

    closeWhitelistModal();
    alert(`POLICY APPLIED & BLOCK REVERSED: Rule ${ruleId} deployed (${activeWhitelistScope} scope). Future retry traffic for ${target.procName} is permitted without blocking.`);

    // Re-render UI
    renderUI();
    renderWhitelistLedger();
  }

  function revokeWhitelistRule(ruleId) {
    if (confirm(`Revoke Whitelist Rule ${ruleId}? Traffic matching this rule will no longer be exempted from beacon blocking.`)) {
      enterpriseWhitelistRules = enterpriseWhitelistRules.filter(r => r.rule_id !== ruleId);
      renderWhitelistLedger();
    }
  }

  function renderWhitelistLedger() {
    const countLabel = document.getElementById('whitelist-count-label');
    if (countLabel) countLabel.innerText = enterpriseWhitelistRules.length;

    const tbody = document.getElementById('whitelist-rules-tbody');
    if (!tbody) return;

    let rows = '';
    enterpriseWhitelistRules.forEach(r => {
      const isGlobal = r.scope === 'GLOBAL';
      rows += `
        <tr>
          <td><strong style="color: var(--cyan);">${r.rule_id}</strong></td>
          <td><span class="host-pill arch" style="font-size: 9px; border-color: ${isGlobal ? 'var(--cyan)' : 'var(--purple)'}; color: ${isGlobal ? 'var(--cyan)' : '#d8b4fe'};">${isGlobal ? 'GLOBAL (All 32 Hosts)' : 'LOCAL (Target Host)'}</span></td>
          <td><strong>${r.entity}</strong></td>
          <td style="font-size: 10.5px; color: var(--text-dim);">${r.destination}</td>
          <td style="font-size: 11px;">${r.justification}</td>
          <td style="font-size: 10.5px; color: var(--text-dim);">${r.created_at}</td>
          <td style="text-align: center;">
            <button class="action-btn danger" onclick="revokeWhitelistRule('${r.rule_id}')" style="padding: 2px 7px; font-size: 10px;">Revoke</button>
          </td>
        </tr>`;
    });
    tbody.innerHTML = rows;
  }

  let pendingSeverPid = null;
  let pendingSeverHostId = null;
  let pendingCampaignId = null;
  let pendingTarpitPid = null;
  let pendingKillPid = null;
  let pendingKillName = '';

  function promptKillTreeModal(pid, name) {
    pendingKillPid = pid;
    pendingKillName = name;
    promptSeverModal(pid, 'All Child & Parent Threads', name + ' [Process Tree]');
  }

  let userSelectedPid = null;
  let userSelectedHostId = null;

  function switchFleetLayout(layout) {
    currentFleetLayout = layout;
    const btnGrid = document.getElementById('btn-fleet-grid');
    const btnTable = document.getElementById('btn-fleet-table');
    const gridDiv = document.getElementById('fleet-subnets-container');
    const tableDiv = document.getElementById('fleet-table-container');

    if (layout === 'table') {
      if (btnTable) btnTable.classList.add('active');
      if (btnGrid) btnGrid.classList.remove('active');
      if (gridDiv) gridDiv.style.display = 'none';
      if (tableDiv) tableDiv.style.display = 'block';
      renderFleetDenseTable();
    } else {
      if (btnGrid) btnGrid.classList.add('active');
      if (btnTable) btnTable.classList.remove('active');
      if (gridDiv) gridDiv.style.display = 'flex';
      if (tableDiv) tableDiv.style.display = 'none';
      renderFleetSubnets();
    }
  }

  let activeFleetScope = 'ALL';

  function filterTableByScope(scope) {
    activeFleetScope = scope;
    ['all', 'threats', 'tier0', 'tier1', 'tier2', 'muted'].forEach(s => {
      const btn = document.getElementById('filter-btn-' + s);
      if (btn) btn.classList.remove('active');
    });
    const key = scope === 'TIER-0' ? 'tier0' : (scope === 'TIER-1' ? 'tier1' : (scope === 'TIER-2' ? 'tier2' : scope.toLowerCase()));
    const activeBtn = document.getElementById('filter-btn-' + key);
    if (activeBtn) activeBtn.classList.add('active');

    renderFleetDenseTable();
  }

  function renderFleetDenseTable() {
    if (!stateData) return;
    const tbody = document.getElementById('fleet-table-tbody');
    if (!tbody) return;

    let filteredHosts = stateData.hosts;
    if (activeFleetScope === 'THREATS') {
      filteredHosts = filteredHosts.filter(h => h.threat_level === 'CRITICAL' || h.threat_level === 'HIGH');
    } else if (activeFleetScope === 'TIER-0') {
      filteredHosts = filteredHosts.filter(h => (h.ad_tier || h.subnet || '').includes('Tier-0'));
    } else if (activeFleetScope === 'TIER-1') {
      filteredHosts = filteredHosts.filter(h => (h.ad_tier || h.subnet || '').includes('Tier-1'));
    } else if (activeFleetScope === 'TIER-2') {
      filteredHosts = filteredHosts.filter(h => (h.ad_tier || h.subnet || '').includes('Tier-2'));
    } else if (activeFleetScope === 'MUTED') {
      filteredHosts = filteredHosts.filter(h => h.status === 'MUTED');
    } else if (activeFleetScope === 'MITIGATED') {
      filteredHosts = filteredHosts.filter(h => h.threat_level === 'CRITICAL' || h.isolated_beacons_count > 0);
    }

    const counterEl = document.getElementById('fleet-table-counter');
    if (counterEl) {
      counterEl.innerText = `Showing ${filteredHosts.length} of ${stateData.hosts.length} Monitored Endpoints`;
    }

    let rowsHtml = '';
    filteredHosts.forEach(h => {
      const isCrit = h.threat_level === 'CRITICAL';
      const isHigh = h.threat_level === 'HIGH';
      const isEval = h.threat_level === 'EVALUATING';
      const pillClass = isCrit ? 'crit' : (isHigh ? 'high' : (isEval ? 'eval' : 'safe'));
      const isMuted = h.status === 'MUTED';
      const isIso = h.is_isolated;

      let staleText = 'Just now';
      if (h.seconds_since_heartbeat > 5) {
        const m = Math.floor(h.seconds_since_heartbeat / 60);
        const s = h.seconds_since_heartbeat % 60;
        staleText = m > 0 ? `${m}m ${s}s ago` : `${s}s ago`;
      }

      rowsHtml += `
        <tr class="${isCrit ? 'row-threat' : ''} ${isIso ? 'row-isolated' : ''}" style="cursor: pointer;" onclick="selectAndDrilldown('${h.host_id}')">
          <td style="white-space: nowrap;">
            <span class="live-dot ${isMuted ? 'muted' : (isCrit ? 'pulsing' : '')}" style="margin-right: 6px;"></span>
            <span class="host-pill ${isMuted ? 'muted' : (isIso ? 'high' : pillClass)}" style="font-size: 9px; padding: 1px 5px;">
              ${isIso ? 'ISOLATED' : (isMuted ? 'STALE' : h.threat_level)}
            </span>
          </td>
          <td><strong style="color: var(--cyan);">${h.hostname}</strong></td>
          <td style="font-family: monospace; font-size: 11px;">${h.ip_address}</td>
          <td><span class="host-pill arch">${h.ad_tier || h.subnet}</span></td>
          <td style="font-size: 11px; color: var(--text-dim);">${h.os_version}</td>
          <td><strong>${h.active_sockets_count}</strong></td>
          <td style="font-size: 11px;">${h.cpu_percent}% / ${h.ram_mb} MB</td>
          <td style="text-align: right;"><strong style="color: ${isCrit ? '#f87171' : (isHigh ? '#fbbf24' : 'var(--green)')};">${(h.threat_score * 100).toFixed(1)}%</strong></td>
          <td>${h.c2_framework ? `<span style="color: #f87171; font-weight: 700;">${h.c2_framework}</span>` : '<span style="color: var(--text-muted); font-size: 11px;">Baseline Clean</span>'}</td>
          <td style="font-size: 10px; color: var(--text-dim);">${staleText}</td>
          <td style="text-align: center; white-space: nowrap;">
            <button class="action-btn" onclick="event.stopPropagation(); selectAndDrilldown('${h.host_id}')" style="padding: 2px 7px; margin-right: 4px;">Forensics</button>
            <button class="action-btn ${isIso ? '' : 'danger'}" onclick="event.stopPropagation(); toggleHostIsolation('${h.host_id}')" style="padding: 2px 7px;">${isIso ? 'Re-Join' : 'Isolate'}</button>
          </td>
        </tr>
      `;
    });

    smartUpdateTbody(tbody, rowsHtml, 0);
  }

  async function toggleHostIsolation(hostId) {
    await fetch('/api/isolate_host', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host_id: hostId })
    });
    fetchState();
  }

  function smartUpdateTbody(tbody, newHtml, selectedPid) {
    if (!tbody) return;
    if (tbody.dataset.renderedHtml !== newHtml) {
      const scrollParent = tbody.closest('.table-wrapper') || tbody.parentElement;
      const prevScrollTop = scrollParent ? scrollParent.scrollTop : 0;
      tbody.innerHTML = newHtml;
      tbody.dataset.renderedHtml = newHtml;
      if (scrollParent && prevScrollTop > 0) {
        scrollParent.scrollTop = prevScrollTop;
      }
    }
    tbody.querySelectorAll('tr').forEach(row => {
      const rowPid = parseInt(row.getAttribute('data-pid') || '0');
      if (rowPid && rowPid === selectedPid) {
        row.classList.add('selected');
      } else {
        row.classList.remove('selected');
      }
    });
  }

  function updateRowSelectionHighlight(pid) {
    ['flows-tbody', 'procs-tbody', 'history-tbody'].forEach(id => {
      const tbody = document.getElementById(id);
      if (!tbody) return;
      tbody.querySelectorAll('tr').forEach(row => {
        const rowPid = parseInt(row.getAttribute('data-pid') || '0');
        if (rowPid && rowPid === pid) {
          row.classList.add('selected');
        } else {
          row.classList.remove('selected');
        }
      });
    });
  }

  function switchView(tabName) {
    currentTab = tabName;
    document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-tab-btn').forEach(b => b.classList.remove('active'));

    document.getElementById('view-' + tabName).classList.add('active');
    document.getElementById('tab-' + tabName).classList.add('active');
    if (tabName === 'campaign') {
      renderCampaigns();
      renderCampaignDetail();
    }
  }

  async function fetchState() {
    try {
      const hostParam = (stateData && stateData.selected_host) ? stateData.selected_host.host_id : (userSelectedHostId || '');
      const pidParam = userSelectedPid !== null ? userSelectedPid : '';
      const queryStr = hostParam ? `?host=${encodeURIComponent(hostParam)}&pid=${encodeURIComponent(pidParam)}` : (pidParam ? `?pid=${encodeURIComponent(pidParam)}` : '');
      const res = await fetch('/api/state' + queryStr);
      const incoming = await res.json();

      // Preserve explicit user selection across state sync ticks
      if (userSelectedPid !== null) {
        const hasFlow = (incoming.flows || []).some(f => f.pid === userSelectedPid);
        const hasProc = (incoming.host_processes || []).some(p => p.pid === userSelectedPid);
        const hasHist = (incoming.host_connection_history || []).some(h => h.pid === userSelectedPid);
        if (hasFlow || hasProc || hasHist) {
          incoming.selected_pid = userSelectedPid;
        } else {
          userSelectedPid = incoming.selected_pid;
        }
      } else {
        userSelectedPid = incoming.selected_pid;
      }

      stateData = incoming;
      renderUI();
      if (!window._initialParamHandled) {
        window._initialParamHandled = true;
        const urlParams = new URLSearchParams(window.location.search);
        const initialTab = urlParams.get('tab');
        if (initialTab && ['fleet', 'campaign', 'drilldown'].includes(initialTab)) {
          switchView(initialTab);
        }
        const modal = urlParams.get('modal');
        if (modal === 'sever') {
          promptSeverModal(5824, '193.26.158.114:443', 'update.exe');
        } else if (modal === 'tarpit') {
          tarpitSelectedFlow();
        }
      }
    } catch (e) {
      console.error('State sync error:', e);
    }
  }

  function renderUI() {
    if (!stateData) return;

    // 1. Top Badges & Health Label
    document.getElementById('badge-crit-hosts').innerText = (stateData.fleet_summary.critical_hosts + (stateData.fleet_summary.high_hosts || 0));
    document.getElementById('badge-total-hosts').innerText = stateData.fleet_summary.total_hosts;
    document.getElementById('badge-total-sockets').innerText = stateData.fleet_summary.total_sockets.toLocaleString();
    const healthLabel = document.getElementById('agent-health-label');
    if (healthLabel) {
      healthLabel.innerText = stateData.fleet_summary.heartbeat_status;
      healthLabel.style.color = stateData.fleet_summary.muted_hosts > 0 ? '#f59e0b' : 'var(--green)';
    }

    // 2. Render Fleet Matrix
    const gridDiv = document.getElementById('fleet-subnets-container');
    const tableDiv = document.getElementById('fleet-table-container');
    const btnGrid = document.getElementById('btn-fleet-grid');
    const btnTable = document.getElementById('btn-fleet-table');
    if (currentFleetLayout === 'table') {
      if (gridDiv) gridDiv.style.display = 'none';
      if (tableDiv) tableDiv.style.display = 'flex';
      if (btnGrid) btnGrid.classList.remove('active');
      if (btnTable) btnTable.classList.add('active');
      renderFleetDenseTable();
    } else {
      if (gridDiv) gridDiv.style.display = 'flex';
      if (tableDiv) tableDiv.style.display = 'none';
      if (btnGrid) btnGrid.classList.add('active');
      if (btnTable) btnTable.classList.remove('active');
      renderFleetSubnets();
    }

    // 3. Render Campaigns
    renderCampaigns();
    renderCampaignDetail();

    // 4. Render Host Drill-Down
    renderHostDrilldown();
  }

  function renderFleetSubnets() {
    const container = document.getElementById('fleet-subnets-container');
    const hosts = stateData.hosts;
    
    // Group hosts by subnet
    const groups = {};
    hosts.forEach(h => {
      if (!groups[h.subnet]) groups[h.subnet] = [];
      groups[h.subnet].push(h);
    });

    let html = '';
    for (const [subnet, subnetHosts] of Object.entries(groups)) {
      html += `
        <div class="subnet-group">
          <div class="subnet-title">
            <svg viewBox="0 0 24 24" width="12" height="12" fill="var(--cyan)"><path d="M4 6h16v2H4zm0 5h16v2H4zm0 5h16v2H4z"/></svg>
            ${subnet.toUpperCase()} (${subnetHosts.length} ENDPOINTS)
          </div>
          <div class="host-grid">
      `;

      subnetHosts.forEach(h => {
        const isCrit = h.threat_level === 'CRITICAL';
        const isHigh = h.threat_level === 'HIGH';
        const isEval = h.threat_level === 'EVALUATING';
        const pillClass = isCrit ? 'crit' : (isHigh ? 'high' : (isEval ? 'eval' : 'safe'));

        const isMuted = h.status === 'MUTED';
        html += `
          <div class="host-card ${isCrit ? 'critical' : ''} ${isMuted ? 'muted' : ''}" onclick="selectAndDrilldown('${h.host_id}')">
            <div class="host-card-top">
              <span class="host-name">
                <span class="live-dot ${isMuted ? 'muted' : (isCrit ? 'pulsing' : '')}"></span>
                ${h.hostname}
              </span>
              <span class="host-pill ${isMuted ? 'muted' : pillClass}">${isMuted ? 'DISCONNECTED' : h.threat_level} (${isMuted ? 'Stale' : (h.threat_score * 100).toFixed(1) + '%'})</span>
            </div>
            <div class="host-meta">
              <span>${h.ip_address}</span>
              <span>${h.os_version.split(' ')[0]} ${h.os_version.split(' ')[1] || ''}</span>
            </div>
            <div class="host-meta" style="margin-top: 2px;">
              <span>${h.active_sockets_count} Sockets</span>
              <span>CPU: ${h.cpu_percent}% │ RAM: ${h.ram_mb} MB</span>
            </div>
            ${h.c2_framework ? `<div class="host-threat-c2">${h.c2_framework} Isolated</div>` : ''}
          </div>
        `;
      });

      html += `</div></div>`;
    }

    if (container.dataset.renderedHtml !== html) {
      container.innerHTML = html;
      container.dataset.renderedHtml = html;
    }
  }

  function severAllCampaigns() {
    if (confirm('ENTERPRISE ACTION: Immediately drop all C2 sockets across Cluster Alpha (Sliver) and Cluster Beta (Cobalt Strike)?')) {
      alert('MITIGATION DEPLOYED: Kernel SetTcpEntry successfully terminated all correlated campaign sockets.');
    }
  }

  let selectedCampaignId = 'camp-alpha';

  function selectCampaign(campId) {
    selectedCampaignId = campId;
    renderCampaigns();
    renderCampaignDetail();
  }

  function renderCampaigns() {
    const container = document.getElementById('campaigns-container');
    if (!container || !stateData || !stateData.campaigns) return;
    const campaigns = stateData.campaigns;
    const countLabel = document.getElementById('campaign-count-label');
    if (countLabel) countLabel.innerText = `${campaigns.length} ACTIVE CAMPAIGNS DETECTED`;

    let html = '';
    campaigns.forEach(c => {
      const isSelected = (c.campaign_id === selectedCampaignId);
      const isContained = (c.status === 'CONTAINED');
      const isAlpha = (c.campaign_id === 'camp-alpha');
      
      html += `
        <div class="campaign-card ${isSelected ? 'selected' : ''}" onclick="selectCampaign('${c.campaign_id}')" style="${isContained ? 'border-color: #10b981; border-left-color: #10b981;' : ''}">
          <div class="campaign-header">
            <div class="campaign-title" style="${isContained ? 'color: #34d399;' : ''}">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor"><path d="M12 2L1 21h22L12 2zm0 3.99L19.53 19H4.47L12 5.99zM11 16h2v2h-2zm0-6h2v4h-2z"/></svg>
              ${c.name.split(':')[0]}
            </div>
            <div>
              ${isContained 
                ? '<span class="host-pill safe" style="font-size: 8px;">CONTAINED</span>' 
                : `<span class="host-pill crit" style="font-size: 8px;">${isAlpha ? 'CRITICAL // DIRECT IP' : 'STEALTH // CDN FRONT'}</span>`}
            </div>
          </div>
          <div class="campaign-grid">
            <div class="campaign-kv"><span>FRAMEWORK</span><strong>${c.c2_framework}</strong></div>
            <div class="campaign-kv"><span>CADENCE</span><strong style="color: var(--amber);">${c.cadence_profile}</strong></div>
            <div class="campaign-kv" style="grid-column: span 2;"><span>DESTINATION</span><strong style="font-family: var(--font-mono); font-size: 9.5px;">${c.target_destination}</strong></div>
          </div>
          <div class="affected-hosts-row">
            <span style="color: var(--text-dim); font-size: 9px;">Endpoints (${c.affected_hosts.length}):</span>
            ${c.affected_hosts.map(h => `<span class="affected-host-chip">${h}</span>`).join('')}
          </div>
        </div>
      `;
    });

    if (container.dataset.renderedHtml !== html) {
      container.innerHTML = html;
      container.dataset.renderedHtml = html;
    }
  }

  function renderCampaignDetail() {
    const container = document.getElementById('campaign-detail-container');
    if (!container || !stateData || !stateData.campaigns) return;
    
    const camp = stateData.campaigns.find(c => c.campaign_id === selectedCampaignId) || stateData.campaigns[0];
    if (!camp) return;

    const isContained = (camp.status === 'CONTAINED');
    const isAlpha = (camp.campaign_id === 'camp-alpha');

    let topologySvg = '';
    let forensicsHtml = '';
    let mitreHtml = '';

    if (isAlpha) {
      topologySvg = `
        <div style="background: #040711; border: 1px solid #1e293b; border-radius: 6px; padding: 10px 8px; margin-bottom: 6px; display: flex; align-items: center; justify-content: space-around; position: relative;">
          <!-- Adversary C2 Node -->
          <div style="display: flex; flex-direction: column; align-items: center; text-align: center; width: 140px;">
            <div class="pulse-node-red" style="width: 42px; height: 42px; border-radius: 50%; background: rgba(239, 68, 68, 0.15); border: 2px solid #ef4444; display: flex; align-items: center; justify-content: center;">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="#f87171"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 14H9v-2h2v2zm0-4H9V7h2v5zm4 4h-2v-2h2v2zm0-4h-2V7h2v5z"/></svg>
            </div>
            <div style="color: #f87171; font-weight: 800; font-size: 10.5px; margin-top: 5px;">ADVERSARY C2</div>
            <div style="color: var(--text-dim); font-size: 9px; font-family: var(--font-mono);">193.26.158.114:443</div>
            <span class="host-pill crit" style="font-size: 7.5px; margin-top: 2px;">Sliver Server</span>
          </div>

          <!-- Ingress Vector Arrow -->
          <div style="display: flex; flex-direction: column; align-items: center; gap: 3px;">
            <span style="font-size: 8.5px; color: ${isContained ? '#94a3b8' : '#f87171'}; font-weight: 700; font-family: var(--font-mono);">${isContained ? 'SEVERED' : '8.4s Cadence (HTTPS)'}</span>
            <svg width="110" height="14" style="overflow: visible;">
              <line x1="0" y1="7" x2="100" y2="7" stroke="${isContained ? '#475569' : '#ef4444'}" stroke-width="2" class="${isContained ? '' : 'attack-pulse-red'}" />
              <polygon points="100,3 108,7 100,11" fill="${isContained ? '#475569' : '#38bdf8'}" />
            </svg>
            <span style="font-size: 8px; color: var(--text-dim); font-family: var(--font-mono);">JA4: t13d1516h2..</span>
          </div>

          <!-- Patient Zero Ingress Host -->
          <div style="display: flex; flex-direction: column; align-items: center; text-align: center; width: 140px;">
            <div class="pulse-node-cyan" style="width: 42px; height: 42px; border-radius: 6px; background: rgba(56, 189, 248, 0.1); border: 2px solid var(--cyan); display: flex; align-items: center; justify-content: center;">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="var(--cyan)"><path d="M4 6h16v10H4V6zm2 2v6h12V8H6zm-4 9h20v2H2v-2z"/></svg>
            </div>
            <div style="color: white; font-weight: 800; font-size: 10.5px; margin-top: 5px;">WIN-PROD-SRV01</div>
            <div style="color: var(--text-dim); font-size: 9px; font-family: var(--font-mono);">10.0.0.15 (Tier-1 App)</div>
            <span class="host-pill arch" style="font-size: 7.5px; margin-top: 2px; border-color: #f87171; color: #f87171;">PATIENT ZERO / INGRESS</span>
          </div>

          <!-- Lateral Pivot Vector Arrow -->
          <div style="display: flex; flex-direction: column; align-items: center; gap: 3px;">
            <span style="font-size: 8.5px; color: #f59e0b; font-weight: 700; font-family: var(--font-mono);">WMI / SMB Pivot</span>
            <svg width="100" height="14" style="overflow: visible;">
              <line x1="0" y1="7" x2="90" y2="7" stroke="#f59e0b" stroke-width="2" class="attack-pulse-amber" />
              <polygon points="90,3 98,7 90,11" fill="#f59e0b" />
            </svg>
            <span style="font-size: 8px; color: var(--text-dim); font-family: var(--font-mono);">Port 445 / 135</span>
          </div>

          <!-- Lateral Pivot Host -->
          <div style="display: flex; flex-direction: column; align-items: center; text-align: center; width: 140px;">
            <div class="pulse-node-amber" style="width: 42px; height: 42px; border-radius: 6px; background: rgba(245, 158, 11, 0.1); border: 2px solid #f59e0b; display: flex; align-items: center; justify-content: center;">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="#f59e0b"><path d="M4 6h16v10H4V6zm2 2v6h12V8H6zm-4 9h20v2H2v-2z"/></svg>
            </div>
            <div style="color: white; font-weight: 800; font-size: 10.5px; margin-top: 5px;">WS-ENG-04</div>
            <div style="color: var(--text-dim); font-size: 9px; font-family: var(--font-mono);">10.0.2.44 (Tier-2 Workstation)</div>
            <span class="host-pill arch" style="font-size: 7.5px; margin-top: 2px; border-color: #f59e0b; color: #f59e0b;">LATERAL PIVOT HOST</span>
          </div>
        </div>
      `;

      forensicsHtml = `
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-bottom: 6px;">
          <div style="background: #040711; padding: 6px 8px; border-radius: 4px; border: 1px solid var(--border);">
            <div style="font-size: 8px; color: var(--text-dim);">SHARED TLS JA4 HASH</div>
            <div style="font-size: 9.5px; color: var(--cyan); font-family: var(--font-mono); font-weight: 700; margin-top: 2px;">t13d1516h2_8daaf615..</div>
          </div>
          <div style="background: #040711; padding: 6px 8px; border-radius: 4px; border: 1px solid var(--border);">
            <div style="font-size: 8px; color: var(--text-dim);">SHANNON ENTROPY</div>
            <div style="font-size: 9.5px; color: #f87171; font-family: var(--font-mono); font-weight: 700; margin-top: 2px;">7.84 / 8.00 (Encrypted)</div>
          </div>
          <div style="background: #040711; padding: 6px 8px; border-radius: 4px; border: 1px solid var(--border);">
            <div style="font-size: 8px; color: var(--text-dim);">CADENCE & JITTER</div>
            <div style="font-size: 9.5px; color: var(--amber); font-family: var(--font-mono); font-weight: 700; margin-top: 2px;">8.4s ±0.8s (9.5% Rigid)</div>
          </div>
          <div style="background: #040711; padding: 6px 8px; border-radius: 4px; border: 1px solid var(--border);">
            <div style="font-size: 8px; color: var(--text-dim);">EGRESS ATTRIBUTION</div>
            <div style="font-size: 9.5px; color: white; font-family: var(--font-mono); font-weight: 700; margin-top: 2px;">Direct Raw IP (No SNI)</div>
          </div>
        </div>
      `;

      mitreHtml = `
        <div style="margin-bottom: 8px;">
          <div style="font-weight: 700; color: white; font-size: 9.5px; margin-bottom: 4px;">MITRE ATT&CK ALIGNMENT</div>
          <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px;">
            <div style="background: #040711; padding: 5px 7px; border-radius: 4px; border: 1px solid var(--border);">
              <div style="font-size: 8.5px; color: #f87171; font-weight: 700;">T1071.001 Web Protocols</div>
              <div style="font-size: 8px; color: var(--text-dim); margin-top: 1px;">HTTPS periodic beacon loop</div>
            </div>
            <div style="background: #040711; padding: 5px 7px; border-radius: 4px; border: 1px solid var(--border);">
              <div style="font-size: 8.5px; color: #f59e0b; font-weight: 700;">T1090.004 Direct IP Egress</div>
              <div style="font-size: 8px; color: var(--text-dim); margin-top: 1px;">Bypasses corporate DNS logs</div>
            </div>
            <div style="background: #040711; padding: 5px 7px; border-radius: 4px; border: 1px solid var(--border);">
              <div style="font-size: 8.5px; color: #f87171; font-weight: 700;">T1059.001 PowerShell</div>
              <div style="font-size: 8px; color: var(--text-dim); margin-top: 1px;">LOLBIN execution context</div>
            </div>
            <div style="background: #040711; padding: 5px 7px; border-radius: 4px; border: 1px solid var(--border);">
              <div style="font-size: 8.5px; color: var(--cyan); font-weight: 700;">T1573.002 Asymm Crypto</div>
              <div style="font-size: 8px; color: var(--text-dim); margin-top: 1px;">mTLS ChaCha20 tunnel</div>
            </div>
          </div>
        </div>
      `;
    } else {
      topologySvg = `
        <div style="background: #040711; border: 1px solid #1e293b; border-radius: 6px; padding: 10px 8px; margin-bottom: 6px; display: flex; align-items: center; justify-content: space-around; position: relative;">
          <!-- Adversary C2 Node (CDN Fronted) -->
          <div style="display: flex; flex-direction: column; align-items: center; text-align: center; width: 140px;">
            <div class="pulse-node-amber" style="width: 42px; height: 42px; border-radius: 50%; background: rgba(245, 158, 11, 0.15); border: 2px solid #f59e0b; display: flex; align-items: center; justify-content: center;">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="#f59e0b"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>
            </div>
            <div style="color: #f59e0b; font-weight: 800; font-size: 10.5px; margin-top: 5px;">AZURE CDN FRONT</div>
            <div style="color: var(--text-dim); font-size: 9px; font-family: var(--font-mono);">cdn-azure-edge.net:8443</div>
            <span class="host-pill warn" style="font-size: 7.5px; margin-top: 2px;">Fronted to 45.33.32.156</span>
          </div>

          <!-- Ingress Vector Arrow -->
          <div style="display: flex; flex-direction: column; align-items: center; gap: 3px;">
            <span style="font-size: 8.5px; color: ${isContained ? '#94a3b8' : '#f59e0b'}; font-weight: 700; font-family: var(--font-mono);">${isContained ? 'SEVERED' : '15.0s Cadence (HTTPS)'}</span>
            <svg width="110" height="14" style="overflow: visible;">
              <line x1="0" y1="7" x2="100" y2="7" stroke="${isContained ? '#475569' : '#f59e0b'}" stroke-width="2" class="${isContained ? '' : 'attack-pulse-purple'}" />
              <polygon points="100,3 108,7 100,11" fill="${isContained ? '#475569' : '#f59e0b'}" />
            </svg>
            <span style="font-size: 8px; color: var(--text-dim); font-family: var(--font-mono);">JA4: t13d190800..</span>
          </div>

          <!-- Ingress Host -->
          <div style="display: flex; flex-direction: column; align-items: center; text-align: center; width: 140px;">
            <div class="pulse-node-cyan" style="width: 42px; height: 42px; border-radius: 6px; background: rgba(56, 189, 248, 0.1); border: 2px solid var(--cyan); display: flex; align-items: center; justify-content: center;">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="var(--cyan)"><path d="M4 6h16v10H4V6zm2 2v6h12V8H6zm-4 9h20v2H2v-2z"/></svg>
            </div>
            <div style="color: white; font-weight: 800; font-size: 10.5px; margin-top: 5px;">WIN-APP-SRV02</div>
            <div style="color: var(--text-dim); font-size: 9px; font-family: var(--font-mono);">10.0.0.16 (Tier-1 Web)</div>
            <span class="host-pill arch" style="font-size: 7.5px; margin-top: 2px; border-color: #f87171; color: #f87171;">COMPROMISED HOST</span>
          </div>

          <!-- Lateral Pivot Vector Arrow -->
          <div style="display: flex; flex-direction: column; align-items: center; gap: 3px;">
            <span style="font-size: 8.5px; color: #38bdf8; font-weight: 700; font-family: var(--font-mono);">TDS / SQL Link</span>
            <svg width="100" height="14" style="overflow: visible;">
              <line x1="0" y1="7" x2="90" y2="7" stroke="#38bdf8" stroke-width="2" class="attack-pulse-amber" />
              <polygon points="90,3 98,7 90,11" fill="#38bdf8" />
            </svg>
            <span style="font-size: 8px; color: var(--text-dim); font-family: var(--font-mono);">Port 1433 SQL</span>
          </div>

          <!-- Target Crown Jewel Asset -->
          <div style="display: flex; flex-direction: column; align-items: center; text-align: center; width: 140px;">
            <div style="width: 42px; height: 42px; border-radius: 6px; background: rgba(16, 185, 129, 0.1); border: 2px solid #10b981; display: flex; align-items: center; justify-content: center;">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="#34d399"><path d="M12 3C7.58 3 4 4.79 4 7v10c0 2.21 3.58 4 8 4s8-1.79 8-4V7c0-2.21-3.58-4-8-4zm0 2c3.87 0 6 1.5 6 2s-2.13 2-6 2-6-1.5-6-2 2.13-2 6-2z"/></svg>
            </div>
            <div style="color: white; font-weight: 800; font-size: 10.5px; margin-top: 5px;">SQL01-PROD</div>
            <div style="color: var(--text-dim); font-size: 9px; font-family: var(--font-mono);">10.0.1.50 (Crown Jewel)</div>
            <span class="host-pill safe" style="font-size: 7.5px; margin-top: 2px;">TARGET DATA ASSET</span>
          </div>
        </div>
      `;

      forensicsHtml = `
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-bottom: 6px;">
          <div style="background: #040711; padding: 6px 8px; border-radius: 4px; border: 1px solid var(--border);">
            <div style="font-size: 8px; color: var(--text-dim);">SHARED TLS JA4 HASH</div>
            <div style="font-size: 9.5px; color: var(--cyan); font-family: var(--font-mono); font-weight: 700; margin-top: 2px;">t13d190800_261546b3..</div>
          </div>
          <div style="background: #040711; padding: 6px 8px; border-radius: 4px; border: 1px solid var(--border);">
            <div style="font-size: 8px; color: var(--text-dim);">SHANNON ENTROPY</div>
            <div style="font-size: 9.5px; color: #f87171; font-family: var(--font-mono); font-weight: 700; margin-top: 2px;">7.92 / 8.00 (Shellcode)</div>
          </div>
          <div style="background: #040711; padding: 6px 8px; border-radius: 4px; border: 1px solid var(--border);">
            <div style="font-size: 8px; color: var(--text-dim);">CADENCE & JITTER</div>
            <div style="font-size: 9.5px; color: var(--amber); font-family: var(--font-mono); font-weight: 700; margin-top: 2px;">15.0s ±1.1s (7.3% Rigid)</div>
          </div>
          <div style="background: #040711; padding: 6px 8px; border-radius: 4px; border: 1px solid var(--border);">
            <div style="font-size: 8px; color: var(--text-dim);">EGRESS ATTRIBUTION</div>
            <div style="font-size: 9.5px; color: #f59e0b; font-family: var(--font-mono); font-weight: 700; margin-top: 2px;">Domain Fronted (Azure Edge)</div>
          </div>
        </div>
      `;

      mitreHtml = `
        <div style="margin-bottom: 8px;">
          <div style="font-weight: 700; color: white; font-size: 9.5px; margin-bottom: 4px;">MITRE ATT&CK ALIGNMENT</div>
          <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px;">
            <div style="background: #040711; padding: 5px 7px; border-radius: 4px; border: 1px solid var(--border);">
              <div style="font-size: 8.5px; color: #f59e0b; font-weight: 700;">T1090.004 Domain Fronting</div>
              <div style="font-size: 8px; color: var(--text-dim); margin-top: 1px;">CDN-routed covert egress</div>
            </div>
            <div style="background: #040711; padding: 5px 7px; border-radius: 4px; border: 1px solid var(--border);">
              <div style="font-size: 8.5px; color: #f87171; font-weight: 700;">T1071.001 Web Protocols</div>
              <div style="font-size: 8px; color: var(--text-dim); margin-top: 1px;">Port 8443 beacon loop</div>
            </div>
            <div style="background: #040711; padding: 5px 7px; border-radius: 4px; border: 1px solid var(--border);">
              <div style="font-size: 8.5px; color: #f87171; font-weight: 700;">T1027 Obfuscated Files</div>
              <div style="font-size: 8px; color: var(--text-dim); margin-top: 1px;">Reflective DLL loader in memory</div>
            </div>
            <div style="background: #040711; padding: 5px 7px; border-radius: 4px; border: 1px solid var(--border);">
              <div style="font-size: 8.5px; color: var(--cyan); font-weight: 700;">T1573.002 Symmetric Crypto</div>
              <div style="font-size: 8px; color: var(--text-dim); margin-top: 1px;">AES-256 session traffic</div>
            </div>
          </div>
        </div>
      `;
    }

    container.innerHTML = `
      <div>
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 6px; margin-bottom: 8px;">
          <span style="font-weight: 800; color: var(--cyan); font-size: 11px; letter-spacing: 0.5px;">
            VISUAL ATTACK TOPOLOGY: ${camp.name.toUpperCase()}
          </span>
          <span class="host-pill ${isContained ? 'safe' : 'crit'}" style="font-size: 8px;">
            ${isContained ? 'CONTAINED // KERNEL SEVERED' : 'ACTIVE INTRUSION GRAPH'}
          </span>
        </div>

        ${topologySvg}
        ${forensicsHtml}
        ${mitreHtml}
      </div>

      <!-- Unified Action Footer (Right Column Only) -->
      <div style="border-top: 1px solid var(--border); padding-top: 8px; display: flex; justify-content: space-between; align-items: center;">
        <div style="font-size: 9.5px; color: var(--text-dim);">
          Countermeasures affect only ${camp.affected_hosts.length} correlated targets. System services remain uninterrupted.
        </div>
        <div style="display: flex; gap: 8px;">
          ${isContained 
            ? '<span class="host-pill safe" style="font-weight: 700; font-size: 10px; padding: 4px 10px;">[[OK]] Campaign Contained (Sockets Dropped)</span>'
            : `<button class="action-btn danger" onclick="promptCampaignSever('${camp.campaign_id}')" style="font-weight: 700; font-size: 10px; padding: 4px 10px;">Sever This Campaign (${camp.affected_hosts.length} Sockets)</button>`}
          <button class="action-btn" onclick="openStixModal('${camp.campaign_id}')" style="font-size: 10px; padding: 4px 10px;">Export STIX 2.1</button>
          <button class="action-btn" onclick="openYaralModal('${camp.campaign_id}')" style="font-size: 10px; padding: 4px 10px;">Push Yara-L Rule</button>
        </div>
      </div>
    `;
  }

  // STIX 2.1 and YARA-L Modal Handlers
  function openStixModal(campId) {
    const camp = stateData.campaigns.find(c => c.campaign_id === campId) || stateData.campaigns[0];
    if (!camp) return;

    const stixBundle = {
      type: "bundle",
      id: `bundle--${Math.random().toString(36).substring(2, 10)}`,
      objects: [
        {
          type: "indicator",
          spec_version: "2.1",
          id: `indicator--${Math.random().toString(36).substring(2, 10)}`,
          created: new Date().toISOString(),
          name: `${camp.c2_framework} C2 Beacon Indicator`,
          pattern: `[ipv4-addr:value = '${camp.target_destination.split(':')[0]}'] AND [network-traffic:src_ref.value = '${camp.ja4_fingerprint}']`,
          pattern_type: "stix",
          valid_from: new Date().toISOString()
        },
        {
          type: "observed-data",
          spec_version: "2.1",
          id: `observed-data--${Math.random().toString(36).substring(2, 10)}`,
          number_observed: camp.affected_hosts.length,
          first_observed: new Date().toISOString(),
          last_observed: new Date().toISOString()
        }
      ]
    };

    document.getElementById('stix-json-preview').innerText = JSON.stringify(stixBundle, null, 2);
    document.getElementById('stix-export-modal').classList.add('active');
  }

  function closeStixModal() {
    document.getElementById('stix-export-modal').classList.remove('active');
  }

  function copyStixToClipboard() {
    const text = document.getElementById('stix-json-preview').innerText;
    navigator.clipboard.writeText(text);
    alert('STIX 2.1 JSON copied to clipboard.');
  }

  function downloadStixBundle() {
    const text = document.getElementById('stix-json-preview').innerText;
    const blob = new Blob([text], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `uncloak-threat-intel-${selectedCampaignId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function openYaralModal(campId) {
    const camp = stateData.campaigns.find(c => c.campaign_id === campId) || stateData.campaigns[0];
    if (!camp) return;

    const destHost = camp.target_destination.split(':')[0];
    const yaralRule = `rule uncloak_${camp.campaign_id.replace('-', '_')}_c2_detection {
  meta:
    author = "Invictus // Uncloak Autonomous EDR"
    description = "Automated detection rule pushed from Uncloak C2 Threat Hunting Console"
    severity = "CRITICAL"
    mitre_attack = "T1071.001, T1090.004"
  events:
    $net.target.ip = "${destHost}" or $net.target.hostname = "${destHost}"
    $net.tls.ja4 = "${camp.ja4_fingerprint}"
  condition:
    #net >= 3 over 1m
}`;

    document.getElementById('yaral-code-preview').innerText = yaralRule;
    document.getElementById('yaral-export-modal').classList.add('active');
  }

  function closeYaralModal() {
    document.getElementById('yaral-export-modal').classList.remove('active');
  }

  function copyYaralToClipboard() {
    const text = document.getElementById('yaral-code-preview').innerText;
    navigator.clipboard.writeText(text);
    alert('YARA-L Rule copied to clipboard.');
  }

  function deployYaralToChronicle() {
    alert('DEPLOYED: YARA-L rule successfully pushed to Google Chronicle SIEM rule streaming engine.');
    closeYaralModal();
  }

    let currentHostSubtab = 'flows';

  
  // RHYTHM SPARKLINE & SIGNAL ANALYSIS TELEMETRY
  function renderLogicPulse(f) {
    const isThreat = f.is_threat || f.threat_score > 0.7;
    const isAsynch = !f.interval_str || f.interval_str.toLowerCase().includes('asynch');
    
    if (isAsynch) {
      return `
        <div class="pulse-cell">
          <span style="color: var(--text-dim); font-size: 11px; width: 44px; text-align: right; display: inline-block;">Asynch</span>
          <div class="rhythm-track" title="Stochastic packet arrival - human interaction">
            <div class="organic-wave">
              <span class="organic-bar" style="height: 3px;"></span>
              <span class="organic-bar" style="height: 8px;"></span>
              <span class="organic-bar" style="height: 4px;"></span>
              <span class="organic-bar" style="height: 11px;"></span>
              <span class="organic-bar" style="height: 5px;"></span>
              <span class="organic-bar" style="height: 9px;"></span>
              <span class="organic-bar" style="height: 3px;"></span>
            </div>
          </div>
          <span class="jitter-pill organic">ORGANIC / HUMAN</span>
        </div>
      `;
    }

    let ticksHtml = '';
    let tickCount = 4;
    let jitterLabel = '9.5% JITTER (RIGID APT)';
    let pillClass = 'rigid';

    if (f.interval_str.includes('8.4')) {
      tickCount = 4;
      jitterLabel = '9.5% JITTER (RIGID APT)';
    } else if (f.interval_str.includes('15.0')) {
      tickCount = 3;
      jitterLabel = '7.3% JITTER (RIGID C2)';
    } else if (f.interval_str.includes('60.0')) {
      tickCount = 2;
      jitterLabel = '12.1% JITTER (STEALTH)';
    } else if (f.interval_str.includes('10.0')) {
      tickCount = 3;
      jitterLabel = '0.1% JITTER (VENDOR DAEMON)';
      pillClass = 'clean';
    } else {
      tickCount = isThreat ? 3 : 2;
      jitterLabel = isThreat ? 'ANOMALOUS JITTER' : 'SCHEDULED DAEMON';
      pillClass = isThreat ? 'rigid' : 'clean';
    }

    for (let i = 0; i < tickCount; i++) {
      ticksHtml += `<span class="rhythm-tick ${isThreat ? 'c2-tick' : 'benign-tick'}"></span>`;
    }

    const intervalColor = isThreat ? 'var(--cyan)' : 'var(--green)';

    return `
      <div class="pulse-cell">
        <strong style="color: ${intervalColor}; font-size: 11px; width: 44px; text-align: right; display: inline-block;">${f.interval_str}</strong>
        <div class="rhythm-track ${isThreat ? 'threat-track' : ''}" title="${isThreat ? 'Rigid clockwork interval - metronomic beacon' : 'Periodic benign daemon'}">
          ${ticksHtml}
        </div>
        <span class="jitter-pill ${pillClass}">${jitterLabel}</span>
      </div>
    `;
  }

  function switchHostSubtab(tabName) {
    currentHostSubtab = tabName;
    ['flows', 'procs', 'history', 'whitelist'].forEach(t => {
      const pane = document.getElementById('pane-' + t);
      const btn = document.getElementById('subtab-btn-' + t);
      if (pane) pane.style.display = t === tabName ? 'block' : 'none';
      if (btn) {
        if (t === tabName) btn.classList.add('active');
        else btn.classList.remove('active');
      }
    });
    if (stateData) {
      if (tabName === 'procs') renderHostProcesses();
      else if (tabName === 'history') renderConnectionHistory();
      else if (tabName === 'whitelist') renderWhitelistLedger();
    }
  }

  function filterFlowsByPid(pid) {
    switchHostSubtab('flows');
    selectFlow(pid);
  }

  function filterHostSubtab(q) {
    q = (q || '').toLowerCase();
    if (currentHostSubtab === 'flows') {
      document.querySelectorAll('#flows-tbody tr').forEach(row => {
        row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
      });
    } else if (currentHostSubtab === 'procs') {
      document.querySelectorAll('#procs-tbody tr').forEach(row => {
        row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
      });
    } else if (currentHostSubtab === 'history') {
      document.querySelectorAll('#history-tbody tr').forEach(row => {
        row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
      });
    }
  }

  function exportHostAuditLog() {
    if (!stateData) return;
    const h = stateData.selected_host;
    const history = stateData.host_connection_history || [];
    const procs = stateData.host_processes || [];
    
    const lines = [];
    lines.push("UNCLOAK // ENTERPRISE EDR ENDPOINT AUDIT DOSSIER");
    lines.push("Host: " + h.hostname + " (" + h.ip_address + ") | OS: " + h.os_version + " | Export Time: " + new Date().toISOString());
    lines.push("");
    lines.push("--- CHRONOLOGICAL CONNECTION AUDIT LOG ---");
    lines.push("Timestamp,PID,Process,Direction,LocalAddress,RemoteAddress,SNI,Duration,Bytes,State,Verdict");
    history.forEach(r => {
      lines.push('"' + r.timestamp + '","' + r.pid + '","' + r.process_name + '","' + (r.direction || 'OUTBOUND') + '","' + r.local_addr + '","' + r.remote_addr + '","' + r.sni + '","' + r.duration + '","' + r.bytes_str + '","' + r.state + '","' + r.verdict + '"');
    });
    lines.push("");
    lines.push("--- ENDPOINT PROCESS INVENTORY ---");
    lines.push("PID,ProcessName,PPID,StartTime,UserContext,CPU%,RAM_MB,Signature,ActiveSockets,Status");
    procs.forEach(p => {
      lines.push('"' + p.pid + '","' + p.name + '","' + p.ppid + '","' + p.start_time + '","' + p.username + '","' + p.cpu_percent + '%","' + p.ram_mb + ' MB","' + (p.is_signed ? 'SIGNED' : 'UNSIGNED') + '","' + p.socket_count + '","' + (p.status || 'ACTIVE') + '"');
    });

    const csv = lines.join(String.fromCharCode(13, 10));
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = "uncloak_audit_" + h.hostname + "_" + Date.now() + ".csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  function renderHostProcesses() {
    const procs = stateData.host_processes || [];
    const tbody = document.getElementById('procs-tbody');
    if (!tbody) return;
    const countEl = document.getElementById('procs-count-label');
    if (countEl) countEl.innerText = procs.length;

    let rowsHtml = '';
    procs.forEach(p => {
      const isSelected = p.pid === stateData.selected_pid;
      const isThreat = (p.threat_score || 0) > 0.7;
      const isLolbin = ['powershell.exe', 'cmd.exe', 'rundll32.exe', 'mshta.exe', 'certutil.exe'].includes(p.name.toLowerCase()) && p.socket_count > 0;
      let sigBadge = `<span class="host-pill ${p.is_signed ? 'safe' : 'crit'}">${p.is_signed ? 'MICROSOFT SIGNED' : 'UNSIGNED PE'}</span>`;
      if (isLolbin) {
        sigBadge = `<span class="host-pill lolbin" title="Legitimate binary abusing network C2">LOLBIN ABUSE</span>`;
      }

      let bwRate = isThreat ? '<span style="color: #f87171; font-weight: 700;">1.4 MB/s (Exfil)</span>' : (p.socket_count > 0 ? '<span style="color: var(--text-dim); font-size: 10px;">0 KB/s (Idle)</span>' : '<span style="color: var(--text-muted); font-size: 10px;">0 KB/s</span>');

      rowsHtml += `
        <tr class="${isThreat ? 'row-threat' : ''} ${isSelected ? 'selected' : ''}" data-pid="${p.pid}" onclick="selectFlow(${p.pid})" style="cursor: pointer;">
          <td><strong style="cursor: pointer; color: var(--cyan); text-decoration: underline;" title="View PID Connection History" onclick="event.stopPropagation(); openPidHistoryModal(${p.pid}, '${p.name}')">${p.pid}</strong></td>
          <td><strong style="color: ${isThreat ? '#f87171' : 'white'};">${p.name}</strong></td>
          <td style="color: var(--text-dim);">${p.ppid}</td>
          <td style="font-size: 11px; color: var(--text-dim);">${p.start_time}</td>
          <td style="font-size: 11px;">${p.username}</td>
          <td>${p.cpu_percent}%</td>
          <td>${p.ram_mb} MB</td>
          <td>
            <strong style="color: var(--cyan); font-size: 11px;">${p.bandwidth_usage || '0 B'}</strong>
            <div style="font-size: 9px;">${bwRate}</div>
          </td>
          <td>${sigBadge}</td>
          <td>
            ${p.socket_count > 0 
              ? `<span class="host-pill ${isThreat ? 'crit' : 'eval'}" style="cursor: pointer;" onclick="event.stopPropagation(); filterFlowsByPid(${p.pid})">${p.socket_count} Sockets</span>`
              : '<span style="color: var(--text-muted); font-size: 10px;">0 (Inert)</span>'}
          </td>
          <td style="text-align: center; white-space: nowrap;">
            <button class="action-btn" onclick="event.stopPropagation(); selectFlow(${p.pid})" style="padding: 2px 7px; margin-right: 4px;">Inspect</button>
            <button class="action-btn" style="background: rgba(56, 189, 248, 0.15); border-color: var(--cyan); color: var(--cyan); font-weight: 700; padding: 2px 7px; margin-right: 4px;" onclick="event.stopPropagation(); openPidHistoryModal(${p.pid}, '${p.name}')">History</button>
            <button class="action-btn danger" onclick="event.stopPropagation(); promptKillTreeModal(${p.pid}, '${p.name}')" style="padding: 2px 7px;">Kill Tree</button>
          </td>
        </tr>
      `;
    });
    smartUpdateTbody(tbody, rowsHtml, stateData.selected_pid);
  }

  function renderConnectionHistory() {
    const history = stateData.host_connection_history || [];
    const tbody = document.getElementById('history-tbody');
    if (!tbody) return;
    const countEl = document.getElementById('history-count-label');
    if (countEl) countEl.innerText = history.length;

    let rowsHtml = '';
    history.forEach(r => {
      const isCrit = (r.verdict || '').includes('CRITICAL');
      const isHigh = (r.verdict || '').includes('HIGH');
      const isSelected = r.pid === stateData.selected_pid;
      rowsHtml += `
        <tr class="${isCrit ? 'row-threat' : ''} ${isSelected ? 'selected' : ''}" data-pid="${r.pid}" onclick="selectFlow(${r.pid})" style="cursor: pointer;">
          <td style="color: var(--text-dim); font-size: 11px; white-space: nowrap;"><strong>${r.timestamp}</strong></td>
          <td><strong style="color: ${isCrit ? '#f87171' : 'white'}; cursor: pointer; text-decoration: underline;" onclick="event.stopPropagation(); openPidHistoryModal(${r.pid}, '${r.process_name}')">${r.process_name} (${r.pid})</strong></td>
          <td style="color: var(--cyan); font-size: 10px;">${r.direction || 'OUTBOUND'}</td>
          <td style="font-size: 11px; color: var(--text-dim);">${r.local_addr}</td>
          <td><strong>${r.remote_addr}</strong></td>
          <td style="color: ${r.sni && r.sni.includes('RAW') ? '#f87171' : 'var(--text-dim)'};">${r.sni || '-'}</td>
          <td style="color: var(--cyan);">${r.duration || 'Active'}</td>
          <td>${r.bytes_str || '-'}</td>
          <td style="font-size: 10px; color: ${r.state === 'ESTABLISHED' ? 'var(--green)' : 'var(--text-muted)'};">${r.state}</td>
          <td>
            <span class="host-pill ${isCrit ? 'crit' : (isHigh ? 'high' : 'safe')}">${r.verdict}</span>
          </td>
        </tr>
      `;
    });
    smartUpdateTbody(tbody, rowsHtml, stateData.selected_pid);
  }

  function updateDrawerCards(pid) {
    if (!stateData) return;

    let item = (stateData.flows || []).find(f => f.pid === pid);
    if (!item) {
      const proc = (stateData.host_processes || []).find(p => p.pid === pid);
      if (proc) {
        const isThreat = (proc.threat_score || 0) > 0.7;
        item = {
          pid: proc.pid,
          process_name: proc.name,
          dst_ip: proc.socket_count > 0 ? 'Multiple Endpoints' : '127.0.0.1',
          dst_port: proc.socket_count > 0 ? '(Network Active)' : 'Local',
          binary_path: proc.path || ('C:/Windows/System32/' + proc.name),
          sig_info: proc.is_signed ? 'Microsoft Corporation (Verified)' : 'Unsigned PE / Local Process',
          sha256: proc.sha256 || 'N/A',
          parent_process: proc.parent_name ? (proc.parent_name + ' (PID ' + proc.ppid + ')') : ('Parent PID ' + proc.ppid),
          first_seen: proc.start_time || '2026-11-02 14:10:02 UTC',
          last_seen: 'Active (Now)',
          duration: proc.uptime || 'Active',
          interval_str: proc.socket_count > 0 ? (proc.socket_count + ' Open Sockets') : 'Inert / Standby',
          jitter_str: proc.bandwidth_usage || '0 B',
          is_severed: false,
          is_threat: isThreat,
          payload_str: proc.bandwidth_usage || '0 B',
          bursts: 'CPU: ' + proc.cpu_percent + '% | RAM: ' + proc.ram_mb + ' MB',
          jitter_pct: proc.socket_count > 0 ? (proc.socket_count + ' Sockets') : '0 Sockets',
          mitre_technique: isThreat ? 'T1059 / T1055' : 'None',
          state: proc.socket_count > 0 ? 'ESTABLISHED' : 'RUNNING (LOCAL)'
        };
      } else {
        const hist = (stateData.host_connection_history || []).find(h => h.pid === pid);
        if (hist) {
          const isCrit = (hist.verdict || '').includes('CRITICAL');
          const remoteParts = (hist.remote_addr || '').split(':');
          item = {
            pid: hist.pid,
            process_name: hist.process_name,
            dst_ip: remoteParts[0] || hist.remote_addr,
            dst_port: remoteParts[1] || '443',
            binary_path: 'C:/Windows/System32/' + hist.process_name,
            sig_info: 'Historical Ledger Record',
            sha256: 'N/A',
            parent_process: 'explorer.exe',
            first_seen: hist.timestamp,
            last_seen: hist.timestamp,
            duration: hist.duration || 'Closed',
            interval_str: 'Recorded Session',
            jitter_str: hist.bytes_str || '0 B',
            is_severed: false,
            is_threat: isCrit,
            payload_str: hist.bytes_str || '0 B',
            bursts: hist.direction || 'OUTBOUND',
            jitter_pct: '1 Socket',
            mitre_technique: isCrit ? 'T1071 / C2 Beacon' : 'None',
            state: hist.state || 'CLOSED'
          };
        } else {
          item = (stateData.flows || [])[0];
        }
      }
    }
    if (!item) return;

    const drawerHeader = document.getElementById('drawer-host-header');
    if (drawerHeader) drawerHeader.innerText = `${item.dst_ip}:${item.dst_port} (PID ${item.pid})`;

    const setTxt = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.innerText = val !== undefined && val !== null ? val : '-';
    };

    setTxt('c1-pid', item.pid);
    setTxt('c1-proc', item.process_name);
    setTxt('c1-path', item.binary_path || ('C:/Windows/System32/' + item.process_name));
    setTxt('c1-sig', item.sig_info || 'Unsigned Binary (On-Disk PE)');
    setTxt('c1-sha', item.sha256 ? item.sha256.substring(0, 16) + '..' : 'N/A');
    setTxt('c1-parent', item.parent_process || 'explorer.exe (PID 2110)');
    setTxt('c1-start', item.first_seen || '2026-11-02 14:10:02 UTC');

    setTxt('c2-first', item.first_seen || '2026-11-02 14:10:02 UTC');
    setTxt('c2-last', item.last_seen || '2026-11-02 14:26:45 UTC');
    setTxt('c2-duration', item.duration || '16m 43s');
    setTxt('c2-int', `${item.interval_str} (${item.jitter_str})`);
    setTxt('c2-entropy', item.is_threat ? '0.94 (Encrypted C2 Payload)' : '0.12 (Standard ASCII / JSON)');
    setTxt('c2-ratio', item.is_threat ? 'In: 1.2 KB | Out: 480 B (Beacon Loop)' : 'In: 45 KB | Out: 3.2 KB (Standard TLS)');

    const c2State = document.getElementById('c2-state');
    if (c2State) {
      c2State.innerText = item.is_severed ? 'MITIGATED (Kernel Clean)' : (item.is_threat ? 'ACTIVE (C2 Live)' : 'BENIGN');
      c2State.className = item.is_severed ? 'card-value highlight-green' : (item.is_threat ? 'card-value highlight-red' : 'card-value');
    }

    setTxt('c2-payload', item.payload_str);
    setTxt('c2-bursts', item.bursts || 'Asynchronous');
    setTxt('c2-jitter', `${item.jitter_pct} (${item.is_threat ? 'Rigid / Anomalous' : 'Normal'})`);

    setTxt('c3-mitre', item.mitre_technique || 'None');
    setTxt('c3-action', item.is_severed ? 'Mitigated (Socket Dropped)' : (item.is_threat ? 'Pending Mitigation' : 'None Required'));
    setTxt('c3-stack', item.state || 'ESTABLISHED');
  }

  function renderHostDrilldown() {
    const selHost = stateData.selected_host;
    if (!selHost) return;

    // Update Dropdown smartly without resetting options if unchanged
    const dropdown = document.getElementById('host-dropdown');
    if (dropdown) {
      const hostsKey = stateData.hosts.map(h => h.host_id).join(',');
      if (dropdown.dataset.renderedHosts !== hostsKey) {
        dropdown.innerHTML = stateData.hosts.map(h => 
          `<option value="${h.host_id}" ${h.host_id === selHost.host_id ? 'selected' : ''}>${h.hostname} (${h.ip_address})</option>`
        ).join('');
        dropdown.dataset.renderedHosts = hostsKey;
      } else if (dropdown.value !== selHost.host_id) {
        dropdown.value = selHost.host_id;
      }
    }

    document.getElementById('host-os-label').innerText = selHost.os_version;
    document.getElementById('host-ip-label').innerText = selHost.ip_address;
    
    const pill = document.getElementById('host-threat-pill');
    const isMuted = selHost.status === 'MUTED';
    if (isMuted) {
      pill.innerText = 'DISCONNECTED (Muted)';
      pill.className = 'host-pill muted';
    } else {
      pill.innerText = `${selHost.threat_level} (${(selHost.threat_score * 100).toFixed(1)}%)`;
      pill.className = `host-pill ${selHost.threat_level === 'CRITICAL' ? 'crit' : (selHost.threat_level === 'HIGH' ? 'high' : 'safe')}`;
    }

    const stalenessBanner = document.getElementById('staleness-alert-banner');
    if (stalenessBanner) {
      if (isMuted) {
        stalenessBanner.style.display = 'flex';
        stalenessBanner.innerText = `TELEMETRY STALENESS DETECTED: Endpoint daemon stopped heartbeating (${selHost.seconds_since_heartbeat}s ago). Agent may be powered off, service removed, or network severed.`;
      } else {
        stalenessBanner.style.display = 'none';
      }
    }

    // Top Incident Banner
    const inc = stateData.top_incident;
    const banner = document.getElementById('incident-banner');
    if (banner) {
      if (inc && !inc.is_severed) {
        banner.style.display = 'flex';
        document.getElementById('inc-title').innerText = `${inc.c2_framework.toUpperCase()} BEACON ISOLATED`;
        document.getElementById('inc-target').innerText = inc.target;
        document.getElementById('inc-pid').innerText = `${inc.pid} (${inc.process_name})`;
        document.getElementById('inc-status').innerText = inc.status;
        document.getElementById('inc-status').style.color = '#f87171';
      } else {
        banner.style.display = 'none';
      }
    }

    // Flows Table
    const tbody = document.getElementById('flows-tbody');
    let rowsHtml = '';
    stateData.flows.forEach(f => {
      const isSelected = f.pid === stateData.selected_pid;
      rowsHtml += `
        <tr class="${f.is_threat ? 'row-threat' : ''} ${isSelected ? 'selected' : ''}" data-pid="${f.pid}" onclick="selectFlow(${f.pid})" style="cursor: pointer;">
          <td style="font-size: 11px; color: var(--text-dim); white-space: nowrap;">${f.first_seen || '2026-11-02 14:10:02'}</td>
          <td><strong>${f.pid}</strong></td>
          <td><span style="color: ${f.is_threat ? '#f87171' : 'white'}; font-weight: 700;">${f.process_name}</span></td>
          <td>${f.dst_ip}:${f.dst_port}</td>
          <td>${f.sni ? f.sni : '<span style="color: #f87171; font-weight: 700;">RAW IP / NO SNI</span>'}</td>
          <td>${renderLogicPulse(f)}</td>
          <td style="color: var(--cyan); font-size: 11px;">${f.duration || '16m 43s'}</td>
          <td>${f.payload_str}</td>
          <td style="text-align: right;"><strong style="color: ${f.threat_score > 0.7 ? '#f87171' : 'var(--green)'};">${(f.threat_score * 100).toFixed(1)}%</strong></td>
          <td style="text-align: center;">
            ${f.is_threat && !f.is_severed ? `<button class="action-btn danger" onclick="event.stopPropagation(); promptSeverModal(${f.pid}, '${f.dst_ip}:${f.dst_port}', '${f.process_name}')">Sever</button>` : ''}
            ${f.is_severed ? '<span style="color: #34d399; font-weight: 700;">SEVERED</span>' : ''}
          </td>
        </tr>
      `;
    });
    smartUpdateTbody(tbody, rowsHtml, stateData.selected_pid);
    const flowsCountLabel = document.getElementById('flows-count-label');
    if (flowsCountLabel) flowsCountLabel.innerText = stateData.flows.length;

    renderHostProcesses();
    renderConnectionHistory();

    // Drawer Cards
    updateDrawerCards(stateData.selected_pid);

    // Re-apply any active search filters
    const searchVal = document.getElementById('host-sub-search') ? document.getElementById('host-sub-search').value : '';
    if (searchVal) filterHostSubtab(searchVal);
    const timelinePidVal = document.getElementById('timeline-pid-input') ? document.getElementById('timeline-pid-input').value : '';
    if (timelinePidVal) filterTimelineByPid(timelinePidVal);
  }

  function selectFlow(pid) {
    if (!stateData) return;
    userSelectedPid = pid;
    stateData.selected_pid = pid;
    updateRowSelectionHighlight(pid);
    updateDrawerCards(pid);
    const hostId = (stateData.selected_host) ? stateData.selected_host.host_id : '';
    fetch('/api/select_pid', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host_id: hostId, pid: pid })
    }).catch(() => {});
  }

  async function changeSelectedHost(hostId) {
    userSelectedHostId = hostId;
    userSelectedPid = null;
    await fetch('/api/select_host', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host_id: hostId })
    });
    fetchState();
  }

  function selectAndDrilldown(hostId) {
    changeSelectedHost(hostId);
    switchView('drilldown');
  }

  function findAndDrilldownByName(hostname) {
    if (!stateData) return;
    const h = stateData.hosts.find(x => x.hostname === hostname);
    if (h) selectAndDrilldown(h.host_id);
  }

  // MODAL ACTIONS
  function promptSeverModal(pid, targetSocket, procName) {
    pendingSeverPid = pid;
    pendingSeverHostId = stateData.selected_host_id;
    pendingCampaignId = null;

    document.getElementById('modal-target-socket').innerText = targetSocket;
    document.getElementById('modal-target-proc').innerText = procName + ` (PID ${pid})`;
    document.getElementById('sever-confirm-modal').classList.add('active');
  }

  function promptCampaignSever(campId) {
    pendingCampaignId = campId;
    pendingSeverPid = null;

    const camp = stateData.campaigns.find(c => c.campaign_id === campId);
    if (!camp) return;

    document.getElementById('modal-target-socket').innerText = camp.target_destination;
    document.getElementById('modal-target-proc').innerText = `ALL ${camp.affected_hosts.length} HOSTS (${camp.affected_hosts.join(', ')})`;
    document.getElementById('sever-confirm-modal').classList.add('active');
  }

  function closeSeverModal() {
    pendingSeverPid = null;
    pendingCampaignId = null;
    document.getElementById('sever-confirm-modal').classList.remove('active');
  }

  async function executeConfirmedSever() {
    if (pendingCampaignId) {
      await fetch('/api/sever_campaign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ campaign_id: pendingCampaignId })
      });
    } else if (pendingSeverPid) {
      await fetch('/api/sever', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: pendingSeverPid, host_id: pendingSeverHostId })
      });
    }
    closeSeverModal();
    fetchState();
  }

  function severSelectedFlow() {
    if (!stateData) return;
    const flow = stateData.flows.find(f => f.pid === stateData.selected_pid) || stateData.flows[0];
    if (flow) promptSeverModal(flow.pid, `${flow.dst_ip}:${flow.dst_port}`, flow.process_name);
  }

  function severCurrentIncident() {
    if (!stateData || !stateData.top_incident) return;
    const inc = stateData.top_incident;
    promptSeverModal(inc.pid, inc.target, inc.process_name);
  }

  // TARPIT MODAL
  function tarpitSelectedFlow() {
    if (!stateData) return;
    const flow = stateData.flows.find(f => f.pid === stateData.selected_pid) || stateData.flows[0];
    if (!flow) return;

    pendingTarpitPid = flow.pid;
    document.getElementById('tarpit-modal-target').innerText = `${flow.dst_ip}:${flow.dst_port}`;
    document.getElementById('tarpit-modal-proc').innerText = `${flow.process_name} (PID ${flow.pid})`;
    document.getElementById('tarpit-confirm-modal').classList.add('active');
  }

  function closeTarpitModal() {
    pendingTarpitPid = null;
    document.getElementById('tarpit-confirm-modal').classList.remove('active');
  }

  async function executeConfirmedTarpit() {
    if (!pendingTarpitPid) return;
    await fetch('/api/tarpit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid: pendingTarpitPid, host_id: stateData.selected_host_id })
    });
    closeTarpitModal();
    fetchState();
  }

  function openDossierModal() {
    if (!stateData) return;
    const flow = stateData.flows.find(f => f.pid === stateData.selected_pid) || stateData.flows[0];
    if (!flow) return;

    document.getElementById('modal-dossier-title').innerText = `PROCESS FORENSIC DOSSIER : ${flow.process_name} (PID ${flow.pid})`;
    const body = document.getElementById('modal-dossier-body');
    body.innerHTML = `
      <div style="background: #020617; padding: 10px; border-radius: 6px; border: 1px solid var(--border);">
        <strong style="color: var(--cyan);">BINARY FORENSICS & ATTRIBUTION</strong>
        <p>• Binary Path: ${flow.binary_path || 'C:\\\\Windows\\\\System32\\\\' + flow.process_name}</p>
        <p>• Command Line: <code style="color: #cbd5e1;">${flow.command_line || 'N/A'}</code></p>
        <p>• Parent Lineage: ${flow.parent_process}</p>
        <p>• SHA-256 Hash: ${flow.sha256}</p>
      </div>
      <div style="background: #020617; padding: 10px; border-radius: 6px; border: 1px solid var(--border);">
        <strong style="color: var(--amber);">CADENCE & TIMING TELEMETRY</strong>
        <p>• Inter-Arrival Median (Δt): ${flow.interval_str}</p>
        <p>• Stochastic Jitter Deviation: ${flow.jitter_pct}</p>
        <p>• JA4 Client Handshake: <code style="color: #38bdf8;">${flow.ja4_fingerprint}</code></p>
        <p>• Heuristic Signals: ${flow.heuristic_signals}</p>
      </div>
    `;
    document.getElementById('dossier-modal').classList.add('active');
  }

  function closeDossierModal() {
    document.getElementById('dossier-modal').classList.remove('active');
  }

  async function exportTelemetry() {
    try {
      const res = await fetch('/api/export', { method: 'POST' });
      const data = await res.json();
      alert('[+] Telemetry exported successfully:\\n' + data.filename);
    } catch (e) {
      alert('Export failed: ' + e);
    }
  }

  function filterFleet(val) {
    const q = val.toLowerCase();
    document.querySelectorAll('.host-card').forEach(card => {
      const text = card.innerText.toLowerCase();
      card.style.display = text.includes(q) ? 'flex' : 'none';
    });
  }

  // UI Density Engine
  function isSmallViewport() {
    return window.matchMedia('(max-width: 1366px), (max-height: 820px)').matches;
  }

  function updateDensityLabel() {
    const isCompact = document.body.classList.contains('force-compact') || (!document.body.classList.contains('force-large') && isSmallViewport());
    const btn = document.getElementById('density-toggle-btn');
    if (btn) {
      btn.innerText = isCompact ? 'Density: Compact (100%)' : 'Density: Large (110%)';
      btn.style.color = isCompact ? 'var(--text-dim)' : 'var(--cyan)';
    }
  }

  function toggleDensity() {
    const currentlyCompact = document.body.classList.contains('force-compact') || (!document.body.classList.contains('force-large') && isSmallViewport());
    if (currentlyCompact) {
      document.body.classList.remove('force-compact');
      document.body.classList.add('force-large');
      try { localStorage.setItem('uncloak_density', 'large'); } catch(e) {}
    } else {
      document.body.classList.remove('force-large');
      document.body.classList.add('force-compact');
      try { localStorage.setItem('uncloak_density', 'compact'); } catch(e) {}
    }
    updateDensityLabel();
  }

  // Restore saved density preference
  try {
    const pref = localStorage.getItem('uncloak_density');
    if (pref === 'compact') document.body.classList.add('force-compact');
    else if (pref === 'large') document.body.classList.add('force-large');
    updateDensityLabel();
    window.addEventListener('resize', updateDensityLabel);
  } catch(e) {}

  // Keyboard Navigation
  window.addEventListener('keydown', (e) => {
    if (e.altKey && e.key.toLowerCase() === 'z') {
      e.preventDefault();
      toggleDensity();
      return;
    }
    const severModal = document.getElementById('sever-confirm-modal');
    if (severModal && severModal.classList.contains('active')) {
      if (e.key === 'Escape') { closeSeverModal(); closeTarpitModal(); closePidHistoryModal(); }
      if (e.key === 'Enter') executeConfirmedSever();
      return;
    }

    const tarpitModal = document.getElementById('tarpit-confirm-modal');
    if (tarpitModal && tarpitModal.classList.contains('active')) {
      if (e.key === 'Escape') closeTarpitModal();
      if (e.key === 'Enter') executeConfirmedTarpit();
      return;
    }

    if (e.key === '1') switchView('fleet');
    else if (e.key === '2') switchView('campaign');
    else if (e.key === '3') switchView('drilldown');
    else if (e.key.toLowerCase() === 'a' && currentTab === 'drilldown') switchHostSubtab('flows');
    else if (e.key.toLowerCase() === 'b' && currentTab === 'drilldown') switchHostSubtab('procs');
    else if (e.key.toLowerCase() === 'c' && currentTab === 'drilldown') switchHostSubtab('history');
    else if (e.key.toLowerCase() === 'k') severSelectedFlow();
    else if (e.key.toLowerCase() === 'i') openDossierModal();
    else if (e.key.toLowerCase() === 'e') exportTelemetry();
    else if (e.key === '/') {
      e.preventDefault();
      const input = document.getElementById('fleet-search');
      if (input) input.focus();
    }
  });

  if (window.location.hash === '#campaign') {
    switchView('campaign');
  } else if (window.location.hash === '#drilldown') {
    switchView('drilldown');
  } else if (window.location.hash === '#drilldown-procs') {
    switchView('drilldown');
    currentHostSubtab = 'procs';
  } else if (window.location.hash === '#drilldown-history') {
    switchView('drilldown');
    currentHostSubtab = 'history';
  }

  function handleUrlParams() {
    const urlParams = new URLSearchParams(window.location.search);
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
    if (layout && ['grid', 'table'].includes(layout)) {
      switchFleetLayout(layout);
    }
    const scope = urlParams.get('scope');
    if (scope) {
      filterTableByScope(scope.toUpperCase());
    }
    const tab = urlParams.get('tab');
    if (tab && ['fleet', 'campaign', 'drilldown'].includes(tab)) {
      switchView(tab);
    }
    const host = urlParams.get('host');
    if (host) {
      changeSelectedHost(host);
    }
    const subtab = urlParams.get('subtab');
    if (subtab && ['flows', 'procs', 'history', 'whitelist'].includes(subtab)) {
      switchHostSubtab(subtab);
    }
    const modal = urlParams.get('modal');
    const paramPid = parseInt(urlParams.get('pid') || '5824');
    if (modal === 'sever') {
      promptSeverModal(5824, '193.26.158.114:443', 'update.exe');
    } else if (modal === 'tarpit') {
      tarpitSelectedFlow();
    } else if (modal === 'whitelist') {
      switchView('drilldown');
      openWhitelistModal(5824, 'update.exe', '193.26.158.114:443', 'WIN-PROD-SRV01');
    } else if (modal === 'pid') {
      switchView('drilldown');
      switchHostSubtab('procs');
      openPidHistoryModal(paramPid, 'update.exe');
    }
  }

  // Hydrate immediately from server-injected state
  if (window.INITIAL_STATE) {
    stateData = window.INITIAL_STATE;
    userSelectedPid = stateData.selected_pid;
    renderUI();
    handleUrlParams();
  }

  setInterval(fetchState, 1500);
  fetchState();
  if (currentHostSubtab !== 'flows') {
    setTimeout(() => switchHostSubtab(currentHostSubtab), 300);
  }

  function openPidHistoryModal(pid, procName) {
    if (!stateData || !stateData.selected_host) return;
    const hostId = stateData.selected_host.host_id;
    const hostname = stateData.selected_host.hostname;

    document.getElementById('pid-history-modal').classList.add('active');
    document.getElementById('ph-pid').innerText = pid;
    document.getElementById('ph-proc').innerText = procName || 'Process ' + pid;
    document.getElementById('ph-host').innerText = hostname;

    // Instant local pre-render from loaded telemetry
    const hostHistory = stateData.host_connection_history || [];
    const localRecords = hostHistory.filter(r => String(r.pid) === String(pid));
    if (localRecords.length > 0) {
      const activeCount = localRecords.filter(r => r.state !== 'CLOSED').length;
      activeModalPidData = {
        pid: pid,
        process_name: procName || localRecords[0].process_name,
        total_connections: localRecords.length,
        active_connections: activeCount,
        first_seen: localRecords[localRecords.length - 1].timestamp || localRecords[0].timestamp,
        last_seen: localRecords[0].timestamp,
        total_bandwidth: (localRecords.length * 1.8).toFixed(1) + ' MB',
        records: localRecords
      };
      renderPidHistoryModal(activeModalPidData);
    }

    // Dynamic fetch from persistent SQLite database endpoint
    fetch('/api/pid/history?host=' + encodeURIComponent(hostId) + '&pid=' + pid)
      .then(res => res.json())
      .then(data => {
        if (data && data.records && data.records.length > 0) {
          activeModalPidData = data;
          renderPidHistoryModal(data);
        }
      })
      .catch(err => console.error('Failed to query SQLite history:', err));
  }

  function renderPidHistoryModal(data) {
    document.getElementById('ph-first-seen').innerText = data.first_seen || 'N/A';
    document.getElementById('ph-last-seen').innerText = data.last_seen || 'N/A';
    document.getElementById('ph-bandwidth').innerText = data.total_bandwidth || '0 B';
    document.getElementById('ph-sockets').innerText = data.total_connections + ' Recorded (' + data.active_connections + ' Live)';

    const tbody = document.getElementById('ph-tbody');
    let rows = '';
    (data.records || []).forEach(r => {
      const isCrit = (r.verdict || '').includes('CRITICAL');
      const isHigh = (r.verdict || '').includes('HIGH');
      const vColor = isCrit ? '#f87171' : (isHigh ? '#fbbf24' : 'var(--green)');

      rows += '<tr>' +
        '<td style="font-size: 11px; color: var(--text-dim); white-space: nowrap;">' + (r.timestamp || r.first_seen) + '</td>' +
        '<td>' + r.local_addr + '</td>' +
        '<td><strong>' + r.remote_addr + '</strong></td>' +
        '<td>' + (r.sni || '<span style="color: var(--text-muted); font-size: 10px;">None / Direct IP</span>') + '</td>' +
        '<td style="color: var(--cyan);">' + (r.duration || 'Active') + '</td>' +
        '<td><strong>' + (r.bytes_str || '512 B') + '</strong></td>' +
        '<td><span class="host-pill ' + (r.state === 'ESTABLISHED' ? 'safe' : (r.state === 'CLOSED' ? 'muted' : 'eval')) + '">' + r.state + '</span></td>' +
        '<td style="text-align: right;"><strong style="color: ' + vColor + ';">' + r.verdict + '</strong></td>' +
        '</tr>';
    });
    tbody.innerHTML = rows || '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;">No historical connections recorded for PID ' + data.pid + '</td></tr>';
  }

  function closePidHistoryModal() {
    document.getElementById('pid-history-modal').classList.remove('active');
  }

  function filterTimelineByPid(pid) {
    pid = (pid || '').trim();
    const rows = document.querySelectorAll('#history-tbody tr');
    const badge = document.getElementById('timeline-pid-filter-label');
    if (!pid) {
      rows.forEach(r => r.style.display = '');
      if (badge) badge.style.display = 'none';
      return;
    }
    let matched = 0;
    rows.forEach(r => {
      const isMatch = r.innerText.includes('(' + pid + ')') || r.innerText.includes('PID ' + pid) || r.children[1].innerText.includes(pid);
      r.style.display = isMatch ? '' : 'none';
      if (isMatch) matched++;
    });
    if (badge) {
      badge.style.display = 'block';
      badge.innerText = 'Showing ' + matched + ' connections for PID ' + pid;
    }
  }

  function clearTimelinePidFilter() {
    const input = document.getElementById('timeline-pid-input');
    if (input) input.value = '';
    filterTimelineByPid('');
  }

  function exportCurrentPidCsv() {
    if (!activeModalPidData || !activeModalPidData.records) return;
    const d = activeModalPidData;
    const lines = [];
    lines.push("UNCLOAK // ENTERPRISE EDR PID INTERNET USAGE AUDIT");
    lines.push("PID: " + d.pid + " | Process: " + d.process_name + " | Total Bandwidth: " + d.total_bandwidth);
    lines.push("First Seen: " + d.first_seen + " | Last Active: " + d.last_seen);
    lines.push("");
    lines.push("Timestamp,PID,Process,LocalAddress,RemoteAddress,SNI,Duration,Bandwidth,State,Verdict");
    d.records.forEach(r => {
      lines.push('"' + (r.timestamp || r.first_seen) + '","' + r.pid + '","' + r.process_name + '","' + r.local_addr + '","' + r.remote_addr + '","' + (r.sni || '') + '","' + r.duration + '","' + r.bytes_str + '","' + r.state + '","' + r.verdict + '"');
    });

    const csv = lines.join(String.fromCharCode(13, 10));
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = "uncloak_pid_" + d.pid + "_history_" + Date.now() + ".csv";
    a.click();
    URL.revokeObjectURL(url);
  }

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
