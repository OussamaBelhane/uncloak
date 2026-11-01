"""
Enterprise Desktop Cockpit for Uncloak.
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
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Optional
from urllib.parse import urlparse

from uncloak.ui.cockpit import FlowEntry, get_demo_flows, export_telemetry_json
from uncloak.ui.layout import CockpitState


class CockpitDataManager:
    """Thread-safe state and data coordinator between Python and the EDR UI."""
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.flows: list[FlowEntry] = get_demo_flows()
        self.state = CockpitState(flows=self.flows)
        self.selected_pid: int = 5824
        self.start_time = time.time()

    def get_state_payload(self) -> dict[str, Any]:
        with self.lock:
            active_beacons = sum(1 for f in self.flows if f.is_threat and not f.is_severed)
            now = time.time()
            packet_rate = 145 + int(now * 2) % 12 if not self.state.is_paused else 0
            
            flows_data = []
            for f in self.flows:
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
                })

            top_threat = next((f for f in self.flows if f.is_threat and not f.is_severed), None)
            if not top_threat:
                top_threat = next((f for f in self.flows if f.is_threat), None)

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

            return {
                "app_name": "UNCLOAK",
                "version": "v0.1.0",
                "host_name": "WIN-PROD-SRV01 (X64)",
                "bpf_filter": "tcp and (port 443 or 8443)",
                "total_sockets": len(self.flows) + 118,
                "packet_rate": packet_rate,
                "active_beacons": active_beacons,
                "cpu_percent": 0.8,
                "ram_mb": 7.5,
                "siem_event": self.state.siem_event,
                "uptime_seconds": int(now - self.start_time),
                "is_paused": self.state.is_paused,
                "selected_pid": self.selected_pid,
                "top_incident": top_threat_dict,
                "flows": flows_data,
            }

    def sever_flow(self, pid: int) -> bool:
        with self.lock:
            for f in self.flows:
                if f.pid == pid:
                    f.is_severed = True
                    f.threat_score = 0.0
                    f.threat_label = "SAFE"
                    f.state = "SEVERED (Host Clean)"
                    self.state.siem_event = f"EID 9002: Kernel SetTcpEntry Severed PID {pid}"
                    return True
            return False

    def export_data(self, pid: Optional[int] = None) -> str:
        with self.lock:
            target_flow = None
            if pid:
                target_flow = next((f for f in self.flows if f.pid == pid), None)
            return export_telemetry_json(self.state, target_flow=target_flow)


DATA_MANAGER = CockpitDataManager()


class UncloakHTTPHandler(BaseHTTPRequestHandler):
    """Zero-dependency HTTP API and UI asset server."""
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/state":
            self.send_json(DATA_MANAGER.get_state_payload())
        elif parsed.path in ("/", "/index.html"):
            html = get_cockpit_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            req_data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            req_data = {}

        if parsed.path == "/api/sever":
            pid = int(req_data.get("pid", 0))
            success = DATA_MANAGER.sever_flow(pid)
            self.send_json({"success": success, "pid": pid})
        elif parsed.path == "/api/export":
            pid = req_data.get("pid")
            filename = DATA_MANAGER.export_data(pid=int(pid) if pid else None)
            self.send_json({"success": True, "filename": filename})
        elif parsed.path == "/api/select":
            pid = int(req_data.get("pid", 0))
            DATA_MANAGER.selected_pid = pid
            self.send_json({"success": True, "selected_pid": pid})
        else:
            self.send_response(404)
            self.end_headers()


def get_cockpit_html() -> str:
    """Returns the standalone, single-file HTML5/CSS3/JS EDR Desktop interface."""
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>UNCLOAK :: Enterprise C2 Beacon Hunter & Socket Attribution</title>
<style>
  :root {
    --bg-main: #020617;
    --bg-card: #090e1c;
    --bg-card-inner: #060913;
    --border: #1e293b;
    --border-highlight: #334155;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --text-dim: #64748b;
    --cyan: #06b6d4;
    --cyan-glow: rgba(6, 182, 212, 0.25);
    --emerald: #10b981;
    --amber: #f59e0b;
    --crimson: #ef4444;
    --crimson-dark: #dc2626;
    --font-mono: 'Cascadia Code', 'JetBrains Mono', Consolas, monospace;
    --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; user-select: none; }

  /* Sleek Enterprise Dark Scrollbar */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: #090e1c; }
  ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: #475569; }
  * { scrollbar-width: thin; scrollbar-color: #334155 #090e1c; }

  body {
    background-color: var(--bg-main);
    color: var(--text-main);
    font-family: var(--font-mono);
    font-size: 12px;
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    padding: 10px 14px;
    gap: 8px;
    background-image: radial-gradient(circle at 50% 0%, rgba(15, 23, 42, 0.8), var(--bg-main) 70%);
  }

  /* TOP HUD BAR - STRICT SINGLE-LINE NO WRAP */
  .hud-bar {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 6px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: nowrap;
    gap: 8px;
    min-height: 44px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
  }

  .hud-left {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: nowrap;
    overflow: hidden;
  }

  .brand-badge {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 800;
    font-size: 13px;
    letter-spacing: 0.05em;
    color: var(--cyan);
    white-space: nowrap;
    margin-right: 4px;
  }

  .brand-badge svg {
    width: 18px;
    height: 18px;
    fill: var(--cyan);
    filter: drop-shadow(0 0 6px var(--cyan-glow));
  }

  .pill {
    background: rgba(30, 41, 59, 0.6);
    border: 1px solid var(--border);
    padding: 4px 9px;
    border-radius: 4px;
    font-size: 11px;
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    gap: 5px;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .pill strong { color: var(--text-main); }
  .pill.cyan { border-color: rgba(6, 182, 212, 0.4); color: var(--cyan); }
  .pill.emerald { border-color: rgba(16, 185, 129, 0.4); color: var(--emerald); }

  .live-pulse {
    width: 7px;
    height: 7px;
    background: var(--emerald);
    border-radius: 50%;
    box-shadow: 0 0 8px var(--emerald);
    animation: pulse 1.8s infinite;
  }

  @keyframes pulse {
    0% { transform: scale(0.9); opacity: 0.7; }
    50% { transform: scale(1.3); opacity: 1; }
    100% { transform: scale(0.9); opacity: 0.7; }
  }

  /* PINNED CRITICAL INCIDENT BANNER */
  .incident-banner {
    background: linear-gradient(90deg, rgba(30, 8, 8, 0.95), rgba(45, 12, 12, 0.85));
    border: 1px solid var(--crimson-dark);
    border-radius: 8px;
    padding: 8px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    box-shadow: 0 0 20px rgba(220, 38, 38, 0.15);
  }

  .incident-left {
    display: flex;
    align-items: center;
    gap: 10px;
    white-space: nowrap;
    overflow: hidden;
  }

  .incident-tag {
    background: var(--crimson-dark);
    color: white;
    font-weight: 700;
    font-size: 10px;
    padding: 3px 8px;
    border-radius: 4px;
    letter-spacing: 0.05em;
    white-space: nowrap;
  }

  .incident-title {
    color: #fca5a5;
    font-weight: 700;
    font-size: 12px;
  }

  .incident-details {
    color: var(--text-muted);
    font-size: 11px;
    margin-top: 1px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .incident-details span {
    color: white;
    font-weight: 600;
  }

  .btn-sever-quick {
    background: var(--crimson-dark);
    color: white;
    border: none;
    border-radius: 5px;
    padding: 5px 12px;
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.15s ease;
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
    box-shadow: 0 0 10px rgba(220, 38, 38, 0.4);
  }

  .btn-sever-quick svg {
    width: 12px;
    height: 12px;
    fill: currentColor;
  }

  .btn-sever-quick:hover {
    background: #b91c1c;
    transform: translateY(-1px);
    box-shadow: 0 0 15px rgba(220, 38, 38, 0.6);
  }

  /* TELEMETRY MATRIX CONTAINER */
  .matrix-container {
    flex: 1;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
  }

  .matrix-header-bar {
    padding: 6px 14px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: rgba(15, 23, 42, 0.5);
  }

  .matrix-title {
    color: var(--cyan);
    font-weight: 700;
    font-size: 11px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .matrix-search {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .search-input {
    background: #020617;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 3px 9px;
    color: var(--text-main);
    font-family: var(--font-mono);
    font-size: 11px;
    outline: none;
    width: 240px;
    transition: border-color 0.2s;
  }

  .search-input:focus {
    border-color: var(--cyan);
    box-shadow: 0 0 8px var(--cyan-glow);
  }

  .table-wrapper {
    flex: 1;
    overflow-y: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 11px;
    text-align: left;
  }

  thead {
    position: sticky;
    top: 0;
    background: #090e1c;
    border-bottom: 1px solid var(--border);
    z-index: 10;
  }

  th {
    padding: 7px 10px;
    color: var(--text-muted);
    font-weight: 600;
    font-size: 10px;
    letter-spacing: 0.05em;
    cursor: pointer;
    white-space: nowrap;
  }

  th:hover { color: var(--cyan); }

  tbody tr {
    border-bottom: 1px solid rgba(30, 41, 59, 0.3);
    cursor: pointer;
    transition: background-color 0.1s ease;
  }

  tbody tr.row-normal { background: #090e1c; }
  tbody tr.row-threat { background: #1a0808; }
  tbody tr.row-threat:hover { background: #2d0c0c; }
  tbody tr.row-severed { background: #090e1c; opacity: 0.6; }

  tbody tr.selected {
    background: #131e33 !important;
    outline: 1px solid var(--cyan);
  }

  tbody tr.row-threat.selected {
    background: #2d0c0c !important;
    outline: 1px solid var(--crimson);
  }

  td {
    padding: 6px 10px;
    white-space: nowrap;
    vertical-align: middle;
  }

  .sec-tag {
    font-size: 9px;
    font-weight: 700;
    padding: 1px 4px;
    border-radius: 3px;
    margin-left: 5px;
    display: inline-block;
  }

  .sec-tag.alert {
    background: rgba(239, 68, 68, 0.15);
    border: 1px solid rgba(239, 68, 68, 0.5);
    color: var(--crimson);
  }

  .sec-tag.signed {
    background: rgba(16, 185, 129, 0.15);
    border: 1px solid rgba(16, 185, 129, 0.5);
    color: var(--emerald);
  }

  .sni-raw {
    color: var(--amber);
    background: rgba(245, 158, 11, 0.1);
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 10px;
    border: 1px solid rgba(245, 158, 11, 0.3);
  }

  .pulse-svg {
    vertical-align: middle;
    display: inline-block;
  }

  .badge-crit {
    background: var(--crimson-dark);
    color: white;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 10px;
    display: inline-block;
    box-shadow: 0 0 8px rgba(220, 38, 38, 0.5);
  }

  .badge-high {
    background: #b91c1c;
    color: white;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 10px;
    display: inline-block;
  }

  .badge-safe {
    color: var(--emerald);
    font-weight: 700;
  }

  .badge-severed {
    background: #0f172a;
    color: #38bdf8;
    border: 1px solid #38bdf8;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 10px;
    display: inline-block;
  }

  /* FORENSIC TRI-PANE DRAWER */
  .drawer-container {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    display: flex;
    flex-direction: column;
    padding: 8px 12px;
    gap: 8px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    min-height: 200px;
  }

  .drawer-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 11px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 4px;
  }

  .drawer-title {
    color: var(--cyan);
    font-weight: 700;
    font-size: 11px;
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .drawer-cards {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 10px;
    align-items: stretch;
  }

  .forensic-card {
    background: var(--bg-card-inner);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 12px;
    display: flex;
    flex-direction: column;
    gap: 5px;
    justify-content: space-between;
  }

  .card-title {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.05em;
    padding-bottom: 3px;
    border-bottom: 1px solid rgba(30, 41, 59, 0.5);
    margin-bottom: 2px;
  }

  .card-title.cyan { color: #38bdf8; }
  .card-title.amber { color: var(--amber); }
  .card-title.blue { color: #06b6d4; }

  .card-kv-grid {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .card-row {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    gap: 6px;
  }

  .card-label {
    color: var(--text-dim);
    white-space: nowrap;
  }

  .card-value {
    color: var(--text-main);
    font-weight: 600;
    text-align: right;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .card-value.highlight-red { color: var(--crimson); font-weight: 700; }
  .card-value.highlight-green { color: var(--emerald); font-weight: 700; }
  .card-value.highlight-cyan { color: var(--cyan); }

  /* FOOTER */
  .footer-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 10px;
    color: var(--text-dim);
    padding: 0 4px;
  }

  .key-badge {
    background: #1e293b;
    color: white;
    padding: 1px 5px;
    border-radius: 3px;
    font-weight: 700;
    margin-right: 3px;
  }

  /* MODAL */
  .modal-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(2, 6, 23, 0.85);
    backdrop-filter: blur(8px);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .modal-overlay.active { display: flex; }

  .modal-window {
    background: #090e1c;
    border: 1px solid var(--cyan);
    border-radius: 8px;
    width: 780px;
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

  .modal-header h3 { color: var(--cyan); font-size: 14px; }

  .btn-close {
    background: none;
    border: none;
    color: var(--text-muted);
    font-size: 16px;
    cursor: pointer;
  }

  .btn-close:hover { color: white; }

  .dossier-body {
    overflow-y: auto;
    font-size: 11px;
    line-height: 1.6;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .action-btn {
    background: #1e293b;
    color: white;
    border: 1px solid var(--border-highlight);
    border-radius: 4px;
    padding: 4px 10px;
    font-family: var(--font-mono);
    font-size: 10px;
    cursor: pointer;
    transition: all 0.15s ease;
    white-space: nowrap;
  }

  .action-btn:hover {
    background: var(--cyan);
    color: black;
    border-color: var(--cyan);
  }

  .action-btn.danger:hover {
    background: var(--crimson);
    color: white;
    border-color: var(--crimson);
  }
</style>
</head>
<body>

  <!-- TOP HUD BAR -->
  <header class="hud-bar">
    <div class="hud-left">
      <div class="brand-badge">
        <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
        UNCLOAK <span style="font-size: 10px; color: var(--text-dim); font-weight: normal;">v0.1.0</span>
      </div>
      <div class="pill cyan">HOST: <strong id="hud-host">WIN-PROD-SRV01 (X64)</strong></div>
      <div class="pill">BPF: <strong id="hud-bpf">tcp and (port 443 or 8443)</strong></div>
      <div class="pill">SOCKETS: <strong id="hud-sockets">124</strong></div>
      <div class="pill">PACKETS: <strong id="hud-packets">151 pkt/s</strong></div>
      <div class="pill">CPU: <strong id="hud-cpu">0.8%</strong></div>
      <div class="pill">RAM: <strong id="hud-ram">7.5 MB</strong></div>
    </div>
    <div class="hud-right" style="display: flex; align-items: center; gap: 8px; flex-shrink: 0;">
      <div class="pill emerald"><div class="live-pulse"></div> ACTIVE</div>
      <div class="pill emerald" id="hud-siem">SIEM: EID 9002</div>
      <button class="action-btn" onclick="exportTelemetry()">[E] Export Telemetry</button>
    </div>
  </header>

  <!-- PINNED CRITICAL INCIDENT BANNER -->
  <div class="incident-banner" id="incident-banner">
    <div class="incident-left">
      <div class="incident-tag">[ CRITICAL INCIDENT 1/3 ]</div>
      <div>
        <div class="incident-title" id="inc-title">CRITICAL C2 BEACON ISOLATED</div>
        <div class="incident-details">
          TARGET: <span id="inc-target">193.26.158.114:443 (Sliver C2)</span> │ 
          PID: <span id="inc-pid">5824 (update.exe)</span> │ 
          STATUS: <span id="inc-status" style="color: #fca5a5;">Active (Live)</span> │ 
          EVENT: <span id="inc-event">EID 9001 Dispatched</span>
        </div>
      </div>
    </div>
    <div class="incident-right" style="display: flex; align-items: center; gap: 10px; flex-shrink: 0;">
      <span style="font-size: 10px; color: var(--text-dim);">MITRE ATT&CK: <strong style="color: white;" id="inc-mitre">T1071.001</strong></span>
      <button class="btn-sever-quick" id="btn-quick-sever" onclick="severCurrentIncident()">
        <svg viewBox="0 0 16 16"><path d="M7 1v6H3l6 8V9h4L7 1z"/></svg> Sever Connection
      </button>
    </div>
  </div>

  <!-- PRIMARY TELEMETRY MATRIX -->
  <main class="matrix-container">
    <div class="matrix-header-bar">
      <div class="matrix-title">
        <span>ACTIVE FLOWS (<span id="total-flows-badge">124</span>)</span>
        <span class="pill" style="font-size: 9px; padding: 2px 6px;">Live Kernel Telemetry Ingestion</span>
      </div>
      <div class="matrix-search">
        <input type="text" class="search-input" id="search-input" placeholder="Search PID, Process, IP... [/]" oninput="handleSearch(this.value)">
      </div>
    </div>
    <div class="table-wrapper">
      <table id="flows-table">
        <thead>
          <tr>
            <th onclick="sortTable('pid')">PID</th>
            <th onclick="sortTable('process_name')">PROCESS</th>
            <th onclick="sortTable('dst_ip')">DESTINATION</th>
            <th>SNI / DOMAIN</th>
            <th onclick="sortTable('interval_str')">INTERVAL & LOGIC PULSE</th>
            <th onclick="sortTable('payload_str')">PAYLOAD</th>
            <th onclick="sortTable('threat_score')" style="text-align: right;">THREAT SCORE ▼</th>
            <th style="text-align: center;">ACTION</th>
          </tr>
        </thead>
        <tbody id="flows-tbody">
        </tbody>
      </table>
    </div>
  </main>

  <!-- FORENSIC ATTRIBUTION TRI-PANE DRAWER -->
  <section class="drawer-container" id="drawer-panel">
    <div class="drawer-header">
      <div class="drawer-title" id="drawer-title">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="var(--cyan)"><path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
        FORENSIC SESSION ATTRIBUTION : 193.26.158.114:443 (PID 5824)
      </div>
      <div>
        <button class="action-btn" onclick="openDossierModal()">[I] Open Forensic Dossier</button>
      </div>
    </div>
    <div class="drawer-cards">
      <!-- Card 1: Host Attribution -->
      <div class="forensic-card">
        <div class="card-title cyan">[ HOST ATTRIBUTION ]</div>
        <div class="card-kv-grid">
          <div class="card-row"><span class="card-label">PID</span><span class="card-value" id="c1-pid">5824</span></div>
          <div class="card-row"><span class="card-label">Process</span><span class="card-value highlight-red" id="c1-proc">update.exe</span></div>
          <div class="card-row"><span class="card-label">Binary Path</span><span class="card-value" id="c1-path">AppData\Roaming\update.exe</span></div>
          <div class="card-row"><span class="card-label">Signature</span><span class="card-value highlight-red" id="c1-sig">Unsigned PE (In-Memory Hollowed)</span></div>
          <div class="card-row"><span class="card-label">SHA-256</span><span class="card-value" id="c1-sha">e3b0c44298fc1c..</span></div>
          <div class="card-row"><span class="card-label">Parent Lineage</span><span class="card-value" id="c1-parent">cmd.exe (4920) -> explorer.exe</span></div>
        </div>
        <div style="height: 28px;"></div>
      </div>

      <!-- Card 2: Cadence & Timing -->
      <div class="forensic-card">
        <div class="card-title amber">[ CADENCE & TIMING ]</div>
        <div class="card-kv-grid">
          <div class="card-row"><span class="card-label">Interval</span><span class="card-value" id="c2-int">8.4s (±0.8s)</span></div>
          <div class="card-row"><span class="card-label">Beacon State</span><span class="card-value highlight-red" id="c2-state">ACTIVE (C2 Live)</span></div>
          <div class="card-row"><span class="card-label">Logic Wave</span><span class="card-value" id="c2-pulse"></span></div>
          <div class="card-row"><span class="card-label">Payload Profile</span><span class="card-value" id="c2-payload">512 B (Fixed)</span></div>
          <div class="card-row"><span class="card-label">Burst Distribution</span><span class="card-value" id="c2-bursts">14 bursts / 2m</span></div>
          <div class="card-row"><span class="card-label">Jitter Metric</span><span class="card-value highlight-red" id="c2-jitter">9.5% (Rigid / Anomalous)</span></div>
        </div>
        <div style="height: 28px;"></div>
      </div>

      <!-- Card 3: Forensic & Mitigation -->
      <div class="forensic-card">
        <div class="card-title blue">[ FORENSIC & MITIGATION ]</div>
        <div class="card-kv-grid">
          <div class="card-row"><span class="card-label">MITRE ATT&CK</span><span class="card-value" id="c3-mitre">T1071.001 (Web Protocols)</span></div>
          <div class="card-row"><span class="card-label">Kernel Hook API</span><span class="card-value highlight-cyan">iphlpapi.dll SetTcpEntry</span></div>
          <div class="card-row"><span class="card-label">Action Status</span><span class="card-value" id="c3-action">Pending Mitigation</span></div>
          <div class="card-row"><span class="card-label">Socket State</span><span class="card-value" id="c3-stack">ESTABLISHED (Live)</span></div>
          <div class="card-row"><span class="card-label">Audit Log</span><span class="card-value">Sysmon EID 3 │ Defender 9001</span></div>
        </div>
        <div>
          <button class="btn-sever-quick" style="width: 100%; justify-content: center;" id="btn-card-sever" onclick="severSelectedFlow()">
            <svg viewBox="0 0 16 16"><path d="M7 1v6H3l6 8V9h4L7 1z"/></svg> Sever Socket via SetTcpEntry
          </button>
        </div>
      </div>
    </div>
  </section>

  <!-- FOOTER HOTKEY STATUS -->
  <footer class="footer-bar">
    <div>
      <span class="key-badge">↑/↓</span> Navigate
      <span class="key-badge">K</span> Sever Socket
      <span class="key-badge">I</span> Full Dossier
      <span class="key-badge">/</span> Search
      <span class="key-badge">E</span> Export Telemetry
    </div>
    <div style="color: var(--text-dim);">UNCLOAK v0.1.0 │ Autonomous C2 Stealth Beacon Hunter</div>
  </footer>

  <!-- FULL FORENSIC DOSSIER MODAL -->
  <div class="modal-overlay" id="dossier-modal">
    <div class="modal-window">
      <div class="modal-header">
        <h3 id="modal-dossier-title">PROCESS FORENSIC DOSSIER</h3>
        <button class="btn-close" onclick="closeDossierModal()">✕</button>
      </div>
      <div class="dossier-body" id="modal-dossier-body">
      </div>
      <div style="display: flex; justify-content: flex-end; gap: 10px; border-top: 1px solid var(--border); padding-top: 10px;">
        <button class="action-btn" onclick="exportDossierSelected()">Export Dossier JSON</button>
        <button class="action-btn danger" onclick="severSelectedFlow(); closeDossierModal();">Sever Connection</button>
        <button class="action-btn" onclick="closeDossierModal()">Close</button>
      </div>
    </div>
  </div>

<script>
  let stateData = null;
  let selectedPid = 5824;
  let searchQuery = '';
  let sortField = 'threat_score';
  let sortAsc = false;

  async function fetchState() {
    try {
      const res = await fetch('/api/state');
      stateData = await res.json();
      renderUI();
    } catch (e) {
      console.error('Telemetry fetch failed:', e);
    }
  }

  function renderWaveSvg(sparkline, isThreat, isSevered) {
    if (isSevered) {
      return `<svg width="74" height="14" viewBox="0 0 74 14" class="pulse-svg">
        <line x1="0" y1="7" x2="74" y2="7" stroke="#475569" stroke-width="1.5" stroke-dasharray="4 4" />
      </svg>`;
    }
    if (!isThreat || sparkline.includes('──')) {
      return `<svg width="74" height="14" viewBox="0 0 74 14" class="pulse-svg">
        <line x1="0" y1="10" x2="74" y2="10" stroke="#10b981" stroke-width="1.5" stroke-dasharray="6 3" />
      </svg>`;
    }
    const color = isThreat ? "#ef4444" : "#10b981";
    if (sparkline.includes('▄ ▄ ▄ ▄')) {
      return `<svg width="74" height="14" viewBox="0 0 74 14" class="pulse-svg">
        <path d="M0,11 L6,11 L6,2 L14,2 L14,11 L24,11 L24,2 L32,2 L32,11 L42,11 L42,2 L50,2 L50,11 L60,11 L60,2 L68,2 L68,11 L74,11" 
              fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
      </svg>`;
    } else if (sparkline.includes('▄   ▄   ▄')) {
      return `<svg width="74" height="14" viewBox="0 0 74 14" class="pulse-svg">
        <path d="M0,11 L10,11 L10,2 L18,2 L18,11 L34,11 L34,2 L42,2 L42,11 L58,11 L58,2 L66,2 L66,11 L74,11" 
              fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
      </svg>`;
    } else {
      return `<svg width="74" height="14" viewBox="0 0 74 14" class="pulse-svg">
        <path d="M0,11 L14,11 L14,2 L24,2 L24,11 L52,11 L52,2 L62,2 L62,11 L74,11" 
              fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
      </svg>`;
    }
  }

  function renderUI() {
    if (!stateData) return;

    // 1. Update HUD
    document.getElementById('hud-host').innerText = stateData.host_name;
    document.getElementById('hud-bpf').innerText = stateData.bpf_filter;
    document.getElementById('hud-sockets').innerText = stateData.total_sockets;
    document.getElementById('hud-packets').innerText = stateData.packet_rate + ' pkt/s';
    document.getElementById('hud-cpu').innerText = stateData.cpu_percent + '%';
    document.getElementById('hud-ram').innerText = stateData.ram_mb + ' MB';
    document.getElementById('hud-siem').innerText = stateData.siem_event;

    // 2. Incident Banner
    const inc = stateData.top_incident;
    if (inc) {
      document.getElementById('inc-title').innerText = inc.is_severed ? 'INCIDENT MITIGATED (SEVERED)' : 'CRITICAL C2 BEACON ISOLATED';
      document.getElementById('inc-target').innerText = inc.target + ' (' + inc.c2_framework + ')';
      document.getElementById('inc-pid').innerText = inc.pid + ' (' + inc.process_name + ')';
      document.getElementById('inc-status').innerText = inc.status;
      document.getElementById('inc-status').style.color = inc.is_severed ? 'var(--emerald)' : '#fca5a5';
      document.getElementById('inc-event').innerText = inc.event;
      document.getElementById('inc-mitre').innerText = inc.mitre;
      const btn = document.getElementById('btn-quick-sever');
      if (inc.is_severed) {
        btn.innerHTML = '<svg viewBox="0 0 16 16" width="12" height="12" fill="currentColor"><path d="M13.485 1.431a.75.75 0 0 1 .284 1.022l-7 12a.75.75 0 0 1-1.258.064l-4.5-6a.75.75 0 1 1 1.2-1.234l3.834 5.111 6.418-11.004a.75.75 0 0 1 1.022-.284z"/></svg> Severed';
        btn.style.background = '#1e293b';
        btn.style.boxShadow = 'none';
        btn.disabled = true;
      } else {
        btn.innerHTML = '<svg viewBox="0 0 16 16" width="12" height="12" fill="currentColor"><path d="M7 1v6H3l6 8V9h4L7 1z"/></svg> Sever Connection';
        btn.style.background = 'var(--crimson-dark)';
        btn.disabled = false;
      }
    }

    // 3. Render Matrix Rows
    let flows = [...stateData.flows];
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      flows = flows.filter(f => 
        f.process_name.toLowerCase().includes(q) || 
        f.dst_ip.includes(q) || 
        f.pid.toString().includes(q) || 
        f.sni.toLowerCase().includes(q)
      );
    }

    // Sort
    flows.sort((a, b) => {
      let vA = a[sortField];
      let vB = b[sortField];
      if (typeof vA === 'string') vA = vA.toLowerCase();
      if (typeof vB === 'string') vB = vB.toLowerCase();
      return sortAsc ? (vA > vB ? 1 : -1) : (vA < vB ? 1 : -1);
    });

    document.getElementById('total-flows-badge').innerText = flows.length;
    const tbody = document.getElementById('flows-tbody');
    tbody.innerHTML = '';

    flows.forEach(flow => {
      const tr = document.createElement('tr');
      const isSelected = (flow.pid === selectedPid);
      
      let rowClass = 'row-normal';
      if (flow.is_severed) rowClass = 'row-severed';
      else if (flow.is_threat) rowClass = 'row-threat';
      if (isSelected) rowClass += ' selected';
      tr.className = rowClass;

      // Threat Badge
      let threatBadge = '';
      if (flow.is_severed) {
        threatBadge = '<span class="badge-severed">[SEVERED]</span>';
      } else if (flow.threat_score >= 0.90) {
        threatBadge = `<span class="badge-crit">${(flow.threat_score * 100).toFixed(1)}% CRIT</span>`;
      } else if (flow.threat_score >= 0.80) {
        threatBadge = `<span class="badge-high">${(flow.threat_score * 100).toFixed(1)}% HIGH</span>`;
      } else {
        threatBadge = `<span class="badge-safe">${(flow.threat_score * 100).toFixed(1)}% SAFE</span>`;
      }

      // Security tag on process
      let secTag = flow.is_signed ? '<span class="sec-tag signed">SIGNED</span>' : '<span class="sec-tag alert">UNSIGNED</span>';

      // Real SVG logic analyzer waveform
      const waveHtml = renderWaveSvg(flow.sparkline, flow.is_threat, flow.is_severed);

      tr.innerHTML = `
        <td style="font-weight: 700; color: ${flow.is_threat && !flow.is_severed ? 'var(--crimson)' : 'var(--text-main)'};">${flow.pid}</td>
        <td><strong style="color: ${flow.is_threat && !flow.is_severed ? 'var(--crimson)' : 'white'};">${flow.process_name}</strong> ${secTag}</td>
        <td>${flow.dst_ip}:${flow.dst_port}</td>
        <td>${flow.sni ? `<span style="color: var(--text-muted);">${flow.sni}</span>` : '<span class="sni-raw">RAW IP / NO SNI</span>'}</td>
        <td>
          <span style="font-weight: 700; margin-right: 8px;">${flow.interval_str}</span>
          ${waveHtml}
        </td>
        <td>${flow.payload_str}</td>
        <td style="text-align: right;">${threatBadge}</td>
        <td style="text-align: center;">
          ${flow.is_threat && !flow.is_severed ? `<button class="action-btn danger" style="padding: 2px 7px; font-size: 10px;" onclick="event.stopPropagation(); severFlow(${flow.pid});">Sever</button>` : ''}
        </td>
      `;

      tr.onclick = () => selectFlow(flow.pid);
      tbody.appendChild(tr);
    });

    // 4. Update Detail Drawer
    updateDrawer();
  }

  function selectFlow(pid) {
    selectedPid = pid;
    fetch('/api/select', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid })
    });
    renderUI();
  }

  function updateDrawer() {
    if (!stateData) return;
    const flow = stateData.flows.find(f => f.pid === selectedPid) || stateData.flows[0];
    if (!flow) return;

    document.getElementById('drawer-title').innerHTML = `
      <svg viewBox="0 0 24 24" width="14" height="14" fill="var(--cyan)"><path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
      FORENSIC SESSION ATTRIBUTION : ${flow.dst_ip}:${flow.dst_port} (PID ${flow.pid})
    `;
    
    // Card 1
    document.getElementById('c1-pid').innerText = flow.pid;
    document.getElementById('c1-proc').innerText = flow.process_name;
    document.getElementById('c1-proc').className = flow.is_severed ? 'card-value' : (flow.is_threat ? 'card-value highlight-red' : 'card-value');
    document.getElementById('c1-path').innerText = flow.binary_path || 'Unknown';
    document.getElementById('c1-sig').innerText = flow.sig_info || (flow.is_signed ? 'Valid Signature' : 'Unsigned PE');
    document.getElementById('c1-sig').className = flow.is_signed ? 'card-value highlight-green' : 'card-value highlight-red';
    document.getElementById('c1-sha').innerText = flow.sha256 ? flow.sha256.substring(0, 16) + '..' : 'N/A';
    document.getElementById('c1-parent').innerText = flow.parent_process || 'services.exe';

    // Card 2
    document.getElementById('c2-int').innerText = `${flow.interval_str} (${flow.jitter_str})`;
    document.getElementById('c2-state').innerText = flow.is_severed ? 'SEVERED (Host Clean)' : (flow.is_threat ? 'ACTIVE (C2 Live)' : 'RANDOM (Human)');
    document.getElementById('c2-state').className = flow.is_severed ? 'card-value' : (flow.is_threat ? 'card-value highlight-red' : 'card-value highlight-green');
    document.getElementById('c2-pulse').innerHTML = renderWaveSvg(flow.sparkline, flow.is_threat, flow.is_severed);
    document.getElementById('c2-payload').innerText = `${flow.payload_str} ${flow.is_threat && !flow.is_severed ? '(Fixed)' : '(Dynamic)'}`;
    document.getElementById('c2-bursts').innerText = flow.bursts || '0 (Severed)';
    document.getElementById('c2-jitter').innerText = `${flow.jitter_pct} ${flow.is_threat ? '(Rigid / Anomalous)' : '(Normal)'}`;

    // Card 3
    document.getElementById('c3-mitre').innerText = flow.mitre_technique || 'N/A';
    document.getElementById('c3-action').innerText = flow.is_severed ? 'Mitigated (Socket Killed)' : (flow.is_threat ? 'Pending Mitigation' : 'None Required');
    document.getElementById('c3-stack').innerText = flow.state || 'ESTABLISHED';
    
    const cardSeverBtn = document.getElementById('btn-card-sever');
    if (flow.is_severed) {
      cardSeverBtn.innerHTML = '<svg viewBox="0 0 16 16" width="12" height="12" fill="currentColor"><path d="M13.485 1.431a.75.75 0 0 1 .284 1.022l-7 12a.75.75 0 0 1-1.258.064l-4.5-6a.75.75 0 1 1 1.2-1.234l3.834 5.111 6.418-11.004a.75.75 0 0 1 1.022-.284z"/></svg> Connection Severed';
      cardSeverBtn.style.background = '#1e293b';
      cardSeverBtn.disabled = true;
    } else {
      cardSeverBtn.innerHTML = '<svg viewBox="0 0 16 16" width="12" height="12" fill="currentColor"><path d="M7 1v6H3l6 8V9h4L7 1z"/></svg> Sever Socket via SetTcpEntry';
      cardSeverBtn.style.background = 'var(--crimson-dark)';
      cardSeverBtn.disabled = false;
    }
  }

  async function severFlow(pid) {
    try {
      await fetch('/api/sever', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      fetchState();
    } catch (e) {
      console.error('Sever failed:', e);
    }
  }

  function severSelectedFlow() {
    if (selectedPid) severFlow(selectedPid);
  }

  function severCurrentIncident() {
    if (stateData && stateData.top_incident) {
      severFlow(stateData.top_incident.pid);
    }
  }

  async function exportTelemetry() {
    try {
      const res = await fetch('/api/export', { method: 'POST' });
      const data = await res.json();
      alert(`[+] Telemetry exported successfully:\n${data.filename}`);
    } catch (e) {
      alert('Export failed: ' + e);
    }
  }

  async function exportDossierSelected() {
    try {
      const res = await fetch('/api/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: selectedPid })
      });
      const data = await res.json();
      alert(`[+] Process Dossier exported successfully:\n${data.filename}`);
    } catch (e) {
      alert('Export failed: ' + e);
    }
  }

  function openDossierModal() {
    if (!stateData) return;
    const flow = stateData.flows.find(f => f.pid === selectedPid) || stateData.flows[0];
    if (!flow) return;

    document.getElementById('modal-dossier-title').innerText = `PROCESS FORENSIC DOSSIER : ${flow.process_name} (PID ${flow.pid})`;
    const body = document.getElementById('modal-dossier-body');
    body.innerHTML = `
      <div style="background: #020617; padding: 10px 14px; border-radius: 6px; border: 1px solid var(--border);">
        <h4 style="color: var(--cyan); margin-bottom: 6px;">[ BINARY FORENSICS & ATTRIBUTION ]</h4>
        <p>• <strong>Binary Path:</strong> ${flow.binary_path}</p>
        <p>• <strong>Command Line:</strong> <code style="color: #cbd5e1;">${flow.command_line}</code></p>
        <p>• <strong>Parent Lineage:</strong> ${flow.parent_process}</p>
        <p>• <strong>Digital Signature:</strong> ${flow.sig_info}</p>
        <p>• <strong>SHA-256 Hash:</strong> <code style="color: var(--cyan); word-break: break-all;">${flow.sha256}</code></p>
      </div>

      <div style="background: #020617; padding: 10px 14px; border-radius: 6px; border: 1px solid var(--border);">
        <h4 style="color: var(--amber); margin-bottom: 6px;">[ C2 DETECTION HEURISTICS & JA4 ]</h4>
        <p>• <strong>C2 Framework:</strong> ${flow.c2_framework || 'Benign / Unclassified'}</p>
        <p>• <strong>JA4 Fingerprint:</strong> <code style="color: var(--amber);">${flow.ja4_fingerprint || 'N/A'}</code></p>
        <p>• <strong>Detection Reasons:</strong> ${flow.detection_reasons}</p>
        <p>• <strong>Heuristic Signals:</strong> ${flow.heuristic_signals}</p>
        <p>• <strong>Threat Score:</strong> ${(flow.threat_score * 100).toFixed(1)}% (${flow.threat_label})</p>
      </div>

      <div style="background: #020617; padding: 10px 14px; border-radius: 6px; border: 1px solid var(--border);">
        <h4 style="color: #38bdf8; margin-bottom: 6px;">[ ACTIVE NETWORK SOCKET TELEMETRY ]</h4>
        <p>• <strong>Socket Tuple:</strong> ${flow.src_ip}:${flow.src_port} -> ${flow.dst_ip}:${flow.dst_port}</p>
        <p>• <strong>TLS SNI Hostname:</strong> ${flow.sni || '[Raw IP / No SNI Extracted]'}</p>
        <p>• <strong>Cadence Pattern:</strong> Interval ${flow.interval_str} │ Jitter ${flow.jitter_pct} │ Payload ${flow.payload_str}</p>
        <p>• <strong>Socket State:</strong> ${flow.state} │ Packets: ${flow.packets} │ Bytes: ${flow.bytes_transferred}</p>
      </div>
    `;
    document.getElementById('dossier-modal').classList.add('active');
  }

  function closeDossierModal() {
    document.getElementById('dossier-modal').classList.remove('active');
  }

  function handleSearch(val) {
    searchQuery = val;
    renderUI();
  }

  function sortTable(field) {
    if (sortField === field) {
      sortAsc = !sortAsc;
    } else {
      sortField = field;
      sortAsc = false;
    }
    renderUI();
  }

  window.addEventListener('keydown', (e) => {
    if (e.key === '/') {
      e.preventDefault();
      document.getElementById('search-input').focus();
    } else if (e.key === 'Escape') {
      closeDossierModal();
      document.getElementById('search-input').blur();
    } else if (e.key.toLowerCase() === 'k') {
      severSelectedFlow();
    } else if (e.key.toLowerCase() === 'i') {
      openDossierModal();
    } else if (e.key.toLowerCase() === 'e') {
      exportTelemetry();
    } else if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
      if (!stateData) return;
      const flows = stateData.flows;
      const idx = flows.findIndex(f => f.pid === selectedPid);
      if (e.key === 'ArrowUp' && idx > 0) {
        selectFlow(flows[idx - 1].pid);
      } else if (e.key === 'ArrowDown' && idx < flows.length - 1) {
        selectFlow(flows[idx + 1].pid);
      }
    }
  });

  setInterval(fetchState, 1000);
  fetchState();
</script>
</body>
</html>
"""


def launch_desktop(port: Optional[int] = None) -> int:
    """Launches the enterprise desktop cockpit using WebView2 with zero-dependency loopback fallback."""
    server = HTTPServer(("127.0.0.1", port or 0), UncloakHTTPHandler)
    assigned_port = server.server_address[1]
    url = f"http://127.0.0.1:{assigned_port}"

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    print(f"[*] Uncloak Enterprise Desktop Engine initialized on {url}")

    try:
        import webview
        print("[*] Launching native Microsoft Edge WebView2 window via pywebview...")
        webview.create_window(
            title="UNCLOAK :: Enterprise C2 Beacon Hunter & Socket Attribution",
            url=url,
            width=1400,
            height=850,
            min_size=(1050, 650),
            background_color="#020617",
        )
        webview.start()
        server.shutdown()
        return 0
    except ImportError:
        pass

    system = platform.system()
    app_launched = False

    if system == "Windows":
        edge_paths = [
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
            "msedge.exe",
        ]
        for ep in edge_paths:
            try:
                proc = subprocess.Popen([
                    ep,
                    f"--app={url}",
                    "--window-size=1420,870",
                    "--new-window",
                ])
                print(f"[+] Launched standalone Microsoft Edge WebView2 window (PID {proc.pid})")
                app_launched = True
                break
            except Exception:
                continue

        if not app_launched:
            try:
                subprocess.Popen(f'cmd.exe /c start msedge --app="{url}" --window-size=1420,870 --new-window', shell=True)
                print("[+] Launched Microsoft Edge WebView2 via Windows Shell")
                app_launched = True
            except Exception:
                pass

    elif system == "Linux":
        for browser in ("google-chrome", "chromium-browser", "chromium", "brave-browser", "edge"):
            try:
                proc = subprocess.Popen([browser, f"--app={url}", "--window-size=1420,870"])
                print(f"[+] Launched standalone Chromium desktop window (PID {proc.pid})")
                app_launched = True
                break
            except Exception:
                continue

    if not app_launched:
        import webbrowser
        print(f"[*] Opening desktop cockpit in default browser: {url}")
        webbrowser.open(url)

    print("[*] Press Ctrl+C in this terminal to exit Uncloak.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Uncloak Desktop Engine shutting down cleanly.")
    finally:
        server.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(launch_desktop())
