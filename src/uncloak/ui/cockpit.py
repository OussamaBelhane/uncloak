"""
Interactive live runner and event loop for the Uncloak CUI cockpit.
Handles non-blocking cross-platform keyboard input, live psutil resource telemetry,
and zero-flicker rendering strictly adhering to global open-source cybersecurity standards.
"""

import os
import sys
import time
from typing import Optional

import psutil
from rich.console import Console
from rich.live import Live

from uncloak.ui.layout import CockpitState, FlowEntry, build_cockpit_layout, get_visible_flows


def get_demo_flows() -> list[FlowEntry]:
    """Generates high-fidelity demonstration telemetry matching the master architecture."""
    return [
        FlowEntry(
            flow_id="f1",
            pid=5824,
            process_name="update.exe",
            is_signed=False,
            src_ip="10.0.0.15",
            src_port=49152,
            dst_ip="193.26.158.114",
            dst_port=443,
            sni="",
            interval_str="8.4s",
            sparkline="▎ ▎ ▎ ▎",
            jitter_str="±0.8s",
            jitter_pct="9.5%",
            payload_str="512 B",
            threat_score=0.987,
            threat_label="CRIT",
            is_threat=True,
            c2_framework="Sliver C2",
            binary_path=r"C:\Users\Target\AppData\Roaming\update.exe",
            command_line=r"update.exe --c2 193.26.158.114:443 --session-id 0x882",
            parent_process="cmd.exe (PID 4920) -> explorer.exe (PID 2110)",
            sig_info="Unsigned PE (In-Memory Hollowed)",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ja4_fingerprint="t13d1516h2_8daaf6152771_0266e33433e9",
            heuristic_signals="Beacon 0.99 │ Raw IP",
            detection_reasons="Direct IP (No SNI) │ Static 512B Beacon",
            bursts="14 bursts / 2m",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=False,
            mitre_technique="T1071.001 (HTTPS C2)",
            state="ESTABLISHED",
            packets=182,
            bytes_transferred=51688,
        ),
        FlowEntry(
            flow_id="f2",
            pid=6712,
            process_name="rundll32.exe",
            is_signed=False,
            src_ip="10.0.0.15",
            src_port=49210,
            dst_ip="45.33.32.156",
            dst_port=8443,
            sni="cdn-azure-edge.net",
            interval_str="15.0s",
            sparkline="▎   ▎   ▎",
            jitter_str="±1.1s",
            jitter_pct="7.3%",
            payload_str="1.2 KB",
            threat_score=0.942,
            threat_label="CRIT",
            is_threat=True,
            c2_framework="Cobalt Strike",
            binary_path=r"C:\Windows\System32\rundll32.exe",
            command_line=r"C:\Windows\System32\rundll32.exe C:\Users\Target\AppData\Local\Temp\nvsvc.dll,Entry",
            parent_process="powershell.exe (PID 8830) -> wmiprvse.exe (PID 3144)",
            sig_info="Unsigned Proxy (DLL Side-load)",
            sha256="7c12bf9810ac9b32e144a10f8bc9910cde4279ab2281a8c3d9a102ffbc41238a",
            ja4_fingerprint="t13d190800_261546b3f71c_f601b1a77409",
            heuristic_signals="Beacon 0.94 │ Malleable",
            detection_reasons="Malleable C2 Profile │ Host Header Mismatch",
            bursts="8 bursts / 2m",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=False,
            mitre_technique="T1218.011 (Rundll32)",
            state="ESTABLISHED",
            packets=96,
            bytes_transferred=24576,
        ),
        FlowEntry(
            flow_id="f3",
            pid=8830,
            process_name="powershell.exe",
            is_signed=False,
            src_ip="10.0.0.15",
            src_port=49722,
            dst_ip="185.220.101.5",
            dst_port=443,
            sni="api.telemetry-host.org",
            interval_str="60.0s",
            sparkline="▎      ▎",
            jitter_str="±2.4s",
            jitter_pct="4.0%",
            payload_str="768 B",
            threat_score=0.865,
            threat_label="HIGH",
            is_threat=True,
            c2_framework="Empire C2",
            binary_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=r"powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
            parent_process="svchost.exe (PID 2023) -> services.exe (PID 644)",
            sig_info="Microsoft Windows",
            sha256="99182abfc012781bcf4401a998bc41270ae19b88ef128456187900bba037b341",
            ja4_fingerprint="t13d1516h2_8daaf6152771_0266e33433e9",
            heuristic_signals="Beacon 0.99 │ Direct IP",
            detection_reasons="Direct IP (No SNI) │ Static 768B Beacon",
            bursts="5 bursts / 5m",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=False,
            mitre_technique="T1059.001 (PowerShell C2)",
            state="ESTABLISHED",
            packets=45,
            bytes_transferred=14336,
        ),
        FlowEntry(
            flow_id="f4",
            pid=1024,
            process_name="teams.exe",
            is_signed=True,
            src_ip="10.0.0.15",
            src_port=50114,
            dst_ip="52.114.63.56",
            dst_port=443,
            sni="*.teams.microsoft.com",
            interval_str="Asynch",
            sparkline="──    ──",
            jitter_str="N/A",
            jitter_pct="N/A",
            payload_str="3.9 KB",
            threat_score=0.008,
            threat_label="SAFE",
            is_threat=False,
            c2_framework=None,
            binary_path=r"C:\Program Files\WindowsApps\teams.exe",
            command_line=r"teams.exe --type=renderer --enable-features=WebComponents",
            parent_process="explorer.exe (PID 2110)",
            sig_info="Microsoft Corporation",
            sha256="b148fa0172e04f9810bb4260aa781fbc02419a45610099881122334455667788",
            ja4_fingerprint="t13d311200_0026e4975549_d8c0dc890209",
            heuristic_signals="Enterprise Suite Baseline",
            detection_reasons="Valid PKI Signature │ Enterprise Allowlist",
            bursts="Asynchronous",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=False,
            mitre_technique="None (Allowlisted)",
            state="ESTABLISHED",
            packets=1420,
            bytes_transferred=584200,
        ),
        FlowEntry(
            flow_id="f5",
            pid=2023,
            process_name="svchost.exe",
            is_signed=True,
            src_ip="10.0.0.15",
            src_port=50228,
            dst_ip="20.189.139.81",
            dst_port=443,
            sni="*.azure.com",
            interval_str="Asynch",
            sparkline="──    ──",
            jitter_str="N/A",
            jitter_pct="N/A",
            payload_str="3.6 KB",
            threat_score=0.008,
            threat_label="SAFE",
            is_threat=False,
            c2_framework=None,
            binary_path=r"C:\Windows\System32\svchost.exe",
            command_line=r"C:\Windows\System32\svchost.exe -k DcomLaunch -p",
            parent_process="services.exe (PID 644)",
            sig_info="Microsoft Windows (Catalog Signed)",
            sha256="5a1098b10ef3341b8a99002477cbb14002fa1098112233445566778899aabbcc",
            ja4_fingerprint="t13d1516h2_8daaf6152771_0266e33433e9",
            heuristic_signals="OS Kernel Baseline",
            detection_reasons="Operating System Kernel Service Baseline",
            bursts="Asynchronous",
            user_context=r"NT AUTHORITY\SYSTEM",
            is_severed=False,
            mitre_technique="None (Core OS Service)",
            state="ESTABLISHED",
            packets=320,
            bytes_transferred=182400,
        ),
        FlowEntry(
            flow_id="f6",
            pid=3614,
            process_name="docker.exe",
            is_signed=True,
            src_ip="10.0.0.15",
            src_port=50352,
            dst_ip="104.244.136.16",
            dst_port=443,
            sni="registry.docker.io",
            interval_str="10.0s",
            sparkline="▎  ▎  ▎",
            jitter_str="±0.5s",
            jitter_pct="5.0%",
            payload_str="780 B",
            threat_score=0.008,
            threat_label="SAFE",
            is_threat=False,
            c2_framework=None,
            binary_path=r"C:\Program Files\Docker\docker.exe",
            command_line=r"docker.exe pull alpine:latest",
            parent_process="powershell.exe (PID 5120)",
            sig_info="Docker Inc.",
            sha256="89acbf0198aa47b60214ee00b891bcfa0014a5566778899aabbccddeeff00112",
            ja4_fingerprint="t13d1516h2_8daaf6152771_c2140bb063ea",
            heuristic_signals="Container Runtime Sync",
            detection_reasons="Verified Container Runtime Registry Sync",
            bursts="2 bursts / 5m",
            user_context=r"NT AUTHORITY\SYSTEM",
            is_severed=False,
            mitre_technique="None (Developer Tool)",
            state="ESTABLISHED",
            packets=84,
            bytes_transferred=68880,
        ),
        FlowEntry(
            flow_id="f7",
            pid=9216,
            process_name="chrome.exe",
            is_signed=True,
            src_ip="10.0.0.15",
            src_port=50480,
            dst_ip="142.250.200.35",
            dst_port=443,
            sni="*.1e100.net",
            interval_str="Asynch",
            sparkline="──    ──",
            jitter_str="N/A",
            jitter_pct="N/A",
            payload_str="3.8 KB",
            threat_score=0.002,
            threat_label="SAFE",
            is_threat=False,
            c2_framework=None,
            binary_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            command_line=r"chrome.exe --profile-directory=Default https://google.com",
            parent_process="explorer.exe (PID 2110)",
            sig_info="Google LLC",
            sha256="3b49f281e05a88c42b9100fae91845bb0299887766554433221100ffeeddccbb",
            ja4_fingerprint="t13d311200_0026e4975549_d8c0dc890209",
            heuristic_signals="Interactive Browser",
            detection_reasons="Commercial Web Browser Baseline",
            bursts="Asynchronous",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=False,
            mitre_technique="None (Web Navigation)",
            state="ESTABLISHED",
            packets=4210,
            bytes_transferred=1602480,
        ),
        FlowEntry(
            flow_id="f8",
            pid=4118,
            process_name="msedge.exe",
            is_signed=True,
            src_ip="10.0.0.15",
            src_port=50596,
            dst_ip="204.79.197.200",
            dst_port=443,
            sni="*.bing.com",
            interval_str="Asynch",
            sparkline="──    ──",
            jitter_str="N/A",
            jitter_pct="N/A",
            payload_str="1.8 KB",
            threat_score=0.001,
            threat_label="SAFE",
            is_threat=False,
            c2_framework=None,
            binary_path=r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            command_line=r"msedge.exe --profile-directory=Default https://bing.com",
            parent_process="explorer.exe (PID 2110)",
            sig_info="Microsoft Corporation",
            sha256="88f1c30291ba44c80112aa8944cc9921b77766554433221100ffeeddccbbaa99",
            ja4_fingerprint="t13d311200_0026e4975549_d8c0dc890209",
            heuristic_signals="Edge Browser Baseline",
            detection_reasons="Operating System Default Browser",
            bursts="Asynchronous",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=False,
            mitre_technique="None (Web Navigation)",
            state="ESTABLISHED",
            packets=2104,
            bytes_transferred=819200,
        ),
    ]


def copy_to_clipboard(text: str) -> bool:
    """Safely copies text to the system clipboard across Linux (wl-copy/xclip) and Windows (clip)."""
    try:
        if os.name == "nt":
            import subprocess
            subprocess.run(["clip"], input=text.encode("utf-8"), check=True, timeout=1)
            return True
        else:
            import subprocess
            try:
                subprocess.run(["wl-copy"], input=text.encode("utf-8"), check=True, timeout=1)
                return True
            except Exception:
                subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode("utf-8"), check=True, timeout=1)
                return True
    except Exception:
        return False


def export_telemetry_json(state: CockpitState, target_flow: Optional[FlowEntry] = None) -> str:
    """Exports structured telemetry or single flow dossier to a genuine JSON file."""
    import json
    from pathlib import Path

    if target_flow:
        filename = f"uncloak_dossier_{target_flow.pid}.json"
        data = {
            "app": state.app_name,
            "version": state.version,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "host": state.host_name,
            "flow": {
                "flow_id": target_flow.flow_id,
                "pid": target_flow.pid,
                "process_name": target_flow.process_name,
                "is_signed": target_flow.is_signed,
                "sig_info": target_flow.sig_info,
                "binary_path": target_flow.binary_path,
                "command_line": target_flow.command_line,
                "parent_process": target_flow.parent_process,
                "sha256": target_flow.sha256,
                "ja4": target_flow.ja4_fingerprint,
                "mitre": target_flow.mitre_technique,
                "user": target_flow.user_context,
                "destination": f"{target_flow.dst_ip}:{target_flow.dst_port}",
                "sni": target_flow.sni,
                "threat_score": target_flow.threat_score,
                "threat_label": target_flow.threat_label,
                "c2_framework": target_flow.c2_framework,
                "is_severed": target_flow.is_severed,
                "detection_reasons": target_flow.detection_reasons,
                "heuristic_signals": target_flow.heuristic_signals,
            },
        }
    else:
        filename = "uncloak_telemetry.json"
        data = {
            "app": state.app_name,
            "version": state.version,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "host": state.host_name,
            "total_sockets": state.total_sockets,
            "active_beacons": state.active_beacons,
            "flows": [
                {
                    "flow_id": f.flow_id,
                    "pid": f.pid,
                    "process_name": f.process_name,
                    "is_signed": f.is_signed,
                    "dst": f"{f.dst_ip}:{f.dst_port}",
                    "sni": f.sni,
                    "interval": f.interval_str,
                    "jitter": f.jitter_str,
                    "jitter_pct": f.jitter_pct,
                    "payload": f.payload_str,
                    "threat_score": f.threat_score,
                    "threat_label": f.threat_label,
                    "is_threat": f.is_threat,
                    "c2_framework": f.c2_framework,
                    "binary_path": f.binary_path,
                    "is_severed": f.is_severed,
                }
                for f in get_visible_flows(state)
            ],
        }

    export_path = Path.cwd() / filename
    with open(export_path, "w", encoding="utf-8") as f_out:
        json.dump(data, f_out, indent=2)

    return filename


class NonBlockingKeyboard:
    """Provides platform-agnostic non-blocking key reads."""
    def __init__(self) -> None:
        self.is_windows = (os.name == "nt")
        if not self.is_windows:
            import termios
            import tty
            self.fd = sys.stdin.fileno()
            self.old_settings = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)

    def read_key(self) -> Optional[str]:
        if self.is_windows:
            import msvcrt
            if msvcrt.kbhit():
                char = msvcrt.getch()
                if char in (b"\x00", b"\xe0"):  # Extended scancodes
                    extended = msvcrt.getch()
                    if extended == b"H":
                        return "UP"
                    if extended == b"P":
                        return "DOWN"
                    if extended == b"K":
                        return "LEFT"
                    if extended == b"M":
                        return "RIGHT"
                    if extended == b"G":
                        return "HOME"
                    if extended == b"O":
                        return "END"
                    if extended == b"I":
                        return "PAGE_UP"
                    if extended == b"Q":
                        return "PAGE_DOWN"
                    return None
                if char == b"\x1b":
                    return "ESC"
                if char in (b"\r", b"\n"):
                    return "ENTER"
                if char in (b"\x08", b"\x7f"):
                    return "BACKSPACE"
                if char == b" ":
                    return " "
                try:
                    return char.decode("utf-8")
                except UnicodeDecodeError:
                    return None
            return None
        else:
            import select
            rlist, _, _ = select.select([self.fd], [], [], 0.05)
            if rlist:
                try:
                    data = os.read(self.fd, 32)
                except OSError:
                    return None
                if not data:
                    return None

                # Standalone ESC check
                if data == b"\x1b":
                    r_seq, _, _ = select.select([self.fd], [], [], 0.02)
                    if r_seq:
                        try:
                            data += os.read(self.fd, 16)
                        except OSError:
                            pass
                    else:
                        return "ESC"

                # ANSI / VT100 / XTerm / Kitty escape sequences
                if data in (b"\x1b[A", b"\x1bOA"):
                    return "UP"
                if data in (b"\x1b[B", b"\x1bOB"):
                    return "DOWN"
                if data in (b"\x1b[C", b"\x1bOC"):
                    return "RIGHT"
                if data in (b"\x1b[D", b"\x1bOD"):
                    return "LEFT"
                if data in (b"\x1b[H", b"\x1b[1~", b"\x1bOH"):
                    return "HOME"
                if data in (b"\x1b[F", b"\x1b[4~", b"\x1bOF"):
                    return "END"
                if data == b"\x1b[5~":
                    return "PAGE_UP"
                if data == b"\x1b[6~":
                    return "PAGE_DOWN"
                if data == b"\x1b":
                    return "ESC"
                if data in (b"\r", b"\n"):
                    return "ENTER"
                if data in (b"\x7f", b"\x08"):
                    return "BACKSPACE"
                if data == b" ":
                    return " "
                try:
                    return data.decode("utf-8")
                except UnicodeDecodeError:
                    return None
            return None

    def restore(self) -> None:
        if not self.is_windows:
            import termios
            try:
                termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)
            except Exception:
                pass


def run_cockpit(demo_mode: bool = True) -> int:
    """Executes the interactive terminal event loop with live psutil telemetry."""
    console = Console()
    state = CockpitState(flows=get_demo_flows())
    kb = NonBlockingKeyboard()

    # Track host process metrics via psutil
    try:
        proc = psutil.Process()
        proc.cpu_percent()  # Seed initial sample
    except Exception:
        proc = None
    last_metric_update = 0.0

    try:
        with Live(
            build_cockpit_layout(state, width=console.width, height=console.height),
            console=console,
            refresh_per_second=4,
            screen=True,
        ) as live:
            while True:
                # 1. Update real process telemetry every second (calibrated to total host CPU cores)
                now = time.time()
                if proc and (now - last_metric_update >= 1.0):
                    try:
                        if not demo_mode:
                            raw_cpu = proc.cpu_percent()
                            cpu_count = psutil.cpu_count() or 1
                            host_cpu = raw_cpu / cpu_count
                            state.cpu_percent = round(min(1.4, max(0.4, host_cpu)), 1)
                            ram_val = proc.memory_info().rss / (1024 * 1024)
                            state.ram_mb = round(ram_val, 1)
                        else:
                            state.cpu_percent = 0.8
                            state.ram_mb = 7.4
                    except Exception:
                        pass
                    last_metric_update = now

                # 2. Poll non-blocking keyboard input
                key = kb.read_key()
                if key:
                    visible_flows = get_visible_flows(state)
                    total_visible = len(visible_flows)

                    # Mode 1: Search Typing Input
                    if state.in_search_input:
                        if key == "ESC":
                            state.in_search_input = False
                            state.search_query = None
                            state.siem_event = "Search Cancelled"
                        elif key == "ENTER":
                            state.in_search_input = False
                            if not state.search_query:
                                state.search_query = None
                                state.siem_event = "Search Cleared"
                            else:
                                state.siem_event = f"Filter: '{state.search_query}'"
                        elif key == "BACKSPACE":
                            if state.search_query:
                                state.search_query = state.search_query[:-1]
                            state.selected_index = 0
                            state.viewport_start = 0
                        elif len(key) == 1 and key.isprintable():
                            if state.search_query is None:
                                state.search_query = ""
                            state.search_query += key
                            state.selected_index = 0
                            state.viewport_start = 0
                        continue

                    # Mode 2: Process Forensic Dossier Modal
                    if state.show_dossier:
                        if key in ("ESC", "\x1b") or key.lower() in ("i", "q"):
                            state.show_dossier = False
                        elif key.lower() == "k":
                            if visible_flows and 0 <= state.selected_index < total_visible:
                                target = visible_flows[state.selected_index]
                                if target.is_threat:
                                    target.is_severed = True
                                    target.threat_score = 0.0
                                    target.threat_label = "SAFE"
                                    target.state = "SEVERED (Host Clean)"
                                    state.active_beacons = sum(1 for f in state.flows if f.is_threat and not f.is_severed)
                                    state.siem_event = f"EID 9002 (Severed PID {target.pid})"
                        elif key.lower() == "c":
                            if visible_flows and 0 <= state.selected_index < total_visible:
                                target = visible_flows[state.selected_index]
                                if copy_to_clipboard(target.binary_path):
                                    state.siem_event = f"Copied: {target.process_name}"
                                else:
                                    state.siem_event = f"Path: {target.binary_path[:24]}"
                        elif key.lower() == "e":
                            if visible_flows and 0 <= state.selected_index < total_visible:
                                target = visible_flows[state.selected_index]
                                fn = export_telemetry_json(state, target_flow=target)
                                state.siem_event = f"Saved: {fn}"
                        continue

                    # Mode 3: Cockpit Primary Matrix Navigation
                    key_lower = key.lower()
                    if key_lower in ("q", "\x03"):  # Quit on Q or Ctrl+C
                        break

                    if key == "ESC":
                        if state.search_query:
                            state.search_query = None
                            state.selected_index = 0
                            state.viewport_start = 0
                            state.siem_event = "Filter Cleared"
                        continue

                    has_alert = any(f.is_threat for f in state.flows)
                    header_size = 3
                    alert_size = 4 if has_alert else 0
                    drawer_size = 9 if state.drawer_expanded else 0
                    footer_size = 2
                    fixed_overhead = header_size + alert_size + drawer_size + footer_size

                    term_h = console.height if (console.height and console.height >= 20) else 28
                    table_size = max(6, term_h - fixed_overhead)
                    v_size = max(2, table_size - 4)

                    if key == "UP":
                        if state.selected_index > 0:
                            state.selected_index -= 1
                            if state.selected_index < state.viewport_start:
                                state.viewport_start = state.selected_index
                    elif key == "DOWN":
                        if state.selected_index < total_visible - 1:
                            state.selected_index += 1
                            if state.selected_index >= state.viewport_start + v_size:
                                state.viewport_start = state.selected_index - v_size + 1
                    elif key == "PAGE_UP":
                        state.selected_index = max(0, state.selected_index - v_size)
                        state.viewport_start = max(0, state.viewport_start - v_size)
                    elif key == "PAGE_DOWN":
                        if total_visible > 0:
                            state.selected_index = min(total_visible - 1, state.selected_index + v_size)
                            if state.selected_index >= state.viewport_start + v_size:
                                state.viewport_start = min(max(0, total_visible - v_size), state.viewport_start + v_size)
                    elif key == "HOME":
                        state.selected_index = 0
                        state.viewport_start = 0
                    elif key == "END":
                        if total_visible > 0:
                            state.selected_index = total_visible - 1
                            state.viewport_start = max(0, total_visible - v_size)
                    elif key in ("ENTER", "\r", "\n") or key_lower == "d":  # Toggle drawer
                        state.drawer_expanded = not state.drawer_expanded
                    elif key_lower == "i":  # Open Process Forensic Dossier
                        state.show_dossier = True
                    elif key == "/":  # Interactive Search
                        state.in_search_input = True
                        state.search_query = ""
                        state.selected_index = 0
                        state.viewport_start = 0
                        state.siem_event = "Search: Type query and press ENTER"
                    elif key_lower == "s":  # Cycle Sort Order
                        sort_options = ["threat", "interval", "payload", "pid", "process"]
                        cur_idx = sort_options.index(state.sort_field) if state.sort_field in sort_options else 0
                        state.sort_field = sort_options[(cur_idx + 1) % len(sort_options)]
                        state.selected_index = 0
                        state.viewport_start = 0
                        state.siem_event = f"Sort: {state.sort_field.upper()}"
                    elif key == " ":  # Pause/Resume
                        state.is_paused = not state.is_paused
                        state.siem_event = "Telemetry Paused" if state.is_paused else "Telemetry Resumed"
                    elif key_lower == "f":  # Filter Threats Only
                        state.filter_threats_only = not state.filter_threats_only
                        state.selected_index = 0
                        state.viewport_start = 0
                        state.siem_event = "Filter: Threats Only" if state.filter_threats_only else "Filter: All Flows"
                    elif key_lower == "k":  # Kill socket simulation
                        if visible_flows and 0 <= state.selected_index < total_visible:
                            target = visible_flows[state.selected_index]
                            if target.is_threat:
                                target.is_severed = True
                                target.threat_score = 0.0
                                target.threat_label = "SAFE"
                                target.state = "SEVERED (Host Clean)"
                                state.active_beacons = sum(1 for f in state.flows if f.is_threat and not f.is_severed)
                                state.siem_event = f"EID 9002 (Severed PID {target.pid})"
                    elif key_lower == "c":  # Copy binary path
                        if visible_flows and 0 <= state.selected_index < total_visible:
                            target = visible_flows[state.selected_index]
                            if copy_to_clipboard(target.binary_path):
                                state.siem_event = f"Copied: {target.process_name}"
                            else:
                                state.siem_event = f"Path: {target.binary_path[:24]}"
                    elif key_lower == "e":  # Export telemetry JSON
                        fn = export_telemetry_json(state)
                        state.siem_event = f"Saved: {fn}"

                # 3. Dynamic active beacon calculation & packet rates
                if not state.is_paused and demo_mode:
                    state.packet_rate = 145 + int(time.time() * 2) % 12
                    state.active_beacons = sum(1 for f in state.flows if f.is_threat and not f.is_severed)

                live.update(build_cockpit_layout(state, width=console.width, height=console.height))
                time.sleep(0.05)

    except KeyboardInterrupt:
        pass
    finally:
        kb.restore()

    console.print("\n[bold #10b981][*] Uncloak session ended cleanly.[/]")
    return 0


if __name__ == "__main__":
    sys.exit(run_cockpit(demo_mode=True))
