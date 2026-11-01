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

from uncloak.ui.layout import CockpitState, FlowEntry, build_cockpit_layout


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
            sparkline="▂▄▆▅▆▇▅█",
            jitter_str="±0.8s",
            jitter_pct="9.5%",
            payload_str="512 B",
            threat_score=0.987,
            threat_label="CRIT",
            is_threat=True,
            c2_framework="Sliver C2",
            binary_path=r"C:\Users\Target\AppData\Roaming\update.exe",
            sig_info="Unsigned PE (In-Memory Hollowed)",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ja4_fingerprint="t13d1516h2_8daaf6152771_0266e33433e9",
            heuristic_signals="Periodicity (0.99) │ Low Jitter (9.5%)",
            detection_reasons="Direct IP (No SNI) │ Static 512B Beacon",
            bursts="14 bursts / 2m",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=False,
            mitre_technique="T1071.001 (Web C2: HTTPS)",
            state="ESTABLISHED",
            packets=182,
            bytes_transferred=51688,
        ),
        FlowEntry(
            flow_id="f2",
            pid=6712,
            process_name="rundll32.exe",
            is_signed=True,
            src_ip="10.0.0.15",
            src_port=49210,
            dst_ip="45.33.32.156",
            dst_port=8443,
            sni="cdn-azure-edge.net",
            interval_str="15.0s",
            sparkline="▅▆▆▅▆█",
            jitter_str="±1.1s",
            jitter_pct="7.3%",
            payload_str="1.2 KB",
            threat_score=0.942,
            threat_label="CRIT",
            is_threat=True,
            c2_framework="Cobalt Strike",
            binary_path=r"C:\Windows\System32\rundll32.exe",
            sig_info="Microsoft Windows (Proxy Exec)",
            sha256="7c12bf9810ac9b32e144a10f8bc9910cde4279ab2281a8c3d9a102ffbc41238a",
            ja4_fingerprint="t13d190800_261546b3f71c_f601b1a77409",
            heuristic_signals="High Periodicity (0.94) │ Uniform Payload",
            detection_reasons="Malleable C2 Profile │ Host Header Mismatch",
            bursts="8 bursts / 2m",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=False,
            mitre_technique="T1218.011 (Signed Binary Proxy: Rundll32)",
            state="ESTABLISHED",
            packets=96,
            bytes_transferred=24576,
        ),
        FlowEntry(
            flow_id="f3",
            pid=8830,
            process_name="powershell.exe",
            is_signed=True,
            src_ip="10.0.0.15",
            src_port=49722,
            dst_ip="185.220.101.5",
            dst_port=443,
            sni="api.telemetry-host.org",
            interval_str="60.0s",
            sparkline="▇▇▇▇▇",
            jitter_str="±2.4s",
            jitter_pct="4.0%",
            payload_str="768 B",
            threat_score=0.865,
            threat_label="HIGH",
            is_threat=True,
            c2_framework="Empire C2",
            binary_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            sig_info="Microsoft Windows (Catalog Signed)",
            sha256="99182abfc012781bcf4401a998bc41270ae19b88ef128456187900bba037b341",
            ja4_fingerprint="t13d1516h2_8daaf6152771_0266e33433e9",
            heuristic_signals="Periodicity (0.99) │ Low Jitter (<3%)",
            detection_reasons="Direct IP (No SNI) │ Static 768B Beacon",
            bursts="5 bursts / 5m",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=True,
            mitre_technique="T1059.001 (Command and Scripting: PowerShell)",
            state="SEVERED (Host Clean)",
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
            interval_str="Irregular",
            sparkline="▅ █ ▅",
            jitter_str="N/A",
            jitter_pct="N/A",
            payload_str="3.9 KB",
            threat_score=0.008,
            threat_label="SAFE",
            is_threat=False,
            c2_framework=None,
            binary_path=r"C:\Program Files\WindowsApps\teams.exe",
            sig_info="Microsoft Corporation",
            sha256="b148fa0172e04f9810bb4260aa781fbc02419a45610099881122334455667788",
            ja4_fingerprint="t13d311200_0026e4975549_d8c0dc890209",
            heuristic_signals="High Entropy Flow │ Aperiodic User Cadence",
            detection_reasons="Valid PKI Signature │ Enterprise Allowlist",
            bursts="Asynchronous",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=False,
            mitre_technique="None (Allowlisted Collaboration Suite)",
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
            interval_str="Irregular",
            sparkline="───",
            jitter_str="N/A",
            jitter_pct="N/A",
            payload_str="3.6 KB",
            threat_score=0.008,
            threat_label="SAFE",
            is_threat=False,
            c2_framework=None,
            binary_path=r"C:\Windows\System32\svchost.exe",
            sig_info="Microsoft Windows (Catalog Signed)",
            sha256="5a1098b10ef3341b8a99002477cbb14002fa1098112233445566778899aabbcc",
            ja4_fingerprint="t13d1516h2_8daaf6152771_0266e33433e9",
            heuristic_signals="Low Frequency Polling │ Non-repetitive Length",
            detection_reasons="Operating System Kernel Service Baseline",
            bursts="Asynchronous",
            user_context=r"NT AUTHORITY\SYSTEM",
            is_severed=False,
            mitre_technique="None (Core Windows Service)",
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
            sparkline="█ ▅",
            jitter_str="±0.5s",
            jitter_pct="5.0%",
            payload_str="780 B",
            threat_score=0.008,
            threat_label="SAFE",
            is_threat=False,
            c2_framework=None,
            binary_path=r"C:\Program Files\Docker\docker.exe",
            sig_info="Docker Inc.",
            sha256="89acbf0198aa47b60214ee00b891bcfa0014a5566778899aabbccddeeff00112",
            ja4_fingerprint="t13d1516h2_8daaf6152771_c2140bb063ea",
            heuristic_signals="Standard TLS Hello │ Normal HTTP Keep-Alive",
            detection_reasons="Verified Container Runtime Registry Sync",
            bursts="2 bursts / 5m",
            user_context=r"NT AUTHORITY\SYSTEM",
            is_severed=False,
            mitre_technique="None (Verified Developer Tooling)",
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
            interval_str="Irregular",
            sparkline="█ ▄ ▇  ▅",
            jitter_str="N/A",
            jitter_pct="N/A",
            payload_str="3.8 KB",
            threat_score=0.002,
            threat_label="SAFE",
            is_threat=False,
            c2_framework=None,
            binary_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            sig_info="Google LLC",
            sha256="3b49f281e05a88c42b9100fae91845bb0299887766554433221100ffeeddccbb",
            ja4_fingerprint="t13d311200_0026e4975549_d8c0dc890209",
            heuristic_signals="High Bandwidth Stream │ Bursty User Activity",
            detection_reasons="Commercial Web Browser Baseline",
            bursts="Asynchronous",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=False,
            mitre_technique="None (Standard User Web Navigation)",
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
            interval_str="Irregular",
            sparkline="▂       ▂",
            jitter_str="N/A",
            jitter_pct="N/A",
            payload_str="1.8 KB",
            threat_score=0.001,
            threat_label="SAFE",
            is_threat=False,
            c2_framework=None,
            binary_path=r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            sig_info="Microsoft Corporation",
            sha256="88f1c30291ba44c80112aa8944cc9921b77766554433221100ffeeddccbbaa99",
            ja4_fingerprint="t13d311200_0026e4975549_d8c0dc890209",
            heuristic_signals="Search Engine Telemetry │ Interactive Sessions",
            detection_reasons="Operating System Default Browser",
            bursts="Asynchronous",
            user_context=r"CORP\jdoe (Standard)",
            is_severed=False,
            mitre_technique="None (Standard User Web Navigation)",
            state="ESTABLISHED",
            packets=2104,
            bytes_transferred=819200,
        ),
    ]


class NonBlockingKeyboard:
    """Provides platform-agnostic non-blocking key reads."""
    def __init__(self) -> None:
        self.is_windows = (os.name == "nt")
        if not self.is_windows:
            import termios
            import tty
            self.old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())

    def read_key(self) -> Optional[str]:
        if self.is_windows:
            import msvcrt
            if msvcrt.kbhit():
                char = msvcrt.getch()
                if char in (b"\x00", b"\xe0"):  # Arrow keys / special keys
                    extended = msvcrt.getch()
                    if extended == b"H":
                        return "UP"
                    if extended == b"P":
                        return "DOWN"
                try:
                    return char.decode("utf-8")
                except UnicodeDecodeError:
                    return None
            return None
        else:
            import select
            rlist, _, _ = select.select([sys.stdin], [], [], 0.05)
            if rlist:
                ch = sys.stdin.read(1)
                if ch == "\x1b":  # Escape sequence for arrow keys
                    seq = sys.stdin.read(2)
                    if seq == "[A":
                        return "UP"
                    if seq == "[B":
                        return "DOWN"
                return ch
            return None

    def restore(self) -> None:
        if not self.is_windows:
            import termios
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_settings)


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
                # 1. Update real process telemetry every second
                now = time.time()
                if proc and (now - last_metric_update >= 1.0):
                    try:
                        cpu_val = proc.cpu_percent()
                        ram_val = proc.memory_info().rss / (1024 * 1024)
                        state.cpu_percent = round(cpu_val, 1)
                        state.ram_mb = round(ram_val, 1)
                    except Exception:
                        pass
                    last_metric_update = now

                # 2. Poll non-blocking keyboard input
                key = kb.read_key()
                if key:
                    key_lower = key.lower()
                    if key_lower in ("q", "\x03"):  # Quit on Q or Ctrl+C
                        break

                    visible_flows = [f for f in state.flows if f.is_threat] if state.filter_threats_only else state.flows
                    total_visible = len(visible_flows)
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
                    elif key_lower in ("\r", "\n", "d"):  # Toggle drawer
                        state.drawer_expanded = not state.drawer_expanded
                    elif key == " ":  # Pause/Resume
                        state.is_paused = not state.is_paused
                    elif key_lower == "f":  # Filter threats only
                        state.filter_threats_only = not state.filter_threats_only
                        state.selected_index = 0
                        state.viewport_start = 0
                    elif key_lower == "k":  # Kill socket simulation
                        if visible_flows and 0 <= state.selected_index < total_visible:
                            target = visible_flows[state.selected_index]
                            if target.is_threat:
                                target.is_severed = True
                                target.state = "SEVERED (Host Clean)"
                                state.active_beacons = sum(1 for f in state.flows if f.is_threat and not f.is_severed)
                                state.siem_event = "EID 9002 (Severed)"
                    elif key_lower == "e":  # Export PCAP simulation
                        state.siem_event = "PCAP Exported: capture.pcap"

                # 3. Dynamic active beacon calculation & packet rates
                if not state.is_paused and demo_mode:
                    state.packet_rate = 145 + int(time.time() * 2) % 12
                    state.active_beacons = sum(1 for f in state.flows if f.is_threat and not f.is_severed)

                live.update(build_cockpit_layout(state, width=console.width, height=console.height))
                time.sleep(0.05)

    finally:
        kb.restore()

    console.print("\n[bold #10b981][*] Uncloak session ended cleanly.[/]")
    return 0


if __name__ == "__main__":
    sys.exit(run_cockpit(demo_mode=True))
