"""
Interactive live runner and event loop for the Uncloak CUI cockpit.
Handles non-blocking cross-platform keyboard input and zero-flicker rendering.
"""

import os
import sys
import time
from typing import Optional

from rich.console import Console
from rich.live import Live

from uncloak.ui.layout import CockpitState, FlowEntry, build_cockpit_layout


def get_demo_flows() -> list[FlowEntry]:
    """Generates realistic demonstration flows for terminal testing."""
    return [
        FlowEntry(
            flow_id="f1",
            pid=4812,
            process_name="powershell.exe",
            is_signed=False,
            dst_ip="185.220.101.5",
            dst_port=443,
            sni="cdn-update-edge.azureedge.net",
            interval_str="8.4s ±0.8s",
            sparkline="▄ ▄ ▄ ▄ ▄ ▄",
            payload_str="284 B",
            threat_score=0.987,
            threat_level="CRITICAL",
            binary_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass -NoP -Enc JABjAD0AbgBlAHc...",
            parent_process="explorer.exe (4102)",
            user_token="CORP\\jdoe",
            is_elevated=False,
            state="ESTABLISHED",
            packets=182,
            bytes_transferred=51688,
            median_delta=8.42,
            iqr_spread=0.28,
            mad_jitter=0.14,
            entropy=0.88,
        ),
        FlowEntry(
            flow_id="f2",
            pid=9216,
            process_name="chrome.exe",
            is_signed=True,
            dst_ip="142.250.200.35",
            dst_port=443,
            sni="*.1e100.net",
            interval_str="Irregular",
            sparkline="█ ▄ ▇ ▂ █ ▄",
            payload_str="3.8 KB",
            threat_score=0.002,
            threat_level="SAFE",
            binary_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            command_line="chrome.exe --type=utility --utility-sub-type=network.mojom.NetworkService",
            parent_process="chrome.exe (3104)",
            user_token="CORP\\jdoe",
            is_elevated=False,
            state="ESTABLISHED",
            packets=4210,
            bytes_transferred=1602480,
            median_delta=0.04,
            iqr_spread=4.12,
            mad_jitter=2.88,
            entropy=4.25,
        ),
        FlowEntry(
            flow_id="f3",
            pid=3488,
            process_name="spoolsv.exe",
            is_signed=True,
            dst_ip="10.7.0.1",
            dst_port=443,
            sni="print.corp.local",
            interval_str="Inactive",
            sparkline="── ── ── ──",
            payload_str="0 B",
            threat_score=0.000,
            threat_level="SAFE",
            binary_path=r"C:\Windows\System32\spoolsv.exe",
            command_line="C:\\Windows\\System32\\spoolsv.exe",
            parent_process="services.exe (688)",
            user_token="NT AUTHORITY\\SYSTEM",
            is_elevated=True,
            state="ESTABLISHED",
            packets=12,
            bytes_transferred=840,
            median_delta=120.0,
            iqr_spread=15.2,
            mad_jitter=12.0,
            entropy=0.10,
        ),
        FlowEntry(
            flow_id="f4",
            pid=6120,
            process_name="svchost.exe",
            is_signed=True,
            dst_ip="20.189.173.1",
            dst_port=443,
            sni="*.azure.com",
            interval_str="12.0s ±1.2s",
            sparkline="▄ ▄ ▄ ▄ ▄ ▄",
            payload_str="820 B",
            threat_score=0.150,
            threat_level="LOW",
            binary_path=r"C:\Windows\System32\svchost.exe",
            command_line="svchost.exe -k netsvcs -p -s BITS",
            parent_process="services.exe (688)",
            user_token="NT AUTHORITY\\SYSTEM",
            is_elevated=True,
            state="ESTABLISHED",
            packets=84,
            bytes_transferred=68880,
            median_delta=12.05,
            iqr_spread=1.12,
            mad_jitter=0.85,
            entropy=1.20,
        ),
        FlowEntry(
            flow_id="f5",
            pid=7412,
            process_name="outlook.exe",
            is_signed=True,
            dst_ip="13.107.42.16",
            dst_port=443,
            sni="outlook.office365.com",
            interval_str="30.0s ±2.5s",
            sparkline="▂ ▂ ▂ ▂ ▂ ▂",
            payload_str="2.1 KB",
            threat_score=0.080,
            threat_level="SAFE",
            binary_path=r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            command_line="OUTLOOK.EXE",
            parent_process="explorer.exe (4102)",
            user_token="CORP\\jdoe",
            is_elevated=False,
            state="ESTABLISHED",
            packets=512,
            bytes_transferred=1075200,
            median_delta=30.02,
            iqr_spread=2.45,
            mad_jitter=1.80,
            entropy=2.15,
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
    """Executes the interactive terminal event loop."""
    console = Console()
    state = CockpitState(flows=get_demo_flows())
    kb = NonBlockingKeyboard()

    try:
        with Live(build_cockpit_layout(state), console=console, refresh_per_second=2, screen=True) as live:
            while True:
                # Poll non-blocking keyboard input
                key = kb.read_key()
                if key:
                    key_lower = key.lower()
                    if key_lower in ("q", "\x03"):  # Quit on Q or Ctrl+C
                        break
                    elif key == "UP":
                        state.selected_index = max(0, state.selected_index - 1)
                    elif key == "DOWN":
                        visible_count = len([f for f in state.flows if not state.filter_threats_only or f.threat_score >= 0.70])
                        state.selected_index = min(visible_count - 1, state.selected_index + 1)
                    elif key_lower in ("\r", "\n", "d"):  # Toggle drawer
                        state.drawer_expanded = not state.drawer_expanded
                    elif key == " ":  # Pause/Resume
                        state.is_paused = not state.is_paused
                    elif key_lower == "f":  # Filter threats only
                        state.filter_threats_only = not state.filter_threats_only
                        state.selected_index = 0
                    elif key_lower == "k":  # Kill socket simulation
                        if state.flows:
                            target = state.flows[state.selected_index]
                            target.state = "TERMINATED (SetTcpEntry)"
                            target.threat_score = 0.0

                # Subtle simulated live packet ticks if not paused
                if not state.is_paused and demo_mode:
                    state.packet_rate = 140 + int(time.time() * 2) % 15

                live.update(build_cockpit_layout(state))
                time.sleep(0.05)

    finally:
        kb.restore()

    console.print("\n[bold cyan][*] Uncloak session ended cleanly.[/]")
    return 0


if __name__ == "__main__":
    sys.exit(run_cockpit(demo_mode=True))
