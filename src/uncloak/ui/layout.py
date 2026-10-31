"""
Terminal layout generator for the Uncloak interactive CUI cockpit.
Implements the 7-column full-width telemetry matrix with a collapsible bottom drawer.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from rich.align import Align
from rich.console import RenderableType
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


@dataclass
class FlowEntry:
    """Represents a display row in the live flow matrix."""
    flow_id: str
    pid: int
    process_name: str
    is_signed: bool
    dst_ip: str
    dst_port: int
    sni: str
    interval_str: str
    sparkline: str
    payload_str: str
    threat_score: float
    threat_level: str  # SAFE, LOW, MED, HIGH, CRITICAL
    binary_path: str = ""
    command_line: str = ""
    parent_process: str = "explorer.exe (4102)"
    user_token: str = "NT AUTHORITY\\SYSTEM"
    is_elevated: bool = True
    state: str = "ESTABLISHED"
    packets: int = 142
    bytes_transferred: int = 40960
    median_delta: float = 8.4
    iqr_spread: float = 0.28
    mad_jitter: float = 0.15
    entropy: float = 0.88


@dataclass
class CockpitState:
    """Current state of the interactive terminal cockpit."""
    flows: list[FlowEntry] = field(default_factory=list)
    selected_index: int = 0
    drawer_expanded: bool = True
    is_paused: bool = False
    filter_threats_only: bool = False
    search_query: Optional[str] = None
    interface: str = "Ethernet0 (Npcap BPF 443)"
    packet_rate: int = 142
    active_beacons: int = 1
    cpu_percent: float = 0.8
    ram_mb: float = 8.2


def render_header(state: CockpitState) -> RenderableType:
    """Builds the compact upper system banner."""
    header_table = Table.grid(expand=True)
    header_table.add_column(ratio=1)
    header_table.add_column(ratio=2, justify="center")
    header_table.add_column(ratio=1, justify="right")

    left_text = Text()
    left_text.append("⚡ UNCLOAK ", style="bold cyan")
    left_text.append("v0.1.0", style="dim white")
    left_text.append(" │ ", style="dim")
    left_text.append(f"{state.interface}", style="white")

    center_text = Text()
    status_style = "bold yellow" if state.is_paused else "bold green"
    status_label = "● PAUSED" if state.is_paused else "● LIVE COCKPIT"
    center_text.append(status_label, style=status_style)
    center_text.append(f" │ {state.packet_rate} pkts/s", style="white")
    if state.active_beacons > 0:
        center_text.append(f" │ {state.active_beacons} BEACON ISOLATED", style="bold red")

    right_text = Text()
    right_text.append(f"CPU: {state.cpu_percent:.1f}% ", style="dim")
    right_text.append(f"RAM: {state.ram_mb:.1f} MB", style="dim")

    header_table.add_row(left_text, center_text, right_text)
    return Panel(header_table, style="dim white on #050811", border_style="dim blue")


def render_pinned_alert(top_threat: Optional[FlowEntry]) -> Optional[RenderableType]:
    """Renders pinned MITRE ATT&CK alert when a high-confidence threat is isolated."""
    if not top_threat or top_threat.threat_score < 0.75:
        return None

    alert_table = Table.grid(expand=True)
    alert_table.add_column(ratio=1)
    alert_table.add_column(ratio=1, justify="right")

    left = Text()
    left.append("🚨 CRITICAL C2 BEACON ISOLATED ", style="bold red on black")
    left.append("[MITRE T1071.001 Web Protocols] ", style="bold yellow")
    left.append(f"PID {top_threat.pid} ({top_threat.process_name}) ➔ {top_threat.dst_ip}:{top_threat.dst_port}", style="bold white")

    right = Text()
    right.append(f"CONFIDENCE: {top_threat.threat_score * 100:.1f}% ", style="bold red")
    right.append("│ Hotkey [K] to Kill Socket", style="bold green")

    alert_table.add_row(left, right)
    return Panel(alert_table, style="bold white on #1a0505", border_style="red")


def render_table(state: CockpitState) -> RenderableType:
    """Renders the full-width 7-column primary telemetry matrix."""
    table = Table(
        expand=True,
        box=None,
        pad_edge=False,
        show_header=True,
        header_style="bold bright_white on #0c1222",
    )

    table.add_column("PID", width=10, justify="left")
    table.add_column("PROCESS", width=18, justify="left")
    table.add_column("DESTINATION", width=22, justify="left")
    table.add_column("SNI / DOMAIN", width=26, justify="left")
    table.add_column("INTERVAL & CADENCE", width=24, justify="left")
    table.add_column("PAYLOAD", width=12, justify="right")
    table.add_column("THREAT SCORE", width=16, justify="right")

    visible_flows = state.flows
    if state.filter_threats_only:
        visible_flows = [f for f in state.flows if f.threat_score >= 0.70]

    if not visible_flows:
        table.add_row("", "", "No active network sessions matching criteria", "", "", "", "")
        return Panel(table, border_style="dim white")

    for idx, flow in enumerate(visible_flows):
        is_selected = (idx == state.selected_index)
        row_prefix = "► " if is_selected else "  "

        # Sign status
        sign_badge = "[✓]" if flow.is_signed else "[?]"
        sign_style = "green" if flow.is_signed else "yellow"
        pid_text = Text()
        pid_text.append(f"{row_prefix}{flow.pid} ", style="bold cyan" if is_selected else "white")
        pid_text.append(sign_badge, style=sign_style)

        # Process
        proc_style = "bold red" if flow.threat_score >= 0.80 else ("bold white" if is_selected else "white")
        proc_text = Text(flow.process_name, style=proc_style)

        # Destination & SNI
        dst_text = Text(f"{flow.dst_ip}:{flow.dst_port}", style="white")
        sni_text = Text(flow.sni or "<No SNI>", style="dim" if not flow.sni else "cyan")

        # Interval + Sparkline
        interval_text = Text()
        interval_text.append(f"{flow.interval_str:<8} ", style="yellow" if flow.threat_score >= 0.80 else "white")
        spark_style = "red" if flow.threat_score >= 0.80 else "green"
        interval_text.append(flow.sparkline, style=spark_style)

        # Payload
        payload_text = Text(flow.payload_str, style="white")

        # Threat Score
        threat_text = Text()
        if flow.threat_score >= 0.80:
            threat_text.append(f"{flow.threat_score * 100:.1f}% [CRIT]", style="bold red")
        elif flow.threat_score >= 0.50:
            threat_text.append(f"{flow.threat_score * 100:.1f}% [MED]", style="bold yellow")
        else:
            threat_text.append(f"{flow.threat_score * 100:.1f}% [SAFE]", style="dim green")

        # Row background for selection
        if is_selected:
            table.add_row(
                pid_text, proc_text, dst_text, sni_text, interval_text, payload_text, threat_text,
                style="on #162035",
            )
        else:
            table.add_row(pid_text, proc_text, dst_text, sni_text, interval_text, payload_text, threat_text)

    panel_title = f"Active Sessions ({len(visible_flows)} Flows)"
    if state.filter_threats_only:
        panel_title += " [FILTERED: Threats Only]"
    return Panel(table, title=panel_title, border_style="dim blue", padding=(0, 1))


def render_bottom_drawer(selected_flow: Optional[FlowEntry]) -> RenderableType:
    """Renders the 3-block horizontal forensic attribution drawer."""
    if not selected_flow:
        return Panel(Text("No session selected for inspection", style="dim center"), border_style="dim")

    drawer_layout = Table.grid(expand=True)
    drawer_layout.add_column(ratio=2)
    drawer_layout.add_column(ratio=2)
    drawer_layout.add_column(ratio=1)

    # Block 1: Host Attribution
    b1 = Table.grid(padding=(0, 1))
    b1.add_column(style="dim", width=14)
    b1.add_column(style="bold white")
    b1.add_row("Executable:", selected_flow.binary_path or f"C:\\Windows\\System32\\{selected_flow.process_name}")
    b1.add_row("Command Line:", selected_flow.command_line or f"{selected_flow.process_name} -Background")
    b1.add_row("Parent Process:", selected_flow.parent_process)
    b1.add_row("User Context:", f"{selected_flow.user_token} ({'ELEVATED' if selected_flow.is_elevated else 'Standard'})")
    panel_b1 = Panel(b1, title="[bold cyan]1. Local Host Attribution[/]", border_style="dim cyan")

    # Block 2: Cadence & Payload Dissection
    b2 = Table.grid(padding=(0, 1))
    b2.add_column(style="dim", width=14)
    b2.add_column(style="bold white")
    b2.add_row("Median Delta:", f"{selected_flow.median_delta:.2f}s (Jitter ±{selected_flow.iqr_spread * 100:.1f}%)")
    b2.add_row("IQR Spread:", f"{selected_flow.iqr_spread:.4f}s (Threshold: < 0.45s)")
    b2.add_row("MAD Deviation:", f"{selected_flow.mad_jitter:.4f}s")
    b2.add_row("Packet Entropy:", f"{selected_flow.entropy:.2f} (High Regularity)")
    panel_b2 = Panel(b2, title="[bold yellow]2. Cadence & Jitter Dissection[/]", border_style="dim yellow")

    # Block 3: Kernel Surgical Action
    b3 = Table.grid(padding=(0, 1))
    b3.add_column(style="dim", width=12)
    b3.add_column(style="bold white")
    b3.add_row("Socket State:", f"[{'red' if selected_flow.threat_score >= 0.8 else 'green'}]{selected_flow.state}[/]")
    b3.add_row("Action [K]:", "[bold red]Kill Socket (SetTcpEntry)[/]")
    b3.add_row("Action [W]:", "[bold yellow]WFP Block Remote IP[/]")
    b3.add_row("Action [E]:", "[bold cyan]Dump Flow PCAP[/]")
    panel_b3 = Panel(b3, title="[bold red]3. Kernel Mitigation[/]", border_style="dim red")

    drawer_layout.add_row(panel_b1, panel_b2, panel_b3)
    return Panel(drawer_layout, title="Forensic Telemetry Drawer [ENTER/D to Toggle]", border_style="blue")


def render_footer(state: CockpitState) -> RenderableType:
    """Renders the ergonomic bottom hotkey guide."""
    footer_text = Text()
    hotkeys = [
        ("[↑/↓]", "Select"),
        ("[ENTER/D]", "Detail" if not state.drawer_expanded else "Collapse"),
        ("[K]", "Kill Socket"),
        ("[SPACE]", "Resume" if state.is_paused else "Pause"),
        ("[F]", "All Flows" if state.filter_threats_only else "Filter Threats"),
        ("[E]", "Dump PCAP"),
        ("[Q]", "Quit"),
    ]
    for key, action in hotkeys:
        footer_text.append(f"{key} ", style="bold cyan")
        footer_text.append(f"{action}  ", style="white")

    return Align.center(footer_text)


def build_cockpit_layout(state: CockpitState) -> Layout:
    """Assembles the complete master layout for the terminal."""
    root = Layout(name="root")
    
    top_threat = next((f for f in state.flows if f.threat_score >= 0.80), None)
    pinned_alert = render_pinned_alert(top_threat)

    if pinned_alert:
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="alert", size=3),
            Layout(name="main_table"),
            Layout(name="drawer", size=10 if state.drawer_expanded else 0),
            Layout(name="footer", size=1),
        )
        root["alert"].update(pinned_alert)
    else:
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="main_table"),
            Layout(name="drawer", size=10 if state.drawer_expanded else 0),
            Layout(name="footer", size=1),
        )

    root["header"].update(render_header(state))
    root["main_table"].update(render_table(state))
    
    if state.drawer_expanded:
        selected_flow = state.flows[state.selected_index] if state.flows else None
        root["drawer"].update(render_bottom_drawer(selected_flow))
        
    root["footer"].update(render_footer(state))
    return root
