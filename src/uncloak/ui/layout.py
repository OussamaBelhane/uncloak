"""
Terminal layout generator for the Uncloak interactive CUI cockpit.
Implements the high-density telemetry matrix strictly adhering to the HTML master design.
Zero AI emojis, zero column wrapping, and pixel-perfect monospace alignment.
"""

from dataclasses import dataclass, field
from typing import Optional

from rich import box
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
    interval_str: str       # "8.4s", "Irregular", "15.0s", "Inactive"
    sparkline: str          # "▄▆▅▆▇▅▆▆", "█ ▄ ▇  ▅", "── ──"
    jitter_str: str         # "±0.8s", "N/A"
    jitter_pct: str         # "9.5%", "7.3%", "N/A"
    payload_str: str        # "512 B", "3.8 KB"
    threat_score: float     # 0.0 - 1.0
    threat_label: str       # "CRIT", "HIGH", "MED", "SAFE"
    is_threat: bool
    binary_path: str = ""
    sig_info: str = "Unsigned PE"
    sha256: str = "e3b0c44298fc1c14..."
    bursts: str = "14 bursts / 2m"
    user_context: str = "CORP\\jdoe"
    is_severed: bool = False
    mitre_technique: str = "T1071.001 (Web C2)"
    state: str = "ESTABLISHED"
    packets: int = 142
    bytes_transferred: int = 40960


@dataclass
class CockpitState:
    """Current state of the interactive terminal cockpit."""
    flows: list[FlowEntry] = field(default_factory=list)
    selected_index: int = 0
    viewport_start: int = 0
    drawer_expanded: bool = True
    is_paused: bool = False
    filter_threats_only: bool = False
    search_query: Optional[str] = None
    host_name: str = "WIN-SRV01"
    bpf_filter: str = "443,8443"
    packet_rate: int = 151
    active_beacons: int = 1
    cpu_percent: float = 0.8
    ram_mb: float = 7.4
    siem_event: str = "EID 9002"


def render_header(state: CockpitState) -> RenderableType:
    """Builds the compact upper system banner without emojis."""
    header_grid = Table.grid(expand=True)
    header_grid.add_column(ratio=6)
    header_grid.add_column(ratio=5, justify="right")

    left = Text()
    left.append("UNCLOAK ", style="bold #10b981")
    left.append("v0.1.0", style="dim white")
    left.append(" │ ", style="#475569")
    left.append("HOST: ", style="#94a3b8")
    left.append(f"{state.host_name}", style="bold white")
    left.append(" │ ", style="#475569")
    left.append("BPF: ", style="#94a3b8")
    left.append(f"{state.bpf_filter}", style="white")
    left.append(" │ ", style="#475569")
    left.append("FLOWS: ", style="#94a3b8")
    left.append(f"{len(state.flows)}", style="bold #06b6d4")

    right = Text()
    right.append("CPU: ", style="#94a3b8")
    right.append(f"{state.cpu_percent:.1f}%", style="bold #10b981")
    right.append(" │ ", style="#475569")
    right.append("RAM: ", style="#94a3b8")
    right.append(f"{state.ram_mb:.1f}M", style="bold #10b981")
    right.append(" │ ", style="#475569")
    if state.is_paused:
        right.append("● PAUSED", style="bold #f59e0b")
    else:
        right.append("● ACTIVE (2s)", style="bold #10b981")
    right.append(" │ ", style="#475569")
    right.append(f"{state.siem_event}", style="bold #10b981")

    header_grid.add_row(left, right)
    return Panel(
        header_grid,
        box=box.ROUNDED,
        style="on #090e1c",
        border_style="#1e293b",
        padding=(0, 1),
    )


def render_pinned_alert(top_threat: Optional[FlowEntry]) -> Optional[RenderableType]:
    """Renders pinned MITRE ATT&CK alert when a high-confidence threat is isolated."""
    if not top_threat or not top_threat.is_threat:
        return None

    alert_grid = Table.grid(expand=True)
    alert_grid.add_column(ratio=6)
    alert_grid.add_column(ratio=5, justify="right")

    al1 = Text()
    al1.append(" CRITICAL C2 ALERT ", style="bold white on #dc2626")
    al1.append("  ")
    al1.append("PERSISTENT PERIODIC BEACON ISOLATED", style="bold #fca5a5")

    ar1 = Text()
    ar1.append("MITRE ATT&CK: ", style="#94a3b8")
    ar1.append("T1071.001", style="bold white")

    alert_grid.add_row(al1, ar1)

    al2 = Text()
    al2.append("TARGET: ", style="#94a3b8")
    al2.append(f"{top_threat.dst_ip}:{top_threat.dst_port}", style="bold #ef4444")
    al2.append(" (Sliver C2)", style="#64748b")
    al2.append(" │ ", style="#475569")
    al2.append("PID: ", style="#94a3b8")
    al2.append(f"{top_threat.pid}", style="bold white")
    al2.append(f" ({top_threat.process_name})", style="#64748b")

    ar2 = Text()
    if top_threat.is_severed:
        ar2.append("ACTION: SetTcpEntry -> RST Injected", style="bold #10b981")
    else:
        ar2.append("ACTION: [K] SetTcpEntry -> RST", style="bold #f59e0b")
    ar2.append(" │ ", style="#475569")
    ar2.append("EID 9002", style="bold white")

    alert_grid.add_row(al2, ar2)
    return Panel(
        alert_grid,
        box=box.ROUNDED,
        style="on #180808",
        border_style="#b91c1c",
        padding=(0, 1),
    )


def render_table(state: CockpitState) -> RenderableType:
    """Renders the full-width 7-column primary telemetry matrix."""
    visible_flows = state.flows
    if state.filter_threats_only:
        visible_flows = [f for f in state.flows if f.is_threat]

    total = len(visible_flows)
    v_size = 6 if state.drawer_expanded else 16
    start = max(0, min(state.viewport_start, max(0, total - v_size)))
    end = min(total, start + v_size)
    slice_flows = visible_flows[start:end]

    # Sub-Header bar
    sub_header = Table.grid(expand=True)
    sub_header.add_column(ratio=1)
    sub_header.add_column(ratio=1, justify="right")

    sh_left = Text()
    sh_left.append(f"ACTIVE FLOWS ({total})", style="bold white")
    if state.filter_threats_only:
        sh_left.append(" [FILTERED: Threats Only]", style="bold #f59e0b")

    sh_right = Text()
    curr_pos = min(total, state.selected_index + 1) if total > 0 else 0
    sh_right.append(f"[ {curr_pos}/{total} ]", style="bold #06b6d4")
    sh_right.append(" │ ", style="#475569")
    scroll_pct = 0 if total <= v_size else int((start / max(1, total - v_size)) * 100)
    scroll_label = "[ Top ]" if scroll_pct == 0 else ("[ Bottom ]" if scroll_pct >= 100 else f"[ {scroll_pct}% ]")
    sh_right.append(scroll_label, style="#64748b")
    sh_right.append(" │ ", style="#475569")
    sh_right.append("[ENTER] Toggle Drawer", style="#94a3b8")

    sub_header.add_row(sh_left, sh_right)

    # 7-Column Table with carefully balanced widths totaling 116 chars
    table = Table(
        box=None,
        expand=True,
        pad_edge=False,
        show_header=True,
        header_style="bold #94a3b8 on #090e1c",
    )
    table.add_column("PID", width=8, no_wrap=True)
    table.add_column("PROCESS", width=19, no_wrap=True)
    table.add_column("DESTINATION", width=21, no_wrap=True)
    table.add_column("SNI / DOMAIN", width=25, no_wrap=True)
    table.add_column("INTERVAL", width=20, no_wrap=True)
    table.add_column("PAYLOAD", width=9, justify="right", no_wrap=True)
    table.add_column("THREAT", width=14, justify="right", no_wrap=True)

    if not slice_flows:
        table.add_row("", "", "No active network sessions matching criteria", "", "", "", "")
    else:
        for idx, flow in enumerate(slice_flows):
            global_idx = start + idx
            is_selected = (global_idx == state.selected_index)
            is_threat = flow.is_threat

            # PID
            prefix = "► " if is_selected else "  "
            pid_style = "bold #ef4444" if is_threat else ("bold #06b6d4" if is_selected else "#64748b")
            c_pid = Text(f"{prefix}{flow.pid}", style=pid_style)

            # Process + Tag
            c_proc = Text()
            proc_style = "bold #fca5a5" if is_threat else ("bold white" if is_selected else "white")
            c_proc.append(f"{flow.process_name} ", style=proc_style)
            tag = "✓" if flow.is_signed else "?"
            tag_style = "bold #10b981" if flow.is_signed else "bold #ef4444"
            c_proc.append(tag, style=tag_style)

            # Destination
            dst_style = "bold #ef4444" if is_threat else ("white" if is_selected else "#94a3b8")
            c_dst = Text(f"{flow.dst_ip}:{flow.dst_port}", style=dst_style)

            # SNI / Domain
            sni_str = flow.sni if flow.sni else "[Raw IP / No SNI]"
            sni_style = "dim #fca5a5" if is_threat else ("#38bdf8" if is_selected else "#64748b")
            c_sni = Text(sni_str, style=sni_style)

            # Interval & Cadence
            c_int = Text()
            int_style = "bold #f59e0b" if is_threat else ("white" if is_selected else "#94a3b8")
            c_int.append(f"{flow.interval_str:<9} ", style=int_style)
            spark_style = "bold #ef4444" if is_threat else "#10b981"
            c_int.append(flow.sparkline, style=spark_style)

            # Payload
            c_pay = Text(flow.payload_str, style="white" if is_selected else "#94a3b8")

            # Threat Score Badge
            c_thr = Text()
            if flow.threat_score >= 0.80:
                c_thr.append(f" {flow.threat_score * 100:.1f}% CRIT ", style="bold white on #dc2626")
            elif flow.threat_score >= 0.50:
                c_thr.append(f" {flow.threat_score * 100:.1f}% MED ", style="bold black on #f59e0b")
            else:
                c_thr.append(f"{flow.threat_score * 100:.1f}% SAFE", style="bold #10b981")

            # Row background style
            if is_threat:
                row_bg = "on #2d0c0c" if is_selected else "on #1a0808"
            else:
                row_bg = "on #131e33" if is_selected else None

            table.add_row(c_pid, c_proc, c_dst, c_sni, c_int, c_pay, c_thr, style=row_bg)

    # Sub-Footer scrollbar track
    sub_footer = Table.grid(expand=True)
    sub_footer.add_column(ratio=1)
    sub_footer.add_column(ratio=1, justify="right")

    sf_left = Text()
    sf_left.append("Scroll: ", style="#64748b")
    bar_len = 16
    thumb_pos = int((scroll_pct / 100.0) * (bar_len - 3)) if total > v_size else 0
    bar_chars = ["-"] * bar_len
    for b in range(thumb_pos, min(bar_len, thumb_pos + 3)):
        bar_chars[b] = "="
    sf_left.append(f"[{''.join(bar_chars)}] ", style="bold #06b6d4")
    sf_left.append(f"{scroll_pct}%", style="#94a3b8")

    sf_right = Text()
    sf_right.append("Navigate: ", style="#64748b")
    sf_right.append("↑/↓", style="bold white")
    sf_right.append(" or ", style="#64748b")
    sf_right.append("PgUp/PgDn", style="bold white")
    sf_right.append(" │ ", style="#475569")
    sf_right.append("Top/Bottom: ", style="#64748b")
    sf_right.append("Home/End", style="bold white")

    sub_footer.add_row(sf_left, sf_right)

    container = Table.grid(expand=True)
    container.add_column()
    container.add_row(sub_header)
    container.add_row(Text(""))
    container.add_row(table)
    container.add_row(Text(""))
    container.add_row(sub_footer)

    return Panel(
        container,
        box=box.ROUNDED,
        style="on #090e1c",
        border_style="#1e293b",
        padding=(0, 1),
    )


def render_bottom_drawer(selected_flow: Optional[FlowEntry]) -> RenderableType:
    """Renders the 3-block horizontal forensic attribution drawer strictly matching HTML."""
    if not selected_flow:
        return Panel(Text("No session selected for inspection", style="dim center"), border_style="#1e293b")

    dt = Table.grid(expand=True)
    dt.add_column(ratio=1)
    dt.add_column(ratio=1, justify="right")
    dt.add_row(
        Text(f"DETAIL : {selected_flow.dst_ip}:{selected_flow.dst_port} (PID {selected_flow.pid})", style="bold #f59e0b"),
        Text("[ENTER] Collapse", style="#94a3b8"),
    )

    # Card 1: Host Attribution
    t1 = Table.grid(padding=(0, 0))
    t1.add_column(style="#64748b", width=15)
    t1.add_column(style="white", width=19)
    t1.add_row("• PID        : ", Text(str(selected_flow.pid), style="bold white"))
    proc_style = "bold #ef4444" if selected_flow.is_threat else "bold white"
    t1.add_row("• Process    : ", Text(selected_flow.process_name, style=proc_style))
    path_display = selected_flow.binary_path
    if len(path_display) > 19:
        path_display = path_display[:8] + "..." + path_display[-8:]
    t1.add_row("• Binary     : ", Text(path_display, style="#94a3b8"))
    sig_style = "bold #ef4444" if not selected_flow.is_signed else "bold #10b981"
    t1.add_row("• Signature  : ", Text(selected_flow.sig_info, style=sig_style))
    t1.add_row("• SHA256     : ", Text(selected_flow.sha256[:15] + "...", style="#64748b"))
    t1.add_row("• Context    : ", Text(selected_flow.user_context[:18], style="#94a3b8"))
    p1 = Panel(
        t1,
        title="[bold #10b981][ HOST ATTRIBUTION ][/]",
        box=box.ROUNDED,
        style="on #060913",
        border_style="#1e293b",
        padding=(0, 1),
    )

    # Card 2: Cadence & Timing
    t2 = Table.grid(padding=(0, 0))
    t2.add_column(style="#64748b", width=15)
    t2.add_column(style="white", width=19)
    t2.add_row("• Interval   : ", Text(f"{selected_flow.interval_str} ({selected_flow.jitter_str})", style="white"))
    pulse_status = f"Active ({selected_flow.interval_str})" if selected_flow.is_threat else "Asynchronous"
    pulse_style = "bold #ef4444" if selected_flow.is_threat else "#94a3b8"
    t2.add_row("• Heartbeat  : ", Text(pulse_status, style=pulse_style))
    spark_label = f"{selected_flow.sparkline} (Rigid)" if selected_flow.is_threat else f"{selected_flow.sparkline} (Normal)"
    t2.add_row("• Pulse      : ", Text(spark_label, style=pulse_style))
    t2.add_row("• Payload    : ", Text(f"{selected_flow.payload_str} ({'Fixed' if selected_flow.is_threat else 'Dynamic'})", style="white"))
    t2.add_row("• Bursts     : ", Text(selected_flow.bursts, style="#94a3b8"))
    jitter_label = f"{selected_flow.jitter_pct} (Anom)" if selected_flow.is_threat else f"{selected_flow.jitter_pct} (Norm)"
    t2.add_row("• Jitter     : ", Text(jitter_label, style=pulse_style))
    p2 = Panel(
        t2,
        title="[bold #f59e0b][ CADENCE & TIMING ][/]",
        box=box.ROUNDED,
        style="on #060913",
        border_style="#1e293b",
        padding=(0, 1),
    )

    # Card 3: Forensic & MITRE
    t3 = Table.grid(padding=(0, 0))
    t3.add_column(style="#64748b", width=15)
    t3.add_column(style="white", width=19)
    t3.add_row("• MITRE      : ", Text(selected_flow.mitre_technique[:18], style="bold white"))
    t3.add_row("• API        : ", Text("SetTcpEntry", style="bold #06b6d4"))
    action_str = "TCP RST Injected" if selected_flow.is_severed else "Stack Inject Ready"
    action_style = "bold #10b981" if selected_flow.is_severed else "bold #f59e0b"
    t3.add_row("• Action     : ", Text(action_str, style=action_style))
    state_str = "SEVERED (Clean)" if selected_flow.is_severed else selected_flow.state
    state_style = "bold #10b981" if selected_flow.is_severed else "bold #ef4444"
    t3.add_row("• State      : ", Text(state_str, style=state_style))
    t3.add_row("• Audit      : ", Text("SQLite #142", style="#94a3b8"))
    t3.add_row("• Event      : ", Text("EID 9002 Alert", style="bold white"))
    p3 = Panel(
        t3,
        title="[bold #06b6d4][ FORENSIC & MITRE ][/]",
        box=box.ROUNDED,
        style="on #060913",
        border_style="#1e293b",
        padding=(0, 1),
    )

    dg = Table.grid(expand=True)
    dg.add_column(ratio=1)
    dg.add_column(ratio=1)
    dg.add_column(ratio=1)
    dg.add_row(p1, p2, p3)

    drawer_container = Table.grid(expand=True)
    drawer_container.add_column()
    drawer_container.add_row(dt)
    drawer_container.add_row(dg)

    return Panel(
        drawer_container,
        box=box.ROUNDED,
        style="on #090e1c",
        border_style="#1e293b",
        padding=(0, 1),
    )


def render_footer(state: CockpitState) -> RenderableType:
    """Renders the pristine UNIX hotkey guide matching HTML."""
    footer_grid = Table.grid(expand=True)
    footer_grid.add_column(ratio=6)
    footer_grid.add_column(ratio=1, justify="right")

    fl = Text()
    fl.append("↑/↓ ", style="bold white on #1e293b")
    fl.append("Select  ", style="#94a3b8")
    fl.append("ENTER ", style="bold white on #1e293b")
    fl.append("Detail  ", style="#94a3b8")
    fl.append("/ ", style="bold #06b6d4 on #1e293b")
    fl.append("Search  ", style="#94a3b8")
    fl.append("S ", style="bold #f59e0b on #1e293b")
    fl.append("Sort  ", style="#94a3b8")
    fl.append("K ", style="bold #ef4444 on #1e293b")
    fl.append("Kill  ", style="#94a3b8")
    fl.append("SPACE ", style="bold white on #1e293b")
    pause_label = "Resume  " if state.is_paused else "Pause  "
    fl.append(pause_label, style="#94a3b8")
    fl.append("F ", style="bold white on #1e293b")
    filter_label = "All Flows  " if state.filter_threats_only else "Filter  "
    fl.append(filter_label, style="#94a3b8")
    fl.append("E ", style="bold white on #1e293b")
    fl.append("PCAP", style="#94a3b8")

    fr = Text()
    fr.append("│  ", style="#475569")
    fr.append("Q ", style="bold white on #1e293b")
    fr.append("Quit", style="#94a3b8")

    footer_grid.add_row(fl, fr)
    return Panel(
        footer_grid,
        box=box.ROUNDED,
        style="on #050811",
        border_style="#1e293b",
        padding=(0, 1),
    )


def build_cockpit_layout(state: CockpitState) -> Layout:
    """Assembles the complete master layout for the terminal."""
    root = Layout(name="root")
    
    top_threat = next((f for f in state.flows if f.is_threat and not f.is_severed), None)
    if not top_threat:
        top_threat = next((f for f in state.flows if f.is_threat), None)
    pinned_alert = render_pinned_alert(top_threat)

    if pinned_alert:
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="alert", size=4),
            Layout(name="main_table"),
            Layout(name="drawer", size=10 if state.drawer_expanded else 0),
            Layout(name="footer", size=3),
        )
        root["alert"].update(pinned_alert)
    else:
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="main_table"),
            Layout(name="drawer", size=10 if state.drawer_expanded else 0),
            Layout(name="footer", size=3),
        )

    root["header"].update(render_header(state))
    root["main_table"].update(render_table(state))
    
    if state.drawer_expanded:
        selected_flow = None
        visible_flows = [f for f in state.flows if f.is_threat] if state.filter_threats_only else state.flows
        if visible_flows and 0 <= state.selected_index < len(visible_flows):
            selected_flow = visible_flows[state.selected_index]
        root["drawer"].update(render_bottom_drawer(selected_flow))
        
    root["footer"].update(render_footer(state))
    return root
