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
    c2_framework: Optional[str] = None
    binary_path: str = ""
    sig_info: str = "Unsigned PE"
    sha256: str = "e3b0c44298fc1c14..."
    bursts: str = "14 bursts / 2m"
    user_context: str = "CORP\\jdoe (Standard)"
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
    app_name: str = "BEACONHUNTER"
    version: str = "v1.0.0"
    host_name: str = "WIN-PROD-SRV01 (X64)"
    bpf_filter: str = "TCP/443,8443"
    total_sockets: int = 124
    packet_rate: int = 151
    active_beacons: int = 1
    cpu_percent: float = 0.8
    ram_mb: float = 7.5
    siem_event: str = "EID 9002"


def render_header(state: CockpitState, width: int = 120) -> RenderableType:
    """Builds the compact upper system banner without emojis matching HTML."""
    inner_w = max(80, width - 4)

    l = Text()
    l.append(f"{state.app_name} ", style="bold #10b981")
    l.append(f"{state.version}", style="bold #10b981")
    l.append(" │ ", style="#334155")
    l.append("HOST: ", style="#64748b")
    if inner_w >= 148:
        l.append("WIN-PROD-SRV01", style="bold white")
        l.append(" (X64)", style="#94a3b8")
    elif inner_w >= 126:
        l.append("WIN-PROD", style="bold white")
        l.append(" (X64)", style="#94a3b8")
    else:
        l.append("WIN-PROD", style="bold white")
    l.append(" │ ", style="#334155")
    l.append("BPF: ", style="#64748b")
    bpf_display = state.bpf_filter if inner_w >= 126 else "443,8443"
    l.append(f"{bpf_display}", style="bold white")
    l.append(" │ ", style="#334155")
    sock_label = "TOTAL SOCKETS: " if inner_w >= 148 else "SOCKETS: "
    l.append(sock_label, style="#64748b")
    l.append(f"{state.total_sockets}", style="bold #06b6d4")

    r = Text()
    r.append("CPU: ", style="#64748b")
    r.append(f"{state.cpu_percent:.1f}%", style="bold #10b981")
    r.append(" │ ", style="#334155")
    r.append("RAM: ", style="#64748b")
    r.append(f"{state.ram_mb:.1f} MB", style="bold #10b981")
    r.append(" │ ", style="#334155")
    if state.is_paused:
        r.append("● PAUSED", style="bold #f59e0b")
    else:
        r.append("● ACTIVE (2s)", style="bold #10b981")
    r.append(" │ ", style="#334155")
    siem_prefix = "SIEM: " if inner_w >= 120 else ""
    r.append(f"{siem_prefix}{state.siem_event}", style="bold #10b981")

    l_len = len(l.plain)
    r_len = len(r.plain)
    spaces = max(1, inner_w - l_len - r_len)

    header_text = Text()
    header_text.append_text(l)
    header_text.append(" " * spaces)
    header_text.append_text(r)

    return Panel(
        header_text,
        box=box.ROUNDED,
        style="on #090e1c",
        border_style="#1e293b",
        padding=(0, 1),
    )


def render_pinned_alert(top_threat: Optional[FlowEntry], width: int = 120) -> Optional[RenderableType]:
    """Renders pinned MITRE ATT&CK alert strictly matching the 2-line HTML card."""
    if not top_threat or not top_threat.is_threat:
        return None

    inner_w = max(80, width - 4)

    # Line 1
    l1 = Text()
    l1.append(" CRITICAL C2 ALERT ", style="bold white on #dc2626")
    l1.append("  ")
    l1.append("PERSISTENT PERIODIC BEACON ISOLATED", style="bold #fca5a5")

    r1 = Text()
    r1.append("MITRE ATT&CK: ", style="#94a3b8")
    r1.append("T1071.001", style="bold white")

    sp1 = max(1, inner_w - len(l1.plain) - len(r1.plain))
    row1 = Text()
    row1.append_text(l1)
    row1.append(" " * sp1)
    row1.append_text(r1)

    # Line 2
    l2 = Text()
    l2.append("TARGET: ", style="#94a3b8")
    l2.append(f"{top_threat.dst_ip}:{top_threat.dst_port}", style="bold #ef4444")
    if top_threat.c2_framework:
        l2.append(f" ({top_threat.c2_framework})", style="#94a3b8")
    l2.append(" │ ", style="#334155")
    l2.append("PID: ", style="#94a3b8")
    l2.append(f"{top_threat.pid}", style="bold white")
    l2.append(f" ({top_threat.process_name})", style="#94a3b8")

    r2 = Text()
    action_str = "ACTION: SetTcpEntry -> RST Injected" if (top_threat.is_severed or inner_w >= 120) else "ACTION: [K] SetTcpEntry -> RST"
    r2.append(action_str, style="bold #10b981")
    r2.append("        ")
    r2.append("EVENT: ", style="#94a3b8")
    r2.append("EID 9002 Dispatched", style="bold white")

    sp2 = max(1, inner_w - len(l2.plain) - len(r2.plain))
    row2 = Text()
    row2.append_text(l2)
    row2.append(" " * sp2)
    row2.append_text(r2)

    content = Text()
    content.append_text(row1)
    content.append("\n")
    content.append_text(row2)

    return Panel(
        content,
        box=box.ROUNDED,
        style="on #180808",
        border_style="#b91c1c",
        padding=(0, 1),
    )


def render_table(state: CockpitState, width: int = 120) -> RenderableType:
    """Renders the full-width 7-column primary telemetry matrix matching HTML."""
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
    sub_header.add_column(no_wrap=True)
    sub_header.add_column(justify="right", no_wrap=True)

    sh_left = Text()
    sh_left.append(f"ACTIVE FLOWS ({state.total_sockets})", style="bold white")
    if state.filter_threats_only:
        sh_left.append(" [FILTERED: Threats Only]", style="bold #f59e0b")

    sh_right = Text()
    curr_pos = min(total, state.selected_index + 1) if total > 0 else 0
    sh_right.append(f"[ {curr_pos}/{state.total_sockets} ]", style="bold #06b6d4")
    sh_right.append(" │ ", style="#334155")

    # Dynamic scrollbar track & thumb (relocated from sub-footer)
    total_items = max(total, state.total_sockets) if state.total_sockets > 0 else max(1, total)
    v_count = len(slice_flows)
    if total > v_count and total > 0:
        pct_val = max(8, min(100, int(round((start + v_count) / total_items * 100))))
        max_offset = 14
        offset = min(max_offset, int((start / max(1, total - v_count)) * max_offset))
        track_before = "─" * offset
        track_after = "─" * (max_offset - offset)
    else:
        pct_val = 8
        track_before = ""
        track_after = "──────────────"

    sh_right.append("Scroll: ", style="#64748b")
    if track_before:
        sh_right.append(track_before, style="#1e293b")
    sh_right.append("▬▬", style="bold #06b6d4")
    if track_after:
        sh_right.append(track_after, style="#1e293b")
    sh_right.append(f" {pct_val}%", style="#64748b")
    sh_right.append(" │ ", style="#334155")
    sh_right.append("[ENTER] Toggle Drawer", style="#94a3b8")

    sub_header.add_row(sh_left, sh_right)

    # 7-Column Table
    table = Table(
        box=None,
        expand=True,
        pad_edge=False,
        show_header=True,
        header_style="bold #94a3b8 on #090e1c",
    )
    table.add_column("PID", width=8, no_wrap=True)
    table.add_column("PROCESS", width=18, no_wrap=True)
    table.add_column("DESTINATION", width=22, no_wrap=True)
    table.add_column("SNI / DOMAIN", width=25, no_wrap=True)
    table.add_column("INTERVAL", width=19, no_wrap=True)
    table.add_column("PAYLOAD", width=9, justify="right", no_wrap=True)
    table.add_column("THREAT ▼", width=15, justify="right", no_wrap=True)

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
            c_int.append(f"{flow.interval_str} ", style=int_style)
            spark_style = "bold #ef4444" if is_threat else "#10b981"
            c_int.append(flow.sparkline, style=spark_style)

            # Payload
            c_pay = Text(flow.payload_str, style="white" if is_selected else "#94a3b8")

            # Threat Score Badge
            c_thr = Text()
            if flow.threat_score >= 0.90:
                c_thr.append(f" {flow.threat_score * 100:.1f}% CRIT ", style="bold white on #dc2626")
            elif flow.threat_score >= 0.80:
                c_thr.append(f" {flow.threat_score * 100:.1f}% HIGH ", style="bold white on #b91c1c")
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

    container = Table.grid(expand=True)
    container.add_column()
    container.add_row(sub_header)
    container.add_row(Text(""))
    container.add_row(table)

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
    dt_left = Text()
    dt_left.append("DETAIL : ", style="bold #f59e0b")
    dt_left.append(f"{selected_flow.dst_ip}:{selected_flow.dst_port} ", style="bold #f59e0b")
    dt_left.append(f"(PID {selected_flow.pid})", style="bold #f59e0b")

    dt_right = Text()
    dt_right.append("[", style="#64748b")
    dt_right.append("ENTER", style="bold white")
    dt_right.append("] Collapse", style="#64748b")

    dt.add_row(dt_left, dt_right)

    # Card 1: Host Attribution
    c1 = Text()
    c1.append("• PID       : ", style="#64748b")
    c1.append(f"{selected_flow.pid}\n", style="bold white")
    c1.append("• Process   : ", style="#64748b")
    proc_style = "bold #ef4444" if selected_flow.is_threat else "bold white"
    c1.append(f"{selected_flow.process_name}\n", style=proc_style)
    c1.append("• Binary    :\n", style="#64748b")
    path_display = selected_flow.binary_path
    if len(path_display) > 55:
        path_display = path_display[:25] + "..." + path_display[-27:]
    c1.append(f"  {path_display}\n", style="#cbd5e1")
    c1.append("• Signature : ", style="#64748b")
    sig_style = "bold #ef4444" if not selected_flow.is_signed else "bold #10b981"
    c1.append(f"{selected_flow.sig_info}\n", style=sig_style)
    c1.append("• SHA256    : ", style="#64748b")
    c1.append(f"{selected_flow.sha256[:16]}...", style="#64748b")
    p1 = Panel(
        c1,
        title="[bold #10b981][ HOST ATTRIBUTION ][/]",
        box=box.ROUNDED,
        style="on #060913",
        border_style="#1e293b",
        padding=(0, 1),
    )

    # Card 2: Cadence & Timing
    c2 = Text()
    c2.append("• Interval  : ", style="#64748b")
    c2.append(f"{selected_flow.interval_str} ", style="bold #f59e0b")
    c2.append(f"({selected_flow.jitter_str})\n", style="#64748b")
    c2.append("• Heartbeat : ", style="#64748b")
    c2.append("SEVERED (Stack Killed)\n", style="bold #10b981")
    c2.append("• Pulse     : ", style="#64748b")
    spark_style = "bold #ef4444" if selected_flow.is_threat else "#10b981"
    c2.append(f"{selected_flow.sparkline} ", style=spark_style)
    spark_tag = "(Rigid)\n" if selected_flow.is_threat else "(Normal)\n"
    c2.append(spark_tag, style="#64748b")
    c2.append("• Payload   : ", style="#64748b")
    c2.append(f"{selected_flow.payload_str} ", style="bold white")
    c2.append(f"({'Fixed' if selected_flow.is_threat else 'Dynamic'})\n", style="#64748b")
    c2.append("• Bursts    : ", style="#64748b")
    c2.append(f"{selected_flow.bursts}\n", style="#cbd5e1")
    c2.append("• Jitter    : ", style="#64748b")
    jitter_style = "bold #ef4444" if selected_flow.is_threat else "#10b981"
    c2.append(f"{selected_flow.jitter_pct} ", style=jitter_style)
    c2.append("(Anomalous)" if selected_flow.is_threat else "(Normal)", style="#64748b")
    p2 = Panel(
        c2,
        title="[bold #f59e0b][ CADENCE & TIMING ][/]",
        box=box.ROUNDED,
        style="on #060913",
        border_style="#1e293b",
        padding=(0, 1),
    )

    # Card 3: Forensic & MITRE
    c3 = Text()
    c3.append("• MITRE     : ", style="#64748b")
    c3.append(f"{selected_flow.mitre_technique}\n", style="bold white")
    c3.append("• API       : ", style="#64748b")
    c3.append("SetTcpEntry\n", style="bold #06b6d4")
    c3.append("• Action    : ", style="#64748b")
    c3.append("TCP RST Injected Stack\n", style="bold #10b981")
    c3.append("• State     : ", style="#64748b")
    c3.append("SEVERED (Host Clean)\n", style="bold #10b981")
    c3.append("• Audit     : ", style="#64748b")
    c3.append("SQLite #142 ", style="#cbd5e1")
    c3.append("│ ", style="#334155")
    c3.append("EID 9002\n", style="#cbd5e1")
    c3.append(" ")
    p3 = Panel(
        c3,
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
    fl.append(" ↑/↓ ", style="bold white on #1e293b")
    fl.append("Select   ", style="#94a3b8")
    fl.append(" ENTER ", style="bold white on #1e293b")
    fl.append("Detail   ", style="#94a3b8")
    fl.append(" / ", style="bold #06b6d4 on #1e293b")
    fl.append("Search   ", style="#94a3b8")
    fl.append(" S ", style="bold #f59e0b on #1e293b")
    fl.append("Sort   ", style="#94a3b8")
    fl.append(" K ", style="bold #ef4444 on #1e293b")
    fl.append("Kill   ", style="#94a3b8")
    fl.append(" SPACE ", style="bold white on #1e293b")
    pause_label = "Pause   " if not state.is_paused else "Resume  "
    fl.append(pause_label, style="#94a3b8")
    fl.append(" F ", style="bold white on #1e293b")
    filter_label = "Filter   " if not state.filter_threats_only else "All   "
    fl.append(filter_label, style="#94a3b8")
    fl.append(" E ", style="bold white on #1e293b")
    fl.append("PCAP", style="#94a3b8")

    fr = Text()
    fr.append("│  ", style="#334155")
    fr.append(" Q ", style="bold white on #1e293b")
    fr.append("Quit", style="#94a3b8")

    footer_grid.add_row(fl, fr)
    return Panel(
        footer_grid,
        box=box.ROUNDED,
        style="on #050811",
        border_style="#1e293b",
        padding=(0, 1),
    )


def build_cockpit_layout(state: CockpitState, width: int = 120) -> Layout:
    """Assembles the complete master layout for the terminal."""
    root = Layout(name="root")
    
    top_threat = state.flows[0] if (state.flows and state.flows[0].is_threat) else next((f for f in state.flows if f.is_threat), None)
    pinned_alert = render_pinned_alert(top_threat, width=width)

    if pinned_alert:
        table_size = 11 if state.drawer_expanded else 17
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="alert", size=4),
            Layout(name="main_table", size=table_size),
            Layout(name="drawer", size=11 if state.drawer_expanded else 0),
            Layout(name="footer", size=3),
        )
        root["alert"].update(pinned_alert)
    else:
        table_size = 15 if state.drawer_expanded else 21
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="main_table", size=table_size),
            Layout(name="drawer", size=11 if state.drawer_expanded else 0),
            Layout(name="footer", size=3),
        )

    root["header"].update(render_header(state, width=width))
    root["main_table"].update(render_table(state, width=width))
    
    if state.drawer_expanded:
        selected_flow = None
        visible_flows = [f for f in state.flows if f.is_threat] if state.filter_threats_only else state.flows
        if visible_flows and 0 <= state.selected_index < len(visible_flows):
            selected_flow = visible_flows[state.selected_index]
        root["drawer"].update(render_bottom_drawer(selected_flow))
        
    root["footer"].update(render_footer(state))
    return root
