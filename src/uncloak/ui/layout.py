"""
Terminal layout generator for the Uncloak interactive CUI cockpit.
Implements the high-density telemetry matrix strictly adhering to global open-source standards.
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
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    sni: str
    interval_str: str       # "8.4s", "Irregular", "15.0s", "Inactive"
    sparkline: str          # "▂▄▆▅▆▇▅█", "█ ▄ ▇  ▅", "── ──"
    jitter_str: str         # "±0.8s", "N/A"
    jitter_pct: str         # "9.5%", "7.3%", "N/A"
    payload_str: str        # "512 B", "3.8 KB"
    threat_score: float     # 0.0 - 1.0
    threat_label: str       # "CRIT", "HIGH", "MED", "SAFE"
    is_threat: bool
    c2_framework: Optional[str] = None
    binary_path: str = ""
    sig_info: str = "Unsigned PE"
    sha256: str = "a4f982d17c63e01948b55209df712839ca004918273645519283746501928374"
    process_guid: str = "{8f3a91c2-4d11-672a-0100-0000000016c0}"
    ja4_fingerprint: str = "t13d1516h2_8daaf6152771_0266e33433e9"
    heuristic_signals: str = "Beacon 0.99 │ Direct IP"
    detection_reasons: str = "Direct IP (No SNI) │ Rigid 8.4s IAT"
    bursts: str = "14 bursts / 2m"
    user_context: str = "CORP\\jdoe (Medium)"
    is_severed: bool = False
    mitre_technique: str = "T1071.001 (Web C2)"
    state: str = "ESTABLISHED"
    packets: int = 142
    bytes_transferred: int = 40960
    command_line: str = ""
    parent_process: str = ""
    first_seen: str = "2026-11-02 14:10:02"
    last_seen: str = "2026-11-02 14:26:45"
    duration: str = "16m 43s"
    iat_mad_ratio: str = "0.095 (Rigid Clockwork)"
    iat_iqr_ratio: str = "0.142 (Low Dispersion)"
    bowley_skew: str = "+0.03 (Symmetric)"
    conn_per_burst: str = "1.00 (Persistent Socket)"


@dataclass
class CockpitState:
    """Current state of the interactive terminal cockpit."""
    flows: list[FlowEntry] = field(default_factory=list)
    selected_index: int = 0
    viewport_start: int = 0
    drawer_expanded: bool = True
    show_dossier: bool = False
    is_paused: bool = False
    filter_threats_only: bool = False
    search_query: Optional[str] = None
    in_search_input: bool = False
    sort_field: str = "threat"  # "threat", "interval", "payload", "pid", "process"
    app_name: str = "UNCLOAK"
    version: str = "v0.2.0"
    demo_mode: bool = True
    host_name: str = "WIN-PROD-SRV01 (X64)"
    bpf_filter: str = "tcp and (port 443 or 8443)"
    total_sockets: int = 124
    packet_rate: int = 151
    active_beacons: int = 1
    cpu_percent: float = 0.8
    ram_mb: float = 7.5
    siem_event: str = "EID 9001/9002"


def get_visible_flows(state: CockpitState) -> list[FlowEntry]:
    """Filters and sorts active flows based on CockpitState settings."""
    flows = list(state.flows)

    # 1. Threat filter
    if state.filter_threats_only:
        flows = [f for f in flows if f.is_threat]

    # 2. Search query filter
    if state.search_query:
        q = state.search_query.strip().lower()
        if q:
            flows = [
                f for f in flows
                if q in f.process_name.lower()
                or q in f.dst_ip.lower()
                or q in f.sni.lower()
                or q in str(f.pid)
                or (f.c2_framework and q in f.c2_framework.lower())
                or q in f.mitre_technique.lower()
            ]

    # 3. Sorting
    sort_field = getattr(state, "sort_field", "threat").lower()
    if sort_field == "threat":
        flows.sort(key=lambda f: -f.threat_score)
    elif sort_field == "interval":
        # Ascending interval duration for periodic beacons first, irregular/inactive last
        def _interval_val(f: FlowEntry) -> tuple[int, float]:
            if f.is_severed:
                return (2, 9999.0)
            if f.interval_str.lower() in ("irregular", "inactive"):
                return (1, 9999.0)
            try:
                num = float(f.interval_str.replace("s", "").strip())
                return (0, num)
            except ValueError:
                return (1, 9999.0)
        flows.sort(key=_interval_val)
    elif sort_field == "payload":
        # Descending bytes transferred
        flows.sort(key=lambda f: -f.bytes_transferred)
    elif sort_field == "pid":
        # Ascending PID
        flows.sort(key=lambda f: f.pid)
    elif sort_field == "process":
        # Alphabetical by process name
        flows.sort(key=lambda f: f.process_name.lower())

    return flows


def render_header(state: CockpitState, width: int = 120) -> RenderableType:
    """Builds the upper system banner matching the reference with valid BPF grammar."""
    inner_w = max(80, width - 6)

    l = Text()
    l.append(f"{state.app_name} ", style="bold #e5e7eb")
    if getattr(state, "demo_mode", True):
        l.append(" DEMO " if inner_w < 162 else " SIMULATED ", style="bold black on #f59e0b")
    else:
        l.append(" LIVE " if inner_w < 162 else " LIVE SENSOR ", style="bold black on #10b981")
    l.append(" │ ", style="#323846")
    l.append("HOST: ", style="#6b7280")
    host_short = state.host_name.split(" (")[0]
    if inner_w >= 166:
        l.append(state.host_name[:22], style="bold #e5e7eb")
    else:
        l.append(host_short[:14], style="bold #e5e7eb")
    l.append(" │ ", style="#323846")
    l.append("BPF: ", style="#6b7280")

    # Standard valid BPF grammar: tcp and (port 443 or 8443)
    bpf_display = "tcp and (port 443 or 8443)"
    l.append(f"{bpf_display}", style="#e5e7eb")
    l.append(" │ ", style="#323846")
    if inner_w >= 160:
        l.append("SOCKETS: ", style="#6b7280")
    else:
        l.append("SOCK: ", style="#6b7280")
    l.append(f"{state.total_sockets}", style="bold #93c5fd")

    r = Text()
    r.append("CPU: ", style="#6b7280")
    r.append(f"{state.cpu_percent:.1f}%", style="bold #e5e7eb")
    r.append(" │ ", style="#323846")
    r.append("RAM: ", style="#6b7280")
    ram_str = f"{state.ram_mb:.1f} MB" if inner_w >= 150 else f"{state.ram_mb:.1f}M"
    r.append(ram_str, style="bold #e5e7eb")
    r.append(" │ ", style="#323846")
    if state.is_paused:
        r.append("● PAUSED", style="bold #f59e0b")
    else:
        active_str = "● ACTIVE (2s)" if inner_w >= 152 else "● ACTIVE"
        r.append(active_str, style="bold #10b981")
    r.append(" │ ", style="#323846")
    siem_prefix = "SIEM: " if inner_w >= 152 else ""
    r.append(f"{siem_prefix}{state.siem_event}", style="#9ca3af")

    l_len = len(l.plain)
    r_len = len(r.plain)
    spaces = max(1, inner_w - l_len - r_len)

    header_text = Text(no_wrap=True)
    header_text.append_text(l)
    header_text.append(" " * spaces)
    header_text.append_text(r)

    return Panel(
        header_text,
        box=box.ROUNDED,
        style="on #101217",
        border_style="#262b38",
        padding=(0, 1),
    )


def render_pinned_alert(top_threat: Optional[FlowEntry], width: int = 120, threat_num: int = 1, total_threats: int = 3) -> Optional[RenderableType]:
    """Renders pinned MITRE ATT&CK alert strictly matching the reference with harmonious contrast."""
    if not top_threat or not top_threat.is_threat:
        return None

    inner_w = max(80, width - 6)

    # Row 1
    l1 = Text()
    badge_label = f" TOP INCIDENT {threat_num}/{max(1, total_threats)} "
    l1.append(badge_label, style="bold white on #b91c1c")
    l1.append("  ")
    l1.append("CRITICAL C2 BEACON ISOLATED", style="bold #fca5a5")

    r1 = Text()
    r1.append("MITRE ATT&CK: ", style="#9ca3af")
    r1.append("T1071.001", style="bold #e5e7eb")

    sp1 = max(1, inner_w - len(l1.plain) - len(r1.plain))
    row1 = Text()
    row1.append_text(l1)
    row1.append(" " * sp1)
    row1.append_text(r1)

    # Row 2
    l2 = Text()
    l2.append("TARGET: ", style="#9ca3af")
    c2_tag = f" ({top_threat.c2_framework.split('(')[0].strip()[:18]})" if top_threat.c2_framework else ""
    l2.append(f"{top_threat.dst_ip}:{top_threat.dst_port}{c2_tag}", style="bold #fca5a5")
    l2.append(" │ ", style="#323846")
    l2.append("PID: ", style="#9ca3af")
    l2.append(f"{top_threat.pid} ({top_threat.process_name})", style="bold #e5e7eb")

    r2 = Text()
    if top_threat.is_severed:
        action_str = "STATUS: Severed (TCB Injected)"
        eid_str = "EID 9002 Dispatched"
        action_style = "bold #6ee7b7"
    else:
        action_str = "STATUS: Active (Live)"
        eid_str = "EID 9001 Dispatched"
        action_style = "bold #fcd34d"

    r2.append(action_str, style=action_style)
    r2.append(" │ ", style="#323846")
    r2.append("EVENT: ", style="#9ca3af")
    r2.append(eid_str, style="bold #e5e7eb")

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
        style="on #160d10",
        border_style="#7f1d1d",
        padding=(0, 1),
    )


def render_table(state: CockpitState, width: int = 120, table_height: Optional[int] = None) -> RenderableType:
    """Renders the full-width 7-column primary telemetry matrix strictly matching reference."""
    visible_flows = get_visible_flows(state)

    total = len(visible_flows)
    has_alert = any(f.is_threat for f in state.flows)
    
    # 1 border top + 1 sub-header + 1 column header + N rows + 1 border bottom = table_height
    if table_height is not None:
        v_size = max(2, table_height - 4)
    else:
        v_size = 6 if state.drawer_expanded else (12 if has_alert else 16)

    start = max(0, min(state.viewport_start, max(0, total - v_size)))
    end = min(total, start + v_size)
    slice_flows = visible_flows[start:end]

    # Sub-Header bar inside the table panel
    sh = Table.grid(expand=True)
    sh.add_column(no_wrap=True)
    sh.add_column(justify="right", no_wrap=True)

    sh_left = Text()
    sh_left.append(f"ACTIVE FLOWS ({state.total_sockets})", style="bold #e5e7eb")
    if state.filter_threats_only:
        sh_left.append(" [Threats Only]", style="bold #f59e0b")
    if state.in_search_input:
        sh_left.append(f" [Search: {state.search_query or ''}█]", style="bold #93c5fd")
    elif state.search_query:
        sh_left.append(f" [Filter: '{state.search_query}']", style="bold #93c5fd")

    sh_right = Text()
    curr_pos = min(total, state.selected_index + 1) if total > 0 else 0
    total_display = total if (state.filter_threats_only or state.search_query) else state.total_sockets
    sh_right.append(f"{curr_pos}/{total_display}", style="bold #93c5fd")
    sh_right.append(" │ ", style="#323846")
    sh_right.append("Scroll: ", style="#6b7280")

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

    if track_before:
        sh_right.append(track_before, style="#262b38")
    sh_right.append("▬▬", style="bold #e5e7eb")
    if track_after:
        sh_right.append(track_after, style="#262b38")
    sh_right.append(f"  {pct_val}%", style="#6b7280")
    sh_right.append(" │ ", style="#323846")
    sh_right.append("[ENTER] Toggle Drawer", style="#9ca3af")

    sh.add_row(sh_left, sh_right, style="on #101217")

    # Dynamic Column Headers matching active sort field
    hdr_pid = "PID ▲" if state.sort_field == "pid" else "PID"
    hdr_proc = "PROCESS ▲" if state.sort_field == "process" else "PROCESS"
    hdr_dst = "DESTINATION"
    hdr_sni = "SNI / DOMAIN"
    hdr_int = "INTERVAL ▲" if state.sort_field == "interval" else "INTERVAL"
    hdr_pay = "PAYLOAD ▼" if state.sort_field == "payload" else "PAYLOAD"
    hdr_thr = "THREAT ▼" if state.sort_field == "threat" else "THREAT"

    # 7-Column Table - Proportional responsive column spacing strictly matching reference
    table = Table(
        box=None,
        expand=True,
        pad_edge=False,
        show_header=True,
        header_style="bold #9ca3af on #14171f",
    )
    if width >= 150:
        table.add_column(hdr_pid, width=10, no_wrap=True)
        table.add_column(hdr_proc, width=26, no_wrap=True)
        table.add_column(hdr_dst, width=26, no_wrap=True)
        table.add_column(hdr_sni, width=32, no_wrap=True)
        table.add_column(hdr_int, width=26, no_wrap=True)
        table.add_column(hdr_pay, width=12, justify="right", no_wrap=True)
        table.add_column(hdr_thr, width=16, justify="right", no_wrap=True)
    elif width >= 135:
        table.add_column(hdr_pid, width=9, no_wrap=True)
        table.add_column(hdr_proc, width=21, no_wrap=True)
        table.add_column(hdr_dst, width=25, no_wrap=True)
        table.add_column(hdr_sni, width=30, no_wrap=True)
        table.add_column(hdr_int, width=24, no_wrap=True)
        table.add_column(hdr_pay, width=11, justify="right", no_wrap=True)
        table.add_column(hdr_thr, width=15, justify="right", no_wrap=True)
    else:
        table.add_column(hdr_pid, width=8, no_wrap=True)
        table.add_column(hdr_proc, width=18, no_wrap=True)
        table.add_column(hdr_dst, width=22, no_wrap=True)
        table.add_column(hdr_sni, width=24, no_wrap=True)
        table.add_column(hdr_int, width=22, no_wrap=True)
        table.add_column(hdr_pay, width=10, justify="right", no_wrap=True)
        table.add_column(hdr_thr, width=14, justify="right", no_wrap=True)

    if not slice_flows:
        table.add_row("", "", "No active network sessions matching criteria", "", "", "", "")
    else:
        for idx, flow in enumerate(slice_flows):
            global_idx = start + idx
            is_selected = (global_idx == state.selected_index)
            is_severed = flow.is_severed
            is_threat = flow.is_threat and not is_severed

            # PID
            prefix = "► " if is_selected else "  "
            if is_severed:
                pid_style = "bold #93c5fd" if is_selected else "#6b7280"
            elif is_threat:
                pid_style = "bold #fca5a5"
            else:
                pid_style = "bold #e5e7eb" if is_selected else "#6b7280"
            c_pid = Text(f"{prefix}{flow.pid}", style=pid_style)

            # Process + Tag
            c_proc = Text()
            if is_severed:
                proc_style = "bold #93c5fd" if is_selected else "#9ca3af"
            elif is_threat:
                proc_style = "bold #fca5a5" if is_selected else "#e5e7eb"
            else:
                proc_style = "bold #e5e7eb" if is_selected else "#d1d5db"
            c_proc.append(f"{flow.process_name} ", style=proc_style)
            tag = "Signed" if flow.is_signed else "!"
            if is_severed:
                tag_style = "#6b7280"
            elif flow.is_signed:
                tag_style = "#6b7280"
            else:
                tag_style = "bold #ef4444"
            c_proc.append(tag, style=tag_style)

            # Destination
            if is_severed:
                dst_style = "#93c5fd" if is_selected else "#6b7280"
            elif is_threat:
                dst_style = "bold #fca5a5" if is_selected else "#f3f4f6"
            else:
                dst_style = "#e5e7eb" if is_selected else "#9ca3af"
            c_dst = Text(f"{flow.dst_ip}:{flow.dst_port}", style=dst_style)

            # SNI / Domain
            sni_str = flow.sni if flow.sni else "Direct IP (No SNI)"
            if is_severed:
                sni_style = "#6b7280"
            elif is_threat:
                sni_style = "#fca5a5" if is_selected else "#9ca3af"
            else:
                sni_style = "#d1d5db" if is_selected else "#6b7280"
            c_sni = Text(sni_str, style=sni_style)

            # Interval & Cadence
            c_int = Text()
            if is_severed:
                c_int.append(f"{'Severed':<8}", style="#6b7280")
                c_int.append("(TCB Kill)", style="bold #93c5fd")
            else:
                int_style = "bold #fcd34d" if is_threat else ("#e5e7eb" if is_selected else "#9ca3af")
                c_int.append(f"{flow.interval_str:<8}", style=int_style)
                if flow.sparkline:
                    spark_style = "bold #ef4444" if is_threat else ("#6b7280" if "▄" in flow.sparkline else "#4b5563")
                    c_int.append(flow.sparkline, style=spark_style)

            # Payload
            c_pay = Text(flow.payload_str, style="#6b7280" if is_severed else ("#e5e7eb" if is_selected else "#9ca3af"))

            # Threat Score Badge - Uniform alignment across all tiers
            c_thr = Text()
            if is_severed:
                c_thr.append("  SEVERED   ", style="bold #6ee7b7 on #171a23")
            elif flow.threat_score >= 0.90:
                c_thr.append(f" {flow.threat_score * 100:.1f}% CRIT ", style="bold white on #b91c1c")
            elif flow.threat_score >= 0.75:
                c_thr.append(f" {flow.threat_score * 100:.1f}% HIGH ", style="bold black on #d97706")
            elif flow.threat_score >= 0.48:
                c_thr.append(f" {flow.threat_score * 100:.1f}% EVAL ", style="bold black on #eab308")
            else:
                c_thr.append(f"  {flow.threat_score * 100:.1f}% OK   ", style="#6b7280")

            # Row background style
            if is_severed:
                row_bg = "on #181c26" if is_selected else "on #101217"
            elif is_threat:
                row_bg = "on #261216" if is_selected else "on #160d10"
            else:
                row_bg = "on #181c26" if is_selected else "on #101217"

            table.add_row(c_pid, c_proc, c_dst, c_sni, c_int, c_pay, c_thr, style=row_bg)

    container = Table.grid(expand=True)
    container.add_column()
    container.add_row(sh, style="on #101217")
    container.add_row(table, style="on #101217")

    return Panel(
        container,
        box=box.ROUNDED,
        style="on #101217",
        border_style="#262b38",
        padding=(0, 1),
    )


def format_forensic_path(path: str) -> str:
    """Semantic forensic path compression preserving critical security zone context."""
    if not path:
        return "Unknown"
    parts = path.replace("/", "\\").split("\\")
    exe = parts[-1]
    low = path.lower()
    if "appdata\\roaming" in low:
        res = f"Roaming\\{exe}"
    elif "appdata\\local\\temp" in low or "windows\\temp" in low:
        res = f"Temp\\{exe}"
    elif "appdata\\local" in low:
        res = f"Local\\{exe}"
    elif "system32" in low or "powershell" in low:
        res = f"Sys32\\{exe}"
    elif "windowsapps" in low:
        res = f"WinApps\\{exe}"
    elif "program files" in low:
        res = f"ProgFiles\\{exe}"
    elif len(parts) > 2:
        res = f"C:\\..\\{exe}"
    else:
        res = path
    if len(res) > 21:
        return res[:18] + ".."
    return res


def render_bottom_drawer(selected_flow: Optional[FlowEntry], width: int = 120) -> RenderableType:
    """Renders the 3-block horizontal forensic attribution drawer strictly matching reference."""
    if not selected_flow:
        return Panel(Text("No session selected for inspection", style="dim center"), border_style="#262b38")

    # Clean anchored header line: ── DETAIL : <IP>:<PORT> (PID <PID>) ──── [ENTER] Collapse  [I] Dossier ──
    left_str = f"── DETAIL : {selected_flow.dst_ip}:{selected_flow.dst_port} (PID {selected_flow.pid}) "
    right_str = " [ENTER] Collapse  [I] Dossier ──"
    rule_w = max(4, width - len(left_str) - len(right_str) - 3)

    dt = Text()
    dt.append("── ", style="#323846")
    dt_color = "bold #93c5fd" if selected_flow.is_severed else ("bold #fca5a5" if selected_flow.is_threat else "bold #e5e7eb")
    dt.append(f"DETAIL : {selected_flow.dst_ip}:{selected_flow.dst_port} (PID {selected_flow.pid})", style=dt_color)
    dt.append(" ", style="#323846")
    dt.append("─" * rule_w, style="#262b38")
    dt.append(" [", style="#6b7280")
    dt.append("ENTER", style="bold #e5e7eb")
    dt.append("] Collapse  [", style="#6b7280")
    dt.append("I", style="bold #93c5fd")
    dt.append("] Dossier ", style="#6b7280")
    dt.append("──", style="#323846")

    # Card 1: Host & Kernel Attribution - Strictly 6 clean lines
    c1 = Text()
    c1.append("PID    : ", style="#6b7280")
    c1.append(f"{selected_flow.pid}\n", style="bold #e5e7eb")
    c1.append("Proc   : ", style="#6b7280")
    proc_style = "bold #93c5fd" if selected_flow.is_severed else ("bold #fca5a5" if selected_flow.is_threat else "bold #e5e7eb")
    c1.append(f"{selected_flow.process_name[:28]}\n", style=proc_style)
    c1.append("Path   : ", style="#6b7280")
    p_disp = format_forensic_path(selected_flow.binary_path)
    c1.append(f"{p_disp}\n", style="#e5e7eb")
    c1.append("Sig    : ", style="#6b7280")
    if selected_flow.process_name in ("powershell.exe", "rundll32.exe", "cmd.exe", "wmic.exe", "wmiprvse.exe") and selected_flow.is_threat:
        sig_disp = "Signed (LOLBin Abuse)"
        sig_style = "bold #fcd34d"
    elif selected_flow.is_signed:
        sig_disp = "Valid (Microsoft)" if "microsoft" in (selected_flow.sig_info or "").lower() else "Valid (Signed)"
        sig_style = "#6ee7b7"
    else:
        sig_disp = "Unsigned PE Binary"
        sig_style = "bold #fca5a5"
    c1.append(f"{sig_disp}\n", style=sig_style)
    c1.append("SHA256 : ", style="#6b7280")
    sha_disp = selected_flow.sha256[:18] + ".." if len(selected_flow.sha256) > 18 else selected_flow.sha256
    c1.append(f"{sha_disp}\n", style="#9ca3af")
    c1.append("GUID   : ", style="#6b7280")
    raw_guid = selected_flow.process_guid or "{8f3a91c2-4d11-672a-0100-0000000016c0}"
    guid_disp = f"{raw_guid[:10]}..{raw_guid[-9:]}" if len(raw_guid) > 22 else raw_guid
    c1.append(f"{guid_disp}", style="#d1d5db")

    p1 = Panel(
        c1,
        title="[bold #e5e7eb] 01 / Host & Kernel Attribution [/]",
        box=box.ROUNDED,
        style="on #0c0e13",
        border_style="#262b38",
        padding=(0, 1),
    )

    # Card 2: Cadence & IAT Signal (V1) - Strictly 6 clean lines
    c2 = Text()
    c2.append("Int    : ", style="#6b7280")
    int_style = "bold #93c5fd" if selected_flow.is_severed else ("bold #fcd34d" if selected_flow.is_threat else "bold #e5e7eb")
    int_text = "Severed (TCB Deleted)" if selected_flow.is_severed else (f"{selected_flow.interval_str} ({selected_flow.jitter_str})" if selected_flow.jitter_str != "N/A" else selected_flow.interval_str)
    c2.append(f"{int_text[:30]}\n", style=int_style)

    c2.append("State  : ", style="#6b7280")
    if selected_flow.is_severed:
        hb_style, hb_text = "bold #93c5fd", "SEVERED (Killed)"
    elif selected_flow.is_threat:
        hb_style, hb_text = "bold #fca5a5", "ACTIVE (C2 BEACON)"
    else:
        hb_style, hb_text = "#6ee7b7", "ORGANIC (Human)"
    c2.append(f"{hb_text}\n", style=hb_style)

    c2.append("MAD    : ", style="#6b7280")
    mad_val = str(selected_flow.iat_mad_ratio or "N/A")[:32]
    c2.append(f"{mad_val}\n", style="bold #fca5a5" if selected_flow.is_threat else "#9ca3af")

    c2.append("IQR    : ", style="#6b7280")
    iqr_val = str(selected_flow.iat_iqr_ratio or "N/A")[:32]
    c2.append(f"{iqr_val}\n", style="#e5e7eb")

    c2.append("Skew   : ", style="#6b7280")
    skew_val = str(selected_flow.bowley_skew or "0.00")[:32]
    c2.append(f"{skew_val}\n", style="#d1d5db")

    c2.append("Conn/B : ", style="#6b7280")
    cpb_val = str(selected_flow.conn_per_burst or "1.00")[:32]
    c2.append(f"{cpb_val}", style="#d1d5db")

    p2 = Panel(
        c2,
        title="[bold #e5e7eb] 02 / Cadence & IAT Signal (v1) [/]",
        box=box.ROUNDED,
        style="on #0c0e13",
        border_style="#262b38",
        padding=(0, 1),
    )

    # Card 3: Containment & SIEM Audit - Strictly 6 clean lines
    c3 = Text()
    c3.append("MITRE  : ", style="#6b7280")
    if selected_flow.mitre_technique:
        mitre_disp = selected_flow.mitre_technique.split(" /")[0][:30]
    elif selected_flow.is_threat:
        mitre_disp = "T1071.001 (Web Protocols)"
    else:
        mitre_disp = "None (Allowlisted)"
    c3.append(f"{mitre_disp}\n", style="bold #e5e7eb")

    c3.append("Kernel : ", style="#6b7280")
    if selected_flow.is_threat or selected_flow.is_severed:
        api_disp, api_style = "SetTcpEntry + WFP", "bold #93c5fd"
    else:
        api_disp, api_style = "GetExtendedTcpTable", "#93c5fd"
    c3.append(f"{api_disp}\n", style=api_style)

    c3.append("Action : ", style="#6b7280")
    if selected_flow.is_severed:
        c3.append("TCB Deleted + Blocked\n", style="#6ee7b7")
    elif selected_flow.is_threat:
        c3.append("Pending [K] Sever\n", style="bold #fcd34d")
    else:
        c3.append("Permitted Baseline\n", style="#9ca3af")

    c3.append("Socket : ", style="#6b7280")
    sock_disp = f":{selected_flow.src_port}->{selected_flow.dst_ip}:{selected_flow.dst_port}"[:32]
    c3.append(f"{sock_disp}\n", style="#d1d5db")

    c3.append("Audit  : ", style="#6b7280")
    if selected_flow.is_severed:
        audit_disp = "SQLite + OCSF │ EID 9002"
    elif selected_flow.is_threat:
        audit_disp = "SQLite + OCSF │ EID 9001"
    else:
        audit_disp = f"Flow #{selected_flow.flow_id} │ Benign"
    c3.append(f"{audit_disp[:32]}\n", style="#d1d5db")

    c3.append("User   : ", style="#6b7280")
    user_disp = (selected_flow.user_context or "SYSTEM").replace(" Integrity)", ")").replace("AppContainer ", "")[:32]
    c3.append(f"{user_disp}", style="#9ca3af")

    p3 = Panel(
        c3,
        title="[bold #e5e7eb] 03 / Containment & SIEM Audit [/]",
        box=box.ROUNDED,
        style="on #0c0e13",
        border_style="#262b38",
        padding=(0, 1),
    )

    dg = Table.grid(expand=True, padding=(0, 1))
    dg.add_column(ratio=1)
    dg.add_column(ratio=1)
    dg.add_column(ratio=1)
    dg.add_row(p1, p2, p3)

    drawer_grid = Table.grid(expand=True)
    drawer_grid.add_column()
    drawer_grid.add_row(dt, style="on #090a0d")
    drawer_grid.add_row(dg, style="on #090a0d")

    return drawer_grid


def render_dossier_modal(flow: Optional[FlowEntry], width: int = 120) -> RenderableType:
    """Renders the comprehensive Process Forensic Dossier overlay modal."""
    if not flow:
        return Panel(Text("No session selected for forensic dossier", style="dim center"), border_style="#262b38")

    body = Text()
    body.append("Process Name   : ", style="#6b7280")
    proc_style = "bold #fca5a5" if flow.is_threat and not flow.is_severed else ("bold #93c5fd" if flow.is_severed else "bold #e5e7eb")
    body.append(f"{flow.process_name} (PID {flow.pid})", style=proc_style)
    
    state_disp = "SEVERED (TCB Deleted)" if flow.is_severed else ("ESTABLISHED (C2 Active)" if flow.is_threat else "ESTABLISHED (Baseline Flow)")
    state_style = "bold #93c5fd" if flow.is_severed else ("bold #fca5a5" if flow.is_threat else "#6ee7b7")
    body.append("          Socket State : ", style="#6b7280")
    body.append(f"{state_disp}\n", style=state_style)

    body.append("Binary Path    : ", style="#6b7280")
    body.append(f"{flow.binary_path}\n", style="bold #e5e7eb")

    cmd = flow.command_line or f"{flow.process_name} --c2 {flow.dst_ip}:{flow.dst_port}"
    body.append("Command Line   : ", style="#6b7280")
    body.append(f"{cmd}\n", style="#d1d5db")

    parent = flow.parent_process or "explorer.exe (PID 2110) [Interactive User Session]"
    body.append("Parent Process : ", style="#6b7280")
    body.append(f"{parent}\n", style="#d1d5db")

    body.append("ProcessGuid    : ", style="#6b7280")
    body.append(f"{flow.process_guid}\n", style="#d1d5db")

    body.append("User Context   : ", style="#6b7280")
    body.append(f"{flow.user_context}\n", style="#d1d5db")

    body.append("Authenticode   : ", style="#6b7280")
    sig_style = "#6ee7b7" if flow.is_signed else "bold #fca5a5"
    sig_text = f"{flow.sig_info} (Verified CA Signature)" if flow.is_signed else f"{flow.sig_info} (WinVerifyTrust Fail)"
    body.append(f"{sig_text}\n", style=sig_style)

    body.append("SHA-256 Hash   : ", style="#6b7280")
    body.append(f"{flow.sha256}\n", style="#9ca3af")

    body.append("JA4 Client     : ", style="#6b7280")
    body.append(f"{flow.ja4_fingerprint}\n", style="#93c5fd")

    body.append("Active Socket  : ", style="#6b7280")
    body.append(f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} (TCP {flow.state})\n", style="#e5e7eb")

    body.append("IAT MAD & IQR  : ", style="#6b7280")
    body.append(f"MAD: {flow.iat_mad_ratio} │ IQR: {flow.iat_iqr_ratio} │ Skew: {flow.bowley_skew}\n", style="#fcd34d")

    body.append("Conn / Burst   : ", style="#6b7280")
    body.append(f"{flow.bursts} │ {flow.conn_per_burst}\n", style="#d1d5db")

    body.append("MITRE ATT&CK   : ", style="#6b7280")
    body.append(f"{flow.mitre_technique}\n", style="bold #e5e7eb")

    body.append("SIEM & Audit   : ", style="#6b7280")
    body.append(f"SQLite #{flow.flow_id} │ OCSF v1.1.0 NDJSON │ Windows Event ID 9001 / 9002\n", style="#d1d5db")

    body.append("Containment    : ", style="#6b7280")
    mit_text = "SEVERED (SetTcpEntry DELETE_TCB + WFP Outbound Block)" if flow.is_severed else "SetTcpEntry + netsh advfirewall Armed -> Press [K] to Contain"
    mit_style = "bold #93c5fd" if flow.is_severed else ("bold #fca5a5" if flow.is_threat else "#6ee7b7")
    body.append(f"{mit_text}\n\n", style=mit_style)

    body.append("ACTIONS: ", style="#6b7280")
    body.append("[ESC / I] Return to Cockpit    [K] Sever Connection    [C] Copy Full Path    [E] Export Dossier", style="#9ca3af")

    return Panel(
        body,
        title=f"[bold #e5e7eb] Process Forensic Dossier : {flow.process_name} (PID {flow.pid}) [/]",
        border_style="#323846",
        style="on #0c0e13",
        padding=(0, 2),
    )


def render_footer(state: CockpitState, width: int = 120) -> RenderableType:
    """Renders the pristine UNIX hotkey guide strictly matching reference (flat bar, NO panel border)."""
    grid = Table.grid(expand=True)
    grid.add_column()
    
    # 1 blank line for vertical breathing room matching reference
    grid.add_row(Text(" " * width, style="on #090a0d"))

    footer_grid = Table.grid(expand=True)
    footer_grid.add_column(no_wrap=True)
    footer_grid.add_column(justify="right", no_wrap=True)

    fl = Text()
    if state.in_search_input:
        fl.append(" ENTER ", style="bold #93c5fd on #1a1e26")
        fl.append(" Apply Filter  ", style="#9ca3af")
        fl.append(" ESC ", style="bold #e5e7eb on #1a1e26")
        fl.append(" Cancel  ", style="#9ca3af")
        fl.append(" BACKSPACE ", style="bold #e5e7eb on #1a1e26")
        fl.append(" Delete Char", style="#9ca3af")
    elif state.show_dossier:
        fl.append(" ESC / I ", style="bold #e5e7eb on #1a1e26")
        fl.append(" Close Dossier  ", style="#9ca3af")
        fl.append(" K ", style="bold #fca5a5 on #1a1e26")
        fl.append(" Sever  ", style="#9ca3af")
        fl.append(" C ", style="bold #e5e7eb on #1a1e26")
        fl.append(" Copy Path  ", style="#9ca3af")
        fl.append(" E ", style="bold #e5e7eb on #1a1e26")
        fl.append(" Export Dossier", style="#9ca3af")
    else:
        fl.append(" ↑/↓ ", style="bold #e5e7eb on #1a1e26")
        fl.append(" Select  ", style="#9ca3af")
        fl.append(" ENTER ", style="bold #e5e7eb on #1a1e26")
        fl.append(" Detail  ", style="#9ca3af")
        fl.append(" / ", style="bold #93c5fd on #1a1e26")
        fl.append(" Search  ", style="#9ca3af")
        fl.append(" S ", style="bold #fcd34d on #1a1e26")
        fl.append(" Sort  ", style="#9ca3af")
        fl.append(" K ", style="bold #fca5a5 on #1a1e26")
        fl.append(" Kill  ", style="#9ca3af")
        fl.append(" SPACE ", style="bold #e5e7eb on #1a1e26")
        pause_label = " Pause  " if not state.is_paused else " Resume "
        fl.append(pause_label, style="#9ca3af")
        fl.append(" F ", style="bold #e5e7eb on #1a1e26")
        filter_label = " Filter  " if not state.filter_threats_only else " All  "
        fl.append(filter_label, style="#9ca3af")
        fl.append(" E ", style="bold #e5e7eb on #1a1e26")
        fl.append(" Export", style="#9ca3af")

    fr = Text()
    fr.append("│  ", style="#323846")
    fr.append(" Q ", style="bold #e5e7eb on #1a1e26")
    fr.append(" Quit", style="#9ca3af")

    footer_grid.add_row(fl, fr, style="on #090a0d")
    grid.add_row(footer_grid, style="on #090a0d")
    return grid


def build_cockpit_layout(state: CockpitState, width: int = 120, height: Optional[int] = None) -> Layout:
    """Assembles the complete master layout strictly matching the reference design with adaptive breathing room."""
    root = Layout(name="root")
    term_height = height if (height and height >= 20) else 28
    header_size = 3
    footer_size = 2

    # Tier 3: Process Forensic Dossier Mode
    if state.show_dossier:
        selected_flow = None
        visible_flows = get_visible_flows(state)
        if visible_flows and 0 <= state.selected_index < len(visible_flows):
            selected_flow = visible_flows[state.selected_index]
        
        dossier_size = term_height - header_size - footer_size
        root.split_column(
            Layout(name="header", size=header_size),
            Layout(name="dossier", size=dossier_size),
            Layout(name="footer", size=footer_size),
        )
        root["header"].update(render_header(state, width=width))
        root["dossier"].update(render_dossier_modal(selected_flow, width=width))
        root["footer"].update(render_footer(state, width=width))
        return root

    active_threats = [f for f in state.flows if f.is_threat and not f.is_severed]
    all_threats = [f for f in state.flows if f.is_threat]
    total_threats = len(all_threats)
    if active_threats:
        top_threat = active_threats[0]
        threat_num = 1
    elif all_threats:
        top_threat = all_threats[0]
        threat_num = total_threats
    else:
        top_threat = None
        threat_num = 0

    pinned_alert = render_pinned_alert(top_threat, width=width, threat_num=threat_num, total_threats=total_threats) if top_threat else None

    alert_size = 4 if pinned_alert else 0
    drawer_size = 9 if state.drawer_expanded else 0
    table_size = 10 if state.drawer_expanded else max(10, term_height - (header_size + alert_size + footer_size))

    # Calculate whether we have vertical headroom for clean 1-line breathing gaps between panels
    base_needed = header_size + alert_size + table_size + drawer_size + footer_size
    surplus = term_height - base_needed
    has_gaps = surplus >= 3

    sections = [
        Layout(name="header", size=header_size),
    ]

    if has_gaps:
        sections.append(Layout(name="gap_1", size=1))

    if pinned_alert:
        sections.append(Layout(name="alert", size=alert_size))
        if has_gaps:
            sections.append(Layout(name="gap_2", size=1))

    sections.append(Layout(name="main_table", size=table_size))

    if has_gaps:
        sections.append(Layout(name="gap_3", size=1))

    if state.drawer_expanded:
        sections.append(Layout(name="drawer", size=drawer_size))
        if has_gaps and surplus >= 4:
            sections.append(Layout(name="gap_4", size=1))

    sections.append(Layout(name="footer", size=footer_size))

    root.split_column(*sections)

    root["header"].update(render_header(state, width=width))
    if has_gaps:
        root["gap_1"].update(Text(" " * width, style="on #090a0d"))

    if pinned_alert:
        root["alert"].update(pinned_alert)
        if has_gaps:
            root["gap_2"].update(Text(" " * width, style="on #090a0d"))

    root["main_table"].update(render_table(state, width=width, table_height=table_size))

    if has_gaps:
        root["gap_3"].update(Text(" " * width, style="on #090a0d"))

    if state.drawer_expanded:
        selected_flow = None
        visible_flows = get_visible_flows(state)
        if visible_flows and 0 <= state.selected_index < len(visible_flows):
            selected_flow = visible_flows[state.selected_index]
        root["drawer"].update(render_bottom_drawer(selected_flow, width=width))
        if has_gaps and surplus >= 4:
            root["gap_4"].update(Text(" " * width, style="on #090a0d"))

    root["footer"].update(render_footer(state, width=width))
    return root
