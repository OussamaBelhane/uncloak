"""
Unified CLI entrypoint for Uncloak Live NDR/EDR + Central SOC Manager.
Implements the live Endpoint + Central SOC architecture (+ Module 12 replay harness):
  1. uncloak service       - Live Windows SYSTEM agent (Npcap, Win32 PID, SetTcpEntry, manager sync & SIEM)
  2. uncloak --ui          - On-demand Live Endpoint Terminal CUI (Rich live socket stream & kill)
  3. uncloak manager       - Live Central SOC Web Cockpit (AD Fleet Matrix, JA4 Campaign Graph, Host Triage)
  4. uncloak -r FILE.pcap  - Module 12 PCAP replay & benchmark harness for the FlowFeaturesV1 engine
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional


def build_parser() -> argparse.ArgumentParser:
    """Constructs the primary CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="uncloak",
        description="Uncloak - Live C2 Jitter Detection, Win32 Kernel Attribution & Central SOC Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    parser.add_argument(
        "-h", "--help",
        action="store_true",
        help="Show structured enterprise CLI command reference and exit",
    )

    parser.add_argument(
        "-v", "--version",
        action="store_true",
        help="Show Uncloak Engine version and active detection capabilities",
    )

    parser.add_argument(
        "subcommand",
        nargs="?",
        choices=["service", "agent", "tui", "hunt", "cli", "web", "manager", "gui", "demo"],
        default=None,
        help="Mode: service/agent (Live Endpoint Daemon), tui/cli (Live Host CUI), manager/web (Live Central SOC Cockpit), demo (Simulated Fleet)",
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--service",
        action="store_true",
        help="Start the live Uncloak Windows endpoint agent writing OCSF NDJSON, Event ID 9001/9002 & streaming to manager",
    )
    mode_group.add_argument(
        "--agent",
        action="store_true",
        help="Alias for --service: live silent endpoint agent daemon",
    )
    mode_group.add_argument(
        "-r", "--read",
        metavar="FILE.pcap",
        help="Module 12 benchmark harness: replay a recorded PCAP/PCAPNG trace through FlowFeaturesV1",
    )
    mode_group.add_argument(
        "--ui", "--tui", "--cli", "--live",
        dest="ui",
        action="store_true",
        help="Launch the on-demand Live Endpoint Terminal CUI (Rich live socket monitor & kill)",
    )
    mode_group.add_argument(
        "--web", "--manager", "--gui",
        dest="web",
        action="store_true",
        help="Launch the Live Central SOC Web Cockpit (Fleet Matrix, JA4 Campaign Graph & Host Drill-Down)",
    )

    # Behavior modifiers (combinable with --ui or --web or --service)
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Enable isolated simulated telemetry data (never mixed with live endpoints)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="With service/--json: run one live SIEM OCSF/EventLog cycle and exit",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8830,
        metavar="PORT",
        help="HTTP port for the Central SOC Web Cockpit (default: 8830)",
    )

    # Ingestion & SIEM options
    parser.add_argument(
        "-i", "--interface",
        metavar="IFACE",
        help="Network interface index or name to capture on",
    )
    parser.add_argument(
        "-f", "--filter",
        default="tcp and (port 443 or port 8443)",
        metavar="BPF",
        help="Berkeley Packet Filter (BPF) string",
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Emit line-delimited OCSF v1.1.0 JSON (NDJSON) to stdout",
    )
    parser.add_argument(
        "--siem-out",
        default="uncloak_alerts.ndjson",
        metavar="PATH",
        help="NDJSON output path for headless sensor SIEM forwarding (default: uncloak_alerts.ndjson)",
    )
    parser.add_argument(
        "-t", "--threshold",
        type=float,
        default=0.75,
        metavar="FLOAT",
        help="Threat score threshold between 0.0 and 1.0 (default: 0.75)",
    )
    parser.add_argument(
        "--min-bursts",
        type=int,
        default=8,
        metavar="INT",
        help="Minimum burst count before Feature Schema v1 evaluation (default: 8)",
    )
    parser.add_argument(
        "--db",
        default="uncloak.db",
        metavar="PATH",
        help="Path to embedded SQLite WAL telemetry database (default: uncloak.db)",
    )
    parser.add_argument(
        "--soc-url",
        dest="soc_url",
        default=None,
        metavar="URL",
        help="Central SOC Manager endpoint URL (default: http://127.0.0.1:<port>)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=15.0,
        metavar="SEC",
        help="Endpoint heartbeat & telemetry sync interval in seconds (default: 15.0)",
    )

    # Windows Startup Service Lifecycle
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install Uncloak Sensor as a silent NT AUTHORITY\\SYSTEM startup task",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove Uncloak Sensor from Windows startup",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Query running status of the Windows Uncloak Sensor task",
    )

    return parser


def _print_cli_overview(console: Optional[object] = None) -> None:
    """Prints the enterprise 4-Tier architecture overview when 'uncloak' is invoked bare."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    out = console or Console(color_system="truecolor")

    hdr = Text()
    hdr.append("UNCLOAK", style="bold #f8fafc")
    hdr.append(" v0.2.0 ", style="bold #10b981")
    hdr.append("|", style="#475569")
    hdr.append(" Live C2 Beacon Detection, Kernel Attribution & Central SOC Platform\n", style="#cbd5e1")
    hdr.append("Engine: ", style="#94a3b8")
    hdr.append("FlowFeaturesV1 (12-Dim Robust IAT)", style="bold #38bdf8")
    hdr.append("  |  ", style="#475569")
    hdr.append("TLS: ", style="#94a3b8")
    hdr.append("JA4 ClientHello", style="#cbd5e1")
    hdr.append("  |  ", style="#475569")
    hdr.append("Containment: ", style="#94a3b8")
    hdr.append("SetTcpEntry + WFP", style="#cbd5e1")
    hdr.append("  |  ", style="#475569")
    hdr.append("SIEM: ", style="#94a3b8")
    hdr.append("OCSF v1.1.0 + EID 9001/9002", style="#cbd5e1")

    out.print(
        Panel(
            hdr,
            title="[bold #f8fafc] Uncloak Enterprise NDR/EDR CLI [/]",
            box=box.ROUNDED,
            border_style="#334155",
            padding=(0, 1),
        )
    )

    tbl = Table(
        box=box.ROUNDED,
        border_style="#334155",
        header_style="bold #94a3b8",
        expand=True,
        padding=(0, 1),
    )
    tbl.add_column("MODE / TIER", width=16, no_wrap=True)
    tbl.add_column("COMMAND SYNTAX", width=30, no_wrap=True)
    tbl.add_column("OPERATIONAL ROLE & ENTERPRISE OUTPUT", ratio=2)

    tbl.add_row(
        Text("01 / Service", style="bold #10b981"),
        Text("uncloak service [--once]\n(uncloak-agent)", style="bold #e2e8f0"),
        "Headless Windows SYSTEM daemon (0 listening ports). Streams OCSF v1.1.0 NDJSON & WinEvent EID 9001/9002.",
    )
    tbl.add_row(
        Text("02 / Replay", style="bold #38bdf8"),
        Text("uncloak -r <pcap> [--json]", style="bold #e2e8f0"),
        "Offline PCAP/PCAPNG replay through FlowFeaturesV1, DNS/SNI correlation, and triad Finding triage cards.",
    )
    tbl.add_row(
        Text("03 / Live CUI", style="bold #f59e0b"),
        Text("uncloak --ui [--demo]", style="bold #e2e8f0"),
        "Interactive terminal cockpit for live endpoint socket inspection, [I] Process Dossier & [K] TCB sever.",
    )
    tbl.add_row(
        Text("04 / Web SOC", style="bold #60a5fa"),
        Text("uncloak web [--demo]\n(uncloak-manager)", style="bold #e2e8f0"),
        "Central SOC Web Console (AD Tier Fleet Matrix, Coordinated JA4 Campaigns, Host Triage & Policy Push).",
    )
    out.print(tbl)

    tips = Text()
    tips.append("QUICK START  ", style="bold #94a3b8")
    tips.append("uncloak --help", style="bold #38bdf8")
    tips.append(" Reference  |  ", style="#64748b")
    tips.append("uncloak --status", style="bold #10b981")
    tips.append(" Service  |  ", style="#64748b")
    tips.append("uncloak service --once", style="bold #e2e8f0")
    tips.append(" Verify SIEM  |  ", style="#64748b")
    tips.append("uncloak web --demo", style="bold #f59e0b")
    tips.append(" Web SOC", style="#64748b")
    out.print(Panel(tips, box=box.ROUNDED, border_style="#334155", padding=(0, 1)))


def _print_rich_help(console: Optional[object] = None) -> None:
    """Renders a structured enterprise CLI reference screen for 'uncloak --help'."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    out = console or Console(color_system="truecolor")

    hdr = Text()
    hdr.append("USAGE  ", style="bold #94a3b8")
    hdr.append("uncloak [MODE] [OPTIONS]", style="bold #f8fafc")
    hdr.append("    |    ", style="#475569")
    hdr.append("DOCS  ", style="bold #94a3b8")
    hdr.append("All modes share FlowFeaturesV1 + OCSF v1.1.0 + Win32 Attribution", style="#cbd5e1")
    out.print(
        Panel(
            hdr,
            title="[bold #f8fafc] Uncloak v0.2.0 // Enterprise Command Reference [/]",
            box=box.ROUNDED,
            border_style="#334155",
            padding=(0, 1),
        )
    )

    tbl = Table(
        box=box.ROUNDED,
        border_style="#334155",
        header_style="bold #94a3b8",
        expand=True,
        show_edge=True,
        padding=(0, 1),
    )
    tbl.add_column("GROUP", width=22, no_wrap=True)
    tbl.add_column("FLAG / SUBCOMMAND", width=30, no_wrap=True)
    tbl.add_column("DESCRIPTION & DEFAULT VALUE", ratio=2)

    # 01 / Operational Modes
    tbl.add_row(Text("01 / Operational Modes", style="bold #10b981"), Text("service, --service, --agent", style="bold #e2e8f0"), "Run silent endpoint daemon writing OCSF NDJSON, WinEvent EID 9001/9002 & syncing to SOC.")
    tbl.add_row("", Text("-r, --read FILE.pcap", style="bold #e2e8f0"), "Replay offline PCAP/PCAPNG capture through the 12-dim FlowFeaturesV1 detector.")
    tbl.add_row("", Text("--ui, --tui, --cli, --live", style="bold #e2e8f0"), "Launch interactive Rich Terminal CUI with real-time socket matrix & kernel containment.")
    tbl.add_row("", Text("web, --web, --manager", style="bold #e2e8f0"), "Launch Central SOC Web Console on --port (default: 8830).")

    # 02 / Capture & Detection Tuning
    tbl.add_row(Text("02 / Capture & Tuning", style="bold #38bdf8"), Text("-i, --interface IFACE", style="bold #e2e8f0"), "Network interface index or adapter name for live capture.")
    tbl.add_row("", Text("-f, --filter BPF", style="bold #e2e8f0"), "Berkeley Packet Filter (default: tcp and (port 443 or port 8443)).")
    tbl.add_row("", Text("-t, --threshold FLOAT", style="bold #e2e8f0"), "C2 confidence threshold in [0.0, 1.0] (default: 0.75).")
    tbl.add_row("", Text("--min-bursts INT", style="bold #e2e8f0"), "Minimum observed bursts before FlowFeaturesV1 scoring (default: 8).")
    tbl.add_row("", Text("--demo", style="bold #e2e8f0"), "Run with isolated simulated enterprise telemetry (never mixed with live endpoints).")

    # 03 / SIEM & Storage Output
    tbl.add_row(Text("03 / SIEM & Output", style="bold #f59e0b"), Text("-j, --json", style="bold #e2e8f0"), "Stream line-delimited OCSF v1.1.0 Network Activity (class_uid 4001) JSON to stdout.")
    tbl.add_row("", Text("--siem-out PATH", style="bold #e2e8f0"), "OCSF NDJSON sink file path (default: uncloak_alerts.ndjson).")
    tbl.add_row("", Text("--db PATH", style="bold #e2e8f0"), "Embedded SQLite WAL history database path (default: uncloak.db).")
    tbl.add_row("", Text("--port PORT / --soc-url URL", style="bold #e2e8f0"), "Central SOC Web port (default: 8830) or remote SOC manager URL.")
    tbl.add_row("", Text("--interval SEC", style="bold #e2e8f0"), "Agent heartbeat & telemetry synchronization interval (default: 15.0s).")
    tbl.add_row("", Text("--once", style="bold #e2e8f0"), "Execute one verification SIEM OCSF/WinEvent emission cycle and exit cleanly.")

    # 04 / Windows SYSTEM Service Lifecycle
    tbl.add_row(Text("04 / Service Lifecycle", style="bold #60a5fa"), Text("--install / --uninstall", style="bold #e2e8f0"), "Register or remove headless NT AUTHORITY\\SYSTEM boot task via Task Scheduler.")
    tbl.add_row("", Text("--status", style="bold #e2e8f0"), "Inspect UncloakEndpointAgent Windows Task Scheduler state & privilege status.")
    tbl.add_row("", Text("-v, --version / -h, --help", style="bold #e2e8f0"), "Display Uncloak Engine version metadata or this command reference.")

    out.print(tbl)


def _print_version(console: Optional[object] = None) -> None:
    """Renders an enterprise version and capability card for 'uncloak --version'."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    out = console or Console(color_system="truecolor")
    body = Text()
    body.append("Uncloak Engine v0.2.0", style="bold #f8fafc")
    body.append("  |  ", style="#475569")
    body.append("ACTIVE\n", style="bold #10b981")
    body.append("Detection : ", style="#94a3b8")
    body.append("FlowFeaturesV1 (12-Dim Robust IAT) + JA4 TLS ClientHello\n", style="#cbd5e1")
    body.append("Kernel    : ", style="#94a3b8")
    body.append("GetExtendedTcpTable + SetTcpEntry(DELETE_TCB) + WFP\n", style="#cbd5e1")
    body.append("Telemetry : ", style="#94a3b8")
    body.append("OCSF v1.1.0 (class_uid 4001) + EID 9001/9002 + SQLite WAL", style="#cbd5e1")
    out.print(
        Panel(
            body,
            title="[bold #f8fafc] Uncloak Platform Version [/]",
            box=box.ROUNDED,
            border_style="#334155",
            padding=(0, 1),
        )
    )


def _print_service_startup_banner(agent: object, siem_out: str, console: Optional[object] = None) -> None:
    """Renders a clean startup status card when continuous headless sensor mode launches."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    out = console or Console(color_system="truecolor")
    body = Text()
    body.append("Host / IP     : ", style="#94a3b8")
    body.append(f"{agent.hostname} ({agent.ip_address})", style="bold #f8fafc")
    body.append("    |    ", style="#475569")
    body.append("Daemon State : ", style="#94a3b8")
    body.append("ACTIVE (Zero UI Ports)\n", style="bold #10b981")
    body.append("SIEM Pipeline : ", style="#94a3b8")
    body.append(f"WinEvent Application (EID 9001/9002) + OCSF NDJSON ({siem_out})\n", style="#38bdf8")
    body.append("SOC Heartbeat : ", style="#94a3b8")
    body.append(f"{agent.manager_url} (Interval: {agent.heartbeat_interval:.1f}s)", style="#cbd5e1")
    out.print(
        Panel(
            body,
            title="[bold #f8fafc] Mode 1 : Headless Endpoint Sensor Running [/]",
            box=box.ROUNDED,
            border_style="#334155",
            padding=(0, 1),
        )
    )


def _handle_policy_cli(args: list[str]) -> int:
    """Executes hierarchical AD Tier & threshold governance commands via 'uncloak policy'."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from urllib import request
    from uncloak.core.policy import PolicyManager

    p = argparse.ArgumentParser(prog="uncloak policy", description="Uncloak Fleet & Host Governance Policy CLI")
    sub = p.add_subparsers(dest="action")

    st = sub.add_parser("status", help="Display active fleet thresholds, AD Tier matrix, and host overrides")
    st.add_argument("--host", default=None, help="Target host_id (defaults to local hostname)")
    st.add_argument("--json", action="store_true", help="Emit raw policy JSON")

    st_tier = sub.add_parser("set-tier", help="Reassign Active Directory Tier for an endpoint")
    st_tier.add_argument("--tier", required=True, choices=["0", "1", "2", "Tier-0", "Tier-1", "Tier-2"], help="Target AD Tier")
    st_tier.add_argument("--host", default=None, help="Target host_id (defaults to local hostname)")

    st_th = sub.add_parser("set-thresholds", help="Tune FlowFeaturesV1 alert & autonomous containment thresholds")
    st_th.add_argument("--alert", type=float, default=None, help="Alert confidence threshold (0.10-0.99)")
    st_th.add_argument("--block", type=float, default=None, help="Autonomous block confidence threshold (0.50-0.99)")
    st_th.add_argument("--mad", type=float, default=None, help="Max IAT MAD/Median ratio (0.01-0.80)")
    st_th.add_argument("--bursts", type=int, default=None, help="Minimum communication bursts (2-50)")

    ov = sub.add_parser("override", help="Override containment policy or maintenance mode on a host")
    ov.add_argument("--mode", required=True, choices=["autonomous", "prompt", "audit", "audit_p1", "quorum", "inherit"], help="Containment mode")
    ov.add_argument("--host", default=None, help="Target host_id (defaults to local hostname)")
    ov.add_argument("--maintenance", action="store_true", help="Enable maintenance mode (audit-only)")
    ov.add_argument("--no-maintenance", action="store_true", help="Disable maintenance mode")

    sy = sub.add_parser("sync", help="Fetch latest fleet policy revision from Central SOC Manager")
    sy.add_argument("--soc-url", default="http://127.0.0.1:8830", help="Central SOC Manager URL")

    if not args:
        args = ["status"]

    parsed = p.parse_args(args)
    pm = PolicyManager()
    out = Console(color_system="truecolor")

    if parsed.action == "status":
        if getattr(parsed, "json", False):
            print(json.dumps(pm.state, indent=2))
            return 0

        th = pm.state.get("thresholds", {})
        tp = pm.state.get("tier_policies", {})
        ov_map = pm.state.get("host_overrides", {})

        hdr = Text()
        hdr.append("POLICY REVISION ", style="bold #94a3b8")
        hdr.append(f"v{pm.state.get('revision', 1)}", style="bold #10b981")
        hdr.append(f"  |  Config: {pm.policy_path}\n", style="#64748b")
        hdr.append(
            f"Alert Threshold (EID 9001): {th.get('alert_confidence', 0.85):.3f}  |  "
            f"Block Threshold (EID 9002): {th.get('block_confidence', 0.90):.3f}  |  "
            f"Max MAD Ratio: {th.get('max_mad_ratio', 0.18):.3f}  |  "
            f"Min Bursts: {th.get('min_bursts', 8)}",
            style="#e2e8f0",
        )
        out.print(Panel(hdr, title="[bold #f8fafc] Uncloak Governance & Policy Status [/]", box=box.ROUNDED, border_style="#334155"))

        tbl = Table(box=box.ROUNDED, border_style="#334155", header_style="bold #94a3b8", expand=True)
        tbl.add_column("AD TIER", width=12)
        tbl.add_column("CONTAINMENT POLICY", width=36)
        tbl.add_column("HOST OVERRIDES", ratio=1)
        for tier_name in ("Tier-0", "Tier-1", "Tier-2"):
            hosts_in_tier = [hid for hid, cfg in ov_map.items() if cfg.get("tier") == tier_name]
            ov_str = ", ".join(hosts_in_tier) if hosts_in_tier else "None (Inherited)"
            tbl.add_row(tier_name, tp.get(tier_name, "prompt_analyst"), ov_str)
        out.print(tbl)
        return 0

    if parsed.action == "set-tier":
        res = pm.set_host_override(host_id=parsed.host, tier=parsed.tier)
        out.print(f"[bold #10b981][+][/] AD Tier reassigned: host={parsed.host or 'local'} -> [bold]{res.get('tier')}[/]")
        return 0

    if parsed.action == "set-thresholds":
        res = pm.set_thresholds(
            alert_confidence=parsed.alert,
            block_confidence=parsed.block,
            max_mad_ratio=parsed.mad,
            min_bursts=parsed.bursts,
        )
        out.print(f"[bold #10b981][+][/] Thresholds updated: Alert={res['alert_confidence']:.3f}, Block={res['block_confidence']:.3f}, MAD={res['max_mad_ratio']:.3f}, Bursts={res['min_bursts']}")
        return 0

    if parsed.action == "override":
        mode_map = {
            "autonomous": "auto_wfp",
            "prompt": "prompt_analyst",
            "audit": "audit_only",
            "audit_p1": "audit_p1",
            "quorum": "quorum",
            "inherit": "inherit",
        }
        maint = True if parsed.maintenance else (False if parsed.no_maintenance else None)
        res = pm.set_host_override(host_id=parsed.host, mode=mode_map[parsed.mode], maintenance_mode=maint)
        out.print(f"[bold #10b981][+][/] Host policy override applied: {res or 'Cleared (Inherited)'}")
        return 0

    if parsed.action == "sync":
        url = parsed.soc_url.rstrip("/") + "/api/policies"
        try:
            with request.urlopen(url, timeout=4.0) as resp:
                remote_pol = json.loads(resp.read().decode("utf-8"))
            pm.state.update(remote_pol)
            pm.save()
            out.print(f"[bold #10b981][+][/] Synced policy revision v{pm.state.get('revision')} from {url}")
            return 0
        except Exception as exc:
            out.print(f"[bold #ef4444][-][/] Failed to sync policy from {url}: {exc}")
            return 1

    return 0


def main(args: Optional[list[str]] = None) -> int:
    """Unified CLI execution entrypoint."""
    eff_args = sys.argv[1:] if args is None else list(args)
    if eff_args and eff_args[0] == "policy":
        return _handle_policy_cli(eff_args[1:])

    if "-h" in eff_args or "--help" in eff_args:
        _print_rich_help()
        return 0

    parser = build_parser()
    parsed_args = parser.parse_args(eff_args)

    if getattr(parsed_args, "version", False):
        _print_version()
        return 0

    if parsed_args.install:
        from uncloak.agent.service import install_windows_service
        return 0 if install_windows_service() else 1

    if parsed_args.uninstall:
        from uncloak.agent.service import uninstall_windows_service
        return 0 if uninstall_windows_service() else 1

    if parsed_args.status:
        from uncloak.agent.service import query_service_status
        query_service_status()
        return 0

    if parsed_args.read:
        from uncloak.capture.pcap import render_pcap_report
        try:
            return render_pcap_report(
                parsed_args.read,
                json_mode=parsed_args.json,
                threshold=parsed_args.threshold,
                min_bursts=parsed_args.min_bursts,
            )
        except Exception as exc:
            print(f"[-] PCAP analysis error: {exc}", file=sys.stderr)
            return 1

    sub = parsed_args.subcommand
    is_service = parsed_args.service or parsed_args.agent or sub in ("service", "agent")
    is_ui = parsed_args.ui or sub in ("tui", "hunt", "cli")
    is_web = parsed_args.web or sub in ("web", "manager", "gui", "demo") or (parsed_args.demo and not is_ui and not is_service)

    if is_service or (parsed_args.json and not parsed_args.read and not is_ui and not is_web):
        from uncloak.agent.service import UncloakAgentService
        from uncloak.export.siem import render_service_console_preview

        mgr_url = parsed_args.soc_url or f"http://127.0.0.1:{parsed_args.port}"
        agent = UncloakAgentService(manager_url=mgr_url, heartbeat_interval=parsed_args.interval)
        if parsed_args.json:
            events, _, _ = agent.emit_siem_cycle(
                ndjson_path=parsed_args.siem_out,
                include_sample_detections=True,
            )
            for ev in events:
                print(json.dumps(ev))
            return 0

        if parsed_args.once:
            from rich.console import Console
            console = Console(color_system="truecolor")
            events, out_path, statuses = agent.emit_siem_cycle(
                ndjson_path=parsed_args.siem_out,
                include_sample_detections=True,
            )
            render_service_console_preview(console, events, out_path, statuses)
            return 0

        _print_service_startup_banner(agent, parsed_args.siem_out)
        agent.start(daemon=False)
        return 0

    if is_ui:
        from uncloak.ui.cockpit import run_cockpit
        return run_cockpit(demo_mode=bool(parsed_args.demo))

    if is_web:
        from uncloak.ui.desktop import launch_desktop
        return launch_desktop(port=parsed_args.port)

    # Bare invocation ('uncloak'): print clean CLI command matrix instead of hijacking browser
    _print_cli_overview()
    return 0


if __name__ == "__main__":
    sys.exit(main())
