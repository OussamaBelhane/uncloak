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
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version="%(prog)s 0.2.0 (Live Endpoint + Central SOC Manager | Schema v1)",
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


def _print_cli_overview() -> None:
    """Prints the Live Endpoint + Central SOC architecture overview when 'uncloak' is invoked bare."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console(color_system="truecolor")
    hdr = Text()
    hdr.append("UNCLOAK v0.2.0", style="bold #10b981")
    hdr.append(" // Live C2 Jitter Detection, Win32 Attribution & Central SOC Manager\n", style="bold white")
    hdr.append("Feature Contract: ", style="#94a3b8")
    hdr.append("Feature Schema v1 (12-Dim Robust IAT Dispersion)", style="#38bdf8")

    console.print(Panel(hdr, box=box.ROUNDED, style="on #090e1c", border_style="#1e293b", padding=(0, 1)))

    tbl = Table(box=box.ROUNDED, style="on #090e1c", border_style="#1e293b", header_style="bold #94a3b8 on #090e1c", expand=True)
    tbl.add_column("COMPONENT", width=14, no_wrap=True)
    tbl.add_column("COMMAND", width=26, no_wrap=True)
    tbl.add_column("SIDE", min_width=11, ratio=1)
    tbl.add_column("LIVE CAPABILITY", ratio=2)

    tbl.add_row(
        Text("Endpoint Agent", style="bold #10b981"),
        Text("uncloak service [--once]\n(uncloak-agent)", style="bold white"),
        "Windows Endpoint (SYSTEM)",
        "Live Npcap capture, Win32 PID attribution, SetTcpEntry kill, manager heartbeat & SIEM EID 9001/9002.",
    )
    tbl.add_row(
        Text("Endpoint CUI", style="bold #f59e0b"),
        Text("uncloak --ui [--demo]", style="bold white"),
        "Endpoint Admin",
        "On-demand live Rich Terminal CUI for real-time host socket streams & surgical severing.",
    )
    tbl.add_row(
        Text("Central SOC", style="bold #38bdf8"),
        Text("uncloak manager [--demo]\n(uncloak-manager)", style="bold white"),
        "Central SOC Analyst",
        "Live Central SOC Web Cockpit (Fleet Matrix, JA4 Campaign Graph, Live Host Triage).",
    )
    tbl.add_row(
        Text("Replay Harness", style="bold #94a3b8"),
        Text("uncloak -r <pcap> [--json]", style="bold white"),
        "Lab Eval & CI",
        "Module 12 PCAP replay harness feeding recorded traces into the live FlowFeaturesV1 engine.",
    )
    console.print(tbl)


def main(args: Optional[list[str]] = None) -> int:
    """Unified CLI execution entrypoint."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

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

        agent = UncloakAgentService(manager_url=f"http://127.0.0.1:{parsed_args.port}")
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

        print(f"[*] Uncloak Headless Endpoint Sensor initialized on [{agent.hostname}]")
        print(f"[*] SIEM Sink Active: Windows Event Log (EID 9001/9002) + OCSF NDJSON ({parsed_args.siem_out})")
        print("[*] Listening Ports : 0 (Zero endpoint HTTP attack surface)")
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
