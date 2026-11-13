"""
POSIX-compliant argument parser for Uncloak Enterprise.
"""

import argparse
import sys
from typing import Optional


def build_parser() -> argparse.ArgumentParser:
    """Constructs the primary CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="uncloak",
        description="Autonomous C2 Stealth Jitter Detection & Win32 Socket Attribution Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="%(prog)s 0.1.0 (Enterprise Architecture)",
    )
    
    # Optional positional subcommand for clean ergonomic CLI (e.g. 'uncloak manager', 'uncloak agent', 'uncloak demo')
    parser.add_argument(
        "subcommand",
        nargs="?",
        choices=["manager", "agent", "gui", "cli", "hunt", "demo"],
        default=None,
        help="Subcommand mode: manager (Fleet Dashboard), agent (Endpoint Daemon), cli/hunt (Terminal TUI), demo (Simulated AD Fleet)",
    )

    # Execution modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--demo",
        action="store_true",
        help="Launch the dedicated enterprise cockpit in simulated demo mode (32 synthetic AD hosts)",
    )
    mode_group.add_argument(
        "--manager",
        action="store_true",
        help="Start the Uncloak Enterprise Central Fleet Manager web dashboard and API",
    )
    mode_group.add_argument(
        "--agent",
        action="store_true",
        help="Start the headless Uncloak Endpoint Agent background daemon",
    )
    mode_group.add_argument(
        "--live",
        action="store_true",
        help="Start real-time packet ingestion and CUI cockpit",
    )
    mode_group.add_argument(
        "-r", "--read",
        metavar="FILE.pcap",
        help="Offline triage mode: replay and analyze a PCAP capture file",
    )
    mode_group.add_argument(
        "--gui",
        action="store_true",
        help="Launch the dedicated enterprise WebView2 desktop cockpit window (default on Windows desktop)",
    )
    mode_group.add_argument(
        "--cli",
        action="store_true",
        help="Force pure terminal CUI cockpit execution (for SSH, WinRM, or headless servers)",
    )
    
    # Ingestion tuning
    parser.add_argument(
        "-i", "--interface",
        metavar="IFACE",
        help="Network interface index or name to capture on (default: auto-detect active adapter)",
    )
    parser.add_argument(
        "-f", "--filter",
        default="tcp and port 443",
        metavar="BPF",
        help="Berkeley Packet Filter (BPF) string (default: 'tcp and port 443')",
    )
    
    # Output & SOC
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Headless output: stream alerts as line-delimited JSON (NDJSON) to stdout",
    )
    parser.add_argument(
        "-t", "--threshold",
        type=float,
        default=0.75,
        metavar="FLOAT",
        help="Threat score alert threshold between 0.0 and 1.0 (default: 0.75)",
    )
    parser.add_argument(
        "--db",
        default="uncloak.db",
        metavar="PATH",
        help="Path to embedded SQLite telemetry database (default: uncloak.db)",
    )

    # Windows Startup Service Lifecycle
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install Uncloak Agent as a silent background Windows daemon starting automatically on PC boot",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove Uncloak Agent background daemon from Windows startup",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Check the running status of the background Windows agent service",
    )
    
    return parser


def main(args: Optional[list[str]] = None) -> int:
    """CLI execution entrypoint."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)
    
    if parsed_args.json:
        print(f"[*] Uncloak v0.1.0 headless NDJSON streaming initialized (Filter: '{parsed_args.filter}')")
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
        from uncloak.capture.pcap import analyze_pcap
        print(f"[*] Replaying capture from: {parsed_args.read}")
        count = 0
        try:
            for flow_key, features in analyze_pcap(parsed_args.read):
                count += 1
                print(
                    f"[+] Flow: {flow_key} | Bursts: {features.n_bursts} | "
                    f"IAT Median: {features.iat_median:.3f}s | "
                    f"MAD: {features.iat_mad_ratio:.3f} | "
                    f"IQR: {features.iat_iqr_ratio:.3f} | "
                    f"Skew: {features.iat_bowley_skew:.3f}"
                )
            print(f"[*] PCAP analysis complete. Extracted features for {count} qualifying flows.")
        except Exception as exc:
            print(f"[-] PCAP analysis error: {exc}")
            return 1
        return 0

    is_demo = parsed_args.demo or parsed_args.subcommand == "demo"
    is_agent = parsed_args.agent or parsed_args.subcommand == "agent"
    is_manager = parsed_args.manager or parsed_args.subcommand == "manager"
    is_cli = parsed_args.cli or parsed_args.subcommand in ("cli", "hunt")
    is_gui = parsed_args.gui or parsed_args.subcommand == "gui"

    if is_agent:
        from uncloak.agent.service import UncloakAgentService
        agent = UncloakAgentService()
        print(f"[*] Uncloak Silent Endpoint Agent initialized on [{agent.hostname}]")
        print(f"[*] Connecting to Manager at {agent.manager_url} (Heartbeat: 15s)...")
        agent.start(daemon=False)
        return 0

    if is_cli:
        from uncloak.ui.cockpit import run_cockpit
        return run_cockpit(demo_mode=is_demo or True)

    if is_demo or is_manager or is_gui or (sys.platform == "win32" and not is_cli):
        # Default on Windows desktop or when manager/demo is requested
        from uncloak.ui.desktop import launch_desktop
        return launch_desktop()

    # Default on Linux/macOS terminal
    from uncloak.ui.cockpit import run_cockpit
    return run_cockpit(demo_mode=True)


if __name__ == "__main__":
    sys.exit(main())
