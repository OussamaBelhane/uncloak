"""
POSIX-compliant argument parser for Uncloak.
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
        version="%(prog)s 0.1.0",
    )
    
    # Execution modes
    mode_group = parser.add_mutually_exclusive_group()
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
    
    return parser


def main(args: Optional[list[str]] = None) -> int:
    """CLI execution entrypoint."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)
    
    if parsed_args.json:
        print(f"[*] Uncloak v0.1.0 headless NDJSON streaming initialized (Filter: '{parsed_args.filter}')")
        return 0

    if parsed_args.cli:
        from uncloak.ui.cockpit import run_cockpit
        return run_cockpit(demo_mode=True)

    if parsed_args.gui or (sys.platform == "win32" and not parsed_args.cli):
        # Default on Windows desktop is the dedicated WebView2 Desktop Cockpit window
        from uncloak.ui.desktop import launch_desktop
        return launch_desktop()

    # Default on Linux/macOS terminal
    from uncloak.ui.cockpit import run_cockpit
    return run_cockpit(demo_mode=True)


if __name__ == "__main__":
    sys.exit(main())
