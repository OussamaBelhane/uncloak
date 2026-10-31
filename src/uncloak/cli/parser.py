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

    # Direct Sovereign Cockpit Execution (Htop / K9s Standard)
    from uncloak.ui.cockpit import run_cockpit
    return run_cockpit(demo_mode=True)


if __name__ == "__main__":
    sys.exit(main())
