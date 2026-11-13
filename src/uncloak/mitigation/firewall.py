"""
Per-Application Firewall Containment via Windows Defender Firewall (netsh).
Blocks beacon reconnects without killing host processes or severing benign system services.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
import sys

logger = logging.getLogger("uncloak.mitigation.firewall")


def _is_valid_ip(ip_str: str) -> bool:
    """Validates IPv4 or IPv6 string format to prevent parameter injection."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def block_application_destination(
    rule_name: str,
    program_path: str,
    remote_ip: str,
) -> bool:
    """
    Enforces a targeted outbound firewall rule specifically scoped to the program binary
    and the C2 destination IP. Uses an argument list without shell=True.
    """
    if not _is_valid_ip(remote_ip):
        logger.error("Invalid IP address supplied for containment rule: %s", remote_ip)
        return False

    if sys.platform != "win32":
        logger.info(
            "[POSIX SIMULATION] block_application_destination: Rule '%s' for program '%s' to IP %s",
            rule_name,
            program_path,
            remote_ip,
        )
        return True

    args = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"program={program_path}",
        f"remoteip={remote_ip}",
        "enable=yes",
    ]

    try:
        res = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode == 0:
            logger.warning(
                "Successfully added firewall containment rule '%s' for %s -> %s",
                rule_name,
                program_path,
                remote_ip,
            )
            return True
        else:
            logger.error("Failed to add firewall rule: %s", res.stderr.strip())
            return False
    except Exception as exc:
        logger.error("Exception executing firewall rule addition: %s", exc)
        return False


def remove_containment_rule(rule_name: str) -> bool:
    """Removes a previously enforced containment firewall rule by name."""
    if sys.platform != "win32":
        logger.info("[POSIX SIMULATION] remove_containment_rule: '%s'", rule_name)
        return True

    args = [
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        f"name={rule_name}",
    ]

    try:
        res = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return res.returncode == 0
    except Exception as exc:
        logger.error("Exception removing firewall rule: %s", exc)
        return False
