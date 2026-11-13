"""
Process Identity & Filesystem Classification for Anti-PID Recycling Attribution.
Computes synthetic ProcessGuid, binary SHA-256, and Feature Schema v1 path classes.
"""

from __future__ import annotations

import hashlib
import os
from typing import Optional


def get_file_sha256(file_path: str) -> Optional[str]:
    """Computes SHA-256 hash of a local binary with chunked reading."""
    if not file_path or not os.path.isfile(file_path):
        return None
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None


def generate_process_guid(boot_time: float, pid: int, create_time: float) -> str:
    """
    Generates a deterministic synthetic ProcessGuid to counter PID recycling.
    Unique across OS reboots and lifetime cycles.
    """
    material = f"{boot_time:.4f}:{pid}:{create_time:.4f}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


def classify_path(exe_path: str) -> int:
    """
    Classifies binary execution location according to Feature Schema v1:
      0 = System / Program Files (trusted administrative directories)
      1 = AppData / Local / User Profile
      2 = Temp / Downloads / Public / Writable Staging
      3 = Unresolved / Exited / Empty
    """
    if not exe_path:
        return 3

    path_lower = exe_path.lower().replace("/", "\\")

    # Tier 2: High-risk staging directories
    if any(k in path_lower for k in [
        "\\temp\\",
        "\\tmp\\",
        "\\downloads\\",
        "\\users\\public\\",
        "\\perflogs\\",
        "\\spool\\drivers\\color\\",
    ]):
        return 2

    # Tier 1: User-writable profile directories
    if any(k in path_lower for k in [
        "\\appdata\\",
        "\\local settings\\",
        "\\users\\",
        "\\home\\",
    ]):
        return 1

    # Tier 0: Protected system and program file locations
    if any(k in path_lower for k in [
        "c:\\windows\\system32\\",
        "c:\\windows\\syswow64\\",
        "c:\\windows\\",
        "c:\\program files\\",
        "c:\\program files (x86)\\",
        "\\usr\\bin\\",
        "\\usr\\sbin\\",
        "\\bin\\",
        "\\sbin\\",
    ]) or any(k in exe_path.lower() for k in ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"]):
        return 0

    # Default to user-space classification if uncertain
    return 1
