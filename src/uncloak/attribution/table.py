"""
Win32 TCP Socket Table Introspection via iphlpapi.dll GetExtendedTcpTable.
Resolves active TCP connections directly to owning Process ID (PID).
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys
from typing import Any

# Windows TCP Connection States
TCP_STATES = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RCVD",
    5: "ESTABLISHED",
    6: "FIN_WAIT1",
    7: "FIN_WAIT2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}

# TCP_TABLE_CLASS enum value for owner PID table
TCP_TABLE_OWNER_PID_ALL = 5


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    """Win32 MIB_TCPROW_OWNER_PID structure."""
    _fields_ = [
        ("dwState", ctypes.c_ulong),
        ("dwLocalAddr", ctypes.c_ulong),
        ("dwLocalPort", ctypes.c_ulong),
        ("dwRemoteAddr", ctypes.c_ulong),
        ("dwRemotePort", ctypes.c_ulong),
        ("dwOwningPid", ctypes.c_ulong),
    ]


def _ntohs(port_raw: int) -> int:
    """Decodes network byte order port from Win32 DWORD."""
    return ((port_raw & 0xFF) << 8) | ((port_raw >> 8) & 0xFF)


def _format_ipv4(addr_raw: int) -> str:
    """Formats 32-bit integer IPv4 address to dotted-decimal string."""
    return socket.inet_ntoa(struct.pack("<L", addr_raw))


def get_extended_tcp_table() -> list[dict[str, Any]]:
    """
    Retrieves the complete IPv4 TCP socket table with owning PID via iphlpapi.dll.
    Provides POSIX/Linux fallback for local development and non-Windows testing.
    """
    if sys.platform != "win32":
        return _get_posix_tcp_table()

    iphlpapi = ctypes.windll.iphlpapi  # type: ignore[attr-defined]
    size = ctypes.c_ulong(0)

    # First probe call to retrieve required buffer size
    ret = iphlpapi.GetExtendedTcpTable(
        None,
        ctypes.byref(size),
        True,  # bOrder: sort by local IP/port
        socket.AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    )

    buf = (ctypes.c_byte * size.value)()
    ret = iphlpapi.GetExtendedTcpTable(
        ctypes.byref(buf),
        ctypes.byref(size),
        True,
        socket.AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    )

    if ret != 0:
        return []

    # First DWORD is dwNumEntries
    num_entries = ctypes.c_ulong.from_buffer_copy(buf, 0).value
    row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
    offset = ctypes.sizeof(ctypes.c_ulong)

    rows: list[dict[str, Any]] = []
    for _ in range(num_entries):
        row = MIB_TCPROW_OWNER_PID.from_buffer_copy(buf, offset)
        offset += row_size
        rows.append({
            "state": TCP_STATES.get(row.dwState, f"UNKNOWN_{row.dwState}"),
            "state_id": row.dwState,
            "local_ip": _format_ipv4(row.dwLocalAddr),
            "local_port": _ntohs(row.dwLocalPort),
            "remote_ip": _format_ipv4(row.dwRemoteAddr),
            "remote_port": _ntohs(row.dwRemotePort),
            "pid": row.dwOwningPid,
        })

    return rows


def _get_posix_tcp_table() -> list[dict[str, Any]]:
    """Fallback reader for Linux /proc/net/tcp during local testing."""
    results: list[dict[str, Any]] = []
    try:
        with open("/proc/net/tcp", "r", encoding="utf-8") as f:
            lines = f.readlines()[1:]
            for line in lines:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                local_hex, local_port_hex = parts[1].split(":")
                remote_hex, remote_port_hex = parts[2].split(":")
                state_hex = parts[3]
                inode = int(parts[9])

                local_ip = socket.inet_ntoa(struct.pack("<L", int(local_hex, 16)))
                remote_ip = socket.inet_ntoa(struct.pack("<L", int(remote_hex, 16)))
                local_port = int(local_port_hex, 16)
                remote_port = int(remote_port_hex, 16)
                state_id = int(state_hex, 16)

                results.append({
                    "state": TCP_STATES.get(state_id, f"STATE_{state_id}"),
                    "state_id": state_id,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "pid": 0,
                    "inode": inode,
                })
    except Exception:
        pass
    return results
