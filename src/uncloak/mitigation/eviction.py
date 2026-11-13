"""
Surgical TCP Connection Teardown via Win32 iphlpapi.dll SetTcpEntry.
Sends an immediate TCP RST packet and deletes the kernel TCB block without terminating the host process.
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys
import logging

logger = logging.getLogger("uncloak.mitigation.eviction")

MIB_TCP_STATE_DELETE_TCB = 12


class MIB_TCPROW(ctypes.Structure):
    """Win32 MIB_TCPROW structure for SetTcpEntry."""
    _fields_ = [
        ("dwState", ctypes.c_ulong),
        ("dwLocalAddr", ctypes.c_ulong),
        ("dwLocalPort", ctypes.c_ulong),
        ("dwRemoteAddr", ctypes.c_ulong),
        ("dwRemotePort", ctypes.c_ulong),
    ]


def _htons(port: int) -> int:
    """Converts host byte order port to network byte order for Win32 API."""
    return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)


def sever_tcp_connection(
    local_ip: str,
    local_port: int,
    remote_ip: str,
    remote_port: int,
) -> bool:
    """
    Surgically severs an established IPv4 TCP connection by issuing MIB_TCP_STATE_DELETE_TCB.
    This instructs the Windows TCP/IP stack to send a TCP RST and flush the socket.
    Returns True on success, False otherwise.
    """
    if sys.platform != "win32":
        logger.info(
            "[POSIX SIMULATION] sever_tcp_connection %s:%d -> %s:%d (DELETE_TCB)",
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        )
        return True

    try:
        iphlpapi = ctypes.windll.iphlpapi  # type: ignore[attr-defined]

        local_addr_int = struct.unpack("<L", socket.inet_aton(local_ip))[0]
        remote_addr_int = struct.unpack("<L", socket.inet_aton(remote_ip))[0]

        row = MIB_TCPROW()
        row.dwState = MIB_TCP_STATE_DELETE_TCB
        row.dwLocalAddr = local_addr_int
        row.dwLocalPort = _htons(local_port)
        row.dwRemoteAddr = remote_addr_int
        row.dwRemotePort = _htons(remote_port)

        res = iphlpapi.SetTcpEntry(ctypes.byref(row))
        if res == 0:
            logger.warning(
                "Successfully evicted TCP socket %s:%d -> %s:%d via SetTcpEntry",
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            )
            return True
        else:
            logger.error(
                "SetTcpEntry failed with Win32 error code: %d",
                res,
            )
            return False
    except Exception as exc:
        logger.error("Exception during SetTcpEntry execution: %s", exc)
        return False
