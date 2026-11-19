"""
TLS ClientHello Dissector & FoxIO JA4 Fingerprinter.
Parses raw TLS handshake records to compute JA4 fingerprints and extract SNI hostnames
without external dependencies or TLS decryption.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional

_TLS_VERSION_MAP = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
}


def is_grease(value: int) -> bool:
    """Returns True if the 16-bit identifier is an RFC 8701 GREASE value."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


@dataclass(frozen=True)
class ClientHelloInfo:
    """Structured metadata extracted from a TLS ClientHello packet."""

    ja4: str
    tls_version: str
    sni: Optional[str]
    alpn: Optional[str]
    cipher_count: int
    extension_count: int


def _parse_sni_extension(data: bytes) -> Optional[str]:
    if len(data) < 5:
        return None
    list_len = struct.unpack_from("!H", data, 0)[0]
    if list_len + 2 > len(data):
        return None
    name_type = data[2]
    name_len = struct.unpack_from("!H", data, 3)[0]
    if name_type != 0 or 5 + name_len > len(data):
        return None
    try:
        return data[5 : 5 + name_len].decode("ascii")
    except UnicodeDecodeError:
        return None


def _parse_alpn_extension(data: bytes) -> Optional[str]:
    if len(data) < 4:
        return None
    list_len = struct.unpack_from("!H", data, 0)[0]
    if list_len + 2 > len(data) or list_len < 2:
        return None
    proto_len = data[2]
    if proto_len == 0 or 3 + proto_len > len(data):
        return None
    try:
        return data[3 : 3 + proto_len].decode("ascii")
    except UnicodeDecodeError:
        return None


def _parse_supported_versions(data: bytes) -> Optional[int]:
    if len(data) < 3:
        return None
    vec_len = data[0]
    if vec_len + 1 > len(data) or vec_len % 2 != 0:
        return None
    versions = [
        struct.unpack_from("!H", data, idx)[0]
        for idx in range(1, 1 + vec_len, 2)
    ]
    valid = [v for v in versions if not is_grease(v) and v in _TLS_VERSION_MAP]
    return max(valid) if valid else None


def _parse_signature_algorithms(data: bytes) -> list[int]:
    if len(data) < 4:
        return []
    vec_len = struct.unpack_from("!H", data, 0)[0]
    if vec_len + 2 > len(data) or vec_len % 2 != 0:
        return []
    return [
        struct.unpack_from("!H", data, idx)[0]
        for idx in range(2, 2 + vec_len, 2)
    ]


def _format_alpn_tag(alpn: Optional[str]) -> str:
    if not alpn:
        return "00"
    first, last = alpn[0], alpn[-1]
    if first.isalnum() and last.isalnum():
        return f"{first}{last}"
    return f"{ord(first):02x}"[0] + f"{ord(last):02x}"[-1]


def parse_tls_client_hello(payload: bytes, transport: str = "t") -> Optional[ClientHelloInfo]:
    """
    Dissects a raw TCP/UDP TLS ClientHello payload and computes its FoxIO JA4 fingerprint.
    Returns None if the payload is not a valid TLS ClientHello record.
    """
    if len(payload) < 43 or payload[0] != 0x16:
        return None

    record_len = struct.unpack_from("!H", payload, 3)[0]
    if record_len + 5 > len(payload):
        return None

    handshake = payload[5 : 5 + record_len]
    if len(handshake) < 38 or handshake[0] != 0x01:
        return None

    legacy_version = struct.unpack_from("!H", handshake, 4)[0]
    offset = 38  # 4B handshake header + 2B version + 32B client random

    if offset >= len(handshake):
        return None
    session_id_len = handshake[offset]
    offset += 1 + session_id_len

    if offset + 2 > len(handshake):
        return None
    cipher_suites_len = struct.unpack_from("!H", handshake, offset)[0]
    offset += 2
    if offset + cipher_suites_len > len(handshake) or cipher_suites_len % 2 != 0:
        return None

    ciphers = [
        struct.unpack_from("!H", handshake, offset + i)[0]
        for i in range(0, cipher_suites_len, 2)
    ]
    ciphers_clean = [c for c in ciphers if not is_grease(c)]
    offset += cipher_suites_len

    if offset >= len(handshake):
        return None
    comp_len = handshake[offset]
    offset += 1 + comp_len

    extensions_clean: list[int] = []
    sni: Optional[str] = None
    alpn: Optional[str] = None
    supported_ver: Optional[int] = None
    sig_algs: list[int] = []

    if offset + 2 <= len(handshake):
        ext_total_len = struct.unpack_from("!H", handshake, offset)[0]
        offset += 2
        ext_end = min(offset + ext_total_len, len(handshake))

        while offset + 4 <= ext_end:
            ext_type, ext_len = struct.unpack_from("!HH", handshake, offset)
            offset += 4
            if offset + ext_len > ext_end:
                break
            ext_data = handshake[offset : offset + ext_len]
            offset += ext_len

            if is_grease(ext_type):
                continue
            extensions_clean.append(ext_type)

            if ext_type == 0x0000 and sni is None:
                sni = _parse_sni_extension(ext_data)
            elif ext_type == 0x0010 and alpn is None:
                alpn = _parse_alpn_extension(ext_data)
            elif ext_type == 0x002B:
                supported_ver = _parse_supported_versions(ext_data)
            elif ext_type == 0x000D:
                sig_algs = _parse_signature_algorithms(ext_data)

    eff_ver_int = supported_ver if supported_ver is not None else legacy_version
    ver_str = _TLS_VERSION_MAP.get(eff_ver_int, "00")
    sni_flag = "d" if sni else "i"
    cipher_cnt = f"{min(len(ciphers_clean), 99):02d}"
    ext_cnt = f"{min(len(extensions_clean), 99):02d}"
    alpn_tag = _format_alpn_tag(alpn)
    ja4_a = f"{transport}{ver_str}{sni_flag}{cipher_cnt}{ext_cnt}{alpn_tag}"

    if ciphers_clean:
        cipher_str = ",".join(f"{c:04x}" for c in sorted(ciphers_clean))
        ja4_b = hashlib.sha256(cipher_str.encode("ascii")).hexdigest()[:12]
    else:
        ja4_b = "000000000000"

    ext_filtered = sorted(e for e in extensions_clean if e not in (0x0000, 0x0010))
    if ext_filtered or sig_algs:
        ext_str = ",".join(f"{e:04x}" for e in ext_filtered)
        if sig_algs:
            sig_str = ",".join(f"{s:04x}" for s in sig_algs)
            ext_str = f"{ext_str}_{sig_str}" if ext_str else f"_{sig_str}"
        ja4_c = hashlib.sha256(ext_str.encode("ascii")).hexdigest()[:12]
    else:
        ja4_c = "000000000000"

    return ClientHelloInfo(
        ja4=f"{ja4_a}_{ja4_b}_{ja4_c}",
        tls_version=ver_str,
        sni=sni,
        alpn=alpn,
        cipher_count=len(ciphers_clean),
        extension_count=len(extensions_clean),
    )
