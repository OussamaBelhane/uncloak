"""Unit tests for the FoxIO JA4 TLS ClientHello fingerprinter."""

import hashlib
import struct

from uncloak.capture.ja4 import is_grease, parse_tls_client_hello


def _build_client_hello(
    legacy_version: int,
    ciphers: list[int],
    extensions: list[tuple[int, bytes]],
) -> bytes:
    """Constructs a minimal RFC-compliant TLS ClientHello record."""
    random_bytes = b"\xaa" * 32
    session_id = b""
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    ext_bytes = b"".join(
        struct.pack("!HH", ext_type, len(ext_data)) + ext_data
        for ext_type, ext_data in extensions
    )

    body = (
        struct.pack("!H", legacy_version)
        + random_bytes
        + bytes([len(session_id)])
        + session_id
        + struct.pack("!H", len(cipher_bytes))
        + cipher_bytes
        + b"\x01\x00"  # compression methods: null
        + struct.pack("!H", len(ext_bytes))
        + ext_bytes
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
    return record


def _sni_ext(hostname: str) -> bytes:
    host_b = hostname.encode("ascii")
    entry = struct.pack("!BH", 0, len(host_b)) + host_b
    return struct.pack("!H", len(entry)) + entry


def _alpn_ext(proto: str) -> bytes:
    proto_b = proto.encode("ascii")
    entry = bytes([len(proto_b)]) + proto_b
    return struct.pack("!H", len(entry)) + entry


def test_grease_detection() -> None:
    assert is_grease(0x0A0A) is True
    assert is_grease(0xFAFA) is True
    assert is_grease(0x1301) is False
    assert is_grease(0x0000) is False


def test_ja4_tls13_with_sni_alpn_and_grease() -> None:
    ciphers = [0x0A0A, 0x1302, 0x1301, 0x1303]  # 0x0a0a is GREASE
    exts = [
        (0x0A0A, b""),  # GREASE extension
        (0x0000, _sni_ext("cdn.example.com")),
        (0x0010, _alpn_ext("h2")),
        (0x002B, b"\x04\x0a\x0a\x03\x04"),  # supported_versions: GREASE + TLS 1.3
        (0x000D, struct.pack("!HHH", 4, 0x0403, 0x0804)),  # sig_algs
    ]
    payload = _build_client_hello(0x0303, ciphers, exts)
    info = parse_tls_client_hello(payload)

    assert info is not None
    assert info.tls_version == "13"
    assert info.sni == "cdn.example.com"
    assert info.alpn == "h2"
    assert info.cipher_count == 3
    assert info.extension_count == 4

    expected_b = hashlib.sha256(b"1301,1302,1303").hexdigest()[:12]
    expected_c = hashlib.sha256(b"000d,002b_0403,0804").hexdigest()[:12]
    assert info.ja4 == f"t13d0304h2_{expected_b}_{expected_c}"


def test_ja4_direct_ip_no_sni_no_alpn() -> None:
    ciphers = [0xC02F, 0xC030]
    exts = [(0x0017, b"")]  # extended_master_secret only
    payload = _build_client_hello(0x0303, ciphers, exts)
    info = parse_tls_client_hello(payload)

    assert info is not None
    assert info.tls_version == "12"
    assert info.sni is None
    assert info.alpn is None
    assert info.ja4.startswith("t12i020100_")


def test_ja4_rejects_non_tls_payloads() -> None:
    assert parse_tls_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None
    assert parse_tls_client_hello(b"\x16\x03\x01\x00\x05hello") is None
