"""
Unit tests for host attribution, digital signature verification, and process identity.
"""

from uncloak.attribution.identity import (
    classify_path,
    generate_process_guid,
    get_file_sha256,
)
from uncloak.attribution.table import get_extended_tcp_table
from uncloak.attribution.trust import verify_authenticode


def test_classify_path_tiers() -> None:
    """Verifies that filesystem path classification maps to Feature Schema v1 tiers."""
    # Tier 0: System & Program Files
    assert classify_path(r"C:\Windows\System32\svchost.exe") == 0
    assert classify_path(r"C:\Program Files\Common Files\service.exe") == 0
    assert classify_path("/usr/bin/python3") == 0

    # Tier 1: User profile & AppData
    assert classify_path(r"C:\Users\John\AppData\Local\Discord\app.exe") == 1
    assert classify_path(r"C:\Users\Administrator\app.exe") == 1

    # Tier 2: Staging directories (Temp, Downloads, Public)
    assert classify_path(r"C:\Users\John\AppData\Local\Temp\beacon.exe") == 2
    assert classify_path(r"C:\Users\John\Downloads\malware.exe") == 2
    assert classify_path(r"C:\Users\Public\update.exe") == 2

    # Tier 3: Unresolved / empty
    assert classify_path("") == 3


def test_generate_process_guid() -> None:
    """Verifies deterministic synthetic ProcessGuid generation."""
    guid1 = generate_process_guid(1700000000.0, 4820, 1700000010.5)
    guid2 = generate_process_guid(1700000000.0, 4820, 1700000010.5)
    guid3 = generate_process_guid(1700000000.0, 4821, 1700000010.5)

    assert len(guid1) == 32
    assert guid1 == guid2
    assert guid1 != guid3


def test_get_extended_tcp_table() -> None:
    """Verifies socket table reader returns valid list without crashing."""
    rows = get_extended_tcp_table()
    assert isinstance(rows, list)
    if rows:
        r = rows[0]
        assert "local_ip" in r
        assert "local_port" in r
        assert "remote_ip" in r
        assert "remote_port" in r
        assert "state" in r
        assert "pid" in r


def test_verify_authenticode() -> None:
    """Verifies Authenticode signature handling."""
    is_signed, error = verify_authenticode("non_existent_file.exe")
    assert is_signed is False
    assert error == "FILE_NOT_FOUND"
