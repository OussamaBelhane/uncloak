"""
Unit tests for surgical TCP eviction and per-app firewall containment.
"""

from uncloak.mitigation.eviction import sever_tcp_connection
from uncloak.mitigation.firewall import (
    block_application_destination,
    remove_containment_rule,
)


def test_sever_tcp_connection_call() -> None:
    """Verifies that sever_tcp_connection executes safely with valid IP arguments."""
    res = sever_tcp_connection("127.0.0.1", 49152, "10.0.0.1", 443)
    assert isinstance(res, bool)


def test_firewall_validation() -> None:
    """Verifies that firewall containment validates IP format against injection."""
    # Invalid IP should be rejected immediately
    res_bad = block_application_destination(
        rule_name="TestBad",
        program_path=r"C:\test.exe",
        remote_ip="invalid; echo pwn",
    )
    assert res_bad is False

    # Valid IPv4 should proceed to execution
    res_good = block_application_destination(
        rule_name="TestGood",
        program_path=r"C:\test.exe",
        remote_ip="193.26.158.114",
    )
    assert res_good is True

    # Rule deletion cleanup
    res_del = remove_containment_rule("TestGood")
    assert res_del is True
