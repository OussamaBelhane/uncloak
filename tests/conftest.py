"""
Global pytest fixtures and test configuration for Uncloak.
"""

import pytest
from uncloak.core.models import AttributionRecord, FlowSession, PacketEvent


@pytest.fixture
def sample_packet_event() -> PacketEvent:
    """Provides a synthetic HTTPS packet event."""
    return PacketEvent(
        timestamp=1700000000.123456,
        src_ip="192.168.1.100",
        src_port=49152,
        dst_ip="198.51.100.25",
        dst_port=443,
        protocol="TCP",
        payload_len=284,
        tcp_flags="PA",
        sni="cdn.legitimate-domain.com",
    )


@pytest.fixture
def sample_flow_session() -> FlowSession:
    """Provides a synthetic 5-tuple TCP session with artificial beacon jitter."""
    # 10s base beacon interval with +/- 10% jitter (9.0s to 11.0s)
    deltas = [10.2, 9.8, 10.1, 9.5, 10.4, 9.9, 10.0, 10.3, 9.7]
    return FlowSession(
        session_id="192.168.1.100:49152->198.51.100.25:443",
        src_ip="192.168.1.100",
        src_port=49152,
        dst_ip="198.51.100.25",
        dst_port=443,
        sni="cdn.legitimate-domain.com",
        packet_count=len(deltas) + 1,
        byte_count=4096,
        delta_times=deltas,
    )


@pytest.fixture
def sample_attribution_record() -> AttributionRecord:
    """Provides a synthetic host process attribution."""
    return AttributionRecord(
        pid=4820,
        process_name="powershell.exe",
        executable_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -ExecutionPolicy Bypass -NoProfile -Enc JABjAD0AbgBlAHc...",
        user_token="CORP\\jdoe",
        is_elevated=False,
    )
