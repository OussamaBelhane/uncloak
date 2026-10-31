"""
Unit tests for core data models.
"""

from uncloak.core.models import FlowSession, PacketEvent, AttributionRecord


def test_packet_event_immutable(sample_packet_event: PacketEvent) -> None:
    """Verifies that PacketEvent is an immutable frozen dataclass."""
    assert sample_packet_event.src_port == 49152
    assert sample_packet_event.dst_port == 443
    assert sample_packet_event.sni == "cdn.legitimate-domain.com"


def test_flow_session_deltas(sample_flow_session: FlowSession) -> None:
    """Verifies delta time tracking on FlowSession."""
    assert len(sample_flow_session.delta_times) == 9
    assert 9.0 <= sample_flow_session.delta_times[0] <= 11.0


def test_attribution_record(sample_attribution_record: AttributionRecord) -> None:
    """Verifies AttributionRecord fields."""
    assert sample_attribution_record.pid == 4820
    assert sample_attribution_record.process_name == "powershell.exe"
    assert not sample_attribution_record.is_elevated
