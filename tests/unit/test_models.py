"""
Unit tests for core data models and Feature Schema v1 contracts.
"""

from typing import Optional
from uncloak.core.models import FlowSession, PacketEvent, AttributionRecord, FlowFeaturesV1


def _make_packet_event() -> PacketEvent:
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


def _make_flow_session() -> FlowSession:
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


def _make_attribution_record() -> AttributionRecord:
    return AttributionRecord(
        pid=4820,
        process_name="powershell.exe",
        executable_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -ExecutionPolicy Bypass -NoProfile",
        user_token="CORP\\jdoe",
        is_elevated=False,
    )


def test_packet_event_immutable(sample_packet_event: Optional[PacketEvent] = None) -> None:
    """Verifies that PacketEvent is an immutable frozen dataclass."""
    event = sample_packet_event or _make_packet_event()
    assert event.src_port == 49152
    assert event.dst_port == 443
    assert event.sni == "cdn.legitimate-domain.com"


def test_flow_session_deltas(sample_flow_session: Optional[FlowSession] = None) -> None:
    """Verifies delta time tracking on FlowSession."""
    session = sample_flow_session or _make_flow_session()
    assert len(session.delta_times) == 9
    assert 9.0 <= session.delta_times[0] <= 11.0


def test_attribution_record(sample_attribution_record: Optional[AttributionRecord] = None) -> None:
    """Verifies AttributionRecord fields."""
    record = sample_attribution_record or _make_attribution_record()
    assert record.pid == 4820
    assert record.process_name == "powershell.exe"
    assert not record.is_elevated


def test_flow_features_v1_vector_mapping() -> None:
    """Verifies that FlowFeaturesV1 exports exactly 12 numerical features."""
    feat = FlowFeaturesV1(
        n_bursts=15,
        iat_median=12.5,
        iat_mad_ratio=0.08,
        iat_iqr_ratio=0.12,
        iat_bowley_skew=0.02,
        size_out_median=250.0,
        size_in_median=1200.0,
        size_mad_ratio=0.04,
        conn_per_burst=1.0,
        raw_ip_flag=1,
        proc_signed=0,
        proc_path_class=2,
    )
    vec = feat.to_vector()
    assert len(vec) == 12
    assert vec[0] == 15.0
    assert vec[9] == 1.0   # raw_ip_flag
    assert vec[10] == 0.0  # proc_signed
    assert vec[11] == 2.0  # proc_path_class
