"""
Core data models and contracts for Uncloak Enterprise.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class PacketEvent:
    """Represents a single dissected network packet event."""
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    payload_len: int
    tcp_flags: Optional[str] = None
    sni: Optional[str] = None


@dataclass
class FlowSession:
    """Tracks a 5-tuple TCP session over time."""
    session_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    sni: Optional[str] = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    delta_times: list[float] = field(default_factory=list)


@dataclass
class AttributionRecord:
    """Contains host process attribution resolved from Win32 kernel tables."""
    pid: int
    process_name: str
    executable_path: str
    command_line: Optional[str] = None
    user_token: Optional[str] = None
    is_elevated: bool = False


@dataclass
class JitterMetrics:
    """Calculated statistical jitter metrics for a session."""
    median_interval: float
    iqr: float
    mad: float
    jitter_percentage: float
    entropy: float
    score: float


@dataclass
class ThreatAlert:
    """Actionable alert generated when a flow crosses detection thresholds."""
    alert_id: str
    timestamp: datetime
    session_id: str
    threat_score: float
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    attribution: AttributionRecord
    metrics: JitterMetrics
    dst_ip: str
    dst_port: int
    sni: Optional[str] = None
    recommended_action: str = "INSPECT"


@dataclass
class HostEndpoint:
    """Represents an enterprise machine monitored by an Uncloak Agent."""
    host_id: str
    hostname: str
    ip_address: str
    subnet: str
    os_version: str
    agent_version: str
    status: str  # ONLINE, DEGRADED, MUTED
    last_heartbeat: float
    threat_level: str  # CRITICAL, HIGH, EVALUATING, HEALTHY
    threat_score: float
    active_sockets_count: int
    isolated_beacons_count: int
    c2_framework: Optional[str] = None
    cpu_percent: float = 0.8
    ram_mb: float = 7.5


@dataclass
class CampaignCluster:
    """Correlates multiple enterprise endpoints exhibiting identical C2 signatures."""
    campaign_id: str
    name: str
    c2_framework: str
    ja4_fingerprint: str
    cadence_profile: str
    affected_hosts: list[str]
    target_destination: str
    threat_score: float
    status: str = "ACTIVE_INTRUSION"  # ACTIVE_INTRUSION, CONTAINED


@dataclass(frozen=True)
class FlowFeaturesV1:
    """Frozen 12-feature schema contract for Uncloak v1.0 inference and training."""
    n_bursts: int
    iat_median: float
    iat_mad_ratio: float
    iat_iqr_ratio: float
    iat_bowley_skew: float
    size_out_median: float
    size_in_median: float
    size_mad_ratio: float
    conn_per_burst: float
    raw_ip_flag: int
    proc_signed: int
    proc_path_class: int
    label: Optional[int] = None

    def to_vector(self) -> list[float]:
        """Returns the 12 numerical features as an inference vector."""
        return [
            float(self.n_bursts),
            self.iat_median,
            self.iat_mad_ratio,
            self.iat_iqr_ratio,
            self.iat_bowley_skew,
            self.size_out_median,
            self.size_in_median,
            self.size_mad_ratio,
            self.conn_per_burst,
            float(self.raw_ip_flag),
            float(self.proc_signed),
            float(self.proc_path_class),
        ]
