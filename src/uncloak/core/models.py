"""
Core data models and contracts for Uncloak.
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
