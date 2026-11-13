"""
Network Burst Aggregator and Feature Extractor for Uncloak.
Groups discrete TCP packets separated by <200ms into application bursts and constructs FlowFeaturesV1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from uncloak.capture.stats import compute_burst_stats
from uncloak.core.models import FlowFeaturesV1


@dataclass
class BurstRecord:
    """Represents an aggregated burst of communication."""
    start_time: float
    end_time: float
    bytes_out: int = 0
    bytes_in: int = 0
    packet_count: int = 0
    connection_ids: set[str] = field(default_factory=set)


class BurstAggregator:
    """
    Stateful burst aggregator for a (process_identity, destination_key) flow stream.
    Merges packets within 200ms into a single communication burst.
    """

    def __init__(self, burst_threshold_seconds: float = 0.200) -> None:
        self.burst_threshold = burst_threshold_seconds
        self.current_burst: Optional[BurstRecord] = None
        self.completed_bursts: list[BurstRecord] = []

    def ingest_packet(
        self,
        timestamp: float,
        payload_bytes: int,
        is_outbound: bool,
        connection_id: str = "conn_default",
    ) -> None:
        """Ingests a dissected network packet and updates burst state."""
        if self.current_burst is None:
            self.current_burst = BurstRecord(
                start_time=timestamp,
                end_time=timestamp,
                bytes_out=payload_bytes if is_outbound else 0,
                bytes_in=0 if is_outbound else payload_bytes,
                packet_count=1,
                connection_ids={connection_id},
            )
            return

        delta_since_burst_end = timestamp - self.current_burst.end_time

        if delta_since_burst_end <= self.burst_threshold:
            # Append packet to existing active burst
            self.current_burst.end_time = max(self.current_burst.end_time, timestamp)
            if is_outbound:
                self.current_burst.bytes_out += payload_bytes
            else:
                self.current_burst.bytes_in += payload_bytes
            self.current_burst.packet_count += 1
            self.current_burst.connection_ids.add(connection_id)
        else:
            # Finalize previous burst and begin new burst
            self.completed_bursts.append(self.current_burst)
            self.current_burst = BurstRecord(
                start_time=timestamp,
                end_time=timestamp,
                bytes_out=payload_bytes if is_outbound else 0,
                bytes_in=0 if is_outbound else payload_bytes,
                packet_count=1,
                connection_ids={connection_id},
            )

    def extract_features(
        self,
        raw_ip_flag: int = 0,
        proc_signed: int = 1,
        proc_path_class: int = 0,
        min_bursts: int = 10,
    ) -> Optional[FlowFeaturesV1]:
        """
        Builds a frozen FlowFeaturesV1 contract record if at least min_bursts are recorded.
        Returns None if gating threshold is not yet met.
        """
        all_bursts = list(self.completed_bursts)
        if self.current_burst:
            all_bursts.append(self.current_burst)

        n_bursts = len(all_bursts)
        if n_bursts < min_bursts:
            return None

        # Calculate inter-arrival times between burst start times
        inter_arrivals: list[float] = []
        sizes_out: list[float] = []
        sizes_in: list[float] = []
        total_connections: set[str] = set()

        for i in range(len(all_bursts)):
            b = all_bursts[i]
            sizes_out.append(float(b.bytes_out))
            sizes_in.append(float(b.bytes_in))
            total_connections.update(b.connection_ids)
            if i > 0:
                iat = b.start_time - all_bursts[i - 1].start_time
                if iat > 0:
                    inter_arrivals.append(iat)

        stats = compute_burst_stats(inter_arrivals, sizes_out, sizes_in)
        conn_per_burst = round(len(total_connections) / n_bursts, 3)

        return FlowFeaturesV1(
            n_bursts=n_bursts,
            iat_median=stats["iat_median"],
            iat_mad_ratio=stats["iat_mad_ratio"],
            iat_iqr_ratio=stats["iat_iqr_ratio"],
            iat_bowley_skew=stats["iat_bowley_skew"],
            size_out_median=stats["size_out_median"],
            size_in_median=stats["size_in_median"],
            size_mad_ratio=stats["size_mad_ratio"],
            conn_per_burst=conn_per_burst,
            raw_ip_flag=raw_ip_flag,
            proc_signed=proc_signed,
            proc_path_class=proc_path_class,
        )
