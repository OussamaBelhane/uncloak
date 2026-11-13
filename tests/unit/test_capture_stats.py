"""
Unit tests for robust timing statistics and burst aggregation.
"""

from uncloak.capture.burst import BurstAggregator
from uncloak.capture.stats import compute_burst_stats
from uncloak.core.models import FlowFeaturesV1


def test_compute_burst_stats_exact() -> None:
    """Verifies median, MAD ratio, IQR ratio, and Bowley skewness."""
    # Synthetic beacon with 10s sleep and uniform jitter between 8s and 12s
    iats = [8.0, 9.0, 10.0, 11.0, 12.0]
    sizes_out = [200.0, 210.0, 195.0, 205.0, 200.0]
    sizes_in = [1200.0, 1250.0, 1180.0, 1210.0, 1200.0]

    stats = compute_burst_stats(iats, sizes_out, sizes_in)

    assert stats["iat_median"] == 10.0
    assert stats["size_out_median"] == 200.0
    assert stats["size_in_median"] == 1200.0
    # Symmetric uniform jitter should yield near-zero Bowley skewness
    assert abs(stats["iat_bowley_skew"]) <= 0.05
    assert stats["iat_mad_ratio"] > 0.0
    assert stats["iat_iqr_ratio"] > 0.0


def test_burst_aggregator_and_feature_schema() -> None:
    """Verifies packet burst grouping (<200ms) and FlowFeaturesV1 generation."""
    aggregator = BurstAggregator(burst_threshold_seconds=0.200)

    # Simulate 12 periodic bursts (10 seconds apart)
    # Each burst composed of 2 packets 50ms apart
    base_time = 1000.0
    for burst_idx in range(12):
        t_start = base_time + (burst_idx * 10.0)
        # Packet 1 (SYN / Outbound request)
        aggregator.ingest_packet(
            timestamp=t_start,
            payload_bytes=180,
            is_outbound=True,
            connection_id=f"conn_{burst_idx}",
        )
        # Packet 2 (Inbound response 50ms later -> merged into same burst)
        aggregator.ingest_packet(
            timestamp=t_start + 0.050,
            payload_bytes=1050,
            is_outbound=False,
            connection_id=f"conn_{burst_idx}",
        )

    features = aggregator.extract_features(
        raw_ip_flag=1,
        proc_signed=0,
        proc_path_class=2,
        min_bursts=10,
    )

    assert features is not None
    assert isinstance(features, FlowFeaturesV1)
    assert features.n_bursts == 12
    assert 9.9 <= features.iat_median <= 10.1
    assert features.size_out_median == 180.0
    assert features.size_in_median == 1050.0
    assert features.raw_ip_flag == 1
    assert features.proc_signed == 0
    assert features.proc_path_class == 2

    # Verify 12-feature vector output
    vec = features.to_vector()
    assert len(vec) == 12
    assert vec[0] == 12.0  # n_bursts
