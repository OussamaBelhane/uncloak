"""
Unit tests verifying Uncloak v0.2.0 4-Tier Architecture & Feature Schema v1 Pipeline:
  1. C2Predictor on FlowFeaturesV1 (CRITICAL C2 vs BENIGN separation)
  2. Offline PCAP Replay on samples/sliver_c2_capture.pcap
  3. Enterprise SIEM Exporter (OCSF v1.1.0 NDJSON + Event ID 9001/9002)
  4. Unified CLI parser across service, -r pcap, --ui, and web modes
"""

from __future__ import annotations

import json
import os
import tempfile

from uncloak.agent.service import UncloakAgentService
from uncloak.capture.pcap import analyze_pcap_detailed
from uncloak.cli.parser import build_parser
from uncloak.core.models import FlowFeaturesV1
from uncloak.detection.model import C2Predictor


def test_c2_predictor_v1_separation() -> None:
    """Verifies Feature Schema v1 scoring separates jittered C2 beacons from organic browsing."""
    predictor = C2Predictor()

    sliver_beacon = FlowFeaturesV1(
        n_bursts=14,
        iat_median=8.4,
        iat_mad_ratio=0.082,
        iat_iqr_ratio=0.120,
        iat_bowley_skew=0.03,
        size_out_median=512.0,
        size_in_median=1280.0,
        size_mad_ratio=0.02,
        conn_per_burst=0.07,
        raw_ip_flag=1,
        proc_signed=0,
        proc_path_class=1,
    )
    res_c2 = predictor.predict_v1(sliver_beacon, host_context_known=True)
    assert res_c2["threat_score"] >= 0.90
    assert res_c2["is_c2"] is True
    assert res_c2["confidence_level"] == "CRITICAL"

    organic_web = FlowFeaturesV1(
        n_bursts=14,
        iat_median=6.2,
        iat_mad_ratio=0.720,
        iat_iqr_ratio=1.350,
        iat_bowley_skew=0.68,
        size_out_median=980.0,
        size_in_median=2400.0,
        size_mad_ratio=0.55,
        conn_per_burst=2.10,
        raw_ip_flag=0,
        proc_signed=1,
        proc_path_class=0,
    )
    res_benign = predictor.predict_v1(organic_web, host_context_known=True)
    assert res_benign["threat_score"] < 0.25
    assert res_benign["is_c2"] is False
    assert res_benign["confidence_level"] == "HEALTHY"


def test_pcap_replay_sliver_sample() -> None:
    """Verifies offline PCAP replay extracts bursts, resolves DNS context, and isolates C2 flows."""
    from pathlib import Path
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sample_pcap = os.path.join(project_root, "samples", "sliver_c2_capture.pcap")
    if not os.path.isfile(sample_pcap):
        import sys
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from samples.generate_sample_pcap import build_sample_pcap
        build_sample_pcap(Path(sample_pcap))
    assert os.path.isfile(sample_pcap), f"Missing sample PCAP: {sample_pcap}"

    results = analyze_pcap_detailed(sample_pcap, min_bursts=8)
    assert len(results) == 5

    by_ip = {r.dst_ip: r for r in results}
    assert by_ip["193.26.158.114"].features.raw_ip_flag == 1
    assert by_ip["193.26.158.114"].prediction["confidence_level"] == "CRITICAL"
    assert by_ip["10.0.3.44"].prediction["confidence_level"] == "CRITICAL"
    assert by_ip["45.33.32.156"].resolved_domain == "cdn-azure-edge.net"
    assert by_ip["45.33.32.156"].prediction["confidence_level"] == "CRITICAL"

    assert by_ip["142.250.200.35"].resolved_domain == "www.google.com"
    assert by_ip["142.250.200.35"].prediction["is_c2"] is False
    assert by_ip["52.114.63.56"].resolved_domain == "teams.microsoft.com"
    assert by_ip["52.114.63.56"].prediction["is_c2"] is False


def test_siem_ocsf_and_ndjson_export() -> None:
    """Verifies headless sensor SIEM exporter emits OCSF v1.1.0 events with Event ID 9001/9002."""
    with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as tf:
        ndjson_path = tf.name

    try:
        if os.path.exists(ndjson_path):
            os.remove(ndjson_path)

        agent = UncloakAgentService(manager_url="http://127.0.0.1:8830")
        events, out_path, _ = agent.emit_siem_cycle(
            ndjson_path=ndjson_path,
            include_sample_detections=True,
        )
        assert len(events) == 2
        assert os.path.isfile(out_path)

        with open(out_path, "r", encoding="utf-8") as fh:
            lines = [json.loads(line) for line in fh if line.strip()]

        assert len(lines) == 2
        assert lines[0]["class_uid"] == 4001
        assert lines[0]["metadata"]["windows_event_id"] == 9001
        assert lines[1]["metadata"]["windows_event_id"] == 9002
        assert "iat_mad_ratio" in lines[0]["uncloak_telemetry"]["features_v1"]
    finally:
        if os.path.exists(ndjson_path):
            os.remove(ndjson_path)


def test_cli_parser_four_modes() -> None:
    """Verifies CLI parser cleanly accepts service, -r pcap, --ui --demo, and web modes."""
    parser = build_parser()

    ns_svc = parser.parse_args(["service", "--once"])
    assert ns_svc.subcommand == "service"
    assert ns_svc.once is True

    ns_pcap = parser.parse_args(["-r", "samples/sliver_c2_capture.pcap", "--json"])
    assert ns_pcap.read == "samples/sliver_c2_capture.pcap"
    assert ns_pcap.json is True

    ns_ui = parser.parse_args(["--ui", "--demo"])
    assert ns_ui.ui is True
    assert ns_ui.demo is True

    ns_web = parser.parse_args(["web", "--port", "8830", "--demo"])
    assert ns_web.subcommand == "web"
    assert ns_web.port == 8830
    assert ns_web.demo is True
