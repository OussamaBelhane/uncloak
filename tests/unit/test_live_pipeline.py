"""End-to-end tests for SocketAttributionCache, LivePacketCapture, and UncloakAgentService."""

import struct
import tempfile
from pathlib import Path
from unittest.mock import patch

from uncloak.agent.service import UncloakAgentService
from uncloak.attribution.cache import CachedSocketAttribution, SocketAttributionCache
from uncloak.capture.live import LivePacketCapture


def _make_client_hello(sni: str) -> bytes:
    host_b = sni.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(host_b)) + host_b
    sni_ext = struct.pack("!HH", 0x0000, len(sni_entry) + 2) + struct.pack("!H", len(sni_entry)) + sni_entry
    ver_ext = struct.pack("!HH", 0x002B, 3) + b"\x02\x03\x04"
    exts = sni_ext + ver_ext
    ciphers = struct.pack("!HH", 0x1301, 0x1302)
    body = (
        struct.pack("!H", 0x0303)
        + b"\x11" * 32
        + b"\x00"
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 0x16, 0x0301, len(hs)) + hs


def test_socket_attribution_cache_ttl_and_eviction() -> None:
    cache = SocketAttributionCache(ttl_seconds=10.0, max_entries=2)
    a1 = CachedSocketAttribution(101, "a.exe", r"C:\Temp\a.exe", "{g1}", "h1", False, 1, 100.0, 100.0)
    a2 = CachedSocketAttribution(102, "b.exe", r"C:\Temp\b.exe", "{g2}", "h2", False, 1, 101.0, 101.0)
    a3 = CachedSocketAttribution(103, "c.exe", r"C:\Temp\c.exe", "{g3}", "h3", True, 0, 102.0, 102.0)

    cache.record("10.0.1.15", 50001, "193.26.158.114", 443, a1)
    cache.record("10.0.1.15", 50002, "193.26.158.114", 443, a2)
    cache.record("10.0.1.15", 50003, "193.26.158.114", 443, a3)

    assert len(cache) == 2
    assert cache.lookup("10.0.1.15", 50001, "193.26.158.114", 443, now=103.0) is None
    assert cache.lookup("10.0.1.15", 50003, "193.26.158.114", 443, now=105.0) is not None
    assert cache.lookup("10.0.1.15", 50003, "193.26.158.114", 443, now=120.0) is None


def test_live_packet_capture_ja4_and_burst_extraction() -> None:
    cap = LivePacketCapture(local_ips={"10.0.1.15"}, max_flows=16)
    hello = _make_client_hello("c2.telemetry.local")

    t0 = 1000.0
    cap.ingest_packet(t0, "10.0.1.15", 51000, "193.26.158.114", 443, hello)
    for i in range(1, 10):
        ts = t0 + i * 10.0
        cap.ingest_packet(ts, "10.0.1.15", 51000, "193.26.158.114", 443, b"X" * 256)
        cap.ingest_packet(ts + 0.02, "193.26.158.114", 443, "10.0.1.15", 51000, b"Y" * 512)

    ready = cap.extract_ready_flows(min_bursts=8)
    assert len(ready) == 1
    state, features = ready[0]
    assert state.sni == "c2.telemetry.local"
    assert state.ja4 is not None and state.ja4.startswith("t13d020200_")
    assert features.n_bursts >= 9
    assert features.iat_mad_ratio < 0.05


def test_agent_end_to_end_live_flow_evaluation() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_uncloak.db"
        pol_file = Path(tmpdir) / "policy.json"

        with patch("uncloak.agent.service.PolicyManager") as mock_pm_cls:
            from uncloak.core.policy import PolicyManager
            pm = PolicyManager(policy_path=pol_file)
            mock_pm_cls.return_value = pm

            agent = UncloakAgentService(db_path=str(db_file))
            agent.live_capture.local_ips.add("10.0.1.15")

            import time
            now_ts = time.time()
            attr = CachedSocketAttribution(
                pid=5824,
                process_name="update.exe",
                executable_path=r"C:\Users\Admin\AppData\Roaming\update.exe",
                process_guid="{8f3a91c2-0001-0000-0000-0000000016c0}",
                sha256="a" * 64,
                is_signed=False,
                path_class=1,
                first_seen=now_ts,
                last_seen=now_ts,
            )
            agent.socket_cache.record("10.0.1.15", 51000, "193.26.158.114", 443, attr)

            t0 = 1000.0
            for i in range(10):
                ts = t0 + i * 10.0
                agent.live_capture.ingest_packet(ts, "10.0.1.15", 51000, "193.26.158.114", 443, b"A" * 256)
                agent.live_capture.ingest_packet(ts + 0.01, "193.26.158.114", 443, "10.0.1.15", 51000, b"B" * 512)

            findings = agent.evaluate_live_flows(min_bursts=8)
            assert len(findings) == 1
            f = findings[0]
            assert f["pid"] == 5824
            assert f["process_name"] == "update.exe"
            assert f["process_sha256"] == "a" * 64
            assert f["threat_score"] >= 0.90
            assert f["mitigated"] is True
