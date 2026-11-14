"""
Generates realistic multi-flow C2 and baseline sample captures in samples/ for CLI replay testing:
  python -m uncloak -r samples/sliver_c2_capture.pcap
"""

from __future__ import annotations

import os
import random
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore[import-untyped]
from scapy.layers.inet import IP, TCP, UDP  # type: ignore[import-untyped]
from scapy.packet import Raw  # type: ignore[import-untyped]
from scapy.utils import wrpcap  # type: ignore[import-untyped]


def build_sample_pcap(out_path: Path) -> Path:
    rng = random.Random(20261113)
    packets = []
    base_ts = 1793628602.0  # 2026-11-02 14:10:02 UTC

    def add_dns_response(ts: float, client_ip: str, domain: str, resolved_ip: str) -> None:
        pkt = (
            IP(src="10.0.0.1", dst=client_ip)
            / UDP(sport=53, dport=rng.randint(50000, 60000))
            / DNS(
                id=rng.randint(1, 65535),
                qr=1,
                aa=1,
                qd=DNSQR(qname=domain),
                an=DNSRR(rrname=domain, ttl=300, rdata=resolved_ip),
            )
        )
        pkt.time = ts
        packets.append(pkt)

    def add_burst(ts: float, src_ip: str, src_port: int, dst_ip: str, dst_port: int, out_bytes: int, in_bytes: int) -> None:
        p_out = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA") / Raw(load=b"\x17\x03\x03" + os.urandom(max(1, out_bytes - 3)))
        p_out.time = ts
        packets.append(p_out)

        p_in = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="PA") / Raw(load=b"\x17\x03\x03" + os.urandom(max(1, in_bytes - 3)))
        p_in.time = ts + 0.042
        packets.append(p_in)

    # 1. Sliver mTLS C2 Beacon (Raw IP, Persistent socket, 8.4s +/- 9.5% jitter)
    t = base_ts
    for _ in range(14):
        add_burst(t, "10.0.1.15", 49152, "193.26.158.114", 443, 512, 1280)
        t += 8.4 * rng.uniform(0.905, 1.095)

    # 2. Cobalt Strike Malleable HTTPS Beacon (DNS -> cdn-azure-edge.net, Reconnects per burst, 15.0s +/- 7.3%)
    add_dns_response(base_ts + 0.2, "10.0.1.16", "cdn-azure-edge.net", "45.33.32.156")
    t = base_ts + 0.5
    for idx in range(12):
        add_burst(t, "10.0.1.16", 50120 + idx, "45.33.32.156", 8443, 1024, 512)
        t += 15.0 * rng.uniform(0.927, 1.073)

    # 3. East-West SMB / WMI Lateral Pivot (10.0.1.15 -> 10.0.3.44:445, 4.0s +/- 5%)
    t = base_ts + 1.0
    for _ in range(15):
        add_burst(t, "10.0.1.15", 51204, "10.0.3.44", 445, 256, 256)
        t += 4.0 * rng.uniform(0.95, 1.05)

    # 4. Organic HTTPS Browsing (www.google.com, stochastic timings and variable payloads)
    add_dns_response(base_ts + 0.1, "10.0.1.15", "www.google.com", "142.250.200.35")
    t = base_ts + 1.5
    for idx in range(14):
        out_sz = rng.choice([280, 920, 410, 1850, 540, 3200, 690, 1140])
        in_sz = rng.choice([450, 2900, 1120, 4800, 760, 1980])
        add_burst(t, "10.0.1.15", 52400 + (idx % 4), "142.250.200.35", 443, out_sz, in_sz)
        t += rng.choice([1.1, 24.5, 3.8, 42.0, 6.4, 15.2, 2.3, 31.8, 0.9, 19.4])

    # 5. Microsoft Teams Enterprise Traffic (teams.microsoft.com, organic chat telemetry)
    add_dns_response(base_ts + 0.15, "10.0.1.15", "teams.microsoft.com", "52.114.63.56")
    t = base_ts + 2.0
    for idx in range(12):
        out_sz = rng.choice([340, 1480, 620, 2750, 490])
        in_sz = rng.choice([580, 2240, 910, 3900])
        add_burst(t, "10.0.1.15", 53100 + (idx % 3), "52.114.63.56", 443, out_sz, in_sz)
        t += rng.choice([1.8, 17.5, 4.2, 29.0, 9.6, 2.1, 38.4])

    packets.sort(key=lambda p: float(p.time))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out_path), packets)
    return out_path


if __name__ == "__main__":
    dest = Path(__file__).resolve().parent / "sliver_c2_capture.pcap"
    written = build_sample_pcap(dest)
    print(f"[+] Generated sample C2 + organic PCAP capture at: {written}")
