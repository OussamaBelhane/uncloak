"""
Offline DFIR PCAP/PCAPNG Replay Engine for Uncloak.
Replays captured network packet streams, groups bursts per flow, and generates FlowFeaturesV1 vectors.
"""

from __future__ import annotations

import os
from typing import Generator

from scapy.layers.inet import IP, TCP  # type: ignore[import-untyped]
from scapy.utils import PcapReader  # type: ignore[import-untyped]

from uncloak.capture.burst import BurstAggregator
from uncloak.core.models import FlowFeaturesV1


def analyze_pcap(
    pcap_path: str,
    min_bursts: int = 10,
) -> Generator[tuple[str, FlowFeaturesV1], None, None]:
    """
    Parses an offline PCAP/PCAPNG file, aggregates TCP application bursts per destination flow,
    and yields (flow_key, FlowFeaturesV1) for every session meeting the minimum burst threshold.
    """
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    flow_aggregators: dict[str, BurstAggregator] = {}

    with PcapReader(pcap_path) as pcap_reader:
        for pkt in pcap_reader:
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            timestamp = float(pkt.time)
            payload_len = len(tcp_layer.payload) if tcp_layer.payload else 0

            # Normalize 5-tuple direction key (canonical flow representation)
            if src_port > dst_port:
                flow_key = f"{src_ip} -> {dst_ip}:{dst_port}"
                is_outbound = True
            else:
                flow_key = f"{dst_ip} -> {src_ip}:{src_port}"
                is_outbound = False

            conn_id = f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}"

            if flow_key not in flow_aggregators:
                flow_aggregators[flow_key] = BurstAggregator()

            flow_aggregators[flow_key].ingest_packet(
                timestamp=timestamp,
                payload_bytes=payload_len,
                is_outbound=is_outbound,
                connection_id=conn_id,
            )

    for flow_key, aggregator in flow_aggregators.items():
        features = aggregator.extract_features(min_bursts=min_bursts)
        if features:
            yield flow_key, features
