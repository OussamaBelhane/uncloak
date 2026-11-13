# Changelog

All notable changes to **Uncloak** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Foundational project architecture adopting the `src/` layout (`uncloak.core`, `uncloak.agent`, `uncloak.manager`, `uncloak.detection`, `uncloak.ui`).
- Core immutable data models (`PacketEvent`, `FlowSession`, `AttributionRecord`, `HostEndpoint`, `CampaignCluster`).
- Enterprise Fleet Manager state machine (`FleetManager`) with simulated fleet demo mode, campaign correlation, and 45-second dead-man switch.
- Rich-based terminal CUI cockpit featuring full-width table and collapsible telemetry drawer.
- WebView2 / loopback desktop cockpit with SVG attack topology and STIX/YARA export modals.
- Embedded SQLite telemetry ledger with Write-Ahead Logging (WAL) mode.
- Silent Windows Task Scheduler installer (`uncloak-agent --install`) and `psutil` process/socket heartbeat collector.
- `C2Predictor` inference wrapper with baseline heuristic fallback.

### Planned (In Progress)
- Native Win32 `iphlpapi.dll` ctypes bindings (`GetExtendedTcpTable` for socket-to-PID attribution, `SetTcpEntry` for TCP RST eviction) and per-app Windows Firewall containment.
- Live Npcap/Scapy BPF packet ingestion and 200 ms burst aggregation pipeline.
- Modern labeled C2 lab dataset and serialized ML model (ONNX/JSON tree export).
