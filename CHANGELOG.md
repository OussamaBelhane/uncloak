# Changelog

All notable changes to **Uncloak** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Foundational project architecture adopting the `src/` layout.
- High-performance packet ingestion pipeline supporting live Npcap BPF and offline PCAP replay.
- Low-level Win32 `iphlpapi.dll` ctypes integration for real-time socket-to-PID attribution.
- Mathematical inter-arrival delta-time engine ($\Delta t$) with IQR and MAD jitter analysis.
- Rich-based terminal CUI cockpit featuring full-width table and collapsible telemetry drawer.
- Embedded SQLite telemetry storage with Write-Ahead Logging (WAL) mode.
