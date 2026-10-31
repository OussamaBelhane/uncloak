# ⚡ Uncloak

<p align="center">
  <strong>Autonomous C2 Stealth Jitter Detection & Win32 Socket Attribution Engine</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/uncloak/"><img src="https://img.shields.io/badge/pypi-v0.1.0-blue.svg" alt="PyPI"></a>
  <a href="https://github.com/uncloak-project/uncloak/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="CI"></a>
  <a href="https://github.com/uncloak-project/uncloak/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg" alt="Python Version"></a>
</p>

---

### What is Uncloak?

Modern command-and-control (C2) implants (Cobalt Strike, Sliver, Havoc, Brute Ratel) evade traditional network intrusion detection systems by **cloaking** their traffic:
- Encrypting payloads within standard HTTPS (port 443) traffic.
- Injecting artificial sleep jitter ($\pm 20-50\%$) to break naive periodic timing rules.
- Masquerading behind Content Delivery Networks (CDNs) and legitimate cloud hosts.
- Injecting shellcode into trusted system processes (`svchost.exe`, `explorer.exe`).

**Uncloak** is a lightweight, host-native threat hunting engine that strips away this concealment. By combining high-speed BPF network packet ingestion with real-time Win32 kernel socket tables (`iphlpapi.dll`), Uncloak mathematically isolates subtle beaconing rhythms through the noise and correlates the anomalous connection directly to the offending Windows process ID, binary path, and user token.

---

### Key Capabilities

* **Mathematical Jitter Defeat:** Uses robust statistical estimators (Interquartile Range, Median Absolute Deviation, Spectral Density) to distinguish human browsing bursts from algorithmic C2 sleep loops.
* **Kernel Socket-to-PID Attribution:** Binds network flows to local Windows processes via native Win32 `GetExtendedTcpTable`, resolving the PID, binary path, and parent hierarchy in real time.
* **Surgical Socket Mitigation:** Capable of severing malicious connections on demand using `SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)` without terminating the host process.
* **Calm Terminal Cockpit:** A responsive full-width Console User Interface (CUI) with a collapsible forensic telemetry drawer for active incident response.
* **Zero Overhead Footprint:** Engineered in high-performance asynchronous Python with ctypes bindings: operates with `< 10 MB` RAM footprint and `< 2%` CPU overhead.
* **Headless SIEM / SOC Streaming:** Streams structured NDJSON alerts (`-j / --json`) directly to Wazuh, Splunk, or Elastic.

---

### Architecture Overview

```
[ Npcap BPF Ingestion ]  ──────────>  [ Inter-Arrival Timing (Δt) ]
         │                                       │
         ▼                                       ▼
[ Win32 Kernel Attribution ]          [ Mathematical Jitter Analysis ]
 (iphlpapi.dll GetExtendedTcpTable)    (IQR / MAD / Entropy / RF)
         │                                       │
         └─────────────────┬─────────────────────┘
                           ▼
                 [ Threat Scorer Engine ]
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
  [ Interactive CUI Cockpit ]     [ SQLite Telemetry (WAL) ]
  (Rich Full-Width + Drawer)      (uncloak.db / NDJSON Stream)
```

---

### Installation

#### Standalone Single Binary (Zero Dependencies)
Download the latest `uncloak.exe` from the [Releases](https://github.com/uncloak-project/uncloak/releases) page. No Python or runtime dependencies required.

#### Via PyPI
```bash
pip install uncloak
```

#### From Source (Development)
```bash
git clone https://github.com/uncloak-project/uncloak.git
cd uncloak
pip install -e ".[dev]"
```

---

### Quick Start

#### 1. Live Threat Hunting on Network Interface
```bash
# Listen on the primary interface with default HTTPS filter
uncloak --live

# Listen on interface 2 with custom BPF filter
uncloak --live -i 2 -f "tcp and port 443"
```

#### 2. Offline DFIR PCAP Triage
```bash
# Analyze a suspected C2 capture file
uncloak hunt -r incident_capture.pcap
```

#### 3. Headless SOC / SIEM Streaming
```bash
# Output pure NDJSON to stdout for log forwarders
uncloak --live --json > /var/log/uncloak.json
```

---

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Uncloak Defense |
| :--- | :--- | :--- | :--- |
| **Command & Control** | `T1071.001` | Application Layer Protocol: Web Protocols | Dissects TLS ClientHello, SNI, and HTTPS handshake rhythms |
| **Command & Control** | `T1573.002` | Encrypted Channel: Asymmetric Cryptography | Detects periodic callbacks independent of payload encryption |
| **Defense Evasion** | `T1027` | Obfuscated Files or Information | Unmasks artificial sleep jitter via statistical spread analysis |
| **Defense Evasion** | `T1055` | Process Injection | Isolates injected PIDs through Win32 kernel socket attribution |

---

### License

This project is licensed under the terms of the [MIT License](LICENSE).
