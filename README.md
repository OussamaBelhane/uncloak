# Uncloak

<p align="center">
  <strong>Autonomous C2 Stealth Jitter Detection & Win32 Socket Attribution Engine</strong>
</p>

<p align="center">
  <a href="https://github.com/OussamaBelhane/uncloak/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg" alt="Python Version"></a>
  <img src="https://img.shields.io/badge/status-alpha-orange.svg" alt="Status: Alpha">
</p>

> **Project Status (Alpha / Active Development):** The UI cockpits (Rich CUI and WebView2 Desktop), SQLite WAL ledger, Fleet Manager state machine (with `--demo` simulated fleet), and core data models are implemented. Live kernel capture, native Win32 `iphlpapi.dll` attribution/eviction, and the trained ML model are currently under active development.

---

### What is Uncloak?

Modern command-and-control (C2) implants (Cobalt Strike, Sliver, Havoc, Brute Ratel) evade traditional network intrusion detection systems by **cloaking** their traffic:
- Encrypting payloads within standard HTTPS (port 443) traffic.
- Injecting artificial sleep jitter ($\pm 20\text{--}50\%$) to break naive periodic timing rules.
- Masquerading behind Content Delivery Networks (CDNs) and legitimate cloud hosts.
- Injecting shellcode into trusted system processes (`svchost.exe`, `explorer.exe`).

**Uncloak** is a lightweight, host-native threat hunting engine designed to strip away this concealment. By combining packet timing burst analysis with real-time Win32 socket-to-process attribution (`iphlpapi.dll`), Uncloak isolates subtle beaconing rhythms through the noise and correlates anomalous connections directly to the offending Windows process ID, binary path, and signature status.

---

### Key Capabilities (Target Architecture)

* **Robust Jitter Analysis:** Uses non-parametric statistical estimators (Median, Median Absolute Deviation, Interquartile Range, Bowley Skew) to distinguish human browsing bursts from algorithmic C2 sleep loops.
* **Kernel Socket-to-PID Attribution:** Binds network flows to local Windows processes via native Win32 `GetExtendedTcpTable`, resolving the PID, binary path, and parent hierarchy.
* **Surgical Socket Mitigation & Per-App Containment:** Designed to sever malicious connections on demand using `SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)` and per-application Windows Firewall rules without terminating critical host processes.
* **Terminal & Desktop Cockpits:** A responsive Rich Console User Interface (CUI) with a collapsible forensic telemetry drawer, plus a WebView2 desktop cockpit for fleet triage.
* **Audit-First Safety:** Operates in non-disruptive audit/detect mode by default before any active enforcement is enabled.
* **Headless SIEM / SOC Streaming:** Streams structured NDJSON alerts (`-j / --json`) for Wazuh, Splunk, or Elastic.

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

### 🪟 Running on Windows (Quickstart Guide)

Uncloak is natively optimized for **Microsoft Windows 10 & 11 (x64)**. It can be run either as an executive enterprise desktop cockpit (GUI), an interactive terminal dashboard (CUI), or a silent background endpoint daemon.

#### 1. Prerequisites
* **Python 3.10, 3.11, or 3.12**: Download from [python.org](https://www.python.org/downloads/). Ensure you check **"Add python.exe to PATH"** during installation.
* **Git for Windows**: Download from [git-scm.com](https://git-scm.com/).
* **Npcap (Optional for Live Sniffing)**: Download from [npcap.com](https://npcap.com/). Select *"Install Npcap in WinPcap API-compatible Mode"*. (Note: Not required for simulated fleet telemetry, offline PCAP triage, or manager/agent communication).

#### 2. Clone & Setup

Open **PowerShell** or **Windows Terminal** and run:

```powershell
# Clone the repository
git clone https://github.com/OussamaBelhane/uncloak.git
cd uncloak

# Create and activate a dedicated virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install in editable development mode
pip install -e .
```

> **PowerShell ExecutionPolicy Note:** If PowerShell displays `execution of scripts is disabled on this system`, run this command in your terminal session:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> ```

#### 3. Execution Modes on Windows

##### Option A: Desktop Cockpit & Web UI (Current Alpha Preview / Demo Mode)
This launches the local Fleet Manager and opens the desktop cockpit window (powered by Microsoft Edge App Mode on Windows):
```powershell
uncloak
# or explicitly:
uncloak manager
# or direct python module:
python -m uncloak
```
* **Dashboard Localhost URL:** `http://127.0.0.1:8830`
* **Current Alpha Status:** Runs in simulated demo mode (`32` simulated hosts) to preview the topology graph, triage drawer, and STIX/YARA-L export layout while the live Npcap/WFP collector is being integrated.

##### Option B: Terminal CUI Cockpit (Console Mode)
For SOC operators working inside Windows Terminal, PowerShell, or remote SSH sessions:
```powershell
uncloak cli
# or:
python -m uncloak cli
```
* **Controls:**
  * `[TAB]` : Toggle forensic inspection drawer
  * `[SPACE]` : Pause / resume live stream
  * `[K]` : Kill selected anomalous socket (`SetTcpEntry DELETE_TCB` - planned)
  * `[Q]` : Quit cleanly

##### Option C: Silent Endpoint Agent (Target Architecture - In Progress)
Planned background sensor workflow once the live capture and Windows Service wrapper are implemented:
```powershell
# Run in foreground:
uncloak agent

# Planned Windows Service lifecycle (Administrator):
uncloak --install
uncloak --status
uncloak --uninstall
```

##### Option D: Portable Quick Run (Zero-Install)
If you prefer running directly without installing the package into your Python environment:
```powershell
pip install -r requirements.txt
$env:PYTHONPATH="src"
python -m uncloak
```

---

### Running on Linux / macOS (UI & Offline Analysis Preview)

Full active endpoint attribution (`GetExtendedTcpTable`, `WinVerifyTrust`, `SetTcpEntry`) targets Windows 10/11. Linux/macOS supports the UI preview and planned offline PCAP triage:

```bash
# Clone and setup
git clone https://github.com/OussamaBelhane/uncloak.git
cd uncloak
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Launch Terminal CUI Cockpit (default on POSIX)
uncloak

# Or launch Central Fleet Manager Web Dashboard
uncloak manager
```

---

### Offline DFIR PCAP Triage & SOC Streaming (Planned v1.0 CLI)

#### 1. Replay & Analyze a Captured PCAP
```bash
uncloak -r incident_capture.pcap
```

#### 2. Headless SOC / SIEM Streaming
Output line-delimited JSON (NDJSON) to stdout for forwarders (Wazuh, Splunk, Elastic):
```bash
uncloak --live --json > uncloak_alerts.json
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
