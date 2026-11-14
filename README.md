# Uncloak

**Host-Native C2 Beacon Jitter Detection, Win32 Kernel Socket Attribution, and Central SOC Platform**

<p align="left">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg" alt="Python 3.10+"></a>
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Server%20x64-0078D6.svg" alt="Platform: Windows x64">
  <img src="https://img.shields.io/badge/telemetry-OCSF%20v1.1.0%20%7C%20EID%209001%2F9002-6366f1.svg" alt="OCSF v1.1.0 & Windows Event ID 9001/9002">
  <img src="https://img.shields.io/badge/tests-27%20passing-10b981.svg" alt="Tests: 27 Passing">
</p>

---

## Executive Overview

Modern Command-and-Control (C2) frameworks - including Sliver, Cobalt Strike, Havoc, and Brute Ratel - bypass perimeter firewalls and signature-based IDS/NDR sensors by masking both transport and cadence:

* **Encrypted HTTPS Transport (Port 443 / 8443):** Hides payload bytes inside standard TLS sessions or fronts traffic behind legitimate cloud CDNs.
* **Randomized Sleep Jitter:** Injects 20% to 50% timing randomness into sleep intervals to defeat fixed-timer detection rules.
* **Process Hollowing & LOLBin Abuse:** Executes C2 implants inside signed Windows binaries (`svchost.exe`, `dllhost.exe`, `wmiprvse.exe`, `powershell.exe`), forcing defenders to hesitate before terminating host processes.

**Uncloak** strips away that concealment at the endpoint and fleet levels. Instead of streaming expensive raw PCAPs across corporate WAN links, Uncloak computes non-parametric burst dispersion mathematics (`FlowFeaturesV1`) directly on the endpoint, binds every anomalous socket to its owning Windows Process ID, binary path, ProcessGuid, SHA-256 digest, and Authenticode trust state (`iphlpapi.dll` + `WinVerifyTrust`), and dispatches surgical kernel containment (`SetTcpEntry`) alongside structured telemetry for **Wazuh**, **Splunk**, and the **Uncloak Central SOC Manager**.

---

## System Architecture & Telemetry Pipeline

Uncloak separates **silent endpoint execution** (zero listening ports, zero interactive UI) from **on-demand local triage** and **centralized fleet management**:

```
+------------------------------------------------------------------------------+
|  ENDPOINT HOST (Windows 10/11 & Windows Server x64)                          |
|                                                                              |
|  [ Network Interface / PCAP ] --> [ 200ms Burst Aggregator + FlowFeaturesV1 ]|
|                                             |                                |
|  [ iphlpapi.dll GetExtendedTcpTable ] ------+--> [ Scoring & JA4 Engine ]    |
|  [ WinVerifyTrust + ProcessGuid + SHA256 ]  |                                |
|                                             v                                |
|     +-------------------+       +------------------------+                   |
|     | uncloak service   |       | uncloak --ui           |                   |
|     | Silent SYSTEM     |       | On-Demand Terminal TUI |                   |
|     | Daemon (0 Ports)  |       | (SSH / Break-Glass)    |                   |
|     +---------+---------+       +------------------------+                   |
|               |                                                              |
|     +---------+----------------------------------+                           |
|     | Dual Enterprise Telemetry Sinks            |                           |
|     v                                            v                           |
|  [ Local SIEM Channel ]                 [ Central Fleet Sync ]               |
|   - WinEvent EID 9001 / 9002             - 15s Signed Heartbeats             |
|   - uncloak_alerts.ndjson                - Process & Socket Inventory        |
|     (OCSF v1.1.0 class_uid 4001)         - Signed Mitigation Commands        |
+--------------------------------------------------+---------------------------+
                                                   |
                                                   v
+------------------------------------------------------------------------------+
|  CENTRAL SOC MANAGER (`uncloak manager` / `uncloak-manager`)                 |
|                                                                              |
|  - 45s Dead-Man Switch Staleness Monitor (ONLINE -> MUTED detection)         |
|  - Cross-Host JA4 & Destination Campaign Correlation                         |
|  - AD Tier-0 / Tier-1 / Tier-2 Containment Guardrails                        |
|  - Dual-Theme Web Console: Fleet, Campaigns, Endpoint Triage, Alerts, SIEM   |
|  - SQLite WAL Persistent Ledger (`uncloak.db`) + STIX 2.1 / YARA-L Exports   |
+------------------------------------------------------------------------------+
```

> [!NOTE]
> **Implementation Status (`v0.2.0-alpha`):** The CLI architecture across all 4 operational modes, `FlowFeaturesV1` statistical engine, PCAP replay harness, OCSF `v1.1.0` / Windows Event Log `EID 9001/9002` exporter, SQLite WAL storage ledger, Rich TUI Cockpit, Central SOC Web Console (with isolated `--demo` 32-endpoint simulation fleet), and Win32 `ctypes` attribution/eviction bindings are implemented and covered by the 27-test suite. End-to-end live Npcap kernel capture integration, trained ML model bundle, and automatic Registry/CIDR AD Tier auto-fingerprinting remain under active development.

---

## The 4 Operational Modes & Complete Command Reference

Invoking bare `uncloak` displays the 4-component architecture matrix in your terminal without hijacking your browser:

```powershell
uncloak
uncloak --version
uncloak --help
```

### Mode 1: Headless Windows SYSTEM Endpoint Agent (`uncloak service` / `uncloak-agent`)

Designed for production deployment across workstations and servers as a silent background daemon running under `NT AUTHORITY\SYSTEM`. Opens **zero listening ports**, exposes **zero taskbar or system tray windows**, and forwards detections continuously to local SIEM agents and the Central SOC Manager.

```powershell
# Run one SIEM emission & validation cycle (writes OCSF NDJSON + Windows Event ID 9001/9002)
uncloak service --once

# Run in foreground continuous daemon mode (or install as SYSTEM startup task)
uncloak service
uncloak service --siem-out C:\ProgramData\Uncloak\logs\uncloak_alerts.ndjson

# Emit line-delimited OCSF v1.1.0 JSON directly to stdout for piping
uncloak service --json

# Windows Task Scheduler service lifecycle (requires Administrator PowerShell)
uncloak --install     # Registers 'UncloakEndpointAgent' via pythonw.exe as SYSTEM / HIGHEST
uncloak --status      # Queries Windows Scheduled Task state
uncloak --uninstall   # Removes 'UncloakEndpointAgent' from Windows startup
```

Standalone agent entrypoint:

```powershell
uncloak-agent --once --siem-out uncloak_alerts.ndjson
uncloak-agent --manager http://10.0.0.5:8830
```

### Mode 2: On-Demand Endpoint Terminal Cockpit (`uncloak --ui` / `uncloak tui`)

Interactive Rich console interface built for direct incident triage over **SSH**, **WinRM**, or an **Administrator PowerShell terminal** on a specific endpoint. Displays a prioritized socket matrix, 3-column live attribution drawer, and deep Process Attribution Dossier without requiring a web browser.

```powershell
# Launch live endpoint terminal cockpit
uncloak --ui

# Launch with isolated simulated multi-beacon dataset (sliver, empire LOLBin, SMB lateral pivot)
uncloak --ui --demo
```

**Interactive TUI Keybindings:**

| Key | Action | Scope |
| :--- | :--- | :--- |
| `UP` / `DOWN` / `PGUP` / `PGDN` / `HOME` / `END` | Navigate active endpoint sockets | Main Cockpit |
| `ENTER` or `D` | Expand / collapse bottom 3-column attribution drawer | Main Cockpit |
| `I` | Open full-screen **Process Attribution Dossier** modal | Main Cockpit |
| `/` | Interactive live substring filter (`ESC` clears filter) | Main Cockpit |
| `S` | Cycle sort order (`threat`, `interval`, `payload`, `pid`, `process`) | Main Cockpit |
| `F` | Toggle Threats-Only filter | Main Cockpit |
| `SPACE` | Pause / resume live telemetry stream updates | Main Cockpit |
| `K` | Execute surgical socket termination (`SetTcpEntry` -> `EID 9002`) | Cockpit & Dossier |
| `C` | Copy target executable path to system clipboard | Cockpit & Dossier |
| `E` | Export active flow or dossier to OCSF JSON file | Cockpit & Dossier |
| `ESC` / `Q` | Close Dossier modal or exit TUI cleanly | Global |

### Mode 3: Central SOC Manager Web Console (`uncloak manager` / `uncloak-manager`)

Centralized 5-module SOC platform serving an **Enterprise Daylight (Default)** and **Soft Slate-Blue Dark** dual-theme interface modeled on modern SIEM/XDR workflows (default `http://127.0.0.1:8830` via `uncloak manager`, or `http://127.0.0.1:8443` via standalone `uncloak-manager`).

```powershell
# Launch Central SOC Manager on default port 8830 (opens Edge App Mode / browser)
uncloak manager

# Launch with isolated 32-endpoint multi-tier simulation fleet on a custom port
uncloak manager --demo --port 8830
```

**Web Console Modules & Capabilities:**

1. **View 1 - Fleet Endpoints:** Priority Triage Queue strip + searchable table (`Table View` default and optional AD-grouped `Card Grid`), filtered across `All Endpoints`, `Active Threats`, `Tier-0 (DCs)`, `Tier-1 (Servers)`, `Tier-2 (Workstations)`, and `Stale` (`45s` Dead-Man Switch `MUTED` detection). Clicking any row opens a non-destructive `460px` Slide-Over Inspector Drawer with 14-burst cadence visualization and kernel attribution.
2. **View 2 - Coordinated Threat Campaigns:** Master-detail outbreak clustering showing multi-host campaigns (`CAMPAIGN-ALPHA` Sliver direct-IP C2 and `CAMPAIGN-BETA` Azure CDN Cobalt Strike), 4-stage kill-chain propagation flow, correlated endpoint drill-down, one-click `Quarantine Campaign`, and **STIX 2.1** / **Google SecOps YARA-L** export modals.
3. **View 3 - Endpoint Triage:** Full per-host workspace with 4 subtabs (`Outbound Sockets`, `Running Processes`, `Connection Timeline`, `Allowlist Rules`), per-PID historical modal with CSV export, local/global allowlist exemption workflow, surgical `SetTcpEntry` termination modal, and persistent **Windows Filtering Platform (WFP)** firewall block modal.
4. **View 4 - Alerts & Event Log:** Multi-day searchable ledger covering Windows Event ID `9001` / `9002` events synchronized with global timeframe controls (`Live`, `24h`, `7d`, `30d`, `All`) and a slide-over raw **OCSF v1.1.0 JSON** inspector drawer.
5. **View 5 - Containment Policies & SIEM:** Active Directory Tier-0 / Tier-1 / Tier-2 response policy controls, `FlowFeaturesV1` threshold configuration, connected SIEM sink status cards, and copy-ready **Wazuh `local_rules.xml`**, **Wazuh `ossec.conf`**, **Splunk `inputs.conf` + SPL**, and **OCSF v1.1.0** schema templates.

> **Direct URL State Parameters:** Individual console states can be deep-linked via query parameters: `?tab=fleet|campaign|drilldown|alerts|policies`, `&theme=light|dark`, `&layout=table|grid`, `&scope=ALL|THREATS|TIER-0|TIER-1|TIER-2|MUTED`, `&camp=camp-alpha|camp-beta`, `&subtab=flows|procs|history|whitelist`, `&time=live|24h|7d|30d|all`, `&drawer=open`, and `&modal=sever|tarpit|whitelist|pid|stix|yaral`.

### Mode 4: Offline PCAP Replay & Benchmark Harness (`uncloak -r <file.pcap>`)

Replays recorded `.pcap` / `.pcapng` packet captures through the production 200ms burst aggregator and `FlowFeaturesV1` scorer for detection validation, threshold tuning, and CI regression testing.

```powershell
# Analyze bundled synthetic multi-flow capture (Sliver raw IP + SMB 445 lateral + Cobalt Strike CDN + benign Google/Teams)
uncloak -r samples/sliver_c2_capture.pcap

# Custom confidence cutoff, minimum bursts, and machine-readable JSON output
uncloak -r samples/sliver_c2_capture.pcap --threshold 0.80 --min-bursts 8 --json
```

---

## Full CLI Flags Reference

| Flag / Argument | Default | Description |
| :--- | :--- | :--- |
| `subcommand` | `None` | Positional mode selector: `service`, `agent`, `tui`, `hunt`, `cli`, `web`, `manager`, `gui`, `demo` |
| `--service` / `--agent` | `False` | Run the silent Windows endpoint sensor writing OCSF NDJSON and Event ID `9001`/`9002` |
| `--ui` / `--tui` / `--cli` / `--live` | `False` | Launch interactive Rich Terminal Cockpit for local host triage |
| `--web` / `--manager` / `--gui` | `False` | Launch Central SOC Web Console (port `8830`) |
| `-r FILE`, `--read FILE` | `None` | Replay offline `.pcap` / `.pcapng` trace through `FlowFeaturesV1` |
| `--demo` | `False` | Load isolated simulated telemetry (strictly separated from real endpoint telemetry) |
| `--once` | `False` | Execute a single SIEM OCSF + Windows Event Log validation cycle and exit |
| `--port PORT` | `8830` | HTTP bind port for the Central SOC Web Console |
| `-i IFACE`, `--interface IFACE` | `None` | Network capture interface index or adapter name |
| `-f BPF`, `--filter BPF` | `tcp and (port 443 or port 8443)` | Berkeley Packet Filter expression for packet ingestion |
| `-j`, `--json` | `False` | Emit line-delimited OCSF v1.1.0 JSON (`NDJSON`) to stdout |
| `--siem-out PATH` | `uncloak_alerts.ndjson` | Destination NDJSON log path for Wazuh / Splunk forwarders |
| `-t FLOAT`, `--threshold FLOAT` | `0.75` | Threat confidence cutoff (`0.0` to `1.0`) |
| `--min-bursts INT` | `8` | Minimum communication bursts required before `FlowFeaturesV1` evaluation |
| `--db PATH` | `uncloak.db` | Embedded SQLite WAL database path |
| `--install` / `--uninstall` / `--status` | `False` | Manage the Windows `UncloakEndpointAgent` SYSTEM scheduled task |
| `-v`, `--version` | - | Print version (`uncloak 0.2.0`) and exit |

---

## FlowFeaturesV1 Detection Contract (12-Dimension Vector)

Every qualified socket session (`>= 8` bursts separated by `>= 200ms` idle gaps) is compressed into an invariant **12-dimension numerical feature vector** defined in `src/uncloak/core/models.py`:

| # | Feature | Type | Detection Signal |
| :--- | :--- | :--- | :--- |
| 1 | `n_bursts` | `int` | Number of discrete request/response bursts observed in the rolling window |
| 2 | `iat_median` | `float` | Median Inter-Arrival Time across bursts; immune to single network latency spikes |
| 3 | `iat_mad_ratio` | `float` | `MAD / Median` normalized timing dispersion; isolates jittered C2 loops (`< 0.180`) from chaotic human browsing |
| 4 | `iat_iqr_ratio` | `float` | `IQR / Median` capturing the middle 50% spread of beacon intervals |
| 5 | `iat_bowley_skew` | `float` | Quantile-based symmetry metric distinguishing uniform pseudo-random jitter (`~0.0`) from right-skewed human clicktails |
| 6 | `size_out_median` | `float` | Median outbound payload size per burst (beacons transmit tight fixed checkin beacons) |
| 7 | `size_in_median` | `float` | Median inbound response size per burst (tracks C2 tasking vs. keep-alive ACKs) |
| 8 | `size_mad_ratio` | `float` | Normalized size regularity across consecutive callbacks |
| 9 | `conn_per_burst` | `float` | Socket multiplexing ratio (`1.00` indicates rigid single-socket polling or persistent loop) |
| 10 | `raw_ip_flag` | `int` | `1` if the endpoint connected to a literal IPv4/IPv6 address without prior DNS/SNI resolution |
| 11 | `proc_signed` | `int` | Binary Authenticode trust check (`WinVerifyTrust`: `1` = signed, `0` = unsigned PE) |
| 12 | `proc_path_class` | `int` | Executable path risk classification (`System32`/`Program Files` vs. user-writable `AppData`/`Temp`) |

---

## Active Directory Tier Containment Guardrails

Autonomous containment on a Domain Controller or Enterprise PKI can sever Kerberos KDC, LDAP replication, or certificate issuance across an entire forest. Uncloak enforces strict tier-aware response policies in the Central SOC Console:

| Active Directory Tier | Assets Protected | Default Enforcement Mode | Technical Safeguard |
| :--- | :--- | :--- | :--- |
| **Tier-0** | Domain Controllers, ADCS PKI, Entra ID Connect, PAWs | **Audit + P1 SIEM Escalation** | Never triggers autonomous socket teardown (`SetTcpEntry`); requires human SOC quorum |
| **Tier-1** | SQL Clusters, Exchange, App & DMZ Servers | **Hold Socket + Analyst Prompt** | Alerts analyst and stages 1-click containment without risking sudden production outages |
| **Tier-2** | Engineering Workstations & User Laptops | **Autonomous `SetTcpEntry` + WFP Block** | Immediately tears down kernel TCB (`MIB_TCP_STATE_DELETE_TCB`) and blocks reconnects when `Score >= 0.90` |

> **Containment Principle:** Surgical TCP teardown via `iphlpapi.dll SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)` drops the malicious socket directly inside the Windows network stack without killing critical host binaries (`svchost.exe`, `explorer.exe`) when memory injection is suspected.

---

## Enterprise SIEM Integration (Wazuh & Splunk)

Every endpoint agent exports detections through two local forwarder-ready channels defined in `src/uncloak/export/siem.py`:

1. **Windows Event Log (`Application` / Source `Microsoft-Windows-Uncloak-Sensor`):**
   * **Event ID `9001`:** C2 Beacon Detected (logged when `FlowFeaturesV1` crosses the configured threat threshold).
   * **Event ID `9002`:** Containment Enforced (`SetTcpEntry` socket teardown or WFP firewall rule applied).
2. **OCSF `v1.1.0` Network Activity (`class_uid: 4001`) NDJSON (`uncloak_alerts.ndjson`):**
   * Machine-readable structured JSON containing full 5-tuple metadata, `actor.process` lineage (`pid`, `uid` ProcessGuid, `file.path`, `SHA-256`, `is_signed`), MITRE ATT&CK technique IDs, and all 12 `FlowFeaturesV1` values.

Copy-ready Wazuh (`local_rules.xml` Rules `100901` / `100902`, `ossec.conf`) and Splunk (`inputs.conf` + multi-host correlation SPL) templates are built directly into **View 5 (`Policies & SIEM`)** of `uncloak manager`.

---

## Installation & Development

### Windows 10 / 11 & Server x64 (Primary Runtime)

```powershell
# 1. Clone repository
git clone https://github.com/OussamaBelhane/uncloak.git
cd uncloak

# 2. Create virtual environment & install editable package
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .

# 3. Verify CLI installation & run test suite
uncloak
python tests/run_tests.py
```

*Optional for live packet capture on Windows:* Install [Npcap](https://npcap.com/) with **"Install Npcap in WinPcap API-compatible Mode"** enabled. Live sniffing and kernel `SetTcpEntry` / WFP mitigation require an Administrator PowerShell prompt; simulated `--demo` fleet inspection, offline PCAP replay (`uncloak -r`), and `uncloak service --once` run with standard privileges.

### Linux / macOS (Manager Console & Offline PCAP Analysis)

```bash
git clone https://github.com/OussamaBelhane/uncloak.git
cd uncloak
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Run offline PCAP replay benchmark or launch Central SOC Manager
uncloak -r samples/sliver_c2_capture.pcap
uncloak manager --demo --port 8830
```

### Verification & Test Suite

Run the full automated unit suite (`27` tests spanning kernel attribution fixtures, burst cadence math, SQLite WAL ledger persistence, mitigation validation, PCAP replay, and OCSF SIEM export):

```powershell
python tests/run_tests.py
# Or with pytest (dev extras):
pip install -e ".[dev]"
pytest
```

### Repository Layout

```
uncloak/
├── src/uncloak/
│   ├── agent/        # Silent Windows endpoint daemon, Task Scheduler lifecycle & heartbeat client
│   ├── attribution/  # Win32 GetExtendedTcpTable bindings, ProcessGuid & Authenticode verification
│   ├── capture/      # 200ms burst aggregator, non-parametric dispersion math & PCAP replay engine
│   ├── cli/          # Unified CLI entrypoint (`uncloak` command router & flag parser)
│   ├── core/         # Frozen 12-dim FlowFeaturesV1 contract & domain dataclasses
│   ├── detection/    # C2 scorer & statistical feature pipeline
│   ├── export/       # OCSF v1.1.0 class_uid 4001 NDJSON & Windows Event Log (EID 9001/9002) emitter
│   ├── manager/      # Fleet state engine, 45s Dead-Man Switch, campaign store & connection ledger
│   ├── mitigation/   # Win32 SetTcpEntry(DELETE_TCB) socket eviction & validated netsh WFP containment
│   ├── storage/      # Embedded SQLite WAL persistence engine
│   └── ui/           # Rich Terminal Cockpit (--ui) and Central SOC Web Console (uncloak manager)
├── samples/          # Bundled synthetic multi-flow capture (`sliver_c2_capture.pcap`) & generator
├── tests/            # 27 automated unit & pipeline tests (`tests/run_tests.py`)
├── docs/             # Scientific foundations, specifications & CI templates
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── pyproject.toml
```

---

## MITRE ATT&CK Coverage

| Tactic | Technique ID | Technique Name | Uncloak Mechanism |
| :--- | :--- | :--- | :--- |
| **Command and Control** | `T1071.001` | Application Layer Protocol: Web Protocols | Inspects HTTPS cadence rhythms, TLS `ClientHello` JA4 fingerprints, and raw IP egress (`raw_ip_flag`) |
| **Command and Control** | `T1573.002` | Encrypted Channel: Asymmetric Cryptography | Quantifies inter-burst IAT regularity (`MAD / Median`, `IQR / Median`, `Bowley Skew`) without TLS decryption |
| **Command and Control** | `T1090.004` | Proxy: Domain Fronting | Flags CDN-fronted C2 callbacks via JA4 client consistency and endpoint process attribution |
| **Defense Evasion** | `T1027` | Obfuscated Files or Information | Defeats 20% to 50% artificial sleep jitter with non-parametric dispersion statistics |
| **Defense Evasion** | `T1055.012` | Process Injection: Process Hollowing | Surfaces signed system binaries (`svchost.exe`, `dllhost.exe`) exhibiting C2 cadence and applies surgical TCB eviction |
| **Lateral Movement** | `T1021.002` | Remote Services: SMB/Windows Admin Shares | Detects periodic East-West SMB port `445` pivoting (`wmiprvse.exe`) across Active Directory tiers |

---

## Security & License

* Security disclosure and hardening policy: see [SECURITY.md](SECURITY.md)
* Contribution workflow & coding standards: see [CONTRIBUTING.md](CONTRIBUTING.md)
* Licensed under the [MIT License](LICENSE)
