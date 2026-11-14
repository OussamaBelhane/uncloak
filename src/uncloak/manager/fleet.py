"""
Uncloak Enterprise Central Fleet Manager.
Coordinates enterprise endpoint fleet health, cross-host campaign correlation, and remote kernel mitigations.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Optional

from uncloak.core.models import CampaignCluster, HostEndpoint
from uncloak.manager.ledger import ConnectionLedger
from uncloak.ui.cockpit import FlowEntry, get_demo_flows


class FleetManager:
    """Thread-safe central coordinator for enterprise endpoints and threat correlation."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.selected_host_id: str = "host-win-prod-srv01"
        self.selected_pid: int = 5824
        self.active_tab: str = "fleet"  # fleet, campaign, drilldown

        # Initialize Enterprise Endpoints
        self.hosts: dict[str, HostEndpoint] = {
            # === TIER-0: IDENTITY & AUTH (CROWN JEWELS) ===
            "host-dc01-prod": HostEndpoint(
                host_id="host-dc01-prod",
                hostname="DC01-PROD",
                ip_address="10.0.0.1",
                subnet="Tier-0 Identity & Auth",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.001,
                active_sockets_count=418,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=1.4,
                ram_mb=9.1,
            ),
            "host-dc02-backup": HostEndpoint(
                host_id="host-dc02-backup",
                hostname="DC02-BACKUP",
                ip_address="10.0.0.2",
                subnet="Tier-0 Identity & Auth",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.001,
                active_sockets_count=380,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=1.2,
                ram_mb=8.9,
            ),
            "host-pki-ca01": HostEndpoint(
                host_id="host-pki-ca01",
                hostname="PKI-CA01",
                ip_address="10.0.0.5",
                subnet="Tier-0 Identity & Auth",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.002,
                active_sockets_count=192,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.7,
                ram_mb=7.4,
            ),
            "host-mgt-paw-01": HostEndpoint(
                host_id="host-mgt-paw-01",
                hostname="MGT-PAW-01",
                ip_address="10.0.0.8",
                subnet="Tier-0 Identity & Auth",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.001,
                active_sockets_count=58,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.5,
                ram_mb=6.8,
            ),
            "host-azure-ad-connect": HostEndpoint(
                host_id="host-azure-ad-connect",
                hostname="AZURE-AD-CONNECT",
                ip_address="10.0.0.10",
                subnet="Tier-0 Identity & Auth",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.004,
                active_sockets_count=312,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=1.1,
                ram_mb=8.5,
            ),

            # === TIER-1: CORE PRODUCTION & ENTERPRISE APPLICATIONS ===
            "host-win-prod-srv01": HostEndpoint(
                host_id="host-win-prod-srv01",
                hostname="WIN-PROD-SRV01",
                ip_address="10.0.1.15",
                subnet="Tier-1 Jump & App Hosts",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="CRITICAL",
                threat_score=0.987,
                active_sockets_count=126,
                isolated_beacons_count=1,
                c2_framework="Active Beacon: Sliver JA4",
                cpu_percent=0.8,
                ram_mb=7.5,
            ),
            "host-win-app-srv02": HostEndpoint(
                host_id="host-win-app-srv02",
                hostname="WIN-APP-SRV02",
                ip_address="10.0.1.16",
                subnet="Tier-1 Jump & App Hosts",
                os_version="Windows Server 2019 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="CRITICAL",
                threat_score=0.942,
                active_sockets_count=94,
                isolated_beacons_count=1,
                c2_framework="Active Beacon: Cobalt Strike JA4",
                cpu_percent=1.1,
                ram_mb=8.2,
            ),
            "host-sql-cluster-01": HostEndpoint(
                host_id="host-sql-cluster-01",
                hostname="SQL-CLUSTER-01",
                ip_address="10.0.1.20",
                subnet="Tier-1 Jump & App Hosts",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.003,
                active_sockets_count=340,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=1.5,
                ram_mb=9.8,
            ),
            "host-sql-cluster-02": HostEndpoint(
                host_id="host-sql-cluster-02",
                hostname="SQL-CLUSTER-02",
                ip_address="10.0.1.21",
                subnet="Tier-1 Jump & App Hosts",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.002,
                active_sockets_count=280,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=1.3,
                ram_mb=9.2,
            ),
            "host-exch-hybrid-01": HostEndpoint(
                host_id="host-exch-hybrid-01",
                hostname="EXCH-HYBRID-01",
                ip_address="10.0.1.25",
                subnet="Tier-1 Jump & App Hosts",
                os_version="Windows Server 2019 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="EVALUATING",
                threat_score=0.584,
                active_sockets_count=490,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=1.6,
                ram_mb=10.4,
            ),
            "host-file-srv-corp": HostEndpoint(
                host_id="host-file-srv-corp",
                hostname="FILE-SRV-CORP",
                ip_address="10.0.1.30",
                subnet="Tier-1 Jump & App Hosts",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.005,
                active_sockets_count=310,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.9,
                ram_mb=8.1,
            ),
            "host-backup-veeam-01": HostEndpoint(
                host_id="host-backup-veeam-01",
                hostname="BACKUP-VEEAM-01",
                ip_address="10.0.1.40",
                subnet="Tier-1 Jump & App Hosts",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.001,
                active_sockets_count=145,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.7,
                ram_mb=7.6,
            ),

            # === TIER-1: CLOUD GATEWAYS & DMZ ===
            "host-gw-edge-01": HostEndpoint(
                host_id="host-gw-edge-01",
                hostname="GW-EDGE-01",
                ip_address="10.0.2.1",
                subnet="Cloud Gateways & DMZ",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.003,
                active_sockets_count=210,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.9,
                ram_mb=7.6,
            ),
            "host-vpn-gateway-02": HostEndpoint(
                host_id="host-vpn-gateway-02",
                hostname="VPN-GATEWAY-02",
                ip_address="10.0.2.2",
                subnet="Cloud Gateways & DMZ",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.004,
                active_sockets_count=520,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=1.4,
                ram_mb=8.8,
            ),
            "host-mon-siem-splunk": HostEndpoint(
                host_id="host-mon-siem-splunk",
                hostname="MON-SIEM-SPLUNK",
                ip_address="10.0.2.10",
                subnet="Cloud Gateways & DMZ",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.002,
                active_sockets_count=640,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=1.8,
                ram_mb=11.2,
            ),

            # === TIER-2: ENGINEERING & DEVOPS WORKSTATIONS ===
            "host-ws-eng-04": HostEndpoint(
                host_id="host-ws-eng-04",
                hostname="WS-ENG-04",
                ip_address="10.0.3.44",
                subnet="Engineering Workstations",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HIGH",
                threat_score=0.865,
                active_sockets_count=82,
                isolated_beacons_count=1,
                c2_framework="Lateral Pivot: Sliver JA4",
                cpu_percent=0.9,
                ram_mb=7.8,
            ),
            "host-ws-eng-09": HostEndpoint(
                host_id="host-ws-eng-09",
                hostname="WS-ENG-09",
                ip_address="10.0.3.49",
                subnet="Engineering Workstations",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="EVALUATING",
                threat_score=0.542,
                active_sockets_count=71,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.7,
                ram_mb=7.2,
            ),
            "host-ws-dev-12": HostEndpoint(
                host_id="host-ws-dev-12",
                hostname="WS-DEV-12",
                ip_address="10.0.3.52",
                subnet="Engineering Workstations",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.008,
                active_sockets_count=64,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.6,
                ram_mb=7.1,
            ),
            "host-ws-dev-15": HostEndpoint(
                host_id="host-ws-dev-15",
                hostname="WS-DEV-15",
                ip_address="10.0.3.55",
                subnet="Engineering Workstations",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.006,
                active_sockets_count=52,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.5,
                ram_mb=6.9,
            ),
            "host-ws-qa-auto": HostEndpoint(
                host_id="host-ws-qa-auto",
                hostname="WS-QA-AUTO",
                ip_address="10.0.3.60",
                subnet="Engineering Workstations",
                os_version="Windows 10 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.004,
                active_sockets_count=110,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.8,
                ram_mb=7.5,
            ),
            "host-ws-build-node1": HostEndpoint(
                host_id="host-ws-build-node1",
                hostname="WS-BUILD-NODE1",
                ip_address="10.0.3.70",
                subnet="Engineering Workstations",
                os_version="Windows Server 2022 (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.005,
                active_sockets_count=138,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=1.0,
                ram_mb=8.0,
            ),

            # === TIER-2: FINANCE & EXECUTIVE ===
            "host-exec-ceo-laptop": HostEndpoint(
                host_id="host-exec-ceo-laptop",
                hostname="EXEC-CEO-LAPTOP",
                ip_address="10.0.4.5",
                subnet="Finance & Executive",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.001,
                active_sockets_count=48,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.4,
                ram_mb=6.7,
            ),
            "host-fin-exec-01": HostEndpoint(
                host_id="host-fin-exec-01",
                hostname="FIN-EXEC-01",
                ip_address="10.0.4.10",
                subnet="Finance & Executive",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.002,
                active_sockets_count=45,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.5,
                ram_mb=6.9,
            ),
            "host-fin-billing-03": HostEndpoint(
                host_id="host-fin-billing-03",
                hostname="FIN-BILLING-03",
                ip_address="10.0.4.14",
                subnet="Finance & Executive",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.001,
                active_sockets_count=38,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.4,
                ram_mb=6.8,
            ),
            "host-fin-treasury-02": HostEndpoint(
                host_id="host-fin-treasury-02",
                hostname="FIN-TREASURY-02",
                ip_address="10.0.4.18",
                subnet="Finance & Executive",
                os_version="Windows 10 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.001,
                active_sockets_count=32,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.3,
                ram_mb=6.5,
            ),
            "host-legal-counsel-01": HostEndpoint(
                host_id="host-legal-counsel-01",
                hostname="LEGAL-COUNSEL-01",
                ip_address="10.0.4.22",
                subnet="Finance & Executive",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.002,
                active_sockets_count=41,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.4,
                ram_mb=6.6,
            ),

            # === TIER-2: OPERATIONS, HR & REMOTE FIELD ===
            "host-hr-director-01": HostEndpoint(
                host_id="host-hr-director-01",
                hostname="HR-DIRECTOR-01",
                ip_address="10.0.5.12",
                subnet="Operations & Remote VPN",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.003,
                active_sockets_count=36,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.4,
                ram_mb=6.6,
            ),
            "host-hr-payroll-02": HostEndpoint(
                host_id="host-hr-payroll-02",
                hostname="HR-PAYROLL-02",
                ip_address="10.0.5.15",
                subnet="Operations & Remote VPN",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.002,
                active_sockets_count=44,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.5,
                ram_mb=6.8,
            ),
            "host-ops-soc-analyst1": HostEndpoint(
                host_id="host-ops-soc-analyst1",
                hostname="OPS-SOC-ANALYST1",
                ip_address="10.0.5.30",
                subnet="Operations & Remote VPN",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.001,
                active_sockets_count=95,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.7,
                ram_mb=7.4,
            ),
            "host-ops-helpdesk-03": HostEndpoint(
                host_id="host-ops-helpdesk-03",
                hostname="OPS-HELPDESK-03",
                ip_address="10.0.5.42",
                subnet="Operations & Remote VPN",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HEALTHY",
                threat_score=0.003,
                active_sockets_count=86,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.6,
                ram_mb=7.1,
            ),
            "host-remote-sales-10": HostEndpoint(
                host_id="host-remote-sales-10",
                hostname="REMOTE-SALES-10",
                ip_address="10.0.5.88",
                subnet="Operations & Remote VPN",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="ONLINE",
                last_heartbeat=time.time(),
                threat_level="HIGH",
                threat_score=0.812,
                active_sockets_count=54,
                isolated_beacons_count=1,
                c2_framework="Active Beacon: Cobalt Strike JA4",
                cpu_percent=0.7,
                ram_mb=7.3,
            ),
            "host-remote-field-08": HostEndpoint(
                host_id="host-remote-field-08",
                hostname="REMOTE-FIELD-08",
                ip_address="10.0.5.94",
                subnet="Operations & Remote VPN",
                os_version="Windows 11 Enterprise (x64)",
                agent_version="0.1.0",
                status="MUTED",
                last_heartbeat=time.time() - 252.0,
                threat_level="HEALTHY",
                threat_score=0.000,
                active_sockets_count=62,
                isolated_beacons_count=0,
                c2_framework=None,
                cpu_percent=0.0,
                ram_mb=0.0,
            ),
        }

        # Initialize Cross-Host Campaigns
        self.campaigns: dict[str, CampaignCluster] = {
            "camp-alpha": CampaignCluster(
                campaign_id="camp-alpha",
                name="CAMPAIGN-ALPHA: Direct-IP Go TLS / Sliver C2 Outbreak",
                c2_framework="Sliver C2 (Go mTLS / HTTPS)",
                ja4_fingerprint="t13d1516h2_8daaf6152771_0266e33433e9",
                cadence_profile="8.4s ±0.8s (MAD Ratio: 0.095)",
                affected_hosts=["WIN-PROD-SRV01", "WS-ENG-04"],
                target_destination="193.26.158.114:443 (Raw IP / No SNI)",
                threat_score=0.987,
                status="ACTIVE_INTRUSION",
            ),
            "camp-beta": CampaignCluster(
                campaign_id="camp-beta",
                name="CAMPAIGN-BETA: Azure CDN-Fronted Cobalt Strike",
                c2_framework="Cobalt Strike (Malleable Profile)",
                ja4_fingerprint="t13d190800_261546b3f71c_f601b1a77409",
                cadence_profile="15.0s ±1.1s (MAD Ratio: 0.073)",
                affected_hosts=["WIN-APP-SRV02", "REMOTE-SALES-10"],
                target_destination="cdn-azure-edge.net:8443 (45.33.32.156)",
                threat_score=0.942,
                status="ACTIVE_INTRUSION",
            ),
        }

        # Host Running Processes & Historical Connection Logs
        self.host_processes: dict[str, list[dict[str, Any]]] = self._init_default_processes()
        self.ledger = ConnectionLedger()
        self.host_connection_history: dict[str, list[dict[str, Any]]] = self._init_default_connection_history()
        for h_id, recs in self.host_connection_history.items():
            self.ledger.seed_initial_records(h_id, recs)

        # Host-Specific Flows
        self.host_flows: dict[str, list[FlowEntry]] = {
            "host-win-prod-srv01": get_demo_flows(),
            "host-win-app-srv02": [
                FlowEntry(
                    flow_id="f201",
                    pid=6712,
                    process_name="rundll32.exe",
                    is_signed=False,
                    src_ip="10.0.1.16",
                    src_port=49210,
                    dst_ip="45.33.32.156",
                    dst_port=8443,
                    sni="cdn-azure-edge.net",
                    interval_str="15.0s",
                    sparkline="▄   ▄   ▄",
                    jitter_str="±1.1s",
                    jitter_pct="7.3%",
                    payload_str="1.2 KB",
                    threat_score=0.942,
                    threat_label="CRIT",
                    is_threat=True,
                    c2_framework="Cobalt Strike JA4 Profile",
                    binary_path=r"C:\Windows\System32\rundll32.exe",
                    command_line=r"rundll32.exe C:\Users\Target\AppData\Local\Temp\nvsvc.dll,Entry",
                    parent_process="wmiprvse.exe (PID 3144) -> powershell.exe (PID 8830) -> rundll32.exe (PID 6712)",
                    sig_info="Unsigned Proxy (DLL Side-load)",
                    sha256="7c12bf9810ac9b32e144a10f8bc9910cde4279ab2281a8c3d9a102ffbc41238a",
                    process_guid="{8f3a91c2-5b19-672a-0900-000000001a38}",
                    ja4_fingerprint="t13d190800_261546b3f71c_f601b1a77409",
                    heuristic_signals="MAD Ratio 0.073 │ CDN Domain Fronting │ DLL Proxy",
                    detection_reasons="Malleable C2 Profile │ Azure CDN Host Header Mismatch",
                    bursts="18 bursts / 4m (96 pkts)",
                    user_context=r"CORP\svc_webapp (Medium Integrity)",
                    is_severed=False,
                    mitre_technique="T1218.011 (Rundll32) / T1090.004",
                    state="ESTABLISHED",
                    packets=96,
                    bytes_transferred=24576,
                    first_seen="2026-11-02 13:52:18",
                    last_seen="2026-11-02 14:26:42",
                    duration="34m 24s",
                    iat_mad_ratio="0.073 (Rigid Malleable)",
                    iat_iqr_ratio="0.118 (Low Dispersion)",
                    bowley_skew="+0.02 (Symmetric Sleep)",
                    conn_per_burst="1.00 (Keep-Alive Tunnel)",
                ),
            ],
            "host-ws-eng-04": [
                FlowEntry(
                    flow_id="f301",
                    pid=7140,
                    process_name="svc_updater.exe",
                    is_signed=False,
                    src_ip="10.0.3.44",
                    src_port=51890,
                    dst_ip="193.26.158.114",
                    dst_port=443,
                    sni="",
                    interval_str="8.4s",
                    sparkline="▄ ▄ ▄ ▄",
                    jitter_str="±0.8s",
                    jitter_pct="9.5%",
                    payload_str="512 B",
                    threat_score=0.865,
                    threat_label="HIGH",
                    is_threat=True,
                    c2_framework="Sliver JA4 (Lateral Pivot)",
                    binary_path=r"C:\ProgramData\Microsoft\Staging\svc_updater.exe",
                    command_line=r"C:\ProgramData\Microsoft\Staging\svc_updater.exe --mtls 193.26.158.114:443",
                    parent_process="services.exe (PID 644) -> wmiprvse.exe (PID 2980) -> svc_updater.exe (PID 7140)",
                    sig_info="Unsigned Binary (WMI Lateral Drop)",
                    sha256="a4f982d17c63e01948b55209df712839ca004918273645519283746501928374",
                    process_guid="{8f3a91c2-6c22-672a-0a00-000000001be4}",
                    ja4_fingerprint="t13d1516h2_8daaf6152771_0266e33433e9",
                    heuristic_signals="MAD Ratio 0.095 │ Direct Raw IP │ Shared SHA-256",
                    detection_reasons="Direct IP (No SNI) │ Correlated Sliver JA4 + SHA256",
                    bursts="12 bursts / 2m (134 pkts)",
                    user_context=r"CORP\eng_admin (High Integrity)",
                    is_severed=False,
                    mitre_technique="T1071.001 (Web C2) / T1047 (WMI)",
                    state="ESTABLISHED",
                    packets=134,
                    bytes_transferred=38400,
                    first_seen="2026-11-02 14:14:38",
                    last_seen="2026-11-02 14:26:44",
                    duration="12m 06s",
                    iat_mad_ratio="0.095 (Rigid Clockwork)",
                    iat_iqr_ratio="0.142 (Low Dispersion)",
                    bowley_skew="+0.03 (Symmetric Loop)",
                    conn_per_burst="1.00 (Persistent Socket)",
                ),
            ],
            "host-remote-sales-10": [
                FlowEntry(
                    flow_id="f401",
                    pid=4412,
                    process_name="dllhost.exe",
                    is_signed=True,
                    src_ip="10.0.5.88",
                    src_port=50411,
                    dst_ip="45.33.32.156",
                    dst_port=8443,
                    sni="cdn-azure-edge.net",
                    interval_str="15.0s",
                    sparkline="▄   ▄   ▄",
                    jitter_str="±1.1s",
                    jitter_pct="7.3%",
                    payload_str="1.2 KB",
                    threat_score=0.812,
                    threat_label="HIGH",
                    is_threat=True,
                    c2_framework="Cobalt Strike JA4 (VPN Ingress)",
                    binary_path=r"C:\Windows\System32\dllhost.exe",
                    command_line=r"C:\Windows\System32\dllhost.exe /Processid:{3EB3C877-1F16-487C-9050-104DBCD66683}",
                    parent_process="svchost.exe (PID 912) -> dllhost.exe (PID 4412)",
                    sig_info="Microsoft Windows (Process Hollowing)",
                    sha256="6d8812fa901bc4432e1098a77654c3210fedcba9876543210abcdef123456789",
                    process_guid="{8f3a91c2-7d33-672a-0b00-00000000113c}",
                    ja4_fingerprint="t13d190800_261546b3f71c_f601b1a77409",
                    heuristic_signals="MAD Ratio 0.073 │ Sacrificial dllhost.exe │ CDN Front",
                    detection_reasons="Cobalt Strike Malleable JA4 │ Sacrificial COM Surrogate",
                    bursts="16 bursts / 4m (112 pkts)",
                    user_context=r"CORP\m.alami (Medium Integrity)",
                    is_severed=False,
                    mitre_technique="T1055.012 (Process Hollowing) / T1090.004",
                    state="ESTABLISHED",
                    packets=112,
                    bytes_transferred=29696,
                    first_seen="2026-11-02 13:48:05",
                    last_seen="2026-11-02 14:26:40",
                    duration="38m 35s",
                    iat_mad_ratio="0.073 (Rigid Malleable)",
                    iat_iqr_ratio="0.118 (Low Dispersion)",
                    bowley_skew="+0.02 (Symmetric Sleep)",
                    conn_per_burst="1.00 (Keep-Alive Tunnel)",
                ),
            ],
        }

    def get_fleet_summary(self) -> dict[str, Any]:
        """Returns fleet health statistics and active alerts."""
        with self.lock:
            now = time.time()
            total_hosts = len(self.hosts)

            # Dead-Man's Switch: Check heartbeat staleness
            demo_hosts = {
                "host-win-prod-srv01", "host-win-app-srv02", "host-ws-eng-04", 
                "host-ws-eng-09", "host-dc01-prod", "host-dc02-backup", 
                "host-ws-dev-12", "host-fin-exec-01", "host-fin-billing-03", "host-gw-edge-01"
            }
            muted_hosts = 0
            for host_id, h in self.hosts.items():
                if host_id not in demo_hosts and (now - h.last_heartbeat > 45.0):
                    h.status = "MUTED"
                    muted_hosts += 1
                elif h.status == "MUTED":
                    muted_hosts += 1
                else:
                    h.status = "ONLINE"

            crit_hosts = sum(1 for h in self.hosts.values() if h.threat_level == "CRITICAL")
            high_hosts = sum(1 for h in self.hosts.values() if h.threat_level == "HIGH")
            eval_hosts = sum(1 for h in self.hosts.values() if h.threat_level == "EVALUATING")
            healthy_hosts = sum(1 for h in self.hosts.values() if h.threat_level == "HEALTHY")
            total_sockets = sum(h.active_sockets_count for h in self.hosts.values())
            active_beacons = sum(h.isolated_beacons_count for h in self.hosts.values())
            active_campaigns = sum(1 for c in self.campaigns.values() if c.status == "ACTIVE_INTRUSION")

            active_hosts = total_hosts - muted_hosts
            if muted_hosts > 0:
                hb_status = f"{active_hosts} of {total_hosts} Agents Active ({muted_hosts} Muted / Disconnected)"
            else:
                hb_status = f"All {total_hosts} Agents Active (0 Muted)"

            return {
                "total_hosts": total_hosts,
                "active_hosts": active_hosts,
                "muted_hosts": muted_hosts,
                "critical_hosts": crit_hosts,
                "high_hosts": high_hosts,
                "evaluating_hosts": eval_hosts,
                "healthy_hosts": healthy_hosts,
                "total_sockets": total_sockets,
                "active_beacons": active_beacons,
                "active_campaigns": active_campaigns,
                "heartbeat_status": hb_status,
                "siem_stream": "NDJSON Active (Wazuh / Splunk Forwarder)",
            }

    def sever_host_socket(self, host_id: str, pid: int) -> bool:
        """Executes kernel TCP teardown on a specific host socket."""
        with self.lock:
            flows = self.host_flows.get(host_id, [])
            for f in flows:
                if f.pid == pid and not f.is_severed:
                    f.is_severed = True
                    f.threat_score = 0.0
                    f.threat_label = "SAFE"
                    f.state = "SEVERED (Kernel TCB Dropped)"
                    if host_id in self.hosts:
                        host = self.hosts[host_id]
                        host.isolated_beacons_count = max(0, host.isolated_beacons_count - 1)
                        if host.isolated_beacons_count == 0:
                            host.threat_level = "HEALTHY"
                            host.threat_score = 0.005
                    return True
        return False

    def tarpit_host_socket(self, host_id: str, pid: int) -> bool:
        """Enforces deceptive TCP Zero-Window tarpit quarantine."""
        with self.lock:
            flows = self.host_flows.get(host_id, [])
            for f in flows:
                if f.pid == pid and not f.is_severed:
                    f.is_severed = True
                    f.threat_score = 0.0
                    f.threat_label = "TARPIT"
                    f.state = "TARPIT (Zero-Window Freeze)"
                    if host_id in self.hosts:
                        host = self.hosts[host_id]
                        host.isolated_beacons_count = max(0, host.isolated_beacons_count - 1)
                    return True
        return False

    def sever_campaign(self, campaign_id: str) -> int:
        """Executes mass coordinated kernel teardown across all campaign endpoints."""
        with self.lock:
            camp = self.campaigns.get(campaign_id)
            if not camp:
                return 0

            count = 0
            for host_name in camp.affected_hosts:
                for h_id, host in self.hosts.items():
                    if host.hostname == host_name:
                        flows = self.host_flows.get(h_id, [])
                        for f in flows:
                            if f.is_threat and not f.is_severed:
                                f.is_severed = True
                                f.threat_score = 0.0
                                f.threat_label = "SAFE"
                                f.state = "SEVERED (Campaign Contained)"
                                host.isolated_beacons_count = max(0, host.isolated_beacons_count - 1)
                                if host.isolated_beacons_count == 0:
                                    host.threat_level = "HEALTHY"
                                    host.threat_score = 0.005
                                count += 1

            camp.status = "CONTAINED"
            return count

    def _init_default_processes(self) -> dict[str, list[dict[str, Any]]]:
        """Pre-populates enterprise process inventories for monitored hosts."""
        return {
            "host-win-prod-srv01": [
                {
                    "pid": 5824, "ppid": 4920, "name": "update.exe",
                    "path": r"C:\Users\Target\AppData\Roaming\update.exe",
                    "username": "CORP\\jdoe", "cpu_percent": 0.8, "ram_mb": 7.5,
                    "start_time": "2026-11-02 14:10:02 UTC", "socket_count": 1,
                    "is_signed": False, "threat_score": 0.987, "bandwidth_usage": "51.6 KB", "status": "MALICIOUS (Sliver JA4)"
                },
                {
                    "pid": 8830, "ppid": 2023, "name": "powershell.exe",
                    "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "username": "CORP\\jdoe", "cpu_percent": 0.5, "ram_mb": 42.1,
                    "start_time": "2026-11-02 14:15:20 UTC", "socket_count": 1,
                    "is_signed": True, "threat_score": 0.865, "bandwidth_usage": "14.3 KB", "status": "SUSPICIOUS (LOLBin C2)"
                },
                {
                    "pid": 3104, "ppid": 1024, "name": "wmiprvse.exe",
                    "path": r"C:\Windows\System32\wbem\wmiprvse.exe",
                    "username": "NT AUTHORITY\\NETWORK SERVICE", "cpu_percent": 0.3, "ram_mb": 16.4,
                    "start_time": "2026-11-02 14:14:10 UTC", "socket_count": 1,
                    "is_signed": True, "threat_score": 0.794, "bandwidth_usage": "24.5 KB", "status": "LATERAL PIVOT (SMB 445)"
                },
                {
                    "pid": 4920, "ppid": 2110, "name": "cmd.exe",
                    "path": r"C:\Windows\System32\cmd.exe",
                    "username": "CORP\\jdoe", "cpu_percent": 0.0, "ram_mb": 4.2,
                    "bandwidth_usage": "0 B", "start_time": "2026-11-02 14:09:44 UTC", "socket_count": 0,
                    "is_signed": True, "threat_score": 0.05, "status": "BENIGN"
                },
                {
                    "pid": 2110, "ppid": 1824, "name": "explorer.exe",
                    "path": r"C:\Windows\explorer.exe",
                    "username": "CORP\\jdoe", "cpu_percent": 0.2, "ram_mb": 86.4,
                    "start_time": "2026-11-02 08:30:11 UTC", "socket_count": 2,
                    "is_signed": True, "threat_score": 0.00, "status": "BENIGN"
                },
                {
                    "pid": 1024, "ppid": 684, "name": "svchost.exe",
                    "path": r"C:\Windows\System32\svchost.exe",
                    "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 0.1, "ram_mb": 18.9,
                    "start_time": "2026-11-02 08:00:15 UTC", "socket_count": 4,
                    "is_signed": True, "threat_score": 0.00, "status": "BENIGN"
                },
                {
                    "pid": 692, "ppid": 684, "name": "lsass.exe",
                    "path": r"C:\Windows\System32\lsass.exe",
                    "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 0.1, "ram_mb": 24.5,
                    "start_time": "2026-11-02 08:00:10 UTC", "socket_count": 0,
                    "is_signed": True, "threat_score": 0.00, "status": "BENIGN (PPL Protected)"
                },
                {
                    "pid": 684, "ppid": 676, "name": "services.exe",
                    "path": r"C:\Windows\System32\services.exe",
                    "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 0.0, "ram_mb": 8.1,
                    "start_time": "2026-11-02 08:00:09 UTC", "socket_count": 0,
                    "is_signed": True, "threat_score": 0.00, "status": "BENIGN"
                },
                {
                    "pid": 1420, "ppid": 684, "name": "spoolsv.exe",
                    "path": r"C:\Windows\System32\spoolsv.exe",
                    "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 0.0, "ram_mb": 12.3,
                    "start_time": "2026-11-02 08:00:22 UTC", "socket_count": 0,
                    "is_signed": True, "threat_score": 0.00, "status": "BENIGN"
                },
                {
                    "pid": 3340, "ppid": 1024, "name": "smartscreen.exe",
                    "path": r"C:\Windows\System32\smartscreen.exe",
                    "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 0.0, "ram_mb": 14.8,
                    "start_time": "2026-11-02 08:35:00 UTC", "socket_count": 1,
                    "is_signed": True, "threat_score": 0.00, "status": "BENIGN"
                },
            ]
        }

    def _init_default_connection_history(self) -> dict[str, list[dict[str, Any]]]:
        """Pre-populates chronological connection audit logs with exact timestamps."""
        return {
            "host-win-prod-srv01": [
                {
                    "timestamp": "2026-11-02 14:26:45.812 UTC", "pid": 5824, "process_name": "update.exe",
                    "direction": "OUTBOUND", "local_addr": "10.0.1.15:49152", "remote_addr": "193.26.158.114:443",
                    "sni": "RAW IP / NO SNI", "duration": "16m 43s", "bytes_str": "512 B",
                    "state": "ESTABLISHED", "verdict": "CRITICAL C2 (Sliver Periodic 8.4s)"
                },
                {
                    "timestamp": "2026-11-02 14:26:40.219 UTC", "pid": 3104, "process_name": "wmiprvse.exe",
                    "direction": "LATERAL", "local_addr": "10.0.1.15:51204", "remote_addr": "10.0.3.44:445",
                    "sni": "INTERNAL SMB / WMI", "duration": "12m 30s", "bytes_str": "1.4 KB",
                    "state": "ESTABLISHED", "verdict": "HIGH PIVOT (SMB Lateral -> WS-ENG-04)"
                },
                {
                    "timestamp": "2026-11-02 14:26:37.408 UTC", "pid": 5824, "process_name": "update.exe",
                    "direction": "OUTBOUND", "local_addr": "10.0.1.15:49152", "remote_addr": "193.26.158.114:443",
                    "sni": "RAW IP / NO SNI", "duration": "16m 35s", "bytes_str": "512 B",
                    "state": "ESTABLISHED", "verdict": "CRITICAL C2 (Sliver Periodic 8.4s)"
                },
                {
                    "timestamp": "2026-11-02 14:26:29.011 UTC", "pid": 5824, "process_name": "update.exe",
                    "direction": "OUTBOUND", "local_addr": "10.0.1.15:49152", "remote_addr": "193.26.158.114:443",
                    "sni": "RAW IP / NO SNI", "duration": "16m 27s", "bytes_str": "512 B",
                    "state": "ESTABLISHED", "verdict": "CRITICAL C2 (Sliver Periodic 8.4s)"
                },
                {
                    "timestamp": "2026-11-02 14:25:20.144 UTC", "pid": 8830, "process_name": "powershell.exe",
                    "direction": "OUTBOUND", "local_addr": "10.0.1.15:49722", "remote_addr": "185.220.101.5:443",
                    "sni": "api.telemetry-host.org", "duration": "10m 00s", "bytes_str": "768 B",
                    "state": "ESTABLISHED", "verdict": "HIGH C2 (Fallback Periodic 60.0s)"
                },
                {
                    "timestamp": "2026-11-02 14:24:20.139 UTC", "pid": 8830, "process_name": "powershell.exe",
                    "direction": "OUTBOUND", "local_addr": "10.0.1.15:49722", "remote_addr": "185.220.101.5:443",
                    "sni": "api.telemetry-host.org", "duration": "9m 00s", "bytes_str": "768 B",
                    "state": "ESTABLISHED", "verdict": "HIGH C2 (Fallback Periodic 60.0s)"
                },
                {
                    "timestamp": "2026-11-02 14:20:12.602 UTC", "pid": 2023, "process_name": "svchost.exe",
                    "direction": "OUTBOUND", "local_addr": "10.0.1.15:50228", "remote_addr": "20.189.139.81:443",
                    "sni": "*.events.data.microsoft.com", "duration": "6h 25m", "bytes_str": "3.6 KB",
                    "state": "ESTABLISHED", "verdict": "BENIGN (Microsoft Telemetry)"
                },
                {
                    "timestamp": "2026-11-02 14:15:20.000 UTC", "pid": 8830, "process_name": "powershell.exe",
                    "direction": "OUTBOUND", "local_addr": "10.0.1.15:49722", "remote_addr": "185.220.101.5:443",
                    "sni": "api.telemetry-host.org", "duration": "Initial", "bytes_str": "128 B",
                    "state": "SYN_SENT", "verdict": "HIGH C2 (Socket Initiation)"
                },
                {
                    "timestamp": "2026-11-02 14:14:10.000 UTC", "pid": 3104, "process_name": "wmiprvse.exe",
                    "direction": "LATERAL", "local_addr": "10.0.1.15:51204", "remote_addr": "10.0.3.44:445",
                    "sni": "INTERNAL SMB / WMI", "duration": "Initial", "bytes_str": "256 B",
                    "state": "SYN_SENT", "verdict": "HIGH PIVOT (Lateral SMB Initiation)"
                },
                {
                    "timestamp": "2026-11-02 14:10:02.000 UTC", "pid": 5824, "process_name": "update.exe",
                    "direction": "OUTBOUND", "local_addr": "10.0.1.15:49152", "remote_addr": "193.26.158.114:443",
                    "sni": "RAW IP / NO SNI", "duration": "Initial", "bytes_str": "128 B",
                    "state": "SYN_SENT", "verdict": "CRITICAL C2 (Socket Initiation)"
                },
                {
                    "timestamp": "2026-11-02 08:30:15.220 UTC", "pid": 1024, "process_name": "teams.exe",
                    "direction": "OUTBOUND", "local_addr": "10.0.1.15:50114", "remote_addr": "52.114.63.56:443",
                    "sni": "*.teams.microsoft.com", "duration": "5h 56m", "bytes_str": "3.9 KB",
                    "state": "ESTABLISHED", "verdict": "BENIGN (Microsoft Teams)"
                },
                {
                    "timestamp": "2026-11-02 08:00:15.000 UTC", "pid": 2023, "process_name": "svchost.exe",
                    "direction": "OUTBOUND", "local_addr": "10.0.1.15:53312", "remote_addr": "10.0.0.1:53",
                    "sni": "dc01-prod.corp.local (DNS)", "duration": "14ms", "bytes_str": "84 B",
                    "state": "CLOSED", "verdict": "BENIGN (Internal AD DNS Resolution)"
                },
            ]
        }

    def register_or_update_agent(self, payload: dict[str, Any]) -> None:
        """Registers a live checking-in endpoint agent or updates its heartbeat status."""
        with self.lock:
            host_id = payload.get("host_id") or "host-unknown"
            hostname = payload.get("hostname") or "UNKNOWN-HOST"
            ip_address = payload.get("ip_address") or "127.0.0.1"
            os_version = payload.get("os_version") or "Windows 11 (x64)"
            agent_version = payload.get("agent_version") or "0.1.0"
            active_sockets = int(payload.get("active_sockets", 14))

            if "processes" in payload and payload["processes"]:
                self.host_processes[host_id] = payload["processes"]
            if "connections" in payload and payload["connections"]:
                self.ledger.record_connections(host_id, payload["connections"])
                self.host_connection_history[host_id] = self.ledger.get_host_history(host_id, limit=200)

            if host_id in self.hosts:
                host = self.hosts[host_id]
                host.last_heartbeat = time.time()
                host.status = "ONLINE"
                host.active_sockets_count = active_sockets or host.active_sockets_count
            else:
                self.hosts[host_id] = HostEndpoint(
                    host_id=host_id,
                    hostname=hostname,
                    ip_address=ip_address,
                    subnet="Local Monitored Endpoints",
                    os_version=os_version,
                    agent_version=agent_version,
                    status="ONLINE",
                    last_heartbeat=time.time(),
                    threat_level="HEALTHY",
                    threat_score=0.015,
                    active_sockets_count=active_sockets or 14,
                    isolated_beacons_count=0,
                    c2_framework=None,
                    cpu_percent=0.6,
                    ram_mb=7.2,
                )
                if host_id not in self.host_flows:
                    self.host_flows[host_id] = [
                        FlowEntry(
                            flow_id=f"f_{host_id}_01",
                            pid=1024,
                            process_name="svchost.exe",
                            is_signed=True,
                            src_ip=ip_address,
                            src_port=50112,
                            dst_ip="20.189.173.8",
                            dst_port=443,
                            sni="*.azure.com",
                            interval_str="Asynch",
                            sparkline="------",
                            jitter_str="N/A",
                            jitter_pct="0.0%",
                            payload_str="2.4 KB",
                            threat_score=0.015,
                            threat_label="SAFE",
                            is_threat=False,
                            c2_framework=None,
                            binary_path=r"C:\Windows\System32\svchost.exe",
                            command_line=r"C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted",
                            parent_process=r"services.exe (PID 684)",
                            sha256="4d71bc294a21...912f",
                            ja4_fingerprint="t13d1516h2_safe",
                            heuristic_signals=["Signed Microsoft PE", "Standard Enterprise Telemetry"],
                            detection_reasons=[],
                            bursts=1,
                            user_context=r"NT AUTHORITY\SYSTEM",
                            is_severed=False,
                            mitre_technique="N/A",
                            state="ESTABLISHED",
                            packets=142,
                            bytes_transferred=45200,
                        )
                    ]
    def get_pid_history_summary(self, host_id: str, pid: int) -> dict[str, Any]:
        """Returns comprehensive chronological connection history and bandwidth metrics for a specific PID."""
        with self.lock:
            return self.ledger.get_pid_history_summary(host_id, pid)


