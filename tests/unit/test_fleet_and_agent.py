"""
Unit tests for Uncloak Enterprise Fleet Manager and Endpoint Agent.
"""

from uncloak.agent.service import UncloakAgentService
from uncloak.manager.fleet import FleetManager


def test_fleet_manager_summary() -> None:
    """Verifies fleet summary calculations across enterprise endpoints."""
    fleet = FleetManager()
    summary = fleet.get_fleet_summary()

    assert summary["total_hosts"] == 32
    assert summary["critical_hosts"] == 2
    assert summary["high_hosts"] == 2
    assert summary["evaluating_hosts"] == 2
    assert summary["healthy_hosts"] == 26
    assert summary["active_campaigns"] == 2
    assert summary["total_sockets"] > 1000


def test_fleet_manager_socket_sever() -> None:
    """Verifies targeted surgical kernel socket eviction on a specific host."""
    fleet = FleetManager()
    target_host = "host-win-prod-srv01"
    target_pid = 5824

    assert fleet.hosts[target_host].threat_level == "CRITICAL"
    success = fleet.sever_host_socket(target_host, target_pid)
    assert success is True

    # Host should now have zero isolated beacons and drop to healthy
    assert fleet.hosts[target_host].threat_level == "HEALTHY"
    assert fleet.hosts[target_host].isolated_beacons_count == 0


def test_fleet_manager_tarpit_enforcement() -> None:
    """Verifies deceptive TCP Zero-Window tarpit quarantine."""
    fleet = FleetManager()
    target_host = "host-win-app-srv02"
    target_pid = 6712

    success = fleet.tarpit_host_socket(target_host, target_pid)
    assert success is True

    flow = next(f for f in fleet.host_flows[target_host] if f.pid == target_pid)
    assert flow.is_severed is True
    assert flow.threat_label == "TARPIT"
    assert "Zero-Window" in flow.state


def test_fleet_manager_campaign_mass_sever() -> None:
    """Verifies cross-host coordinated campaign eviction."""
    fleet = FleetManager()
    camp_id = "camp-alpha"

    assert fleet.campaigns[camp_id].status == "ACTIVE_INTRUSION"
    severed_count = fleet.sever_campaign(camp_id)
    assert severed_count >= 1
    assert fleet.campaigns[camp_id].status == "CONTAINED"


def test_agent_service_init() -> None:
    """Verifies silent endpoint agent initialization."""
    agent = UncloakAgentService(manager_url="http://127.0.0.1:8443")
    assert agent.hostname != ""
    assert agent.heartbeat_interval == 15.0
    assert agent.ip_address != ""


def test_fleet_manager_agent_registration() -> None:
    """Verifies live agent registration and heartbeat processing."""
    fleet = FleetManager()
    payload = {
        "host_id": "host-test-client",
        "hostname": "TEST-CLIENT",
        "ip_address": "192.168.1.50",
        "os_version": "Windows 11 Enterprise",
        "agent_version": "0.1.0",
        "active_sockets": 25,
    }
    fleet.register_or_update_agent(payload)
    assert "host-test-client" in fleet.hosts
    assert fleet.hosts["host-test-client"].hostname == "TEST-CLIENT"
    assert fleet.hosts["host-test-client"].status == "ONLINE"
    assert "host-test-client" in fleet.host_flows


def test_fleet_manager_detects_disconnected_agent() -> None:
    """Verifies that the Central Manager detects when an agent stops heartbeating (Dead-Man Switch)."""
    import time
    fleet = FleetManager()
    payload = {
        "host_id": "host-temp-worker",
        "hostname": "TEMP-WORKER",
        "ip_address": "10.0.5.12",
        "os_version": "Windows 11",
        "active_sockets": 20,
    }
    fleet.register_or_update_agent(payload)
    assert fleet.hosts["host-temp-worker"].status == "ONLINE"

    # Simulate agent dying or being disconnected 60s ago
    fleet.hosts["host-temp-worker"].last_heartbeat = time.time() - 60.0
    summary = fleet.get_fleet_summary()

    # Manager detects dead-man switch trip
    assert fleet.hosts["host-temp-worker"].status == "MUTED"
    assert summary["muted_hosts"] >= 1
    assert "Muted / Disconnected" in summary["heartbeat_status"]
def test_connection_ledger_records_and_persists():
    """Verifies that ConnectionLedger records network history and calculates PID metrics."""
    import tempfile
    import os
    from uncloak.manager.ledger import ConnectionLedger

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    ledger = ConnectionLedger(db_path=db_path)
    connections = [
        {
            "pid": 5824,
            "process_name": "update.exe",
            "local_addr": "10.0.0.15:49152",
            "remote_addr": "193.26.158.114:443",
            "sni": "RAW IP",
            "duration": "16m 43s",
            "bytes_str": "512 B",
            "state": "ESTABLISHED",
            "verdict": "CRITICAL C2",
        },
        {
            "pid": 5824,
            "process_name": "update.exe",
            "local_addr": "10.0.0.15:49154",
            "remote_addr": "193.26.158.114:443",
            "sni": "RAW IP",
            "duration": "10s",
            "bytes_str": "128 B",
            "state": "CLOSED",
            "verdict": "CRITICAL C2",
        }
    ]

    ledger.record_connections("test-host", connections)
    history = ledger.get_host_history("test-host")
    assert len(history) == 2
    assert history[0]["pid"] == 5824

    pid_summary = ledger.get_pid_history_summary("test-host", 5824)
    assert pid_summary["pid"] == 5824
    assert pid_summary["process_name"] == "update.exe"
    assert pid_summary["total_connections"] == 2
    assert len(pid_summary["records"]) == 2

    try:
        os.remove(db_path)
    except Exception:
        pass


def test_fleet_manager_pid_history_summary():
    """Verifies that FleetManager provides full PID connection history with dates and bandwidth."""
    from uncloak.manager.fleet import FleetManager

    fleet = FleetManager()
    summary = fleet.get_pid_history_summary("host-win-prod-srv01", 5824)

    assert summary["pid"] == 5824
    assert summary["process_name"] == "update.exe"
    assert summary["total_connections"] >= 1
    assert "records" in summary
    assert len(summary["records"]) >= 1

    first_record = summary["records"][0]
    assert "timestamp" in first_record
    assert "remote_addr" in first_record
    assert "bytes_str" in first_record
    assert "verdict" in first_record


def test_desktop_data_manager_select_pid_persistence():
    """Verifies that selecting a PID is preserved across desktop state sync calls."""
    from uncloak.ui.desktop import CockpitDataManager

    dm = CockpitDataManager()
    dm.select_pid(None, 7788)
    assert dm.fleet.selected_pid == 7788

    payload = dm.get_state_payload()
    assert payload["selected_pid"] == 7788

    payload2 = dm.get_state_payload(pid=9999)
    assert payload2["selected_pid"] == 9999
    assert dm.fleet.selected_pid == 9999
