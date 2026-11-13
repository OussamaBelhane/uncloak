"""
Unit tests for embedded SQLite WAL telemetry database.
"""

import os
import tempfile
import sqlite3
from uncloak.storage.database import TelemetryDatabase


def test_sqlite_wal_database_lifecycle() -> None:
    """Verifies table creation, WAL mode configuration, and record persistence."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_file = os.path.join(tmp_dir, "test_uncloak.db")
        db = TelemetryDatabase(db_path=db_file)

        # Verify WAL mode is configured
        conn = sqlite3.connect(db_file)
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        conn.close()
        assert journal_mode.lower() == "wal"

        # Insert a classified flow event
        db.insert_flow(
            flow_id="flow_test_01",
            pid=5824,
            process_name="update.exe",
            exe_path=r"C:\Users\Public\update.exe",
            src_ip="10.0.0.15",
            src_port=49152,
            dst_ip="193.26.158.114",
            dst_port=443,
            threat_score=0.985,
            verdict="CRITICAL_C2",
            features={"iat_median": 8.4, "iat_mad_ratio": 0.095},
        )

        # Record a mitigation action
        db.record_mitigation(
            action_id="act_01",
            action_type="SEVER_SOCKET",
            target_pid=5824,
            target_destination="193.26.158.114:443",
            success=True,
            details="SetTcpEntry DELETE_TCB dispatched",
        )

        # Query back to verify integrity
        conn2 = sqlite3.connect(db_file)
        conn2.row_factory = sqlite3.Row
        flow_row = conn2.execute("SELECT * FROM flow_events WHERE flow_id = 'flow_test_01';").fetchone()
        assert flow_row is not None
        assert flow_row["pid"] == 5824
        assert flow_row["verdict"] == "CRITICAL_C2"
        assert flow_row["threat_score"] == 0.985

        mit_row = conn2.execute("SELECT * FROM mitigation_log WHERE action_id = 'act_01';").fetchone()
        assert mit_row is not None
        assert mit_row["action_type"] == "SEVER_SOCKET"
        assert mit_row["success"] == 1
        conn2.close()
