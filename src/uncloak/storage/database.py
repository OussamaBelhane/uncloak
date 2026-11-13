"""
Embedded SQLite Telemetry & Audit Ledger Subsystem for Uncloak.
Configures SQLite in Write-Ahead Logging (WAL) mode for low-latency concurrent auditing.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Optional


class TelemetryDatabase:
    """Thread-safe SQLite storage ledger with WAL mode and schema versioning."""

    def __init__(self, db_path: str = "uncloak.db") -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable Write-Ahead Logging for high-throughput concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        """Initializes relational tables for flow telemetry, alerts, and mitigations."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.executescript("""
                    CREATE TABLE IF NOT EXISTS flow_events (
                        flow_id TEXT PRIMARY KEY,
                        timestamp REAL NOT NULL,
                        pid INTEGER NOT NULL,
                        process_name TEXT,
                        exe_path TEXT,
                        src_ip TEXT NOT NULL,
                        src_port INTEGER NOT NULL,
                        dst_ip TEXT NOT NULL,
                        dst_port INTEGER NOT NULL,
                        threat_score REAL DEFAULT 0.0,
                        verdict TEXT DEFAULT 'HEALTHY',
                        features_json TEXT
                    );

                    CREATE TABLE IF NOT EXISTS alerts (
                        alert_id TEXT PRIMARY KEY,
                        timestamp REAL NOT NULL,
                        flow_id TEXT,
                        threat_score REAL NOT NULL,
                        threat_level TEXT NOT NULL,
                        recommended_action TEXT,
                        details_json TEXT,
                        FOREIGN KEY (flow_id) REFERENCES flow_events(flow_id)
                    );

                    CREATE TABLE IF NOT EXISTS mitigation_log (
                        action_id TEXT PRIMARY KEY,
                        timestamp REAL NOT NULL,
                        action_type TEXT NOT NULL,
                        target_pid INTEGER NOT NULL,
                        target_destination TEXT,
                        success INTEGER NOT NULL,
                        details TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_flow_timestamp ON flow_events(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_flow_pid ON flow_events(pid);
                    CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alerts(timestamp);
                    """)
            finally:
                conn.close()

    def insert_flow(
        self,
        flow_id: str,
        pid: int,
        process_name: str,
        exe_path: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        threat_score: float = 0.0,
        verdict: str = "HEALTHY",
        features: Optional[dict[str, Any]] = None,
    ) -> None:
        """Inserts or updates a classified flow record."""
        features_json = json.dumps(features) if features else None
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO flow_events
                        (flow_id, timestamp, pid, process_name, exe_path, src_ip, src_port, dst_ip, dst_port, threat_score, verdict, features_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        flow_id,
                        time.time(),
                        pid,
                        process_name,
                        exe_path,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        threat_score,
                        verdict,
                        features_json,
                    ))
            finally:
                conn.close()

    def record_mitigation(
        self,
        action_id: str,
        action_type: str,
        target_pid: int,
        target_destination: str,
        success: bool,
        details: str = "",
    ) -> None:
        """Audits an executed mitigation action in the local database."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        INSERT INTO mitigation_log
                        (action_id, timestamp, action_type, target_pid, target_destination, success, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        action_id,
                        time.time(),
                        action_type,
                        target_pid,
                        target_destination,
                        1 if success else 0,
                        details,
                    ))
            finally:
                conn.close()
