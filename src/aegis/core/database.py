"""SQLite database layer for Aegis.

Uses WAL mode for concurrent read/write from multiple processes.
Stores events, alerts, baselines, feedback, and audit logs.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from aegis.core.models import (
    AegisEvent,
    Alert,
    AlertStatus,
    SensorType,
    Severity,
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    sensor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_sensor ON events(sensor);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    sensor TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    confidence REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    data TEXT NOT NULL,
    mitre_ids TEXT NOT NULL DEFAULT '[]',
    recommended_actions TEXT NOT NULL DEFAULT '[]',
    priority_score REAL NOT NULL DEFAULT 0,
    dismiss_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);

CREATE TABLE IF NOT EXISTS connection_reputation (
    address TEXT PRIMARY KEY,
    address_type TEXT NOT NULL,
    score REAL NOT NULL DEFAULT 50.0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    total_connections INTEGER NOT NULL DEFAULT 0,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS device_whitelist (
    device_id TEXT PRIMARY KEY,
    device_type TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    added_at REAL NOT NULL,
    approved_by TEXT NOT NULL DEFAULT 'auto'
);

CREATE TABLE IF NOT EXISTS process_whitelist (
    process_hash TEXT PRIMARY KEY,
    process_name TEXT NOT NULL,
    process_path TEXT NOT NULL,
    added_at REAL NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS user_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    sensor TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp REAL NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_feedback_alert_type ON user_feedback(alert_type);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    component TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
"""


class AegisDatabase:
    """SQLite database manager for Aegis.

    Uses WAL journal mode for concurrent access from multiple processes.
    """

    def __init__(self, db_path: str | Path):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    @property
    def journal_mode(self) -> str:
        cursor = self._conn.execute("PRAGMA journal_mode")
        return cursor.fetchone()[0]

    def close(self) -> None:
        self._conn.close()

    def list_tables(self) -> list[str]:
        cursor = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        return [row[0] for row in cursor.fetchall()]

    # --- Events ---

    def insert_event(self, event: AegisEvent) -> None:
        self._conn.execute(
            "INSERT INTO events (event_id, timestamp, sensor, event_type, severity, data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.timestamp,
                event.sensor.value,
                event.event_type,
                event.severity.value,
                json.dumps(event.data),
            ),
        )
        self._conn.commit()

    def get_event(self, event_id: str) -> AegisEvent | None:
        cursor = self._conn.execute(
            "SELECT * FROM events WHERE event_id = ?", (event_id,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_event(row)

    def query_events(
        self,
        sensor: SensorType | None = None,
        since: float | None = None,
        limit: int = 1000,
    ) -> list[AegisEvent]:
        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []
        if sensor is not None:
            query += " AND sensor = ?"
            params.append(sensor.value)
        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cursor = self._conn.execute(query, params)
        return [self._row_to_event(row) for row in cursor.fetchall()]

    def event_count(self, sensor: SensorType | None = None) -> int:
        if sensor is not None:
            cursor = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE sensor = ?", (sensor.value,)
            )
        else:
            cursor = self._conn.execute("SELECT COUNT(*) FROM events")
        return cursor.fetchone()[0]

    def _row_to_event(self, row: sqlite3.Row) -> AegisEvent:
        return AegisEvent(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            sensor=SensorType.from_string(row["sensor"]),
            event_type=row["event_type"],
            severity=Severity.from_string(row["severity"]),
            data=json.loads(row["data"]),
        )

    # --- Alerts ---

    def insert_alert(self, alert: Alert) -> None:
        self._conn.execute(
            "INSERT INTO alerts "
            "(alert_id, event_id, timestamp, sensor, alert_type, severity, "
            "title, description, confidence, status, data, mitre_ids, "
            "recommended_actions, priority_score, dismiss_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.alert_id,
                alert.event_id,
                alert.timestamp,
                alert.sensor.value,
                alert.alert_type,
                alert.severity.value,
                alert.title,
                alert.description,
                alert.confidence,
                alert.status.value,
                json.dumps(alert.data),
                json.dumps(alert.mitre_ids),
                json.dumps(alert.recommended_actions),
                alert.priority_score,
                alert.dismiss_count,
            ),
        )
        self._conn.commit()

    def get_alert(self, alert_id: str) -> Alert | None:
        cursor = self._conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_alert(row)

    def query_alerts(
        self,
        status: AlertStatus | None = None,
        severity: Severity | None = None,
        limit: int = 100,
    ) -> list[Alert]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if status is not None:
            query += " AND status = ?"
            params.append(status.value)
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity.value)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cursor = self._conn.execute(query, params)
        return [self._row_to_alert(row) for row in cursor.fetchall()]

    def update_alert_status(self, alert_id: str, status: AlertStatus) -> None:
        self._conn.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?",
            (status.value, alert_id),
        )
        self._conn.commit()

    def alert_count(self, severity: Severity | None = None) -> int:
        if severity is not None:
            cursor = self._conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity = ?", (severity.value,)
            )
        else:
            cursor = self._conn.execute("SELECT COUNT(*) FROM alerts")
        return cursor.fetchone()[0]

    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        return Alert(
            alert_id=row["alert_id"],
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            sensor=SensorType.from_string(row["sensor"]),
            alert_type=row["alert_type"],
            severity=Severity.from_string(row["severity"]),
            title=row["title"],
            description=row["description"],
            confidence=row["confidence"],
            status=AlertStatus(row["status"]),
            data=json.loads(row["data"]),
            mitre_ids=json.loads(row["mitre_ids"]),
            recommended_actions=json.loads(row["recommended_actions"]),
            dismiss_count=row["dismiss_count"],
        )

    # --- Audit Log ---

    def audit(self, component: str, action: str, detail: str = "") -> None:
        self._conn.execute(
            "INSERT INTO audit_log (timestamp, component, action, detail) "
            "VALUES (?, ?, ?, ?)",
            (time.time(), component, action, detail),
        )
        self._conn.commit()

    def get_audit_log(self, limit: int = 50) -> list[dict[str, Any]]:
        cursor = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return [
            {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "component": row["component"],
                "action": row["action"],
                "detail": row["detail"],
            }
            for row in cursor.fetchall()
        ]
