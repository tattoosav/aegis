"""Tests for ForensicLogger — audit trail for security actions."""

from __future__ import annotations

import json
import time

import pytest

from aegis.core.database import AegisDatabase
from aegis.response.forensic_logger import (
    RETENTION_SECONDS,
    ForensicLogger,
    LogEntry,
)

# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #

@pytest.fixture()
def db() -> AegisDatabase:
    return AegisDatabase(":memory:")


@pytest.fixture()
def fl(db: AegisDatabase) -> ForensicLogger:
    return ForensicLogger(db)


# ------------------------------------------------------------------ #
# log_alert
# ------------------------------------------------------------------ #

class TestLogAlert:
    """Tests for log_alert()."""

    def test_creates_audit_entry(
        self, fl: ForensicLogger, db: AegisDatabase,
    ) -> None:
        fl.log_alert(
            alert_id="alt-001",
            alert_type="anomaly",
            severity="high",
            title="Test alert",
            confidence=0.9,
        )
        logs = db.get_audit_log(limit=1)
        assert len(logs) == 1
        assert logs[0]["component"] == "detection"
        assert logs[0]["action"] == "alert_raised"

    def test_detail_contains_alert_fields(
        self, fl: ForensicLogger, db: AegisDatabase,
    ) -> None:
        fl.log_alert(
            alert_id="alt-002",
            alert_type="rule_match",
            severity="critical",
            title="Critical rule",
            confidence=0.95,
            sensor="network",
            mitre_ids=["T1071"],
        )
        detail = json.loads(db.get_audit_log(limit=1)[0]["detail"])
        assert detail["alert_id"] == "alt-002"
        assert detail["severity"] == "critical"
        assert detail["mitre_ids"] == ["T1071"]
        assert detail["log_type"] == "alert"


# ------------------------------------------------------------------ #
# log_user_action
# ------------------------------------------------------------------ #

class TestLogUserAction:
    """Tests for log_user_action()."""

    def test_records_approve_action(
        self, fl: ForensicLogger, db: AegisDatabase,
    ) -> None:
        fl.log_user_action(
            alert_id="alt-010",
            action="approve",
            user="admin",
            reason="Confirmed threat",
        )
        logs = db.get_audit_log(limit=1)
        detail = json.loads(logs[0]["detail"])
        assert detail["action"] == "approve"
        assert detail["user"] == "admin"
        assert logs[0]["action"] == "user_approve"

    def test_records_dismiss_action(
        self, fl: ForensicLogger, db: AegisDatabase,
    ) -> None:
        fl.log_user_action(alert_id="alt-011", action="dismiss")
        logs = db.get_audit_log(limit=1)
        assert logs[0]["action"] == "user_dismiss"


# ------------------------------------------------------------------ #
# log_action_result
# ------------------------------------------------------------------ #

class TestLogActionResult:
    """Tests for log_action_result()."""

    def test_records_successful_action(
        self, fl: ForensicLogger, db: AegisDatabase,
    ) -> None:
        fl.log_action_result(
            action_id="act-001",
            action_type="block_ip",
            success=True,
            message="Firewall rule created.",
            target="10.0.0.1",
        )
        detail = json.loads(db.get_audit_log(limit=1)[0]["detail"])
        assert detail["success"] is True
        assert detail["action_type"] == "block_ip"
        assert detail["approved_by"] == "user"

    def test_records_failed_action(
        self, fl: ForensicLogger, db: AegisDatabase,
    ) -> None:
        fl.log_action_result(
            action_id="act-002",
            action_type="kill_process",
            success=False,
            message="Process not found.",
        )
        detail = json.loads(db.get_audit_log(limit=1)[0]["detail"])
        assert detail["success"] is False


# ------------------------------------------------------------------ #
# query_logs
# ------------------------------------------------------------------ #

class TestQueryLogs:
    """Tests for query_logs()."""

    def test_returns_log_entries(self, fl: ForensicLogger) -> None:
        fl.log_alert("a1", "t", "high", "T", 0.9)
        entries = fl.query_logs()
        assert len(entries) >= 1
        assert isinstance(entries[0], LogEntry)

    def test_filter_by_log_type(self, fl: ForensicLogger) -> None:
        fl.log_alert("a1", "t", "high", "T", 0.9)
        fl.log_user_action("a1", "approve")
        alerts = fl.query_logs(log_type="alert")
        assert all(e.log_type == "alert" for e in alerts)

    def test_filter_by_since(self, fl: ForensicLogger) -> None:
        fl.log_alert("a1", "t", "high", "T", 0.9)
        future = time.time() + 1000
        entries = fl.query_logs(since=future)
        assert len(entries) == 0

    def test_respects_limit(self, fl: ForensicLogger) -> None:
        for i in range(10):
            fl.log_alert(f"a{i}", "t", "high", "T", 0.9)
        entries = fl.query_logs(limit=3)
        assert len(entries) == 3


# ------------------------------------------------------------------ #
# export_timeline
# ------------------------------------------------------------------ #

class TestExportTimeline:
    """Tests for export_timeline()."""

    def test_returns_list_of_dicts(self, fl: ForensicLogger) -> None:
        fl.log_alert("a1", "t", "high", "T", 0.9)
        fl.log_user_action("a1", "approve")
        timeline = fl.export_timeline()
        assert isinstance(timeline, list)
        assert len(timeline) >= 2
        for item in timeline:
            assert "timestamp" in item
            assert "type" in item
            assert "source" in item

    def test_timeline_sorted_oldest_first(
        self, fl: ForensicLogger,
    ) -> None:
        fl.log_alert("a1", "t", "high", "T", 0.9)
        fl.log_user_action("a1", "dismiss")
        timeline = fl.export_timeline()
        timestamps = [t["timestamp"] for t in timeline]
        assert timestamps == sorted(timestamps)


# ------------------------------------------------------------------ #
# purge_old_entries
# ------------------------------------------------------------------ #

class TestPurgeOldEntries:
    """Tests for retention purge."""

    def test_purge_removes_old_entries(
        self, fl: ForensicLogger, db: AegisDatabase,
    ) -> None:
        # Insert an entry with very old timestamp
        old_ts = time.time() - RETENTION_SECONDS - 1000
        db._conn.execute(
            "INSERT INTO audit_log (timestamp, component, action, detail) "
            "VALUES (?, ?, ?, ?)",
            (old_ts, "test", "old_action", "{}"),
        )
        db._conn.commit()

        # Insert a fresh entry
        fl.log_alert("a1", "t", "high", "T", 0.9)

        deleted = fl.purge_old_entries()
        assert deleted >= 1

        # Fresh entry should still exist
        remaining = db.get_audit_log(limit=100)
        assert len(remaining) >= 1

    def test_purge_returns_zero_when_nothing_old(
        self, fl: ForensicLogger,
    ) -> None:
        fl.log_alert("a1", "t", "high", "T", 0.9)
        assert fl.purge_old_entries() == 0
