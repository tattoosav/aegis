"""Tests for Aegis SQLite database layer."""

import time

from aegis.core.database import AegisDatabase
from aegis.core.models import AegisEvent, Alert, AlertStatus, SensorType, Severity


class TestDatabaseInit:
    def test_creates_database_file(self, tmp_data_dir):
        db_path = tmp_data_dir / "test.db"
        db = AegisDatabase(db_path)
        assert db_path.exists()
        db.close()

    def test_creates_all_tables(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        tables = db.list_tables()
        assert "events" in tables
        assert "alerts" in tables
        assert "connection_reputation" in tables
        assert "device_whitelist" in tables
        assert "process_whitelist" in tables
        assert "user_feedback" in tables
        assert "audit_log" in tables
        db.close()

    def test_uses_wal_mode(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        assert db.journal_mode == "wal"
        db.close()


class TestEventStorage:
    def test_insert_and_retrieve_event(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_created",
            data={"pid": 1234, "name": "notepad.exe"},
        )
        db.insert_event(event)
        retrieved = db.get_event(event.event_id)
        assert retrieved is not None
        assert retrieved.event_id == event.event_id
        assert retrieved.sensor == SensorType.PROCESS
        assert retrieved.data["pid"] == 1234
        db.close()

    def test_query_events_by_sensor(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        for i in range(5):
            db.insert_event(AegisEvent(
                sensor=SensorType.NETWORK, event_type="connection", data={"i": i}
            ))
        for i in range(3):
            db.insert_event(AegisEvent(
                sensor=SensorType.PROCESS, event_type="process_created", data={"i": i}
            ))
        net_events = db.query_events(sensor=SensorType.NETWORK)
        assert len(net_events) == 5
        proc_events = db.query_events(sensor=SensorType.PROCESS)
        assert len(proc_events) == 3
        db.close()

    def test_query_events_by_time_range(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        now = time.time()
        db.insert_event(AegisEvent(
            sensor=SensorType.NETWORK, event_type="old", data={},
            timestamp=now - 3600,
        ))
        db.insert_event(AegisEvent(
            sensor=SensorType.NETWORK, event_type="recent", data={},
            timestamp=now - 60,
        ))
        recent = db.query_events(since=now - 300)
        assert len(recent) == 1
        assert recent[0].event_type == "recent"
        db.close()

    def test_event_count(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        for i in range(10):
            db.insert_event(AegisEvent(
                sensor=SensorType.FILE, event_type="changed", data={"i": i}
            ))
        assert db.event_count() == 10
        assert db.event_count(sensor=SensorType.FILE) == 10
        assert db.event_count(sensor=SensorType.NETWORK) == 0
        db.close()


class TestAlertStorage:
    def _make_alert(self, **kwargs):
        defaults = {
            "event_id": "evt-test",
            "sensor": SensorType.NETWORK,
            "alert_type": "test",
            "severity": Severity.MEDIUM,
            "title": "Test Alert",
            "description": "A test alert.",
            "confidence": 0.75,
            "data": {},
        }
        defaults.update(kwargs)
        return Alert(**defaults)

    def test_insert_and_retrieve_alert(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        alert = self._make_alert()
        db.insert_alert(alert)
        retrieved = db.get_alert(alert.alert_id)
        assert retrieved is not None
        assert retrieved.title == "Test Alert"
        assert retrieved.confidence == 0.75
        db.close()

    def test_query_alerts_by_status(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        db.insert_alert(self._make_alert(title="New1"))
        alert2 = self._make_alert(title="Dismissed")
        alert2.status = AlertStatus.DISMISSED
        db.insert_alert(alert2)

        new_alerts = db.query_alerts(status=AlertStatus.NEW)
        assert len(new_alerts) == 1
        assert new_alerts[0].title == "New1"
        db.close()

    def test_update_alert_status(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        alert = self._make_alert()
        db.insert_alert(alert)
        db.update_alert_status(alert.alert_id, AlertStatus.INVESTIGATING)
        updated = db.get_alert(alert.alert_id)
        assert updated.status == AlertStatus.INVESTIGATING
        db.close()

    def test_alert_count(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        for i in range(5):
            db.insert_alert(self._make_alert(title=f"Alert {i}"))
        assert db.alert_count() == 5
        assert db.alert_count(severity=Severity.MEDIUM) == 5
        assert db.alert_count(severity=Severity.CRITICAL) == 0
        db.close()


class TestAuditLog:
    def test_write_and_read_audit(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        db.audit("sensor.network", "started", "Network sensor initialized")
        db.audit("sensor.process", "started", "Process sensor initialized")
        entries = db.get_audit_log(limit=10)
        assert len(entries) == 2
        assert entries[0]["component"] == "sensor.process"
        db.close()
