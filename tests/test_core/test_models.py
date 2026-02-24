"""Tests for Aegis event data models."""

from aegis.core.models import (
    AegisEvent,
    Alert,
    AlertStatus,
    SensorType,
    Severity,
)


class TestAegisEvent:
    def test_create_event_with_required_fields(self):
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_created",
            data={"pid": 1234, "name": "notepad.exe"},
        )
        assert event.sensor == SensorType.PROCESS
        assert event.event_type == "process_created"
        assert event.data["pid"] == 1234
        assert event.severity == Severity.INFO
        assert event.timestamp > 0

    def test_event_generates_unique_id(self):
        e1 = AegisEvent(sensor=SensorType.NETWORK, event_type="connection", data={})
        e2 = AegisEvent(sensor=SensorType.NETWORK, event_type="connection", data={})
        assert e1.event_id != e2.event_id

    def test_event_to_dict_roundtrip(self):
        event = AegisEvent(
            sensor=SensorType.FILE,
            event_type="file_modified",
            severity=Severity.HIGH,
            data={"path": "C:\\test.txt", "hash": "abc123"},
        )
        d = event.to_dict()
        assert d["sensor"] == "file"
        assert d["severity"] == "high"
        assert d["data"]["path"] == "C:\\test.txt"

        restored = AegisEvent.from_dict(d)
        assert restored.sensor == SensorType.FILE
        assert restored.severity == Severity.HIGH
        assert restored.event_id == event.event_id

    def test_event_to_json_bytes(self):
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="test",
            data={"key": "value"},
        )
        raw = event.to_bytes()
        assert isinstance(raw, bytes)
        restored = AegisEvent.from_bytes(raw)
        assert restored.event_id == event.event_id
        assert restored.data == event.data


class TestAlert:
    def test_create_alert(self):
        alert = Alert(
            event_id="evt-123",
            sensor=SensorType.NETWORK,
            alert_type="port_scan",
            severity=Severity.HIGH,
            title="Port scan detected",
            description="Host 192.168.1.100 scanned 500 ports in 10 seconds.",
            confidence=0.85,
            data={"source_ip": "192.168.1.100", "ports_scanned": 500},
        )
        assert alert.severity == Severity.HIGH
        assert alert.confidence == 0.85
        assert alert.status == AlertStatus.NEW
        assert alert.priority_score > 0

    def test_alert_priority_scoring(self):
        critical = Alert(
            event_id="e1",
            sensor=SensorType.FILE,
            alert_type="ransomware",
            severity=Severity.CRITICAL,
            title="Ransomware",
            description="test",
            confidence=0.95,
            data={},
        )
        low = Alert(
            event_id="e2",
            sensor=SensorType.PROCESS,
            alert_type="anomaly",
            severity=Severity.LOW,
            title="Anomaly",
            description="test",
            confidence=0.4,
            data={},
        )
        assert critical.priority_score > low.priority_score

    def test_alert_to_dict_roundtrip(self):
        alert = Alert(
            event_id="evt-456",
            sensor=SensorType.EVENTLOG,
            alert_type="brute_force",
            severity=Severity.MEDIUM,
            title="Brute force attempt",
            description="50 failed logins.",
            confidence=0.7,
            data={"failed_count": 50},
        )
        d = alert.to_dict()
        restored = Alert.from_dict(d)
        assert restored.alert_id == alert.alert_id
        assert restored.confidence == 0.7
        assert restored.status == AlertStatus.NEW


class TestSeverity:
    def test_severity_ordering(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFO.weight

    def test_severity_from_string(self):
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("info") == Severity.INFO
