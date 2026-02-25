"""Tests for event feature extraction."""
from __future__ import annotations

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.ml.feature_extractor import FeatureExtractor


class TestFeatureExtractor:
    def test_extract_returns_dict(self):
        extractor = FeatureExtractor()
        event = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="connection_snapshot",
            data={"total_connections": 5, "unique_remote_ips": 3},
        )
        features = extractor.extract(event)
        assert isinstance(features, dict)
        assert "total_connections" in features

    def test_extract_network_features(self):
        extractor = FeatureExtractor()
        event = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="connection_snapshot",
            data={
                "total_connections": 10,
                "unique_remote_ips": 5,
                "unique_remote_ports": 3,
                "dns_query_count": 20,
            },
        )
        features = extractor.extract(event)
        assert features["total_connections"] == 10
        assert features["unique_remote_ips"] == 5
        assert features["unique_remote_ports"] == 3
        assert features["dns_query_count"] == 20

    def test_extract_process_features(self):
        extractor = FeatureExtractor()
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={
                "cpu_percent": 45.2,
                "memory_mb": 128.5,
                "num_threads": 12,
                "cmdline": "powershell.exe -enc abc123",
            },
        )
        features = extractor.extract(event)
        assert features["cpu_percent"] == 45.2
        assert features["memory_mb"] == 128.5
        assert features["num_threads"] == 12
        assert "cmdline_entropy" in features

    def test_extract_file_features(self):
        extractor = FeatureExtractor()
        event = AegisEvent(
            sensor=SensorType.FILE,
            event_type="file_change",
            data={"files_changed": 7, "entropy_increase_rate": 0.85},
        )
        features = extractor.extract(event)
        assert features["files_changed"] == 7
        assert features["entropy_increase_rate"] == 0.85

    def test_unknown_sensor_returns_generic(self):
        extractor = FeatureExtractor()
        event = AegisEvent(
            sensor=SensorType.EVENTLOG,
            event_type="eventlog.powershell_scriptblock",
            data={"script_text": "Get-Process"},
        )
        features = extractor.extract(event)
        assert "data_field_count" in features

    def test_generic_includes_severity_ordinal(self):
        extractor = FeatureExtractor()
        event = AegisEvent(
            sensor=SensorType.HARDWARE,
            event_type="hardware_status",
            severity=Severity.HIGH,
            data={"temp_celsius": 90},
        )
        features = extractor.extract(event)
        assert "severity_ordinal" in features
        assert features["severity_ordinal"] == Severity.HIGH.weight

    def test_generic_includes_timestamp(self):
        extractor = FeatureExtractor()
        event = AegisEvent(
            sensor=SensorType.CLIPBOARD,
            event_type="clipboard_copy",
            data={"length": 100},
            timestamp=1700000000.0,
        )
        features = extractor.extract(event)
        assert "timestamp" in features
        assert features["timestamp"] == 1700000000.0

    def test_batch_extract(self):
        extractor = FeatureExtractor()
        events = [
            AegisEvent(
                sensor=SensorType.PROCESS,
                event_type="process_new",
                data={"name": "test.exe", "pid": 1},
            )
            for _ in range(5)
        ]
        batch = extractor.batch_extract(events)
        assert len(batch) == 5
        assert all(isinstance(f, dict) for f in batch)

    def test_batch_extract_empty(self):
        extractor = FeatureExtractor()
        batch = extractor.batch_extract([])
        assert batch == []

    def test_network_missing_keys_default_to_zero(self):
        extractor = FeatureExtractor()
        event = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="connection_snapshot",
            data={"total_connections": 3},
        )
        features = extractor.extract(event)
        assert features["total_connections"] == 3
        assert features["unique_remote_ips"] == 0.0
