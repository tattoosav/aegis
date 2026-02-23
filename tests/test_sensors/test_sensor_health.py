"""Tests for the SensorHealth dataclass."""

from __future__ import annotations

import time

import pytest

from aegis.core.models import SensorType
from aegis.sensors.health import SensorHealth


class TestSensorHealthDefaults:
    def test_default_is_not_running(self):
        h = SensorHealth(sensor_name="test", sensor_type=SensorType.PROCESS)
        assert h.is_running is False

    def test_default_enabled(self):
        h = SensorHealth(sensor_name="test", sensor_type=SensorType.PROCESS)
        assert h.enabled is True

    def test_default_events_zero(self):
        h = SensorHealth(sensor_name="test", sensor_type=SensorType.PROCESS)
        assert h.events_emitted == 0

    def test_default_errors_zero(self):
        h = SensorHealth(sensor_name="test", sensor_type=SensorType.PROCESS)
        assert h.errors == 0
        assert h.consecutive_errors == 0

    def test_default_last_event_time_none(self):
        h = SensorHealth(sensor_name="test", sensor_type=SensorType.PROCESS)
        assert h.last_event_time is None

    def test_default_started_at_none(self):
        h = SensorHealth(sensor_name="test", sensor_type=SensorType.PROCESS)
        assert h.started_at is None

    def test_default_restarts_zero(self):
        h = SensorHealth(sensor_name="test", sensor_type=SensorType.PROCESS)
        assert h.restarts == 0


class TestSensorHealthEventsPerSecond:
    def test_zero_when_no_events(self):
        h = SensorHealth(
            sensor_name="test", sensor_type=SensorType.PROCESS,
            started_at=time.time() - 10,
        )
        assert h.events_per_second == 0.0

    def test_zero_when_not_started(self):
        h = SensorHealth(
            sensor_name="test", sensor_type=SensorType.PROCESS,
            events_emitted=100,
        )
        assert h.events_per_second == 0.0

    def test_calculation(self):
        h = SensorHealth(
            sensor_name="test", sensor_type=SensorType.PROCESS,
            events_emitted=100,
            started_at=time.time() - 10,
        )
        eps = h.events_per_second
        assert 9.0 <= eps <= 11.0  # ~10 events/sec


class TestSensorHealthToDict:
    def test_contains_all_fields(self):
        h = SensorHealth(sensor_name="net", sensor_type=SensorType.NETWORK)
        d = h.to_dict()
        assert d["sensor_name"] == "net"
        assert d["sensor_type"] == "network"
        assert "is_running" in d
        assert "enabled" in d
        assert "events_emitted" in d
        assert "errors" in d
        assert "consecutive_errors" in d
        assert "last_event_time" in d
        assert "last_error_time" in d
        assert "last_error_message" in d
        assert "last_collect_duration" in d
        assert "started_at" in d
        assert "restarts" in d
        assert "events_per_second" in d

    def test_sensor_type_is_string(self):
        h = SensorHealth(sensor_name="p", sensor_type=SensorType.PROCESS)
        d = h.to_dict()
        assert isinstance(d["sensor_type"], str)
        assert d["sensor_type"] == "process"

    def test_error_tracking_fields(self):
        h = SensorHealth(
            sensor_name="x", sensor_type=SensorType.FILE,
            errors=5, consecutive_errors=2,
            last_error_message="timeout",
        )
        d = h.to_dict()
        assert d["errors"] == 5
        assert d["consecutive_errors"] == 2
        assert d["last_error_message"] == "timeout"
