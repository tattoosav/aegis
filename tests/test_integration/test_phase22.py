"""Phase 22 integration tests — sensor manager and transport."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.core.transport import InProcessTransport, create_transport
from aegis.sensors.health import SensorHealth
from aegis.sensors.manager import SENSOR_REGISTRY, SensorManager


def _make_event(**kwargs):
    defaults = {
        "sensor": SensorType.PROCESS,
        "event_type": "test",
        "data": {},
    }
    defaults.update(kwargs)
    return AegisEvent(**defaults)


def _make_config(overrides=None):
    """Create a mock config that returns defaults."""
    cfg = MagicMock()
    data = {
        "sensors.process.enabled": False,
        "sensors.network.enabled": False,
        "sensors.fim.enabled": False,
        "sensors.eventlog.enabled": False,
        "sensors.registry.enabled": False,
        "sensors.clipboard.enabled": False,
        "sensors.hardware.enabled": False,
        "sensors.health_check_interval": 10.0,
        "sensors.max_consecutive_errors": 10,
        "transport.backend": "inprocess",
    }
    if overrides:
        data.update(overrides)
    cfg.get.side_effect = lambda key, default=None: data.get(key, default)
    return cfg


class TestSensorManagerInit:
    def test_init_empty(self):
        cfg = _make_config()
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        assert sm.sensor_count == 0

    def test_setup_no_enabled_sensors(self):
        cfg = _make_config()
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        assert sm.sensor_count == 0

    def test_sensor_names_empty(self):
        cfg = _make_config()
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        assert sm.sensor_names == []


class TestSensorManagerSetup:
    def test_setup_creates_process_sensor(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        assert "process" in sm.sensor_names
        assert sm.sensor_count == 1

    def test_setup_creates_health_record(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        h = sm.get_health("process")
        assert h is not None
        assert h.sensor_name == "process"
        assert h.sensor_type == SensorType.PROCESS

    def test_setup_failed_import_graceful(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        with patch("importlib.import_module", side_effect=ImportError):
            sm.setup()
        assert sm.sensor_count == 0

    def test_setup_health_initially_not_running(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        h = sm.get_health("process")
        assert h is not None
        assert h.is_running is False

    def test_setup_multiple_sensors(self):
        cfg = _make_config({
            "sensors.process.enabled": True,
            "sensors.network.enabled": True,
        })
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        assert sm.sensor_count == 2
        assert "process" in sm.sensor_names
        assert "network" in sm.sensor_names


class TestSensorManagerLifecycle:
    def test_start_sets_running(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        sm.start()
        h = sm.get_health("process")
        assert h.is_running is True
        assert h.started_at is not None
        sm.stop()

    def test_stop_sets_not_running(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        sm.start()
        sm.stop()
        h = sm.get_health("process")
        assert h.is_running is False

    def test_start_failed_sensor_does_not_block(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        sensor = sm.get_sensor("process")
        sensor.start = MagicMock(side_effect=RuntimeError("boom"))
        sm.start()
        h = sm.get_health("process")
        assert h.errors >= 1
        sm.stop()


class TestSensorManagerEventCallback:
    def test_callback_sends_to_transport(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        h = sm.get_health("process")
        cb = sm._make_event_callback("process", h)
        cb(_make_event())
        assert t.pending == 1

    def test_callback_increments_event_count(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        h = sm.get_health("process")
        cb = sm._make_event_callback("process", h)
        cb(_make_event())
        cb(_make_event())
        assert h.events_emitted == 2

    def test_callback_updates_last_event_time(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        h = sm.get_health("process")
        cb = sm._make_event_callback("process", h)
        cb(_make_event())
        assert h.last_event_time is not None

    def test_callback_transport_error_increments_errors(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = MagicMock()
        t.send.side_effect = RuntimeError("transport fail")
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        h = sm.get_health("process")
        cb = sm._make_event_callback("process", h)
        cb(_make_event())
        assert h.errors == 1
        assert h.consecutive_errors == 1

    def test_callback_resets_consecutive_on_success(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        h = sm.get_health("process")
        h.consecutive_errors = 5
        cb = sm._make_event_callback("process", h)
        cb(_make_event())
        assert h.consecutive_errors == 0


class TestSensorManagerQuery:
    def test_get_health_by_name(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        assert sm.get_health("process") is not None
        assert sm.get_health("nonexistent") is None

    def test_get_all_health(self):
        cfg = _make_config({
            "sensors.process.enabled": True,
            "sensors.network.enabled": True,
        })
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        all_h = sm.get_all_health()
        assert len(all_h) == 2
        assert "process" in all_h
        assert "network" in all_h

    def test_get_sensor_by_name(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        assert sm.get_sensor("process") is not None
        assert sm.get_sensor("nonexistent") is None

    def test_get_status(self):
        cfg = _make_config({"sensors.process.enabled": True})
        t = InProcessTransport()
        sm = SensorManager(config=cfg, transport=t)
        sm.setup()
        status = sm.get_status()
        assert status["sensor_count"] == 1
        assert "sensors" in status
        assert "process" in status["sensors"]


class TestSensorRegistryKeys:
    def test_all_registry_entries_have_valid_sensor_types(self):
        for key, (mod, cls, stype) in SENSOR_REGISTRY.items():
            assert isinstance(stype, SensorType)

    def test_registry_has_seven_sensors(self):
        assert len(SENSOR_REGISTRY) == 7

    def test_registry_keys_match_config(self):
        expected = {
            "process", "network", "fim", "eventlog",
            "registry", "clipboard", "hardware",
        }
        assert set(SENSOR_REGISTRY.keys()) == expected
