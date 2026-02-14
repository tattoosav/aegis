"""Integration test: verify Phase 1 components work together."""

import pytest
import time
import random
from aegis.core.config import AegisConfig
from aegis.core.engine import EventEngine
from aegis.core.bus import EventPublisher
from aegis.core.models import AegisEvent, Alert, SensorType, Severity
from aegis.sensors.base import BaseSensor
from aegis.ui.tray import AegisTrayManager, TrayState


def _rand_ports():
    base = random.randint(55000, 64000)
    return base, base + 1


class StubSensor(BaseSensor):
    sensor_type = SensorType.PROCESS
    sensor_name = "stub"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.events_generated = 0

    def setup(self):
        pass

    def collect(self):
        self.events_generated += 1
        return [AegisEvent(
            sensor=self.sensor_type,
            event_type="stub_event",
            data={"count": self.events_generated},
        )]

    def teardown(self):
        pass


class TestPhase1Integration:
    def test_full_pipeline_sensor_to_database(self, tmp_data_dir):
        """Sensor -> EventBus -> EventEngine -> Database."""
        pp, sp = _rand_ports()
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "integration.db"))

        engine = EventEngine(config=config, pub_port=pp, sub_port=sp)
        engine.start()
        # Allow bus and subscriber to fully initialize
        time.sleep(0.5)

        pub = EventPublisher(port=pp, topic="sensor.process")
        # Allow publisher connection and subscription propagation
        time.sleep(0.5)

        events_sent = []
        for i in range(3):
            event = AegisEvent(
                sensor=SensorType.PROCESS,
                event_type="test_integration",
                data={"iteration": i},
            )
            events_sent.append(event)
            pub.send(event)
            time.sleep(0.1)  # Small gap between sends

        # Allow time for all messages to be routed and processed
        time.sleep(2.0)

        for event in events_sent:
            stored = engine.db.get_event(event.event_id)
            assert stored is not None, (
                f"Event {event.event_id} not found in database. "
                f"Engine processed {engine.events_processed} events."
            )

        assert engine.events_processed >= 3

        pub.close()
        engine.stop()

    def test_alert_storage_and_retrieval(self, tmp_data_dir):
        """Alerts can be created, stored, queried, and status-updated."""
        pp, sp = _rand_ports()
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "alerts.db"))
        engine = EventEngine(config=config, pub_port=pp, sub_port=sp)
        engine.start()
        time.sleep(0.2)

        alert = Alert(
            event_id="evt-integration",
            sensor=SensorType.NETWORK,
            alert_type="port_scan",
            severity=Severity.HIGH,
            title="Integration test alert",
            description="Testing end-to-end alert flow",
            confidence=0.9,
            data={"source_ip": "10.0.0.1"},
            mitre_ids=["T1046"],
            recommended_actions=["Block IP 10.0.0.1"],
        )
        engine.db.insert_alert(alert)

        retrieved = engine.db.get_alert(alert.alert_id)
        assert retrieved.title == "Integration test alert"
        assert retrieved.mitre_ids == ["T1046"]
        assert retrieved.priority_score > 0

        engine.stop()

    def test_tray_reflects_alert_state(self):
        """Tray manager state updates correctly."""
        tray = AegisTrayManager(headless=True)
        assert tray.state == TrayState.LEARNING

        tray.set_state(TrayState.ALL_CLEAR)
        assert tray.state == TrayState.ALL_CLEAR

        tray.set_state(TrayState.CRITICAL)
        assert tray.state == TrayState.CRITICAL

        tray.set_state(TrayState.ALL_CLEAR)
        assert tray.state == TrayState.ALL_CLEAR

    def test_config_persists_across_restarts(self, tmp_data_dir):
        """Config changes survive save/load cycle."""
        config_path = tmp_data_dir / "config.yaml"
        config = AegisConfig()
        config.set("sensors.hardware.enabled", True)
        config.set("alerting.auto_suppress_after_dismissals", 5)
        config.save(config_path)

        loaded = AegisConfig.load(config_path)
        assert loaded.get("sensors.hardware.enabled") is True
        assert loaded.get("alerting.auto_suppress_after_dismissals") == 5
        assert loaded.get("sensors.network.enabled") is True
