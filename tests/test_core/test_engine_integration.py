"""Tests for EventEngine integration with detection pipeline,
alert manager, and forensic logger.

These tests verify the wiring — that events flow from engine
through detection to alert processing without live ZeroMQ.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from aegis.core.config import AegisConfig
from aegis.core.engine import EventEngine
from aegis.core.models import (
    AegisEvent,
    Alert,
    SensorType,
    Severity,
)


def _make_event(**overrides):
    defaults = dict(
        sensor=SensorType.PROCESS,
        event_type="process_created",
        data={"pid": 1234, "name": "test.exe"},
    )
    defaults.update(overrides)
    return AegisEvent(**defaults)


def _make_alert(event):
    return Alert(
        event_id=event.event_id,
        sensor=event.sensor,
        alert_type="test_rule",
        severity=Severity.HIGH,
        title="Test alert",
        description="Test detection",
        confidence=0.9,
        data={"_engine": "rule_engine"},
    )


class TestEngineWiring:
    """Test that EventEngine correctly wires pipeline → manager → logger."""

    def test_event_feeds_detection_pipeline(self, tmp_data_dir):
        """Pipeline.process_event is called for each event."""
        pipeline = MagicMock()
        pipeline.process_event.return_value = []

        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "wire1.db"))

        engine = EventEngine(
            config=config,
            detection_pipeline=pipeline,
        )
        engine.start()

        event = _make_event()
        engine._on_event(event)

        pipeline.process_event.assert_called_once_with(event)
        assert engine.events_processed == 1
        engine.stop()

    def test_alerts_route_through_manager(self, tmp_data_dir):
        """Alerts from pipeline are fed to the alert manager."""
        event = _make_event()
        alert = _make_alert(event)

        pipeline = MagicMock()
        pipeline.process_event.return_value = [alert]

        manager = MagicMock()
        manager.process_alert.return_value = alert

        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "wire2.db"))

        engine = EventEngine(
            config=config,
            detection_pipeline=pipeline,
            alert_manager=manager,
        )
        engine.start()
        engine._on_event(event)

        manager.process_alert.assert_called_once_with(alert)
        assert engine.alerts_generated == 1
        engine.stop()

    def test_dedup_suppresses_alert(self, tmp_data_dir):
        """When alert manager returns None (dedup), alert is not stored."""
        event = _make_event()
        alert = _make_alert(event)

        pipeline = MagicMock()
        pipeline.process_event.return_value = [alert]

        manager = MagicMock()
        manager.process_alert.return_value = None  # suppressed

        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "wire3.db"))

        engine = EventEngine(
            config=config,
            detection_pipeline=pipeline,
            alert_manager=manager,
        )
        engine.start()
        engine._on_event(event)

        assert engine.alerts_generated == 0
        engine.stop()

    def test_forensic_logger_receives_alert(self, tmp_data_dir):
        """ForensicLogger.log_alert is called for surviving alerts."""
        event = _make_event()
        alert = _make_alert(event)

        pipeline = MagicMock()
        pipeline.process_event.return_value = [alert]

        forensic = MagicMock()

        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "wire4.db"))

        engine = EventEngine(
            config=config,
            detection_pipeline=pipeline,
            forensic_logger=forensic,
        )
        engine.start()
        engine._on_event(event)

        forensic.log_alert.assert_called_once()
        call_kwargs = forensic.log_alert.call_args
        assert call_kwargs[1]["alert_id"] == alert.alert_id
        assert call_kwargs[1]["severity"] == "high"
        engine.stop()

    def test_alert_stored_in_database(self, tmp_data_dir):
        """Alerts that pass dedup are persisted via db.insert_alert."""
        event = _make_event()
        alert = _make_alert(event)

        pipeline = MagicMock()
        pipeline.process_event.return_value = [alert]

        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "wire5.db"))

        engine = EventEngine(
            config=config,
            detection_pipeline=pipeline,
        )
        engine.start()
        engine._on_event(event)

        # Verify alert was stored
        stored = engine.db.query_alerts()
        assert len(stored) == 1
        assert stored[0].alert_id == alert.alert_id
        engine.stop()

    def test_pipeline_error_does_not_crash(self, tmp_data_dir):
        """Pipeline exception is caught; event count still increments."""
        pipeline = MagicMock()
        pipeline.process_event.side_effect = RuntimeError("boom")

        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "wire6.db"))

        engine = EventEngine(
            config=config,
            detection_pipeline=pipeline,
        )
        engine.start()
        engine._on_event(_make_event())

        assert engine.events_processed == 1
        assert engine.alerts_generated == 0
        engine.stop()

    def test_no_pipeline_still_stores_events(self, tmp_data_dir):
        """Without a pipeline, events are stored but no alerts generated."""
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "wire7.db"))

        engine = EventEngine(config=config)
        engine.start()

        event = _make_event()
        engine._on_event(event)

        assert engine.events_processed == 1
        assert engine.alerts_generated == 0
        stored = engine.db.get_event(event.event_id)
        assert stored is not None
        engine.stop()

    def test_multiple_alerts_from_single_event(self, tmp_data_dir):
        """Pipeline can return multiple alerts for one event."""
        event = _make_event()
        alert1 = _make_alert(event)
        alert2 = Alert(
            event_id=event.event_id,
            sensor=event.sensor,
            alert_type="anomaly",
            severity=Severity.MEDIUM,
            title="Anomaly detected",
            description="Statistical anomaly",
            confidence=0.6,
            data={"_engine": "isolation_forest"},
        )

        pipeline = MagicMock()
        pipeline.process_event.return_value = [alert1, alert2]

        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "wire8.db"))

        engine = EventEngine(
            config=config,
            detection_pipeline=pipeline,
        )
        engine.start()
        engine._on_event(event)

        assert engine.alerts_generated == 2
        stored = engine.db.query_alerts()
        assert len(stored) == 2
        engine.stop()

    def test_alerts_generated_property(self, tmp_data_dir):
        """alerts_generated accurately tracks count."""
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "wire9.db"))

        engine = EventEngine(config=config)
        engine.start()
        assert engine.alerts_generated == 0
        engine.stop()
