"""Integration test: event → pipeline → alert → engine storage.

Tests the full wired flow without ZeroMQ, verifying that an event
injected directly into the engine produces alerts in the database.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from aegis.alerting.manager import AlertManager
from aegis.core.config import AegisConfig
from aegis.core.engine import EventEngine
from aegis.core.models import (
    AegisEvent,
    SensorType,
    Severity,
)
from aegis.detection.pipeline import DetectionPipeline
from aegis.response.forensic_logger import ForensicLogger


class TestFullFlow:
    """End-to-end: event → pipeline → manager → DB → forensic log."""

    def test_event_produces_alert_in_database(self, tmp_data_dir):
        """A rule-engine match produces an alert stored in the DB."""
        # Mock rule engine that always matches
        rule_engine = MagicMock()
        rule_match = MagicMock()
        rule_match.name = "suspicious_cmd"
        rule_match.description = "Suspicious command detected"
        rule_match.severity = "high"
        rule_match.mitre = "T1059"
        rule_engine.evaluate.return_value = [rule_match]

        pipeline = DetectionPipeline(rule_engine=rule_engine)
        manager = AlertManager()

        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "flow.db"))

        engine = EventEngine(
            config=config,
            detection_pipeline=pipeline,
            alert_manager=manager,
        )
        engine.start()

        # Wire forensic logger
        logger = ForensicLogger(engine.db)
        engine._forensic_logger = logger

        # Inject event
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_created",
            data={"pid": 5555, "name": "cmd.exe", "cmdline": "whoami"},
        )
        engine._on_event(event)

        # Verify alert in DB
        alerts = engine.db.query_alerts()
        assert len(alerts) >= 1
        assert alerts[0].alert_type.startswith("rule_")
        assert alerts[0].severity == Severity.HIGH

        # Verify forensic log entry
        audit = engine.db.get_audit_log(limit=50)
        alert_entries = [
            r for r in audit
            if r.get("action") == "alert_raised"
        ]
        assert len(alert_entries) >= 1

        engine.stop()

    def test_dedup_suppresses_duplicate_alerts(self, tmp_data_dir):
        """Same alert type within 60s window is deduplicated."""
        rule_engine = MagicMock()
        rule_match = MagicMock()
        rule_match.name = "dup_rule"
        rule_match.description = "Duplicate test"
        rule_match.severity = "medium"
        rule_match.mitre = ""
        rule_engine.evaluate.return_value = [rule_match]

        pipeline = DetectionPipeline(rule_engine=rule_engine)
        manager = AlertManager()

        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "dedup.db"))

        engine = EventEngine(
            config=config,
            detection_pipeline=pipeline,
            alert_manager=manager,
        )
        engine.start()

        # Send same event type twice
        for _ in range(2):
            event = AegisEvent(
                sensor=SensorType.PROCESS,
                event_type="process_created",
                data={"pid": 1111},
            )
            engine._on_event(event)

        # Only first should survive dedup
        alerts = engine.db.query_alerts()
        assert len(alerts) == 1
        assert engine.alerts_generated == 1

        engine.stop()

    def test_pipeline_without_engines_produces_no_alerts(
        self, tmp_data_dir,
    ):
        """Empty pipeline (no engines) processes events without alerts."""
        pipeline = DetectionPipeline()
        manager = AlertManager()

        config = AegisConfig()
        config.set(
            "database.path", str(tmp_data_dir / "empty.db"),
        )

        engine = EventEngine(
            config=config,
            detection_pipeline=pipeline,
            alert_manager=manager,
        )
        engine.start()

        event = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="connection",
            data={"dst_ip": "8.8.8.8"},
        )
        engine._on_event(event)

        assert engine.events_processed == 1
        assert engine.alerts_generated == 0
        engine.stop()

    def test_multiple_engines_produce_multiple_alerts(
        self, tmp_data_dir,
    ):
        """Rule + graph engines can each produce alerts for same event."""
        rule_engine = MagicMock()
        rule_match = MagicMock()
        rule_match.name = "test_rule"
        rule_match.description = "Test"
        rule_match.severity = "medium"
        rule_match.mitre = ""
        rule_engine.evaluate.return_value = [rule_match]

        # Graph analyzer that produces a chain match
        graph_analyzer = MagicMock()
        graph_analyzer.add_event.return_value = None
        chain_match = MagicMock()
        chain_match.chain_name = "test_chain"
        chain_match.confidence = 0.9
        chain_match.mitre_ids = ["T1059"]
        graph_analyzer.analyze.return_value = [chain_match]

        pipeline = DetectionPipeline(
            rule_engine=rule_engine,
            graph_analyzer=graph_analyzer,
        )

        config = AegisConfig()
        config.set(
            "database.path", str(tmp_data_dir / "multi.db"),
        )

        engine = EventEngine(
            config=config,
            detection_pipeline=pipeline,
        )
        engine.start()

        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_created",
            data={"pid": 999},
        )
        engine._on_event(event)

        alerts = engine.db.query_alerts()
        assert len(alerts) == 2
        types = {a.alert_type for a in alerts}
        assert "rule_test_rule" in types
        assert "chain_test_chain" in types

        engine.stop()
