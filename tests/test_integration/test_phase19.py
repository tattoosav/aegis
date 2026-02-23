"""Phase 19 integration tests — response pipeline end-to-end.

Validates that alerts flow through the ResponseRouter to trigger
playbooks, generate reports, persist executions, and surface in
the SystemHealth aggregator.
"""

from __future__ import annotations

import time
import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from aegis.alerting.correlation_engine import Incident
from aegis.core.config import AegisConfig
from aegis.core.coordinator import AegisCoordinator
from aegis.core.database import AegisDatabase
from aegis.core.models import Alert, SensorType, Severity
from aegis.response.execution_store import ExecutionStore
from aegis.response.playbook_engine import (
    Playbook,
    PlaybookEngine,
    PlaybookStep,
    PlaybookTrigger,
)
from aegis.response.response_router import ResponseRouter

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _make_alert(
    alert_type: str = "test.alert",
    severity: Severity = Severity.MEDIUM,
    data: dict[str, Any] | None = None,
) -> Alert:
    return Alert(
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        sensor=SensorType.PROCESS,
        alert_type=alert_type,
        severity=severity,
        title=f"Test: {alert_type}",
        description="Test",
        confidence=0.9,
        data=data or {},
        mitre_ids=[],
    )


def _make_playbook(
    alert_type: str = "test.alert",
    min_severity: str = "medium",
) -> Playbook:
    return Playbook(
        playbook_id=f"pb-{uuid.uuid4().hex[:8]}",
        name="Test Playbook",
        trigger=PlaybookTrigger(
            alert_type=alert_type,
            min_severity=min_severity,
        ),
        steps=[
            PlaybookStep(
                step_id="s1", action="test_action", target="test",
            ),
        ],
    )


def _make_incident(
    alert_count: int = 1,
    severity: Severity = Severity.MEDIUM,
    title: str = "Test Incident",
) -> Incident:
    """Build a lightweight Incident with the given alert count."""
    alerts = [_make_alert(severity=severity) for _ in range(alert_count)]
    return Incident(
        incident_id=f"inc-{uuid.uuid4().hex[:8]}",
        title=title,
        severity=severity,
        alerts=alerts,
        first_seen=time.time() - 60,
        last_seen=time.time(),
    )


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture
def db(tmp_path):
    return AegisDatabase(str(tmp_path / "test.db"))


@pytest.fixture
def config(tmp_path):
    cfg = AegisConfig()
    cfg._data["database"]["path"] = str(tmp_path / "test.db")
    cfg._data["canary"]["directories"] = []
    return cfg


@pytest.fixture
def coordinator(config):
    c = AegisCoordinator(config)
    c.setup()
    return c


# ------------------------------------------------------------------ #
# TestAlertToPlaybookFlow
# ------------------------------------------------------------------ #


class TestAlertToPlaybookFlow:
    """Alerts trigger matching playbooks through the ResponseRouter."""

    def test_matching_alert_triggers_playbook(self):
        engine = PlaybookEngine()
        pb = _make_playbook()
        engine.add_playbook(pb)
        router = ResponseRouter(playbook_engine=engine)
        alert = _make_alert()
        result = router.route_alert(alert)
        assert len(result.executions_started) == 1
        assert len(result.playbooks_triggered) == 1

    def test_non_matching_alert_no_trigger(self):
        engine = PlaybookEngine()
        pb = _make_playbook(alert_type="other.type")
        engine.add_playbook(pb)
        router = ResponseRouter(playbook_engine=engine)
        alert = _make_alert(alert_type="test.alert")
        result = router.route_alert(alert)
        assert len(result.executions_started) == 0
        assert len(result.playbooks_triggered) == 0

    def test_multiple_playbooks_triggered(self):
        engine = PlaybookEngine()
        engine.add_playbook(_make_playbook())
        engine.add_playbook(_make_playbook())
        router = ResponseRouter(playbook_engine=engine)
        alert = _make_alert()
        result = router.route_alert(alert)
        assert len(result.executions_started) == 2
        assert len(result.playbooks_triggered) == 2

    def test_severity_threshold(self):
        """Alert below min_severity should not trigger."""
        engine = PlaybookEngine()
        pb = _make_playbook(min_severity="high")
        engine.add_playbook(pb)
        router = ResponseRouter(playbook_engine=engine)
        alert = _make_alert(severity=Severity.LOW)
        result = router.route_alert(alert)
        assert len(result.executions_started) == 0

    def test_execution_has_steps(self):
        engine = PlaybookEngine()
        engine.add_playbook(_make_playbook())
        router = ResponseRouter(playbook_engine=engine)
        alert = _make_alert()
        result = router.route_alert(alert)
        exec_id = result.executions_started[0]
        execution = engine.get_execution(exec_id)
        assert execution is not None
        assert len(execution.steps) >= 1

    def test_stats_updated(self):
        engine = PlaybookEngine()
        engine.add_playbook(_make_playbook())
        router = ResponseRouter(playbook_engine=engine)
        alert = _make_alert()
        router.route_alert(alert)
        stats = router.get_stats()
        assert stats["playbooks_triggered"] == 1
        assert stats["responses_total"] == 1

    def test_active_responses_populated(self):
        engine = PlaybookEngine()
        engine.add_playbook(_make_playbook())
        router = ResponseRouter(playbook_engine=engine)
        alert = _make_alert()
        router.route_alert(alert)
        active = router.get_active_responses()
        assert len(active) == 1
        assert "execution_id" in active[0]
        assert active[0]["status"] == "running"

    def test_playbook_engine_exception_handled(self):
        engine = PlaybookEngine()
        engine.add_playbook(_make_playbook())
        router = ResponseRouter(playbook_engine=engine)
        with patch.object(
            engine,
            "evaluate_trigger",
            side_effect=RuntimeError("boom"),
        ):
            alert = _make_alert()
            result = router.route_alert(alert)
        assert len(result.errors) >= 1
        assert "boom" in result.errors[0]


# ------------------------------------------------------------------ #
# TestAlertToReportFlow
# ------------------------------------------------------------------ #


class TestAlertToReportFlow:
    """Incidents trigger report generation via the ResponseRouter."""

    def test_incident_with_3_alerts_triggers_report(self):
        router = ResponseRouter(
            report_generator=MagicMock(),
            min_alerts_for_report=3,
        )
        incident = _make_incident(alert_count=3)
        alert = _make_alert()
        result = router.route_alert(alert, incident=incident)
        assert result.report_generated is True

    def test_high_severity_incident_triggers_report(self):
        router = ResponseRouter(
            report_generator=MagicMock(),
            min_alerts_for_report=10,
        )
        incident = _make_incident(
            alert_count=1, severity=Severity.HIGH,
        )
        alert = _make_alert()
        result = router.route_alert(alert, incident=incident)
        assert result.report_generated is True

    def test_critical_incident_triggers_report(self):
        router = ResponseRouter(
            report_generator=MagicMock(),
            min_alerts_for_report=10,
        )
        incident = _make_incident(
            alert_count=1, severity=Severity.CRITICAL,
        )
        alert = _make_alert()
        result = router.route_alert(alert, incident=incident)
        assert result.report_generated is True

    def test_low_severity_small_incident_no_report(self):
        router = ResponseRouter(
            report_generator=MagicMock(),
            min_alerts_for_report=3,
        )
        incident = _make_incident(
            alert_count=1, severity=Severity.LOW,
        )
        alert = _make_alert()
        result = router.route_alert(alert, incident=incident)
        assert result.report_generated is False

    def test_report_title_contains_incident(self):
        router = ResponseRouter(
            report_generator=MagicMock(),
            min_alerts_for_report=1,
        )
        incident = _make_incident(
            alert_count=1,
            severity=Severity.HIGH,
            title="Ransomware Attack",
        )
        alert = _make_alert()
        result = router.route_alert(alert, incident=incident)
        assert "Ransomware Attack" in result.report_title

    def test_report_generator_exception_handled(self):
        mock_gen = MagicMock()
        mock_gen.generate_report.side_effect = RuntimeError("fail")
        router = ResponseRouter(
            report_generator=mock_gen,
            min_alerts_for_report=1,
        )
        incident = _make_incident(
            alert_count=1, severity=Severity.HIGH,
        )
        alert = _make_alert()
        result = router.route_alert(alert, incident=incident)
        assert len(result.errors) >= 1
        assert result.report_generated is False


# ------------------------------------------------------------------ #
# TestExecutionPersistence
# ------------------------------------------------------------------ #


class TestExecutionPersistence:
    """ExecutionStore persists playbook executions to the database."""

    def test_execution_persisted_to_db(self, db):
        engine = PlaybookEngine()
        engine.add_playbook(_make_playbook())
        store = ExecutionStore(engine, db=db)
        alert = _make_alert()
        matches = engine.evaluate_trigger(alert)
        execution = engine.start_execution(matches[0], alert)
        store.persist_execution(execution)
        row = db.get_execution(execution.execution_id)
        assert row is not None
        assert row["execution_id"] == execution.execution_id

    def test_steps_persisted(self, db):
        engine = PlaybookEngine()
        engine.add_playbook(_make_playbook())
        store = ExecutionStore(engine, db=db)
        alert = _make_alert()
        execution = engine.start_execution(
            engine.evaluate_trigger(alert)[0], alert,
        )
        store.persist_execution(execution)
        steps = db.get_execution_steps(execution.execution_id)
        assert len(steps) == len(execution.steps)

    def test_sync_from_engine(self, db):
        engine = PlaybookEngine()
        engine.add_playbook(_make_playbook())
        store = ExecutionStore(engine, db=db)
        # Start 3 executions
        for _ in range(3):
            alert = _make_alert()
            engine.start_execution(
                engine.evaluate_trigger(alert)[0], alert,
            )
        synced = store.sync_from_engine()
        assert synced == 3
        assert db.execution_count() == 3

    def test_step_status_update(self, db):
        engine = PlaybookEngine()
        engine.add_playbook(_make_playbook())
        store = ExecutionStore(engine, db=db)
        alert = _make_alert()
        execution = engine.start_execution(
            engine.evaluate_trigger(alert)[0], alert,
        )
        store.persist_execution(execution)
        store.update_step_status(
            execution.execution_id, 0, "executed", "done",
        )
        steps = db.get_execution_steps(execution.execution_id)
        assert steps[0]["status"] == "executed"

    def test_completed_execution(self, db):
        engine = PlaybookEngine()
        engine.add_playbook(_make_playbook())
        store = ExecutionStore(engine, db=db)
        alert = _make_alert()
        execution = engine.start_execution(
            engine.evaluate_trigger(alert)[0], alert,
        )
        store.persist_execution(execution)
        # Mark all steps done and complete the execution
        for step in execution.steps:
            engine.mark_step_executed(step.step_id, True, "ok")
        # Persist again — now status should be "completed"
        store.persist_execution(execution)
        row = db.get_execution(execution.execution_id)
        assert row is not None
        assert row["status"] == "completed"
        assert row["completed_at"] is not None

    def test_stats_match_db(self, db):
        engine = PlaybookEngine()
        engine.add_playbook(_make_playbook())
        store = ExecutionStore(engine, db=db)
        alert = _make_alert()
        engine.start_execution(
            engine.evaluate_trigger(alert)[0], alert,
        )
        store.sync_from_engine()
        stats = store.get_stats()
        assert stats["db_executions"] == db.execution_count()
        assert stats["total_executions"] == 1


# ------------------------------------------------------------------ #
# TestSystemHealthIntegration
# ------------------------------------------------------------------ #


class TestSystemHealthIntegration:
    """SystemHealth pulls stats from a fully wired coordinator."""

    def test_coordinator_creates_system_health(self, coordinator):
        assert coordinator.system_health is not None

    def test_health_collect_all_sections(self, coordinator):
        health = coordinator.system_health
        result = health.collect()
        expected = [
            "engine", "enricher", "correlation", "scheduler",
            "canary", "whitelist", "database", "playbooks",
            "response_router",
        ]
        for key in expected:
            assert key in result

    def test_health_database_counts(self, coordinator):
        health = coordinator.system_health
        section = health.collect()["database"]
        assert isinstance(section["event_count"], int)
        assert isinstance(section["alert_count"], int)
        assert isinstance(section["incident_count"], int)
        assert section["event_count"] >= 0
        assert section["alert_count"] >= 0
        assert section["incident_count"] >= 0

    def test_health_scheduler_stats(self, coordinator):
        health = coordinator.system_health
        section = health.collect()["scheduler"]
        # Coordinator registers tasks in setup
        assert section["task_count"] >= 0
        assert isinstance(section["task_count"], int)

    def test_health_response_router_stats(self, coordinator):
        health = coordinator.system_health
        section = health.collect()["response_router"]
        assert isinstance(section, dict)
        assert "playbooks_triggered" in section

    def test_health_playbooks_loaded(self, coordinator):
        health = coordinator.system_health
        section = health.collect()["playbooks"]
        assert "loaded" in section
        assert isinstance(section["loaded"], int)

    def test_health_enricher_stats(self, coordinator):
        health = coordinator.system_health
        section = health.collect()["enricher"]
        assert section["events_enriched"] == 0
        assert section["ioc_matches_found"] == 0


# ------------------------------------------------------------------ #
# TestCoordinatorPhase19Wiring
# ------------------------------------------------------------------ #


class TestCoordinatorPhase19Wiring:
    """Coordinator creates and wires Phase 19 components."""

    def test_coordinator_creates_response_router(self, coordinator):
        assert coordinator.response_router is not None

    def test_coordinator_creates_execution_store(self, coordinator):
        assert coordinator.execution_store is not None

    def test_coordinator_creates_system_health(self, coordinator):
        assert coordinator.system_health is not None

    def test_response_router_wired_to_engine(self, coordinator):
        engine = coordinator.engine
        assert engine is not None
        assert engine._response_router is not None
        assert engine._response_router is coordinator.response_router

    def test_execution_store_sync_task_registered(
        self, coordinator,
    ):
        scheduler = coordinator.scheduler
        assert scheduler is not None
        task_names = [t.name for t in scheduler.list_tasks()]
        assert "execution_store_sync" in task_names

    def test_coordinator_new_properties(self, coordinator):
        """All Phase 19 properties must be accessible."""
        assert coordinator.response_router is not None
        assert coordinator.execution_store is not None
        assert coordinator.system_health is not None
        assert coordinator.playbook_engine is not None
        assert coordinator.report_generator is not None

    def test_coordinator_db_has_execution_tables(
        self, coordinator,
    ):
        db = coordinator.db
        assert db is not None
        tables = db.list_tables()
        assert "playbook_executions" in tables
        assert "playbook_execution_steps" in tables


# ------------------------------------------------------------------ #
# TestEndToEndResponsePipeline
# ------------------------------------------------------------------ #


class TestEndToEndResponsePipeline:
    """Full flow: alert -> playbook -> execution -> persist -> health."""

    def test_full_response_pipeline(self, coordinator):
        """Route an alert, verify execution is persisted and
        visible in health stats.
        """
        # Add a playbook matching our test alert type
        pb_engine = coordinator.playbook_engine
        pb_engine.add_playbook(_make_playbook())

        router = coordinator.response_router
        alert = _make_alert()
        result = router.route_alert(alert)
        assert len(result.executions_started) == 1

        # Persist via execution store
        exec_store = coordinator.execution_store
        exec_store.sync_from_engine()

        db = coordinator.db
        assert db.execution_count() >= 1

        # Health should reflect the activity
        health = coordinator.system_health
        h = health.collect()
        assert h["response_router"]["responses_total"] >= 1

    def test_response_and_incident_combined(self, coordinator):
        """Alert creates incident and triggers playbook."""
        pb_engine = coordinator.playbook_engine
        pb_engine.add_playbook(_make_playbook())

        router = coordinator.response_router
        alert = _make_alert()

        # Create incident via correlation
        incident_store = coordinator.incident_store
        incident = incident_store.process_alert(alert)
        assert incident is not None

        result = router.route_alert(alert, incident=incident)
        assert len(result.executions_started) >= 1

    def test_response_stats_in_health(self, coordinator):
        """health.collect() includes response_router stats."""
        pb_engine = coordinator.playbook_engine
        pb_engine.add_playbook(_make_playbook())

        router = coordinator.response_router
        router.route_alert(_make_alert())

        health = coordinator.system_health
        section = health.collect()["response_router"]
        assert section["responses_total"] >= 1
        assert section["playbooks_triggered"] >= 1

    def test_multiple_alerts_cumulative(self, coordinator):
        """Multiple alerts accumulate stats."""
        pb_engine = coordinator.playbook_engine
        pb_engine.add_playbook(_make_playbook())

        router = coordinator.response_router
        for _ in range(5):
            router.route_alert(_make_alert())

        stats = router.get_stats()
        assert stats["responses_total"] == 5
        assert stats["playbooks_triggered"] == 5

    def test_execution_store_db_query(self, coordinator):
        """Query executions by status from DB after sync."""
        pb_engine = coordinator.playbook_engine
        pb_engine.add_playbook(_make_playbook())

        router = coordinator.response_router
        router.route_alert(_make_alert())

        exec_store = coordinator.execution_store
        exec_store.sync_from_engine()

        db = coordinator.db
        running = db.query_executions(status="running")
        assert len(running) >= 1
        assert running[0]["status"] == "running"

    def test_health_reflects_response_activity(
        self, coordinator,
    ):
        """After routing, health stats are updated."""
        pb_engine = coordinator.playbook_engine
        pb_engine.add_playbook(_make_playbook())

        router = coordinator.response_router
        router.route_alert(_make_alert())
        router.route_alert(_make_alert())

        health = coordinator.system_health
        section = health.collect()["response_router"]
        assert section["responses_total"] == 2
        assert section["playbooks_triggered"] == 2
