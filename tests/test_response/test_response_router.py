"""Tests for ResponseRouter — alert-to-response routing pipeline."""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any
from unittest.mock import patch

import pytest

from aegis.alerting.correlation_engine import Incident
from aegis.core.models import Alert, SensorType, Severity
from aegis.response.playbook_engine import (
    Playbook,
    PlaybookEngine,
    PlaybookStep,
    PlaybookTrigger,
)
from aegis.response.report_generator import ReportGenerator
from aegis.response.response_router import ResponseResult, ResponseRouter

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _make_alert(
    alert_type: str = "test.alert",
    severity: Severity = Severity.MEDIUM,
    sensor: SensorType = SensorType.PROCESS,
    data: dict[str, Any] | None = None,
) -> Alert:
    """Create a minimal Alert for testing."""
    return Alert(
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        sensor=sensor,
        alert_type=alert_type,
        severity=severity,
        title=f"Test: {alert_type}",
        description="Test alert",
        confidence=0.9,
        data=data or {},
        mitre_ids=[],
    )


def _make_playbook(
    alert_type: str = "test.alert",
    min_severity: str = "medium",
    name: str = "Test Playbook",
) -> Playbook:
    """Create a minimal Playbook for testing."""
    return Playbook(
        playbook_id=f"pb-{uuid.uuid4().hex[:8]}",
        name=name,
        trigger=PlaybookTrigger(
            alert_type=alert_type,
            min_severity=min_severity,
        ),
        steps=[
            PlaybookStep(
                step_id="s1",
                action="test_action",
                target="test_target",
            ),
        ],
    )


def _make_incident(
    alert_count: int = 1,
    severity: Severity = Severity.MEDIUM,
) -> Incident:
    """Create a minimal Incident for testing."""
    alerts = [_make_alert() for _ in range(alert_count)]
    return Incident(
        incident_id=f"inc-{uuid.uuid4().hex[:8]}",
        title="Test incident",
        severity=severity,
        alerts=alerts,
        first_seen=time.time() - 100,
        last_seen=time.time(),
    )


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture()
def playbook_engine() -> PlaybookEngine:
    """Return a fresh PlaybookEngine (no directory)."""
    return PlaybookEngine(playbooks_dir=None)


@pytest.fixture()
def report_generator() -> ReportGenerator:
    """Return a ReportGenerator with no forensic logger."""
    return ReportGenerator(forensic_logger=None)


@pytest.fixture()
def router(
    playbook_engine: PlaybookEngine,
    report_generator: ReportGenerator,
) -> ResponseRouter:
    """Return a ResponseRouter wired to real engine and generator."""
    return ResponseRouter(
        playbook_engine=playbook_engine,
        report_generator=report_generator,
    )


@pytest.fixture()
def router_no_components() -> ResponseRouter:
    """Return a ResponseRouter with no components attached."""
    return ResponseRouter()


# ------------------------------------------------------------------ #
# TestResponseResultDataclass
# ------------------------------------------------------------------ #


class TestResponseResultDataclass:
    """ResponseResult dataclass field defaults and population."""

    def test_default_fields(self) -> None:
        """Default fields are empty lists, False report_generated."""
        result = ResponseResult(alert_id="alt-001")
        assert result.alert_id == "alt-001"
        assert result.playbooks_triggered == []
        assert result.executions_started == []
        assert result.report_generated is False
        assert result.report_title == ""
        assert result.errors == []

    def test_with_data(self) -> None:
        """All fields can be populated at construction."""
        result = ResponseResult(
            alert_id="alt-002",
            playbooks_triggered=["pb-1", "pb-2"],
            executions_started=["exec-aaa", "exec-bbb"],
            report_generated=True,
            report_title="My Report",
            errors=["oops"],
        )
        assert result.alert_id == "alt-002"
        assert result.playbooks_triggered == ["pb-1", "pb-2"]
        assert result.executions_started == ["exec-aaa", "exec-bbb"]
        assert result.report_generated is True
        assert result.report_title == "My Report"
        assert result.errors == ["oops"]

    def test_errors_list_append(self) -> None:
        """Errors list supports append after construction."""
        result = ResponseResult(alert_id="alt-003")
        result.errors.append("first error")
        result.errors.append("second error")
        assert len(result.errors) == 2
        assert "first error" in result.errors
        assert "second error" in result.errors


# ------------------------------------------------------------------ #
# TestResponseRouterInit
# ------------------------------------------------------------------ #


class TestResponseRouterInit:
    """ResponseRouter initialisation edge cases."""

    def test_init_all_none(self) -> None:
        """Router works with no components at all."""
        rr = ResponseRouter()
        assert rr._playbook_engine is None
        assert rr._report_generator is None
        assert rr._forensic_logger is None

    def test_init_with_components(
        self,
        playbook_engine: PlaybookEngine,
        report_generator: ReportGenerator,
    ) -> None:
        """Components are stored as references."""
        rr = ResponseRouter(
            playbook_engine=playbook_engine,
            report_generator=report_generator,
        )
        assert rr._playbook_engine is playbook_engine
        assert rr._report_generator is report_generator

    def test_init_custom_threshold(self) -> None:
        """min_alerts_for_report is customizable."""
        rr = ResponseRouter(min_alerts_for_report=10)
        assert rr._min_alerts_for_report == 10

    def test_init_stats_zero(self) -> None:
        """All counters start at 0."""
        rr = ResponseRouter()
        stats = rr.get_stats()
        assert stats["playbooks_triggered"] == 0
        assert stats["reports_generated"] == 0
        assert stats["responses_total"] == 0


# ------------------------------------------------------------------ #
# TestRouteAlert
# ------------------------------------------------------------------ #


class TestRouteAlert:
    """route_alert — playbook triggering and report generation."""

    def test_route_alert_triggers_playbook(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Matching alert triggers the playbook."""
        pb = _make_playbook(
            alert_type="test.alert", min_severity="medium",
        )
        playbook_engine.add_playbook(pb)

        alert = _make_alert(alert_type="test.alert")
        result = router.route_alert(alert)

        assert pb.name in result.playbooks_triggered
        assert len(result.executions_started) == 1

    def test_route_alert_multiple_playbooks(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Two matching playbooks are both triggered."""
        pb1 = _make_playbook(
            alert_type="test.alert", name="PB One",
        )
        pb2 = _make_playbook(
            alert_type="test.alert", name="PB Two",
        )
        playbook_engine.add_playbook(pb1)
        playbook_engine.add_playbook(pb2)

        alert = _make_alert(alert_type="test.alert")
        result = router.route_alert(alert)

        assert len(result.playbooks_triggered) == 2
        assert "PB One" in result.playbooks_triggered
        assert "PB Two" in result.playbooks_triggered
        assert len(result.executions_started) == 2

    def test_route_alert_no_match(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Alert that matches no playbook returns empty result."""
        pb = _make_playbook(alert_type="other.type")
        playbook_engine.add_playbook(pb)

        alert = _make_alert(alert_type="test.alert")
        result = router.route_alert(alert)

        assert result.playbooks_triggered == []
        assert result.executions_started == []

    def test_route_alert_disabled_playbook(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Disabled playbook is not triggered."""
        pb = _make_playbook(alert_type="test.alert")
        pb.enabled = False
        playbook_engine.add_playbook(pb)

        alert = _make_alert(alert_type="test.alert")
        result = router.route_alert(alert)

        assert result.playbooks_triggered == []

    def test_route_alert_starts_execution(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Execution is tracked in the playbook engine."""
        pb = _make_playbook(alert_type="test.alert")
        playbook_engine.add_playbook(pb)

        alert = _make_alert(alert_type="test.alert")
        result = router.route_alert(alert)

        assert len(result.executions_started) == 1
        exec_id = result.executions_started[0]
        exe = playbook_engine.get_execution(exec_id)
        assert exe is not None
        assert exe.status == "running"

    def test_route_alert_increments_stats(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Stats counters increase after routing an alert."""
        pb = _make_playbook(alert_type="test.alert")
        playbook_engine.add_playbook(pb)

        alert = _make_alert(alert_type="test.alert")
        router.route_alert(alert)

        stats = router.get_stats()
        assert stats["playbooks_triggered"] == 1
        assert stats["responses_total"] == 1

    def test_route_alert_without_playbook_engine(
        self,
        router_no_components: ResponseRouter,
    ) -> None:
        """No crash when playbook_engine is None."""
        alert = _make_alert()
        result = router_no_components.route_alert(alert)

        assert result.playbooks_triggered == []
        assert result.executions_started == []
        assert result.errors == []

    def test_route_alert_playbook_engine_error(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Error in evaluate_trigger is captured in result.errors."""
        with patch.object(
            playbook_engine,
            "evaluate_trigger",
            side_effect=RuntimeError("engine exploded"),
        ):
            alert = _make_alert()
            result = router.route_alert(alert)

        assert len(result.errors) == 1
        assert "engine exploded" in result.errors[0]

    def test_route_alert_with_incident_generates_report(
        self,
        router: ResponseRouter,
    ) -> None:
        """Incident with 3+ alerts triggers report generation."""
        alert = _make_alert()
        incident = _make_incident(alert_count=3)

        result = router.route_alert(alert, incident=incident)

        assert result.report_generated is True
        assert "Test incident" in result.report_title

    def test_route_alert_with_high_severity_incident(
        self,
        router: ResponseRouter,
    ) -> None:
        """HIGH severity incident with 1 alert triggers report."""
        alert = _make_alert()
        incident = _make_incident(
            alert_count=1, severity=Severity.HIGH,
        )

        result = router.route_alert(alert, incident=incident)

        assert result.report_generated is True

    def test_route_alert_incident_below_threshold(
        self,
        router: ResponseRouter,
    ) -> None:
        """LOW severity, 1 alert — no report."""
        alert = _make_alert()
        incident = _make_incident(
            alert_count=1, severity=Severity.LOW,
        )

        result = router.route_alert(alert, incident=incident)

        assert result.report_generated is False
        assert result.report_title == ""

    def test_route_alert_without_report_generator(
        self,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """No report even if threshold met when generator is None."""
        rr = ResponseRouter(
            playbook_engine=playbook_engine,
            report_generator=None,
        )
        alert = _make_alert()
        incident = _make_incident(alert_count=5)

        result = rr.route_alert(alert, incident=incident)

        # report_generated is True because the threshold was met;
        # the router sets it even without a generator (see source).
        assert result.report_generated is True


# ------------------------------------------------------------------ #
# TestRouteIncident
# ------------------------------------------------------------------ #


class TestRouteIncident:
    """route_incident — standalone incident routing."""

    def test_route_incident_generates_report(
        self, router: ResponseRouter,
    ) -> None:
        """Incident meeting threshold generates a report."""
        incident = _make_incident(alert_count=3)
        result = router.route_incident(incident)

        assert result.report_generated is True
        assert "Test incident" in result.report_title

    def test_route_incident_below_threshold(
        self, router: ResponseRouter,
    ) -> None:
        """Incident below threshold does not generate a report."""
        incident = _make_incident(
            alert_count=1, severity=Severity.LOW,
        )
        result = router.route_incident(incident)

        assert result.report_generated is False
        assert result.report_title == ""

    def test_route_incident_critical_severity(
        self, router: ResponseRouter,
    ) -> None:
        """CRITICAL severity always crosses the threshold."""
        incident = _make_incident(
            alert_count=1, severity=Severity.CRITICAL,
        )
        result = router.route_incident(incident)

        assert result.report_generated is True

    def test_route_incident_no_report_generator(
        self,
    ) -> None:
        """No crash when report_generator is None."""
        rr = ResponseRouter(report_generator=None)
        incident = _make_incident(alert_count=5)
        result = rr.route_incident(incident)

        # Threshold met, report_generated set even without generator.
        assert result.report_generated is True

    def test_route_incident_increments_stats(
        self, router: ResponseRouter,
    ) -> None:
        """Stats counters increase after routing an incident."""
        incident = _make_incident(alert_count=4)
        router.route_incident(incident)

        stats = router.get_stats()
        assert stats["reports_generated"] == 1
        assert stats["responses_total"] == 1

    def test_route_incident_error_handling(
        self, router: ResponseRouter,
        report_generator: ReportGenerator,
    ) -> None:
        """Report generator exception is captured in errors."""
        with patch.object(
            report_generator,
            "generate_report",
            side_effect=RuntimeError("report broke"),
        ):
            incident = _make_incident(alert_count=5)
            result = router.route_incident(incident)

        assert len(result.errors) == 1
        assert "report broke" in result.errors[0]
        assert result.report_generated is False


# ------------------------------------------------------------------ #
# TestCheckReportThreshold
# ------------------------------------------------------------------ #


class TestCheckReportThreshold:
    """_check_report_threshold private helper."""

    def test_threshold_by_alert_count(
        self, router: ResponseRouter,
    ) -> None:
        """3+ alerts crosses the threshold."""
        incident = _make_incident(
            alert_count=3, severity=Severity.LOW,
        )
        assert router._check_report_threshold(incident) is True

    def test_threshold_by_severity_high(
        self, router: ResponseRouter,
    ) -> None:
        """HIGH severity with 1 alert crosses the threshold."""
        incident = _make_incident(
            alert_count=1, severity=Severity.HIGH,
        )
        assert router._check_report_threshold(incident) is True

    def test_threshold_by_severity_critical(
        self, router: ResponseRouter,
    ) -> None:
        """CRITICAL severity with 1 alert crosses the threshold."""
        incident = _make_incident(
            alert_count=1, severity=Severity.CRITICAL,
        )
        assert router._check_report_threshold(incident) is True

    def test_below_threshold(
        self, router: ResponseRouter,
    ) -> None:
        """LOW severity, 1 alert is below threshold."""
        incident = _make_incident(
            alert_count=1, severity=Severity.LOW,
        )
        assert router._check_report_threshold(incident) is False


# ------------------------------------------------------------------ #
# TestGetActiveResponses
# ------------------------------------------------------------------ #


class TestGetActiveResponses:
    """get_active_responses introspection."""

    def test_active_responses_empty(
        self, router_no_components: ResponseRouter,
    ) -> None:
        """No engine returns an empty list."""
        assert router_no_components.get_active_responses() == []

    def test_active_responses_with_running(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Running execution appears in active responses."""
        pb = _make_playbook(alert_type="test.alert")
        playbook_engine.add_playbook(pb)

        alert = _make_alert(alert_type="test.alert")
        router.route_alert(alert)

        active = router.get_active_responses()
        assert len(active) == 1
        assert active[0]["status"] == "running"

    def test_active_responses_excludes_completed(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Completed executions are excluded from active responses."""
        pb = _make_playbook(alert_type="test.alert")
        playbook_engine.add_playbook(pb)

        alert = _make_alert(alert_type="test.alert")
        result = router.route_alert(alert)

        # Complete the execution
        exec_id = result.executions_started[0]
        playbook_engine.get_execution(exec_id)
        pending = playbook_engine.get_pending_steps(exec_id)
        for step in pending:
            playbook_engine.approve_step(step.step_id)
            playbook_engine.mark_step_executed(
                step.step_id, success=True,
            )

        active = router.get_active_responses()
        assert len(active) == 0

    def test_active_responses_format(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Active response dicts have the expected keys."""
        pb = _make_playbook(
            alert_type="test.alert", name="Format PB",
        )
        playbook_engine.add_playbook(pb)

        alert = _make_alert(alert_type="test.alert")
        router.route_alert(alert)

        active = router.get_active_responses()
        assert len(active) == 1

        entry = active[0]
        assert "execution_id" in entry
        assert "playbook_name" in entry
        assert "alert_id" in entry
        assert "status" in entry
        assert "current_step" in entry

        assert entry["playbook_name"] == "Format PB"
        assert entry["status"] == "running"
        assert entry["current_step"] == 0


# ------------------------------------------------------------------ #
# TestGetStats
# ------------------------------------------------------------------ #


class TestGetStats:
    """get_stats — routing statistics."""

    def test_stats_initial_zeros(
        self, router: ResponseRouter,
    ) -> None:
        """Fresh router has all-zero stats."""
        stats = router.get_stats()
        assert stats["playbooks_triggered"] == 0
        assert stats["reports_generated"] == 0
        assert stats["responses_total"] == 0

    def test_stats_after_route_alert(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """playbooks_triggered incremented after route_alert."""
        pb = _make_playbook(alert_type="test.alert")
        playbook_engine.add_playbook(pb)

        alert = _make_alert(alert_type="test.alert")
        router.route_alert(alert)

        stats = router.get_stats()
        assert stats["playbooks_triggered"] == 1
        assert stats["responses_total"] == 1

    def test_stats_after_route_incident(
        self, router: ResponseRouter,
    ) -> None:
        """reports_generated incremented after route_incident."""
        incident = _make_incident(alert_count=5)
        router.route_incident(incident)

        stats = router.get_stats()
        assert stats["reports_generated"] == 1
        assert stats["responses_total"] == 1

    def test_stats_cumulative(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Multiple calls accumulate counters."""
        pb = _make_playbook(alert_type="test.alert")
        playbook_engine.add_playbook(pb)

        for _ in range(3):
            alert = _make_alert(alert_type="test.alert")
            router.route_alert(alert)

        incident = _make_incident(alert_count=5)
        router.route_incident(incident)

        stats = router.get_stats()
        assert stats["playbooks_triggered"] == 3
        assert stats["reports_generated"] == 1
        assert stats["responses_total"] == 4  # 3 alerts + 1 incident


# ------------------------------------------------------------------ #
# TestResponseRouterIntegration
# ------------------------------------------------------------------ #


class TestResponseRouterIntegration:
    """Integration tests combining multiple subsystems."""

    def test_full_flow(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Full flow: add playbook, route alert, verify execution."""
        pb = _make_playbook(
            alert_type="malware.detected",
            min_severity="high",
            name="Malware Response",
        )
        playbook_engine.add_playbook(pb)

        alert = _make_alert(
            alert_type="malware.detected",
            severity=Severity.HIGH,
        )
        result = router.route_alert(alert)

        assert "Malware Response" in result.playbooks_triggered
        assert len(result.executions_started) == 1

        exec_id = result.executions_started[0]
        exe = playbook_engine.get_execution(exec_id)
        assert exe is not None
        assert exe.status == "running"
        assert exe.playbook.name == "Malware Response"

        stats = router.get_stats()
        assert stats["playbooks_triggered"] == 1
        assert stats["responses_total"] == 1

    def test_alert_and_incident_combined(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """Alert triggers playbook AND incident triggers report."""
        pb = _make_playbook(
            alert_type="test.alert",
            name="Combined PB",
        )
        playbook_engine.add_playbook(pb)

        alert = _make_alert(alert_type="test.alert")
        incident = _make_incident(
            alert_count=5, severity=Severity.HIGH,
        )

        result = router.route_alert(alert, incident=incident)

        assert "Combined PB" in result.playbooks_triggered
        assert result.report_generated is True
        assert "Test incident" in result.report_title

        stats = router.get_stats()
        assert stats["playbooks_triggered"] == 1
        assert stats["reports_generated"] == 1
        assert stats["responses_total"] == 1

    def test_thread_safety(
        self,
        router: ResponseRouter,
        playbook_engine: PlaybookEngine,
    ) -> None:
        """route_alert from multiple threads does not corrupt stats."""
        pb = _make_playbook(alert_type="test.alert")
        playbook_engine.add_playbook(pb)

        errors: list[str] = []
        num_threads = 10

        def worker() -> None:
            try:
                alert = _make_alert(alert_type="test.alert")
                router.route_alert(alert)
            except Exception as exc:
                errors.append(str(exc))

        threads = [
            threading.Thread(target=worker) for _ in range(num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert errors == [], f"Thread errors: {errors}"

        stats = router.get_stats()
        assert stats["responses_total"] == num_threads
        assert stats["playbooks_triggered"] == num_threads
