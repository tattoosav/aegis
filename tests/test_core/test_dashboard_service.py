"""Tests for aegis.core.dashboard_service — DashboardDataService.

Validates that DashboardDataService correctly aggregates data from
all Aegis subsystems (database, health, scheduler, correlation,
canary, response router, playbook engine, etc.) for dashboard
display.  Each method must degrade gracefully when subsystems
are unavailable or raise exceptions.
"""

from __future__ import annotations

import inspect
import time
import uuid
from unittest.mock import MagicMock

import pytest

from aegis.core.database import AegisDatabase
from aegis.core.models import (
    AegisEvent,
    Alert,
    AlertStatus,
    SensorType,
    Severity,
)

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _make_coordinator(**overrides):
    """Create a mock coordinator with all properties defaulting to None."""
    coord = MagicMock()
    coord.engine = overrides.get("engine", None)
    coord.db = overrides.get("db", None)
    coord.system_health = overrides.get("system_health", None)
    coord.incident_store = overrides.get("incident_store", None)
    coord.response_router = overrides.get("response_router", None)
    coord.execution_store = overrides.get("execution_store", None)
    coord.playbook_engine = overrides.get("playbook_engine", None)
    coord.canary_system = overrides.get("canary_system", None)
    coord.scheduler = overrides.get("scheduler", None)
    coord.whitelist_manager = overrides.get("whitelist_manager", None)
    coord.enricher = overrides.get("enricher", None)
    coord.correlation_engine = overrides.get("correlation_engine", None)
    return coord


def _make_alert(
    severity="medium",
    status="new",
    title="Test Alert",
    **kwargs,
):
    """Factory for creating Alert objects for testing."""
    return Alert(
        alert_id=kwargs.get("alert_id", str(uuid.uuid4())),
        event_id=kwargs.get("event_id", str(uuid.uuid4())),
        timestamp=kwargs.get("timestamp", time.time()),
        sensor=SensorType.PROCESS,
        alert_type="test",
        severity=Severity.from_string(severity),
        title=title,
        description="Test description",
        confidence=0.8,
        status=AlertStatus(status),
        data={},
        mitre_ids=["T1059"],
        recommended_actions=["Investigate"],
    )


def _make_event(**kwargs):
    """Factory for creating AegisEvent objects for testing."""
    return AegisEvent(
        sensor=kwargs.get("sensor", SensorType.PROCESS),
        event_type=kwargs.get("event_type", "test_event"),
        data=kwargs.get("data", {"pid": 1234}),
        severity=kwargs.get("severity", Severity.INFO),
        timestamp=kwargs.get("timestamp", time.time()),
        event_id=kwargs.get(
            "event_id", f"evt-{uuid.uuid4().hex[:12]}",
        ),
    )


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture
def db(tmp_path):
    """Real AegisDatabase pointed at tmp_path."""
    return AegisDatabase(tmp_path / "test.db")


@pytest.fixture
def svc():
    """DashboardDataService with all-None mock coordinator."""
    from aegis.core.dashboard_service import DashboardDataService

    coord = _make_coordinator()
    return DashboardDataService(coord)


@pytest.fixture
def svc_with_db(db):
    """DashboardDataService backed by a real database."""
    from aegis.core.dashboard_service import DashboardDataService

    coord = _make_coordinator(db=db)
    return DashboardDataService(coord), db


# ================================================================== #
# TestDashboardServiceInit
# ================================================================== #


class TestDashboardServiceInit:
    """Construction and basic module-level checks."""

    def test_init_stores_coordinator(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator()
        svc = DashboardDataService(coord)
        assert svc._coordinator is coord

    def test_init_with_none_coordinator(self):
        """Passing None should not crash on construction."""
        from aegis.core.dashboard_service import DashboardDataService

        svc = DashboardDataService(None)
        assert svc._coordinator is None

    def test_init_no_pyside6_import(self):
        """The dashboard_service module must not import PySide6."""
        import aegis.core.dashboard_service as mod  # noqa: I001

        source = inspect.getsource(mod)
        assert "PySide6" not in source
        assert "from PySide6" not in source
        assert "import PySide6" not in source

    def test_type_hints_present(self):
        """All public methods have return annotations."""
        from aegis.core.dashboard_service import DashboardDataService

        for name in (
            "get_home_data",
            "get_alerts_data",
            "get_incidents_data",
            "get_executions_data",
            "get_system_status",
            "get_canary_status",
        ):
            method = getattr(DashboardDataService, name)
            sig = inspect.signature(method)
            assert sig.return_annotation is not inspect.Parameter.empty, (
                f"{name} missing return annotation"
            )

    def test_module_docstring_present(self):
        """Module has a docstring."""
        import aegis.core.dashboard_service as mod

        assert mod.__doc__ is not None
        assert len(mod.__doc__.strip()) > 0


# ================================================================== #
# TestGetHomeData
# ================================================================== #


class TestGetHomeData:
    """Tests for get_home_data()."""

    def test_returns_dict(self, svc):
        result = svc.get_home_data()
        assert isinstance(result, dict)

    def test_has_all_keys(self, svc):
        result = svc.get_home_data()
        for key in (
            "health_summary",
            "sensor_status",
            "recent_alerts",
            "stats",
            "canary_overview",
            "scheduler_overview",
        ):
            assert key in result, f"Missing key: {key}"

    def test_stats_events_24h_int(self, svc):
        result = svc.get_home_data()
        assert isinstance(result["stats"]["events_24h"], int)

    def test_stats_alerts_24h_int(self, svc):
        result = svc.get_home_data()
        assert isinstance(result["stats"]["alerts_24h"], int)

    def test_stats_incidents_open_int(self, svc):
        result = svc.get_home_data()
        assert isinstance(result["stats"]["incidents_open"], int)

    def test_stats_responses_total_int(self, svc):
        result = svc.get_home_data()
        assert isinstance(result["stats"]["responses_total"], int)

    def test_recent_alerts_list(self, svc):
        result = svc.get_home_data()
        assert isinstance(result["recent_alerts"], list)

    def test_recent_alerts_max_10(self, svc_with_db):
        """Insert 15 alerts, only 10 most recent returned."""
        svc, db = svc_with_db
        for i in range(15):
            alert = _make_alert(
                timestamp=time.time() - (15 - i),
                title=f"Alert {i}",
            )
            db.insert_alert(alert)
        result = svc.get_home_data()
        assert len(result["recent_alerts"]) <= 10

    def test_recent_alerts_dict_shape(self, svc_with_db):
        """Each recent alert dict has the expected keys."""
        svc, db = svc_with_db
        alert = _make_alert()
        db.insert_alert(alert)
        result = svc.get_home_data()
        assert len(result["recent_alerts"]) >= 1
        a = result["recent_alerts"][0]
        for key in (
            "alert_id",
            "timestamp",
            "severity",
            "title",
            "sensor",
            "confidence",
            "status",
        ):
            assert key in a, f"Missing key in recent alert: {key}"

    def test_sensor_status_list(self, svc):
        result = svc.get_home_data()
        assert isinstance(result["sensor_status"], list)

    def test_health_summary_from_system_health(self):
        """When system_health is available, collect() is used."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_health = MagicMock()
        mock_health.collect.return_value = {
            "engine": {"events_processed": 99},
        }
        coord = _make_coordinator(system_health=mock_health)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert result["health_summary"] == {
            "engine": {"events_processed": 99},
        }
        mock_health.collect.assert_called_once()

    def test_events_24h_from_db(self, svc_with_db):
        """Insert events within 24h window, verify count."""
        svc, db = svc_with_db
        now = time.time()
        # 3 events within 24h
        for _ in range(3):
            db.insert_event(_make_event(timestamp=now - 100))
        # 1 event outside 24h
        db.insert_event(_make_event(timestamp=now - 90000))
        result = svc.get_home_data()
        assert result["stats"]["events_24h"] >= 3

    def test_alerts_24h_from_db(self, svc_with_db):
        """Insert alerts within 24h window, verify count."""
        svc, db = svc_with_db
        now = time.time()
        for _ in range(4):
            db.insert_alert(_make_alert(timestamp=now - 50))
        # 1 alert outside 24h
        db.insert_alert(_make_alert(timestamp=now - 90000))
        result = svc.get_home_data()
        assert result["stats"]["alerts_24h"] >= 4

    def test_incidents_open_from_db(self, svc_with_db):
        """Insert incidents, verify open count."""
        svc, db = svc_with_db
        now = time.time()
        db.insert_incident(
            "inc-1", "Incident 1", "high", "open",
            ["T1059"], [], now, now,
        )
        db.insert_incident(
            "inc-2", "Incident 2", "medium", "closed",
            [], [], now, now,
        )
        db.insert_incident(
            "inc-3", "Incident 3", "low", "open",
            [], [], now, now,
        )
        result = svc.get_home_data()
        assert result["stats"]["incidents_open"] >= 2

    def test_empty_db_returns_zero_stats(self, svc_with_db):
        """Empty database should yield zero counts."""
        svc, _db = svc_with_db
        result = svc.get_home_data()
        assert result["stats"]["events_24h"] == 0
        assert result["stats"]["alerts_24h"] == 0
        assert result["stats"]["incidents_open"] == 0

    def test_canary_overview_dict(self, svc):
        result = svc.get_home_data()
        assert isinstance(result["canary_overview"], dict)

    def test_scheduler_overview_dict(self, svc):
        result = svc.get_home_data()
        assert isinstance(result["scheduler_overview"], dict)

    def test_responses_total_from_router(self):
        """responses_total comes from response_router.get_stats()."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_rr = MagicMock()
        mock_rr.get_stats.return_value = {"responses_total": 15}
        coord = _make_coordinator(response_router=mock_rr)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert result["stats"]["responses_total"] >= 15


# ================================================================== #
# TestGetHomeDataEdgeCases
# ================================================================== #


class TestGetHomeDataEdgeCases:
    """Edge cases where subsystems are None or raise."""

    def test_no_database(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(db=None)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert isinstance(result, dict)
        assert result["stats"]["events_24h"] == 0

    def test_no_engine(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(engine=None)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert isinstance(result, dict)

    def test_no_system_health(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(system_health=None)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert isinstance(result["health_summary"], dict)

    def test_no_correlation_engine(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(correlation_engine=None)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert isinstance(result, dict)

    def test_no_response_router(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(response_router=None)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert isinstance(result, dict)
        assert result["stats"]["responses_total"] == 0

    def test_no_canary_system(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(canary_system=None)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert isinstance(result["canary_overview"], dict)

    def test_no_scheduler(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(scheduler=None)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert isinstance(result["scheduler_overview"], dict)

    def test_database_error_handled(self, tmp_path):
        """If db raises, get_home_data returns safe defaults."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_db = MagicMock()
        mock_db.query_alerts.side_effect = RuntimeError("DB error")
        mock_db.query_events.side_effect = RuntimeError("DB error")
        mock_db.event_count.side_effect = RuntimeError("DB error")
        mock_db.alert_count.side_effect = RuntimeError("DB error")
        mock_db.incident_count.side_effect = RuntimeError("DB error")
        coord = _make_coordinator(db=mock_db)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert isinstance(result, dict)
        assert result["stats"]["events_24h"] == 0


# ================================================================== #
# TestGetAlertsData
# ================================================================== #


class TestGetAlertsData:
    """Tests for get_alerts_data()."""

    def test_returns_dict(self, svc):
        result = svc.get_alerts_data()
        assert isinstance(result, dict)

    def test_has_all_keys(self, svc):
        result = svc.get_alerts_data()
        for key in (
            "alerts",
            "severity_counts",
            "status_counts",
            "total_count",
        ):
            assert key in result, f"Missing key: {key}"

    def test_alerts_are_list_of_dicts(self, svc_with_db):
        svc, db = svc_with_db
        db.insert_alert(_make_alert())
        result = svc.get_alerts_data()
        assert isinstance(result["alerts"], list)
        if result["alerts"]:
            assert isinstance(result["alerts"][0], dict)

    def test_severity_counts_correct(self, svc_with_db):
        """Insert alerts with mixed severities, verify counts."""
        svc, db = svc_with_db
        db.insert_alert(_make_alert(severity="critical"))
        db.insert_alert(_make_alert(severity="critical"))
        db.insert_alert(_make_alert(severity="high"))
        db.insert_alert(_make_alert(severity="medium"))
        db.insert_alert(_make_alert(severity="low"))
        db.insert_alert(_make_alert(severity="info"))
        result = svc.get_alerts_data()
        sc = result["severity_counts"]
        assert sc.get("critical", 0) >= 2
        assert sc.get("high", 0) >= 1
        assert sc.get("medium", 0) >= 1
        assert sc.get("low", 0) >= 1
        assert sc.get("info", 0) >= 1

    def test_status_counts_correct(self, svc_with_db):
        """Insert alerts with mixed statuses, verify counts."""
        svc, db = svc_with_db
        db.insert_alert(_make_alert(status="new"))
        db.insert_alert(_make_alert(status="new"))
        db.insert_alert(_make_alert(status="investigating"))
        db.insert_alert(_make_alert(status="resolved"))
        result = svc.get_alerts_data()
        sc = result["status_counts"]
        assert sc.get("new", 0) >= 2
        assert sc.get("investigating", 0) >= 1
        assert sc.get("resolved", 0) >= 1

    def test_total_count_matches(self, svc_with_db):
        svc, db = svc_with_db
        for _ in range(5):
            db.insert_alert(_make_alert())
        result = svc.get_alerts_data()
        assert result["total_count"] >= 5

    def test_empty_db(self, svc_with_db):
        svc, _db = svc_with_db
        result = svc.get_alerts_data()
        assert result["alerts"] == []
        assert result["total_count"] == 0

    def test_no_database(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(db=None)
        svc = DashboardDataService(coord)
        result = svc.get_alerts_data()
        assert isinstance(result, dict)
        assert result["alerts"] == []
        assert result["total_count"] == 0

    def test_limit_parameter(self, svc_with_db):
        """Passing limit constrains the number of alerts returned."""
        svc, db = svc_with_db
        for _ in range(10):
            db.insert_alert(_make_alert())
        result = svc.get_alerts_data(limit=3)
        assert len(result["alerts"]) <= 3

    def test_filter_by_severity(self, svc_with_db):
        """Filter by severity='critical' returns only critical alerts."""
        svc, db = svc_with_db
        db.insert_alert(_make_alert(severity="critical"))
        db.insert_alert(_make_alert(severity="low"))
        db.insert_alert(_make_alert(severity="critical"))
        result = svc.get_alerts_data(severity="critical")
        for a in result["alerts"]:
            assert a["severity"] == "critical"

    def test_filter_by_status(self, svc_with_db):
        """Filter by status='new' returns only new alerts."""
        svc, db = svc_with_db
        db.insert_alert(_make_alert(status="new"))
        db.insert_alert(_make_alert(status="resolved"))
        result = svc.get_alerts_data(status="new")
        for a in result["alerts"]:
            assert a["status"] == "new"

    def test_filter_both(self, svc_with_db):
        """Filter by both severity and status simultaneously."""
        svc, db = svc_with_db
        db.insert_alert(
            _make_alert(severity="high", status="new"),
        )
        db.insert_alert(
            _make_alert(severity="high", status="resolved"),
        )
        db.insert_alert(
            _make_alert(severity="low", status="new"),
        )
        result = svc.get_alerts_data(
            severity="high", status="new",
        )
        for a in result["alerts"]:
            assert a["severity"] == "high"
            assert a["status"] == "new"

    def test_severity_counts_all_levels_present(self, svc_with_db):
        """severity_counts has keys for all standard levels."""
        svc, _db = svc_with_db
        result = svc.get_alerts_data()
        sc = result["severity_counts"]
        for level in ("critical", "high", "medium", "low", "info"):
            assert level in sc, f"Missing severity level: {level}"

    def test_status_counts_all_statuses_present(self, svc_with_db):
        """status_counts has keys for all standard statuses."""
        svc, _db = svc_with_db
        result = svc.get_alerts_data()
        sc = result["status_counts"]
        for status in ("new", "investigating", "resolved", "dismissed"):
            assert status in sc, f"Missing status: {status}"


# ================================================================== #
# TestGetAlertsDataEnrichment
# ================================================================== #


class TestGetAlertsDataEnrichment:
    """Verify alerts are enriched with incident/response info."""

    def test_alert_has_incident_id_key(self, svc_with_db):
        svc, db = svc_with_db
        db.insert_alert(_make_alert())
        result = svc.get_alerts_data()
        if result["alerts"]:
            assert "incident_id" in result["alerts"][0]

    def test_alert_has_response_status_key(self, svc_with_db):
        svc, db = svc_with_db
        db.insert_alert(_make_alert())
        result = svc.get_alerts_data()
        if result["alerts"]:
            assert "response_status" in result["alerts"][0]

    def test_incident_id_linked(self, svc_with_db):
        """Insert alert + incident + link, verify incident_id populated."""
        svc, db = svc_with_db
        alert = _make_alert(alert_id="alt-linked")
        db.insert_alert(alert)
        now = time.time()
        db.insert_incident(
            "inc-link-1", "Linked Incident", "high", "open",
            [], [], now, now,
        )
        db.add_alert_to_incident("inc-link-1", "alt-linked")
        result = svc.get_alerts_data()
        found = [
            a for a in result["alerts"]
            if a["alert_id"] == "alt-linked"
        ]
        assert len(found) == 1
        assert found[0]["incident_id"] == "inc-link-1"

    def test_incident_id_none_when_no_link(self, svc_with_db):
        svc, db = svc_with_db
        db.insert_alert(_make_alert())
        result = svc.get_alerts_data()
        if result["alerts"]:
            assert result["alerts"][0]["incident_id"] is None

    def test_response_status_from_router(self, svc_with_db):
        """Mock active_responses to verify response_status."""
        svc, db = svc_with_db
        alert = _make_alert(alert_id="alt-resp-1")
        db.insert_alert(alert)
        mock_router = MagicMock()
        mock_router.get_active_responses.return_value = [
            {"alert_id": "alt-resp-1", "status": "running"},
        ]
        svc._coordinator.response_router = mock_router
        result = svc.get_alerts_data()
        found = [
            a for a in result["alerts"]
            if a["alert_id"] == "alt-resp-1"
        ]
        if found:
            assert found[0]["response_status"] is not None

    def test_response_status_none_when_no_response(self, svc_with_db):
        svc, db = svc_with_db
        db.insert_alert(_make_alert())
        result = svc.get_alerts_data()
        if result["alerts"]:
            assert result["alerts"][0]["response_status"] is None

    def test_no_incident_store(self, svc_with_db):
        """Without incident_store, incident_id is still None."""
        svc, db = svc_with_db
        svc._coordinator.incident_store = None
        db.insert_alert(_make_alert())
        result = svc.get_alerts_data()
        if result["alerts"]:
            assert result["alerts"][0]["incident_id"] is None

    def test_no_response_router(self, svc_with_db):
        """Without response_router, response_status is still None."""
        svc, db = svc_with_db
        svc._coordinator.response_router = None
        db.insert_alert(_make_alert())
        result = svc.get_alerts_data()
        if result["alerts"]:
            assert result["alerts"][0]["response_status"] is None


# ================================================================== #
# TestGetIncidentsData
# ================================================================== #


class TestGetIncidentsData:
    """Tests for get_incidents_data()."""

    def test_returns_dict(self, svc):
        result = svc.get_incidents_data()
        assert isinstance(result, dict)

    def test_has_all_keys(self, svc):
        result = svc.get_incidents_data()
        for key in ("incidents", "status_counts", "total_count"):
            assert key in result, f"Missing key: {key}"

    def test_incidents_are_list_of_dicts(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        db.insert_incident(
            "inc-1", "Test", "high", "open",
            [], [], now, now,
        )
        result = svc.get_incidents_data()
        assert isinstance(result["incidents"], list)
        if result["incidents"]:
            assert isinstance(result["incidents"][0], dict)

    def test_incident_has_alert_count(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        db.insert_incident(
            "inc-ac", "Test", "high", "open",
            [], [], now, now,
        )
        db.add_alert_to_incident("inc-ac", "alt-1")
        db.add_alert_to_incident("inc-ac", "alt-2")
        result = svc.get_incidents_data()
        found = [
            i for i in result["incidents"]
            if i["incident_id"] == "inc-ac"
        ]
        assert len(found) == 1
        assert found[0]["alert_count"] == 2

    def test_incident_has_alert_ids(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        db.insert_incident(
            "inc-aids", "Test", "high", "open",
            [], [], now, now,
        )
        db.add_alert_to_incident("inc-aids", "alt-a")
        result = svc.get_incidents_data()
        found = [
            i for i in result["incidents"]
            if i["incident_id"] == "inc-aids"
        ]
        assert len(found) == 1
        assert "alt-a" in found[0]["alert_ids"]

    def test_incident_has_active_responses(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        db.insert_incident(
            "inc-ar", "Test", "high", "open",
            [], [], now, now,
        )
        result = svc.get_incidents_data()
        found = [
            i for i in result["incidents"]
            if i["incident_id"] == "inc-ar"
        ]
        assert len(found) == 1
        assert "active_responses" in found[0]

    def test_incident_has_duration_seconds(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        db.insert_incident(
            "inc-dur", "Test", "high", "open",
            [], [], now - 200, now,
        )
        result = svc.get_incidents_data()
        found = [
            i for i in result["incidents"]
            if i["incident_id"] == "inc-dur"
        ]
        assert len(found) == 1
        assert "duration_seconds" in found[0]
        assert found[0]["duration_seconds"] >= 200

    def test_status_counts_correct(self, svc_with_db):
        """Insert open + closed incidents, verify counts."""
        svc, db = svc_with_db
        now = time.time()
        db.insert_incident(
            "inc-s1", "Open", "high", "open",
            [], [], now, now,
        )
        db.insert_incident(
            "inc-s2", "Closed", "medium", "closed",
            [], [], now, now,
        )
        db.insert_incident(
            "inc-s3", "Open2", "low", "open",
            [], [], now, now,
        )
        result = svc.get_incidents_data()
        sc = result["status_counts"]
        assert sc.get("open", 0) >= 2
        assert sc.get("closed", 0) >= 1

    def test_total_count_matches(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        for i in range(4):
            db.insert_incident(
                f"inc-tc-{i}", f"T{i}", "medium", "open",
                [], [], now, now,
            )
        result = svc.get_incidents_data()
        assert result["total_count"] >= 4

    def test_empty_returns_empty(self, svc_with_db):
        svc, _db = svc_with_db
        result = svc.get_incidents_data()
        assert result["incidents"] == []
        assert result["total_count"] == 0

    def test_no_database(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(db=None)
        svc = DashboardDataService(coord)
        result = svc.get_incidents_data()
        assert result["incidents"] == []
        assert result["total_count"] == 0

    def test_limit_parameter(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        for i in range(10):
            db.insert_incident(
                f"inc-lim-{i}", f"L{i}", "medium", "open",
                [], [], now, now,
            )
        result = svc.get_incidents_data(limit=3)
        assert len(result["incidents"]) <= 3


# ================================================================== #
# TestGetIncidentsDataEdgeCases
# ================================================================== #


class TestGetIncidentsDataEdgeCases:
    """Edge cases for get_incidents_data()."""

    def test_no_response_router(self, svc_with_db):
        """Without response_router, active_responses is empty."""
        svc, db = svc_with_db
        svc._coordinator.response_router = None
        now = time.time()
        db.insert_incident(
            "inc-nr", "Test", "high", "open",
            [], [], now, now,
        )
        result = svc.get_incidents_data()
        found = [
            i for i in result["incidents"]
            if i["incident_id"] == "inc-nr"
        ]
        if found:
            assert found[0]["active_responses"] == [] or (
                found[0]["active_responses"] == 0
            )

    def test_incident_with_no_alerts(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        db.insert_incident(
            "inc-na", "No Alerts", "low", "open",
            [], [], now, now,
        )
        result = svc.get_incidents_data()
        found = [
            i for i in result["incidents"]
            if i["incident_id"] == "inc-na"
        ]
        assert len(found) == 1
        assert found[0]["alert_count"] == 0
        assert found[0]["alert_ids"] == []

    def test_closed_incident(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        db.insert_incident(
            "inc-cl", "Closed", "medium", "closed",
            [], [], now - 500, now,
        )
        result = svc.get_incidents_data(status="closed")
        found = [
            i for i in result["incidents"]
            if i["incident_id"] == "inc-cl"
        ]
        assert len(found) == 1

    def test_duration_calculation(self, svc_with_db):
        """first_seen=100, last_seen=200 -> duration >= 100."""
        svc, db = svc_with_db
        db.insert_incident(
            "inc-dc", "Duration", "high", "open",
            [], [], 100.0, 200.0,
        )
        result = svc.get_incidents_data()
        found = [
            i for i in result["incidents"]
            if i["incident_id"] == "inc-dc"
        ]
        assert len(found) == 1
        assert found[0]["duration_seconds"] == pytest.approx(
            100.0, abs=1.0,
        )

    def test_db_error_handled(self):
        """If db raises, incidents_data returns safe defaults."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_db = MagicMock()
        mock_db.query_incidents.side_effect = RuntimeError("boom")
        mock_db.incident_count.side_effect = RuntimeError("boom")
        coord = _make_coordinator(db=mock_db)
        svc = DashboardDataService(coord)
        result = svc.get_incidents_data()
        assert isinstance(result, dict)
        assert result["incidents"] == []


# ================================================================== #
# TestGetExecutionsData
# ================================================================== #


class TestGetExecutionsData:
    """Tests for get_executions_data()."""

    def test_returns_dict(self, svc):
        result = svc.get_executions_data()
        assert isinstance(result, dict)

    def test_has_all_keys(self, svc):
        result = svc.get_executions_data()
        for key in (
            "executions",
            "status_counts",
            "total_count",
            "playbooks_loaded",
        ):
            assert key in result, f"Missing key: {key}"

    def test_executions_are_list_of_dicts(self, svc_with_db):
        svc, db = svc_with_db
        db.insert_execution(
            "exec-1", "pb-1", "Test PB", "alt-1",
            status="running", started_at=time.time(),
        )
        result = svc.get_executions_data()
        assert isinstance(result["executions"], list)
        if result["executions"]:
            assert isinstance(result["executions"][0], dict)

    def test_execution_has_steps(self, svc_with_db):
        svc, db = svc_with_db
        db.insert_execution(
            "exec-steps", "pb-1", "Test PB", "alt-1",
            status="running", started_at=time.time(),
        )
        db.insert_execution_step(
            "exec-steps", 0, "step-0", "block_ip",
            target="1.2.3.4", status="completed",
        )
        result = svc.get_executions_data()
        found = [
            e for e in result["executions"]
            if e["execution_id"] == "exec-steps"
        ]
        assert len(found) == 1
        assert "steps" in found[0]
        assert isinstance(found[0]["steps"], list)
        assert len(found[0]["steps"]) >= 1

    def test_execution_has_alert_title(self, svc_with_db):
        svc, db = svc_with_db
        alert = _make_alert(
            alert_id="alt-title", title="Malware Found",
        )
        db.insert_alert(alert)
        db.insert_execution(
            "exec-at", "pb-1", "Test PB", "alt-title",
            status="running", started_at=time.time(),
        )
        result = svc.get_executions_data()
        found = [
            e for e in result["executions"]
            if e["execution_id"] == "exec-at"
        ]
        assert len(found) == 1
        assert "alert_title" in found[0]
        assert found[0]["alert_title"] == "Malware Found"

    def test_status_counts_correct(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        db.insert_execution(
            "exec-r1", "pb-1", "PB1", "a1",
            status="running", started_at=now,
        )
        db.insert_execution(
            "exec-c1", "pb-1", "PB1", "a2",
            status="completed", started_at=now,
        )
        db.insert_execution(
            "exec-r2", "pb-1", "PB1", "a3",
            status="running", started_at=now,
        )
        result = svc.get_executions_data()
        sc = result["status_counts"]
        assert sc.get("running", 0) >= 2
        assert sc.get("completed", 0) >= 1

    def test_total_count_matches(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        for i in range(5):
            db.insert_execution(
                f"exec-tc-{i}", "pb-1", "PB", f"a-{i}",
                status="running", started_at=now,
            )
        result = svc.get_executions_data()
        assert result["total_count"] >= 5

    def test_steps_ordered_by_index(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        db.insert_execution(
            "exec-ord", "pb-1", "PB", "alt-1",
            status="running", started_at=now,
        )
        db.insert_execution_step(
            "exec-ord", 2, "step-2", "quarantine",
        )
        db.insert_execution_step(
            "exec-ord", 0, "step-0", "block_ip",
        )
        db.insert_execution_step(
            "exec-ord", 1, "step-1", "kill_process",
        )
        result = svc.get_executions_data()
        found = [
            e for e in result["executions"]
            if e["execution_id"] == "exec-ord"
        ]
        assert len(found) == 1
        steps = found[0]["steps"]
        assert len(steps) == 3
        indices = [s["step_index"] for s in steps]
        assert indices == sorted(indices)

    def test_empty_returns_empty(self, svc_with_db):
        svc, _db = svc_with_db
        result = svc.get_executions_data()
        assert result["executions"] == []
        assert result["total_count"] == 0

    def test_no_database(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(db=None)
        svc = DashboardDataService(coord)
        result = svc.get_executions_data()
        assert result["executions"] == []
        assert result["total_count"] == 0

    def test_limit_parameter(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        for i in range(10):
            db.insert_execution(
                f"exec-l-{i}", "pb-1", "PB", f"a-{i}",
                status="running", started_at=now,
            )
        result = svc.get_executions_data(limit=4)
        assert len(result["executions"]) <= 4

    def test_playbooks_loaded_from_engine(self):
        """playbooks_loaded comes from playbook_engine.playbook_count."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_pe = MagicMock()
        mock_pe.playbook_count = 7
        coord = _make_coordinator(playbook_engine=mock_pe)
        svc = DashboardDataService(coord)
        result = svc.get_executions_data()
        assert result["playbooks_loaded"] == 7


# ================================================================== #
# TestGetExecutionsDataEdgeCases
# ================================================================== #


class TestGetExecutionsDataEdgeCases:
    """Edge cases for get_executions_data()."""

    def test_no_playbook_engine(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(playbook_engine=None)
        svc = DashboardDataService(coord)
        result = svc.get_executions_data()
        assert result["playbooks_loaded"] == 0

    def test_execution_without_alert_in_db(self, svc_with_db):
        """Execution references alert not in DB -> alert_title is ''."""
        svc, db = svc_with_db
        db.insert_execution(
            "exec-noalt", "pb-1", "PB", "alt-nonexistent",
            status="running", started_at=time.time(),
        )
        result = svc.get_executions_data()
        found = [
            e for e in result["executions"]
            if e["execution_id"] == "exec-noalt"
        ]
        assert len(found) == 1
        assert found[0]["alert_title"] == ""

    def test_completed_execution(self, svc_with_db):
        svc, db = svc_with_db
        now = time.time()
        db.insert_execution(
            "exec-comp", "pb-1", "PB", "a-1",
            status="completed", started_at=now - 60,
        )
        db.update_execution(
            "exec-comp", completed_at=now,
        )
        result = svc.get_executions_data(status="completed")
        found = [
            e for e in result["executions"]
            if e["execution_id"] == "exec-comp"
        ]
        assert len(found) == 1

    def test_running_execution(self, svc_with_db):
        svc, db = svc_with_db
        db.insert_execution(
            "exec-run", "pb-1", "PB", "a-1",
            status="running", started_at=time.time(),
        )
        result = svc.get_executions_data(status="running")
        found = [
            e for e in result["executions"]
            if e["execution_id"] == "exec-run"
        ]
        assert len(found) == 1

    def test_db_error_handled(self):
        """If db raises, executions_data returns safe defaults."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_db = MagicMock()
        mock_db.query_executions.side_effect = RuntimeError("boom")
        mock_db.execution_count.side_effect = RuntimeError("boom")
        coord = _make_coordinator(db=mock_db)
        svc = DashboardDataService(coord)
        result = svc.get_executions_data()
        assert isinstance(result, dict)
        assert result["executions"] == []


# ================================================================== #
# TestGetSystemStatus
# ================================================================== #


class TestGetSystemStatus:
    """Tests for get_system_status()."""

    def test_returns_dict(self, svc):
        result = svc.get_system_status()
        assert isinstance(result, dict)

    def test_has_all_keys(self, svc):
        result = svc.get_system_status()
        for key in (
            "health",
            "scheduler_tasks",
            "whitelist_entries",
            "baseline_progress",
            "uptime_stats",
        ):
            assert key in result, f"Missing key: {key}"

    def test_health_from_system_health(self):
        """Mock system_health.collect() and verify it appears."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_health = MagicMock()
        mock_health.collect.return_value = {
            "engine": {"events_processed": 50},
        }
        coord = _make_coordinator(system_health=mock_health)
        svc = DashboardDataService(coord)
        result = svc.get_system_status()
        assert result["health"] == {
            "engine": {"events_processed": 50},
        }

    def test_scheduler_tasks_list(self):
        from aegis.core.dashboard_service import DashboardDataService

        mock_sched = MagicMock()
        mock_sched.list_tasks.return_value = [
            MagicMock(name="task1"),
        ]
        mock_sched.get_stats.return_value = {
            "task_count": 1,
            "total_runs": 0,
            "total_errors": 0,
            "tasks": [{"name": "task1"}],
        }
        coord = _make_coordinator(scheduler=mock_sched)
        svc = DashboardDataService(coord)
        result = svc.get_system_status()
        assert isinstance(result["scheduler_tasks"], list)

    def test_whitelist_entries_from_manager(self):
        from aegis.core.dashboard_service import DashboardDataService

        mock_wm = MagicMock()
        mock_wm.entry_count = 42
        coord = _make_coordinator(whitelist_manager=mock_wm)
        svc = DashboardDataService(coord)
        result = svc.get_system_status()
        assert result["whitelist_entries"] == 42

    def test_baseline_progress_none_when_unavailable(self, svc):
        result = svc.get_system_status()
        assert result["baseline_progress"] is None

    def test_uptime_events_processed_int(self, svc):
        result = svc.get_system_status()
        assert isinstance(
            result["uptime_stats"]["events_processed"], int,
        )

    def test_uptime_alerts_generated_int(self, svc):
        result = svc.get_system_status()
        assert isinstance(
            result["uptime_stats"]["alerts_generated"], int,
        )

    def test_uptime_is_running_bool(self, svc):
        result = svc.get_system_status()
        assert isinstance(
            result["uptime_stats"]["is_running"], bool,
        )

    def test_no_system_health_fallback(self):
        """Without system_health, health is an empty dict."""
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(system_health=None)
        svc = DashboardDataService(coord)
        result = svc.get_system_status()
        assert result["health"] == {}

    def test_no_scheduler_fallback(self):
        """Without scheduler, scheduler_tasks is empty list."""
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(scheduler=None)
        svc = DashboardDataService(coord)
        result = svc.get_system_status()
        assert result["scheduler_tasks"] == []

    def test_no_whitelist_manager_fallback(self):
        """Without whitelist_manager, whitelist_entries is 0."""
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(whitelist_manager=None)
        svc = DashboardDataService(coord)
        result = svc.get_system_status()
        assert result["whitelist_entries"] == 0

    def test_uptime_stats_from_engine(self):
        """Verify uptime_stats reflects engine counters."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_engine = MagicMock()
        mock_engine.events_processed = 100
        mock_engine.alerts_generated = 5
        mock_engine.is_running = True
        coord = _make_coordinator(engine=mock_engine)
        svc = DashboardDataService(coord)
        result = svc.get_system_status()
        us = result["uptime_stats"]
        assert us["events_processed"] == 100
        assert us["alerts_generated"] == 5
        assert us["is_running"] is True


# ================================================================== #
# TestGetCanaryStatus
# ================================================================== #


class TestGetCanaryStatus:
    """Tests for get_canary_status()."""

    def test_returns_dict(self, svc):
        result = svc.get_canary_status()
        assert isinstance(result, dict)

    def test_has_all_keys(self, svc):
        result = svc.get_canary_status()
        for key in ("overview", "canaries", "last_verification"):
            assert key in result, f"Missing key: {key}"

    def test_overview_from_system(self):
        from aegis.core.dashboard_service import DashboardDataService

        mock_canary = MagicMock()
        mock_canary.get_status.return_value = {
            "total_deployed": 10,
            "healthy": 8,
            "triggered": 1,
            "errors": 1,
        }
        mock_canary.get_canaries.return_value = []
        mock_canary.last_verification = None
        coord = _make_coordinator(canary_system=mock_canary)
        svc = DashboardDataService(coord)
        result = svc.get_canary_status()
        ov = result["overview"]
        assert ov["total_deployed"] == 10
        assert ov["healthy"] == 8
        assert ov["triggered"] == 1

    def test_canaries_list_of_dicts(self):
        from aegis.core.dashboard_service import DashboardDataService

        mock_canary = MagicMock()
        mock_canary.get_status.return_value = {
            "total_deployed": 1,
            "healthy": 1,
            "triggered": 0,
            "errors": 0,
        }
        mock_canary.get_canaries.return_value = [
            {
                "canary_id": "c-1",
                "path": "/tmp/canary.txt",
                "file_type": ".txt",
                "status": "healthy",
                "last_verified": time.time(),
                "trigger_reason": None,
            },
        ]
        mock_canary.last_verification = time.time()
        coord = _make_coordinator(canary_system=mock_canary)
        svc = DashboardDataService(coord)
        result = svc.get_canary_status()
        assert isinstance(result["canaries"], list)
        if result["canaries"]:
            assert isinstance(result["canaries"][0], dict)

    def test_canary_has_expected_keys(self):
        from aegis.core.dashboard_service import DashboardDataService

        now = time.time()
        mock_canary = MagicMock()
        mock_canary.get_status.return_value = {
            "total_deployed": 1,
            "healthy": 1,
            "triggered": 0,
            "errors": 0,
        }
        mock_canary.get_canaries.return_value = [
            {
                "canary_id": "c-1",
                "path": "/tmp/canary.txt",
                "file_type": ".txt",
                "status": "healthy",
                "last_verified": now,
                "trigger_reason": None,
            },
        ]
        mock_canary.last_verification = now
        coord = _make_coordinator(canary_system=mock_canary)
        svc = DashboardDataService(coord)
        result = svc.get_canary_status()
        if result["canaries"]:
            c = result["canaries"][0]
            for key in (
                "canary_id",
                "path",
                "file_type",
                "status",
                "last_verified",
                "trigger_reason",
            ):
                assert key in c, f"Missing key in canary: {key}"

    def test_no_canary_system(self):
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(canary_system=None)
        svc = DashboardDataService(coord)
        result = svc.get_canary_status()
        assert isinstance(result, dict)
        assert result["canaries"] == []
        ov = result["overview"]
        assert ov.get("total_deployed", 0) == 0

    def test_last_verification_from_canaries(self):
        from aegis.core.dashboard_service import DashboardDataService

        now = time.time()
        canary_obj = MagicMock()
        canary_obj.canary_id = "c1"
        canary_obj.path = "/tmp/canary.txt"
        canary_obj.file_type = ".txt"
        canary_obj.status = "deployed"
        canary_obj.last_verified = now
        canary_obj.trigger_reason = ""

        mock_canary = MagicMock()
        mock_canary.get_status.return_value = {
            "total_deployed": 1,
            "healthy": 1,
            "triggered": 0,
            "errors": 0,
        }
        mock_canary.canaries = [canary_obj]
        coord = _make_coordinator(canary_system=mock_canary)
        svc = DashboardDataService(coord)
        result = svc.get_canary_status()
        assert result["last_verification"] == now

    def test_empty_canary_system(self):
        from aegis.core.dashboard_service import DashboardDataService

        mock_canary = MagicMock()
        mock_canary.get_status.return_value = {
            "total_deployed": 0,
            "healthy": 0,
            "triggered": 0,
            "errors": 0,
        }
        mock_canary.get_canaries.return_value = []
        mock_canary.last_verification = None
        coord = _make_coordinator(canary_system=mock_canary)
        svc = DashboardDataService(coord)
        result = svc.get_canary_status()
        assert result["canaries"] == []
        assert result["last_verification"] is None

    def test_overview_has_errors_key(self):
        """overview should include an errors count."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_canary = MagicMock()
        mock_canary.get_status.return_value = {
            "total_deployed": 5,
            "healthy": 3,
            "triggered": 1,
            "errors": 1,
        }
        mock_canary.get_canaries.return_value = []
        mock_canary.last_verification = None
        coord = _make_coordinator(canary_system=mock_canary)
        svc = DashboardDataService(coord)
        result = svc.get_canary_status()
        assert "errors" in result["overview"]
        assert result["overview"]["errors"] == 1


# ================================================================== #
# TestGracefulDegradation
# ================================================================== #


class TestGracefulDegradation:
    """All methods must return valid dicts even when degraded."""

    def test_all_subsystems_none(self):
        """All 6 methods return valid dicts with all-None coordinator."""
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator()
        svc = DashboardDataService(coord)

        for method_name in (
            "get_home_data",
            "get_alerts_data",
            "get_incidents_data",
            "get_executions_data",
            "get_system_status",
            "get_canary_status",
        ):
            method = getattr(svc, method_name)
            result = method()
            assert isinstance(result, dict), (
                f"{method_name} did not return dict"
            )

    def test_partial_setup_db_only(self, db):
        """Only db is available, everything else is None."""
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator(db=db)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert isinstance(result, dict)
        assert result["stats"]["events_24h"] == 0
        assert result["stats"]["alerts_24h"] == 0

    def test_subsystem_exception_caught(self):
        """Mock a subsystem to raise, verify it's handled."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_health = MagicMock()
        mock_health.collect.side_effect = RuntimeError("crash")
        coord = _make_coordinator(system_health=mock_health)
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert isinstance(result, dict)
        assert isinstance(result["health_summary"], dict)

    def test_database_closed_handled(self, tmp_path):
        """If the database connection is closed, methods still work."""
        from aegis.core.dashboard_service import DashboardDataService

        db = AegisDatabase(tmp_path / "closed.db")
        db.close()
        coord = _make_coordinator(db=db)
        svc = DashboardDataService(coord)
        # Should not raise
        result = svc.get_home_data()
        assert isinstance(result, dict)

    def test_multiple_calls_consistent(self, svc):
        """Calling the same method twice returns same structure."""
        r1 = svc.get_home_data()
        r2 = svc.get_home_data()
        assert set(r1.keys()) == set(r2.keys())
        assert set(r1["stats"].keys()) == set(r2["stats"].keys())

    def test_get_home_data_never_crashes(self):
        """get_home_data with every subsystem raising never crashes."""
        from aegis.core.dashboard_service import DashboardDataService

        coord = _make_coordinator()
        # Make every attribute raise on access
        mock_db = MagicMock()
        mock_db.query_alerts.side_effect = Exception("fail")
        mock_db.query_events.side_effect = Exception("fail")
        mock_db.event_count.side_effect = Exception("fail")
        mock_db.alert_count.side_effect = Exception("fail")
        mock_db.incident_count.side_effect = Exception("fail")
        coord.db = mock_db
        mock_health = MagicMock()
        mock_health.collect.side_effect = Exception("fail")
        coord.system_health = mock_health
        svc = DashboardDataService(coord)
        result = svc.get_home_data()
        assert isinstance(result, dict)

    def test_get_alerts_data_never_crashes(self):
        """get_alerts_data with broken db never crashes."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_db = MagicMock()
        mock_db.query_alerts.side_effect = Exception("fail")
        mock_db.alert_count.side_effect = Exception("fail")
        coord = _make_coordinator(db=mock_db)
        svc = DashboardDataService(coord)
        result = svc.get_alerts_data()
        assert isinstance(result, dict)

    def test_get_incidents_data_never_crashes(self):
        """get_incidents_data with broken db never crashes."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_db = MagicMock()
        mock_db.query_incidents.side_effect = Exception("fail")
        mock_db.incident_count.side_effect = Exception("fail")
        coord = _make_coordinator(db=mock_db)
        svc = DashboardDataService(coord)
        result = svc.get_incidents_data()
        assert isinstance(result, dict)

    def test_get_executions_data_never_crashes(self):
        """get_executions_data with broken db never crashes."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_db = MagicMock()
        mock_db.query_executions.side_effect = Exception("fail")
        mock_db.execution_count.side_effect = Exception("fail")
        coord = _make_coordinator(db=mock_db)
        svc = DashboardDataService(coord)
        result = svc.get_executions_data()
        assert isinstance(result, dict)

    def test_get_system_status_never_crashes(self):
        """get_system_status with broken subsystems never crashes."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_health = MagicMock()
        mock_health.collect.side_effect = Exception("fail")
        mock_sched = MagicMock()
        mock_sched.get_stats.side_effect = Exception("fail")
        mock_sched.list_tasks.side_effect = Exception("fail")
        coord = _make_coordinator(
            system_health=mock_health,
            scheduler=mock_sched,
        )
        svc = DashboardDataService(coord)
        result = svc.get_system_status()
        assert isinstance(result, dict)

    def test_get_canary_status_never_crashes(self):
        """get_canary_status with broken canary_system never crashes."""
        from aegis.core.dashboard_service import DashboardDataService

        mock_canary = MagicMock()
        mock_canary.get_status.side_effect = Exception("fail")
        mock_canary.get_canaries.side_effect = Exception("fail")
        coord = _make_coordinator(canary_system=mock_canary)
        svc = DashboardDataService(coord)
        result = svc.get_canary_status()
        assert isinstance(result, dict)

    def test_none_coordinator_all_methods(self):
        """DashboardDataService(None) — all methods return valid dicts."""
        from aegis.core.dashboard_service import DashboardDataService

        svc = DashboardDataService(None)
        for method_name in (
            "get_home_data",
            "get_alerts_data",
            "get_incidents_data",
            "get_executions_data",
            "get_system_status",
            "get_canary_status",
        ):
            result = getattr(svc, method_name)()
            assert isinstance(result, dict), (
                f"{method_name} failed with None coordinator"
            )


# ================================================================== #
# TestIntegrationWithRealCoordinator
# ================================================================== #


class TestIntegrationWithRealCoordinator:
    """Integration tests using a real AegisCoordinator."""

    @pytest.fixture
    def coordinator(self, tmp_path):
        from aegis.core.config import AegisConfig
        from aegis.core.coordinator import AegisCoordinator

        cfg = AegisConfig()
        cfg._data["database"]["path"] = str(tmp_path / "test.db")
        cfg._data["canary"]["enabled"] = False
        cfg._data["canary"]["directories"] = []
        coord = AegisCoordinator(cfg)
        coord.setup()
        return coord

    def test_coordinator_creates_dashboard_service(
        self, coordinator,
    ):
        """After wiring, coordinator should expose dashboard_service."""
        from aegis.core.dashboard_service import DashboardDataService

        svc = DashboardDataService(coordinator)
        assert svc is not None
        assert svc._coordinator is coordinator

    def test_full_coordinator_home_data(self, coordinator):
        from aegis.core.dashboard_service import DashboardDataService

        svc = DashboardDataService(coordinator)
        result = svc.get_home_data()
        assert isinstance(result, dict)
        assert "health_summary" in result
        assert "stats" in result

    def test_full_coordinator_alerts_data(self, coordinator):
        from aegis.core.dashboard_service import DashboardDataService

        svc = DashboardDataService(coordinator)
        result = svc.get_alerts_data()
        assert isinstance(result, dict)
        assert "alerts" in result
        assert "severity_counts" in result

    def test_full_coordinator_incidents_data(self, coordinator):
        from aegis.core.dashboard_service import DashboardDataService

        svc = DashboardDataService(coordinator)
        result = svc.get_incidents_data()
        assert isinstance(result, dict)
        assert "incidents" in result

    def test_full_coordinator_executions_data(self, coordinator):
        from aegis.core.dashboard_service import DashboardDataService

        svc = DashboardDataService(coordinator)
        result = svc.get_executions_data()
        assert isinstance(result, dict)
        assert "executions" in result
        assert "playbooks_loaded" in result

    def test_full_coordinator_system_status(self, coordinator):
        from aegis.core.dashboard_service import DashboardDataService

        svc = DashboardDataService(coordinator)
        result = svc.get_system_status()
        assert isinstance(result, dict)
        assert "health" in result
        assert "uptime_stats" in result

    def test_full_coordinator_canary_status(self, coordinator):
        from aegis.core.dashboard_service import DashboardDataService

        svc = DashboardDataService(coordinator)
        result = svc.get_canary_status()
        assert isinstance(result, dict)
        assert "overview" in result
        assert "canaries" in result

    def test_home_data_after_alert_insert(self, coordinator):
        """Insert an alert to DB, verify it appears in recent_alerts."""
        from aegis.core.dashboard_service import DashboardDataService

        db = coordinator.db
        assert db is not None
        alert = _make_alert(
            alert_id="alt-integ-1",
            title="Integration Alert",
        )
        db.insert_alert(alert)
        svc = DashboardDataService(coordinator)
        result = svc.get_home_data()
        alert_ids = [
            a["alert_id"] for a in result["recent_alerts"]
        ]
        assert "alt-integ-1" in alert_ids
