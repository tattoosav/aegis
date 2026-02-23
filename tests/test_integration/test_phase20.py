"""Phase 20 integration tests -- DashboardDataService end-to-end.

Validates that the DashboardDataService integrates correctly with a
fully wired AegisCoordinator, returning enriched data structures
for every dashboard page without importing PySide6.
"""

from __future__ import annotations

import time
import uuid

import pytest

from aegis.core.config import AegisConfig
from aegis.core.coordinator import AegisCoordinator
from aegis.core.dashboard_service import DashboardDataService
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


def _make_config(tmp_path):
    """Build a minimal AegisConfig pointing at a temp database."""
    cfg = AegisConfig()
    cfg._data["database"]["path"] = str(tmp_path / "test.db")
    cfg._data["canary"]["enabled"] = False
    cfg._data["canary"]["directories"] = []
    cfg._data["scheduler"]["enabled"] = True
    cfg._data["whitelist"]["enabled"] = True
    return cfg


def _make_alert(
    severity="medium",
    status="new",
    title="Test Alert",
    **kw,
):
    """Create a lightweight Alert for testing."""
    return Alert(
        alert_id=kw.get("alert_id", str(uuid.uuid4())),
        event_id=kw.get("event_id", str(uuid.uuid4())),
        timestamp=kw.get("timestamp", time.time()),
        sensor=SensorType.PROCESS,
        alert_type="test",
        severity=Severity.from_string(severity),
        title=title,
        description="Test alert description",
        confidence=0.8,
        status=AlertStatus(status),
        data={},
        mitre_ids=["T1059"],
        recommended_actions=["Investigate"],
    )


def _make_event(**kw):
    """Create a lightweight AegisEvent for testing."""
    return AegisEvent(
        event_id=kw.get("event_id", str(uuid.uuid4())),
        timestamp=kw.get("timestamp", time.time()),
        sensor=kw.get("sensor", SensorType.PROCESS),
        event_type=kw.get("event_type", "process_start"),
        severity=kw.get("severity", Severity.INFO),
        data=kw.get("data", {"pid": 1234, "name": "test.exe"}),
    )


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture
def coordinator(tmp_path):
    """Return a fully wired AegisCoordinator backed by a temp DB."""
    config = _make_config(tmp_path)
    coord = AegisCoordinator(config)
    coord.setup()
    return coord


# ------------------------------------------------------------------ #
# TestPhase20DashboardIntegration
# ------------------------------------------------------------------ #


class TestPhase20DashboardIntegration:
    """End-to-end tests for DashboardDataService with a full coordinator."""

    # ---- Coordinator wiring ----

    def test_dashboard_service_created_by_coordinator(
        self, coordinator,
    ):
        """Coordinator.setup() creates a DashboardDataService."""
        assert coordinator.dashboard_service is not None
        assert isinstance(
            coordinator.dashboard_service, DashboardDataService,
        )

    # ---- Home page data ----

    def test_home_data_structure(self, coordinator):
        """get_home_data() returns all 6 expected top-level keys."""
        svc = coordinator.dashboard_service
        data = svc.get_home_data()

        expected_keys = {
            "health_summary",
            "sensor_status",
            "recent_alerts",
            "stats",
            "canary_overview",
            "scheduler_overview",
        }
        assert expected_keys == set(data.keys())

        # Stats sub-structure.
        stats = data["stats"]
        assert isinstance(stats, dict)
        for key in (
            "events_24h", "alerts_24h",
            "incidents_open", "responses_total",
        ):
            assert key in stats

    def test_home_data_after_alert_insertion(self, coordinator):
        """Inserting alerts makes them visible in get_home_data()."""
        db = coordinator.db
        for _ in range(3):
            db.insert_alert(_make_alert())

        svc = coordinator.dashboard_service
        data = svc.get_home_data()

        assert len(data["recent_alerts"]) == 3
        assert data["stats"]["alerts_24h"] >= 3

    def test_home_data_24h_filtering(self, coordinator):
        """stats.alerts_24h only counts recent alerts; recent_alerts
        returns all regardless of age."""
        db = coordinator.db

        # Recent alert (within 24 h).
        db.insert_alert(_make_alert(timestamp=time.time()))

        # Old alert (> 24 h ago).
        db.insert_alert(
            _make_alert(timestamp=time.time() - 100_000),
        )

        svc = coordinator.dashboard_service
        data = svc.get_home_data()

        assert data["stats"]["alerts_24h"] == 1
        assert len(data["recent_alerts"]) == 2

    # ---- Alerts page data ----

    def test_alerts_data_matches_db(self, coordinator):
        """Severity counts in get_alerts_data() match insertions."""
        db = coordinator.db
        for _ in range(2):
            db.insert_alert(_make_alert(severity="critical"))
        for _ in range(2):
            db.insert_alert(_make_alert(severity="medium"))
        db.insert_alert(_make_alert(severity="low"))

        svc = coordinator.dashboard_service
        data = svc.get_alerts_data()

        assert data["total_count"] == 5
        assert data["severity_counts"]["critical"] == 2
        assert data["severity_counts"]["medium"] == 2

    def test_alerts_data_filtering(self, coordinator):
        """get_alerts_data() respects severity filter."""
        db = coordinator.db
        for _ in range(3):
            db.insert_alert(_make_alert(severity="critical"))
        for _ in range(2):
            db.insert_alert(_make_alert(severity="low"))

        svc = coordinator.dashboard_service

        crit = svc.get_alerts_data(severity="critical")
        assert crit["total_count"] == 5  # total is unfiltered
        assert len(crit["alerts"]) == 3

        low = svc.get_alerts_data(severity="low")
        assert len(low["alerts"]) == 2

    # ---- Incidents page data ----

    def test_incidents_data_structure(self, coordinator):
        """get_incidents_data() returns the expected shape."""
        svc = coordinator.dashboard_service
        data = svc.get_incidents_data()

        assert isinstance(data["incidents"], list)
        assert isinstance(data["status_counts"], dict)
        assert isinstance(data["total_count"], int)

    def test_incidents_data_after_insertion(self, coordinator):
        """Inserted incidents and linked alerts are reflected."""
        db = coordinator.db
        now = time.time()

        # Create two incidents.
        db.insert_incident(
            incident_id="inc-test-001",
            title="Incident One",
            severity="high",
            status="open",
            mitre_chain=["T1059"],
            entities=["ip:10.0.0.1"],
            first_seen=now - 60,
            last_seen=now,
        )
        db.insert_incident(
            incident_id="inc-test-002",
            title="Incident Two",
            severity="medium",
            status="open",
            mitre_chain=[],
            entities=[],
            first_seen=now - 30,
            last_seen=now,
        )

        # Link 2 alerts to the first incident.
        alert1 = _make_alert()
        alert2 = _make_alert()
        db.insert_alert(alert1)
        db.insert_alert(alert2)
        db.add_alert_to_incident("inc-test-001", alert1.alert_id)
        db.add_alert_to_incident("inc-test-001", alert2.alert_id)

        svc = coordinator.dashboard_service
        data = svc.get_incidents_data()

        assert data["total_count"] == 2
        assert len(data["incidents"]) == 2

        # Find the first incident and verify alert_count.
        inc1 = next(
            i for i in data["incidents"]
            if i["incident_id"] == "inc-test-001"
        )
        assert inc1["alert_count"] == 2

    # ---- Executions page data ----

    def test_executions_data_structure(self, coordinator):
        """get_executions_data() returns the expected shape."""
        svc = coordinator.dashboard_service
        data = svc.get_executions_data()

        assert isinstance(data["executions"], list)
        assert isinstance(data["status_counts"], dict)
        assert isinstance(data["total_count"], int)
        assert isinstance(data["playbooks_loaded"], int)

    def test_executions_data_after_insertion(self, coordinator):
        """Inserted execution and steps are reflected."""
        db = coordinator.db
        exec_id = f"exec-{uuid.uuid4().hex[:8]}"
        alert = _make_alert()
        db.insert_alert(alert)

        db.insert_execution(
            execution_id=exec_id,
            playbook_id="pb-001",
            playbook_name="Test Playbook",
            alert_id=alert.alert_id,
            status="running",
            started_at=time.time(),
        )
        db.insert_execution_step(
            execution_id=exec_id,
            step_index=0,
            step_id="s1",
            action="isolate_host",
            target="10.0.0.1",
        )
        db.insert_execution_step(
            execution_id=exec_id,
            step_index=1,
            step_id="s2",
            action="block_ip",
            target="10.0.0.99",
        )

        svc = coordinator.dashboard_service
        data = svc.get_executions_data()

        assert data["total_count"] == 1
        assert len(data["executions"]) == 1

        execution = data["executions"][0]
        assert len(execution["steps"]) == 2

    # ---- System status page ----

    def test_system_status_structure(self, coordinator):
        """get_system_status() returns the expected shape."""
        svc = coordinator.dashboard_service
        data = svc.get_system_status()

        assert isinstance(data["health"], dict)
        assert isinstance(data["scheduler_tasks"], list)
        assert isinstance(data["whitelist_entries"], int)
        assert isinstance(data["uptime_stats"], dict)

    def test_system_status_health_matches(self, coordinator):
        """get_system_status().health matches coordinator health."""
        svc = coordinator.dashboard_service
        data = svc.get_system_status()

        expected = coordinator.system_health.collect()
        assert data["health"] == expected

    # ---- Canary status ----

    def test_canary_status_disabled(self, coordinator):
        """Canary is disabled in config; overview shows zeros."""
        svc = coordinator.dashboard_service
        data = svc.get_canary_status()

        overview = data["overview"]
        assert overview["total_deployed"] == 0
        assert overview["healthy"] == 0
        assert overview["triggered"] == 0

    # ---- Full pipeline ----

    def test_full_pipeline_end_to_end(self, coordinator):
        """Full pipeline: event -> alert -> incident -> execution,
        all visible through every dashboard data method."""
        db = coordinator.db
        now = time.time()

        # 1. Insert event.
        event = _make_event(event_id="evt-e2e-001")
        db.insert_event(event)

        # 2. Insert alert linked to the event.
        alert = _make_alert(
            event_id="evt-e2e-001",
            title="E2E Alert",
        )
        db.insert_alert(alert)

        # 3. Insert incident and link alert.
        db.insert_incident(
            incident_id="inc-e2e-001",
            title="E2E Incident",
            severity="high",
            status="open",
            mitre_chain=["T1059"],
            entities=["ip:10.0.0.1"],
            first_seen=now - 30,
            last_seen=now,
        )
        db.add_alert_to_incident("inc-e2e-001", alert.alert_id)

        # 4. Insert execution linked to alert.
        exec_id = f"exec-{uuid.uuid4().hex[:8]}"
        db.insert_execution(
            execution_id=exec_id,
            playbook_id="pb-e2e",
            playbook_name="E2E Playbook",
            alert_id=alert.alert_id,
            status="running",
            started_at=now,
        )

        svc = coordinator.dashboard_service

        # Verify home page sees the alert.
        home = svc.get_home_data()
        home_alert_ids = [
            a["alert_id"] for a in home["recent_alerts"]
        ]
        assert alert.alert_id in home_alert_ids

        # Verify alerts page has the alert.
        alerts_data = svc.get_alerts_data()
        alert_ids = [a["alert_id"] for a in alerts_data["alerts"]]
        assert alert.alert_id in alert_ids

        # Verify incidents page has the incident with linked alert.
        inc_data = svc.get_incidents_data()
        assert inc_data["total_count"] >= 1
        inc = next(
            i for i in inc_data["incidents"]
            if i["incident_id"] == "inc-e2e-001"
        )
        assert alert.alert_id in inc["alert_ids"]
        assert inc["alert_count"] >= 1

        # Verify executions page has the execution.
        exec_data = svc.get_executions_data()
        assert exec_data["total_count"] >= 1
        exec_ids = [
            e["execution_id"] for e in exec_data["executions"]
        ]
        assert exec_id in exec_ids

    # ---- Health and response stats on home ----

    def test_health_and_response_stats_in_home(self, coordinator):
        """Home data includes scheduler overview with task_count,
        health_summary dict, and responses_total of zero initially."""
        svc = coordinator.dashboard_service
        data = svc.get_home_data()

        # Scheduler overview has task_count.
        sched = data["scheduler_overview"]
        assert "task_count" in sched
        assert isinstance(sched["task_count"], int)

        # Health summary is a dict.
        assert isinstance(data["health_summary"], dict)

        # No responses have been routed yet.
        assert data["stats"]["responses_total"] == 0
