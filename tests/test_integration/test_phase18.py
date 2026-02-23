"""Phase 18 integration tests — cross-component feature validation.

Tests that Phase 18 features (enrichment, incident persistence,
whitelist-in-pipeline, scheduler, canary deployment, coordinator
lifecycle, and database incident CRUD) work correctly together.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from aegis.alerting.correlation_engine import CorrelationEngine
from aegis.alerting.incident_store import IncidentStore
from aegis.core.config import AegisConfig
from aegis.core.coordinator import AegisCoordinator
from aegis.core.database import AegisDatabase
from aegis.core.enricher import EventEnricher
from aegis.core.models import AegisEvent, Alert, SensorType, Severity
from aegis.core.scheduler import TaskScheduler
from aegis.core.whitelist_manager import WhitelistManager, WhitelistType
from aegis.detection.pipeline import DetectionPipeline
from aegis.sensors.canary_system import CanaryConfig, CanaryDeploymentSystem

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _make_event(
    sensor: SensorType = SensorType.NETWORK,
    data: dict[str, Any] | None = None,
) -> AegisEvent:
    return AegisEvent(
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        timestamp=time.time(),
        sensor=sensor,
        event_type="test",
        severity=Severity.INFO,
        data=data or {},
    )


def _make_alert(
    alert_type: str = "test.alert",
    severity: Severity = Severity.MEDIUM,
    data: dict[str, Any] | None = None,
    mitre_ids: list[str] | None = None,
) -> Alert:
    return Alert(
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        sensor=SensorType.PROCESS,
        alert_type=alert_type,
        severity=severity,
        title=f"Test: {alert_type}",
        description="Test alert",
        confidence=0.9,
        data=data or {},
        mitre_ids=mitre_ids or [],
    )


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture
def db(tmp_path: Path) -> AegisDatabase:
    return AegisDatabase(str(tmp_path / "test.db"))


@pytest.fixture
def config(tmp_path: Path) -> AegisConfig:
    cfg = AegisConfig()
    cfg._data["database"]["path"] = str(tmp_path / "test.db")
    cfg._data["canary"]["directories"] = []
    return cfg


# ------------------------------------------------------------------ #
# TestFullEventFlow
# ------------------------------------------------------------------ #


class TestFullEventFlow:
    """Event -> enrichment -> detection -> alert end-to-end."""

    def test_event_enriched_with_ioc(self, db: AegisDatabase) -> None:
        """Insert IOC, create matching event, verify _ioc_match."""
        db.upsert_ioc(
            ioc_type="ipv4-addr",
            value="10.0.0.99",
            source="unit-test",
            severity="high",
        )
        enricher = EventEnricher(db=db)
        event = _make_event(data={"dst_ip": "10.0.0.99"})
        enricher.enrich(event)

        assert event.data["_ioc_match"] is True
        assert event.data["_ioc_source"] == "unit-test"
        assert event.data["_ioc_severity"] == "high"

    def test_event_enriched_with_reputation(
        self, db: AegisDatabase,
    ) -> None:
        """Insert reputation score, verify _reputation_score."""
        with db._lock:
            db._conn.execute(
                "INSERT INTO connection_reputation "
                "(address, address_type, score, first_seen, "
                "last_seen, total_connections) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("192.168.1.50", "ipv4", 25.0, time.time(),
                 time.time(), 5),
            )
            db._conn.commit()

        enricher = EventEnricher(db=db)
        event = _make_event(data={"dst_ip": "192.168.1.50"})
        enricher.enrich(event)

        assert event.data["_reputation_score"] == 25.0

    def test_enrichment_does_not_crash_without_db(self) -> None:
        """EventEnricher without db returns event without error."""
        enricher = EventEnricher(db=None)
        event = _make_event(data={"dst_ip": "1.2.3.4"})
        result = enricher.enrich(event)

        assert result is event
        assert "_ioc_match" not in event.data

    def test_enriched_event_preserves_data(
        self, db: AegisDatabase,
    ) -> None:
        """Original data keys survive enrichment."""
        enricher = EventEnricher(db=db)
        event = _make_event(
            data={"dst_ip": "8.8.8.8", "custom_key": "value"},
        )
        enricher.enrich(event)

        assert event.data["custom_key"] == "value"
        assert event.data["dst_ip"] == "8.8.8.8"

    def test_multiple_enrichment_types(
        self, db: AegisDatabase,
    ) -> None:
        """Event with both IP and domain gets both enriched."""
        db.upsert_ioc(
            "ipv4-addr", "10.10.10.10", "feed-a", "medium",
        )
        db.upsert_ioc(
            "domain-name", "evil.example.com", "feed-b", "high",
        )
        enricher = EventEnricher(db=db)
        event = _make_event(
            data={
                "dst_ip": "10.10.10.10",
                "domain": "evil.example.com",
            },
        )
        enricher.enrich(event)

        assert event.data["_ioc_match"] is True
        # At least one source is recorded
        assert event.data.get("_ioc_source") in (
            "feed-a", "feed-b",
        )

    def test_enrichment_stats_tracking(
        self, db: AegisDatabase,
    ) -> None:
        """get_stats() reflects enrichment activity."""
        db.upsert_ioc(
            "ipv4-addr", "172.16.0.1", "test", "low",
        )
        enricher = EventEnricher(db=db)
        enricher.enrich(
            _make_event(data={"dst_ip": "172.16.0.1"}),
        )
        enricher.enrich(
            _make_event(data={"dst_ip": "172.16.0.2"}),
        )

        stats = enricher.get_stats()
        assert stats["events_enriched"] == 2
        assert stats["ioc_matches_found"] >= 1
        assert stats["reputation_lookups"] >= 1

    def test_enrichment_idempotent(
        self, db: AegisDatabase,
    ) -> None:
        """Enriching the same event twice doesn't duplicate fields."""
        db.upsert_ioc(
            "ipv4-addr", "203.0.113.5", "test", "medium",
        )
        enricher = EventEnricher(db=db)
        event = _make_event(data={"dst_ip": "203.0.113.5"})
        enricher.enrich(event)
        enricher.enrich(event)

        # _ioc_match should still be a single boolean, not a list
        assert event.data["_ioc_match"] is True
        assert isinstance(event.data["_ioc_source"], str)


# ------------------------------------------------------------------ #
# TestWhitelistPipelineIntegration
# ------------------------------------------------------------------ #


class TestWhitelistPipelineIntegration:
    """Whitelist suppression inside the detection pipeline."""

    def test_whitelisted_event_suppressed(self) -> None:
        """Whitelisted process event returns [] from pipeline."""
        wlm = WhitelistManager()
        wlm.add_entry(
            WhitelistType.PROCESS,
            "C:\\Windows\\explorer.exe",
        )
        # Use a mock rule engine that always produces an alert
        rule_engine = MagicMock()
        rule_match = MagicMock()
        rule_match.rule_id = "test_rule"
        rule_match.description = "Test"
        rule_match.severity = Severity.HIGH
        rule_match.mitre_ids = []
        rule_engine.evaluate.return_value = [rule_match]

        pipeline = DetectionPipeline(
            whitelist_manager=wlm,
            rule_engine=rule_engine,
        )
        event = _make_event(
            sensor=SensorType.PROCESS,
            data={"exe": "C:\\Windows\\explorer.exe"},
        )
        alerts = pipeline.process_event(event)
        assert alerts == []

    def test_non_whitelisted_event_passes(self) -> None:
        """Non-whitelisted event reaches detection engines."""
        wlm = WhitelistManager()
        wlm.add_entry(
            WhitelistType.PROCESS,
            "C:\\Windows\\explorer.exe",
        )
        rule_engine = MagicMock()
        rule_match = MagicMock()
        rule_match.rule_id = "r1"
        rule_match.description = "Malicious"
        rule_match.severity = Severity.HIGH
        rule_match.mitre_ids = []
        rule_engine.evaluate.return_value = [rule_match]

        pipeline = DetectionPipeline(
            whitelist_manager=wlm,
            rule_engine=rule_engine,
        )
        event = _make_event(
            sensor=SensorType.PROCESS,
            data={"exe": "C:\\evil.exe"},
        )
        alerts = pipeline.process_event(event)
        assert len(alerts) >= 1

    def test_whitelist_ip_suppression(self) -> None:
        """Whitelisted IP suppresses network event."""
        wlm = WhitelistManager()
        wlm.add_entry(WhitelistType.IP, "192.168.1.1")

        rule_engine = MagicMock()
        rule_match = MagicMock()
        rule_match.rule_id = "r_net"
        rule_match.description = "Net alert"
        rule_match.severity = Severity.MEDIUM
        rule_match.mitre_ids = []
        rule_engine.evaluate.return_value = [rule_match]

        pipeline = DetectionPipeline(
            whitelist_manager=wlm,
            rule_engine=rule_engine,
        )
        event = _make_event(
            data={"dst_ip": "192.168.1.1"},
        )
        alerts = pipeline.process_event(event)
        assert alerts == []

    def test_whitelist_domain_suppression(self) -> None:
        """Whitelisted domain suppresses event."""
        wlm = WhitelistManager()
        wlm.add_entry(
            WhitelistType.DOMAIN, "safe.example.com",
        )

        rule_engine = MagicMock()
        rule_match = MagicMock()
        rule_match.rule_id = "r_dns"
        rule_match.description = "DNS alert"
        rule_match.severity = Severity.MEDIUM
        rule_match.mitre_ids = []
        rule_engine.evaluate.return_value = [rule_match]

        pipeline = DetectionPipeline(
            whitelist_manager=wlm,
            rule_engine=rule_engine,
        )
        event = _make_event(
            data={"domain": "safe.example.com"},
        )
        alerts = pipeline.process_event(event)
        assert alerts == []

    def test_pipeline_without_whitelist(self) -> None:
        """Pipeline without whitelist_manager processes normally."""
        rule_engine = MagicMock()
        rule_match = MagicMock()
        rule_match.rule_id = "r1"
        rule_match.description = "Alert"
        rule_match.severity = Severity.MEDIUM
        rule_match.mitre_ids = []
        rule_engine.evaluate.return_value = [rule_match]

        pipeline = DetectionPipeline(rule_engine=rule_engine)
        event = _make_event(
            data={"exe": "C:\\Windows\\explorer.exe"},
        )
        alerts = pipeline.process_event(event)
        assert len(alerts) >= 1

    def test_whitelist_disabled_in_pipeline(self) -> None:
        """Pipeline constructed without whitelist passes events."""
        pipeline = DetectionPipeline()
        event = _make_event(
            data={"exe": "C:\\anything.exe"},
        )
        alerts = pipeline.process_event(event)
        # No engines configured, so no alerts — but no crash
        assert alerts == []


# ------------------------------------------------------------------ #
# TestIncidentPersistence
# ------------------------------------------------------------------ #


class TestIncidentPersistence:
    """Alerts -> correlation -> incidents stored in DB."""

    def test_single_alert_creates_incident(
        self, db: AegisDatabase,
    ) -> None:
        """process_alert creates an incident in the engine."""
        engine = CorrelationEngine(min_alerts_for_incident=1)
        store = IncidentStore(engine, db=db)
        alert = _make_alert(data={"dst_ip": "10.0.0.1"})
        incident = store.process_alert(alert)

        assert incident is not None
        assert incident.incident_id.startswith("inc-")

    def test_incident_persisted_to_db(
        self, db: AegisDatabase,
    ) -> None:
        """After process_alert, db.get_incident() returns data."""
        engine = CorrelationEngine(min_alerts_for_incident=1)
        store = IncidentStore(engine, db=db)
        alert = _make_alert(data={"dst_ip": "10.0.0.2"})
        incident = store.process_alert(alert)
        assert incident is not None

        row = db.get_incident(incident.incident_id)
        assert row is not None
        assert row["incident_id"] == incident.incident_id
        assert row["status"] == "open"

    def test_alert_linked_to_incident(
        self, db: AegisDatabase,
    ) -> None:
        """db.get_incident_alerts() returns the alert_id."""
        engine = CorrelationEngine(min_alerts_for_incident=1)
        store = IncidentStore(engine, db=db)
        alert = _make_alert(data={"dst_ip": "10.0.0.3"})
        incident = store.process_alert(alert)
        assert incident is not None

        linked = db.get_incident_alerts(incident.incident_id)
        assert alert.alert_id in linked

    def test_multiple_alerts_same_incident(
        self, db: AegisDatabase,
    ) -> None:
        """Two alerts with same entity go to the same incident."""
        engine = CorrelationEngine(
            time_window=300, min_alerts_for_incident=1,
        )
        store = IncidentStore(engine, db=db)
        a1 = _make_alert(data={"dst_ip": "10.0.0.4"})
        a2 = _make_alert(data={"dst_ip": "10.0.0.4"})
        inc1 = store.process_alert(a1)
        inc2 = store.process_alert(a2)

        assert inc1 is not None and inc2 is not None
        assert inc1.incident_id == inc2.incident_id
        linked = db.get_incident_alerts(inc1.incident_id)
        assert a1.alert_id in linked
        assert a2.alert_id in linked

    def test_incident_close_persists(
        self, db: AegisDatabase,
    ) -> None:
        """close_incident updates DB status."""
        engine = CorrelationEngine(min_alerts_for_incident=1)
        store = IncidentStore(engine, db=db)
        alert = _make_alert(data={"dst_ip": "10.0.0.5"})
        incident = store.process_alert(alert)
        assert incident is not None

        closed = store.close_incident(incident.incident_id)
        assert closed is True

        row = db.get_incident(incident.incident_id)
        assert row is not None
        assert row["status"] == "closed"

    def test_sync_from_engine(
        self, db: AegisDatabase,
    ) -> None:
        """sync_from_engine persists all engine incidents to DB."""
        engine = CorrelationEngine(
            time_window=0.001, min_alerts_for_incident=1,
        )
        # Use store without DB first to accumulate in-memory
        store = IncidentStore(engine, db=None)
        a1 = _make_alert(data={"dst_ip": "10.1.1.1"})
        a1.sensor = SensorType.NETWORK
        a1.timestamp = time.time() - 1000
        store.process_alert(a1)

        a2 = _make_alert(data={"dst_ip": "10.2.2.2"})
        a2.sensor = SensorType.FILE
        a2.timestamp = time.time()
        store.process_alert(a2)

        # Attach DB and sync
        store._db = db
        store._known_incidents.clear()
        synced = store.sync_from_engine()

        assert synced >= 2
        assert db.incident_count() >= 2

    def test_incident_severity_escalation(
        self, db: AegisDatabase,
    ) -> None:
        """Higher severity alert escalates incident severity."""
        engine = CorrelationEngine(
            time_window=300, min_alerts_for_incident=1,
        )
        store = IncidentStore(engine, db=db)
        a1 = _make_alert(
            severity=Severity.LOW, data={"dst_ip": "10.0.0.6"},
        )
        inc = store.process_alert(a1)
        assert inc is not None
        assert inc.severity == Severity.LOW

        a2 = _make_alert(
            severity=Severity.CRITICAL,
            data={"dst_ip": "10.0.0.6"},
        )
        inc2 = store.process_alert(a2)
        assert inc2 is not None
        assert inc2.severity == Severity.CRITICAL

    def test_incident_stats_accurate(
        self, db: AegisDatabase,
    ) -> None:
        """get_stats() matches actual state."""
        engine = CorrelationEngine(
            time_window=0.001, min_alerts_for_incident=1,
        )
        store = IncidentStore(engine, db=db)
        a1 = _make_alert(data={"dst_ip": "10.3.0.1"})
        a1.sensor = SensorType.NETWORK
        a1.timestamp = time.time() - 1000
        store.process_alert(a1)

        a2 = _make_alert(data={"dst_ip": "10.3.0.2"})
        a2.sensor = SensorType.FILE
        a2.timestamp = time.time()
        store.process_alert(a2)

        stats = store.get_stats()
        assert stats["total_incidents"] >= 2
        assert stats["active_incidents"] >= 2
        assert stats["db_incidents"] >= 2


# ------------------------------------------------------------------ #
# TestSchedulerIntegration
# ------------------------------------------------------------------ #


class TestSchedulerIntegration:
    """Scheduler with real callbacks."""

    def test_retention_cleanup_fires(
        self, db: AegisDatabase,
    ) -> None:
        """Retention task purges old events when ticked."""
        old_event = _make_event()
        # Backdate the event by 100 days
        old_event.timestamp = time.time() - (100 * 86400)
        db.insert_event(old_event)
        assert db.event_count() == 1

        scheduler = TaskScheduler()
        scheduler.add_task(
            name="retention_cleanup",
            callback=lambda: db.purge_old_events(90),
            interval_seconds=86400,
        )
        scheduler.tick(now=time.time())

        assert db.event_count() == 0

    def test_scheduler_tick_executes_tasks(self) -> None:
        """add_task + tick with correct timestamp runs callback."""
        results: list[str] = []
        scheduler = TaskScheduler()
        scheduler.add_task(
            name="test_task",
            callback=lambda: results.append("ran"),
            interval_seconds=60,
        )
        scheduler.tick(now=time.time())

        assert results == ["ran"]

    def test_multiple_tasks_fire(self) -> None:
        """Three tasks all fire on a single tick."""
        counter: dict[str, int] = {"a": 0, "b": 0, "c": 0}
        scheduler = TaskScheduler()
        scheduler.add_task(
            "task_a", lambda: counter.__setitem__("a", 1), 10,
        )
        scheduler.add_task(
            "task_b", lambda: counter.__setitem__("b", 1), 10,
        )
        scheduler.add_task(
            "task_c", lambda: counter.__setitem__("c", 1), 10,
        )

        scheduler.tick(now=time.time())
        assert counter == {"a": 1, "b": 1, "c": 1}

    def test_disabled_task_skipped(self) -> None:
        """Disabled task is not executed on tick."""
        called = {"flag": False}
        scheduler = TaskScheduler()
        task = scheduler.add_task(
            "skip_me",
            lambda: called.__setitem__("flag", True),
            10,
        )
        scheduler.disable_task(task.task_id)
        scheduler.tick(now=time.time())

        assert called["flag"] is False

    def test_scheduler_error_handling(self) -> None:
        """Task that raises does not prevent other tasks."""
        ok_ran = {"value": False}

        def bad_task() -> None:
            raise RuntimeError("boom")

        scheduler = TaskScheduler()
        scheduler.add_task("bad", bad_task, 10)
        scheduler.add_task(
            "good",
            lambda: ok_ran.__setitem__("value", True),
            10,
        )
        results = scheduler.tick(now=time.time())

        assert ok_ran["value"] is True
        assert any(not r.success for r in results)
        assert any(r.success for r in results)

    def test_scheduler_stats(self) -> None:
        """get_stats() after tick reflects execution counts."""
        scheduler = TaskScheduler()
        scheduler.add_task("s1", lambda: None, 60)
        scheduler.add_task("s2", lambda: None, 60)
        scheduler.tick(now=time.time())

        stats = scheduler.get_stats()
        assert stats["task_count"] == 2
        assert stats["total_runs"] == 2
        assert stats["total_errors"] == 0


# ------------------------------------------------------------------ #
# TestCanaryIntegration
# ------------------------------------------------------------------ #


class TestCanaryIntegration:
    """Canary deployment and verification with real files."""

    def test_canary_deploy(self, tmp_path: Path) -> None:
        """Deploy canaries, verify files exist."""
        canary_dir = tmp_path / "canary_target"
        canary_dir.mkdir()
        cfg = CanaryConfig(
            directories=[canary_dir],
            file_types=[".txt"],
            files_per_directory=1,
        )
        system = CanaryDeploymentSystem(cfg)
        deployed = system.deploy_all()

        assert len(deployed) >= 1
        for c in deployed:
            assert c.path.exists()

    def test_canary_verify_healthy(self, tmp_path: Path) -> None:
        """Deploy then verify_all returns empty (no triggers)."""
        canary_dir = tmp_path / "healthy_dir"
        canary_dir.mkdir()
        cfg = CanaryConfig(
            directories=[canary_dir],
            file_types=[".txt"],
            files_per_directory=1,
        )
        system = CanaryDeploymentSystem(cfg)
        system.deploy_all()
        triggered = system.verify_all()

        assert triggered == []

    def test_canary_trigger_on_modify(
        self, tmp_path: Path,
    ) -> None:
        """Modifying a canary file triggers on verify_all."""
        canary_dir = tmp_path / "modify_dir"
        canary_dir.mkdir()
        cfg = CanaryConfig(
            directories=[canary_dir],
            file_types=[".txt"],
            files_per_directory=1,
        )
        system = CanaryDeploymentSystem(cfg)
        deployed = system.deploy_all()
        assert len(deployed) >= 1

        # Modify the first canary file
        deployed[0].path.write_text("hacked by ransomware")
        triggered = system.verify_all()

        assert len(triggered) >= 1
        assert triggered[0].status == "triggered"
        assert "modified" in triggered[0].trigger_reason.lower()

    def test_canary_trigger_on_delete(
        self, tmp_path: Path,
    ) -> None:
        """Deleting a canary file triggers on verify_all."""
        canary_dir = tmp_path / "delete_dir"
        canary_dir.mkdir()
        cfg = CanaryConfig(
            directories=[canary_dir],
            file_types=[".txt"],
            files_per_directory=1,
        )
        system = CanaryDeploymentSystem(cfg)
        deployed = system.deploy_all()
        assert len(deployed) >= 1

        deployed[0].path.unlink()
        triggered = system.verify_all()

        assert len(triggered) >= 1
        assert triggered[0].status == "missing"
        assert "deleted" in triggered[0].trigger_reason.lower()

    def test_canary_to_events(self, tmp_path: Path) -> None:
        """Triggered canaries convert to CRITICAL events."""
        canary_dir = tmp_path / "events_dir"
        canary_dir.mkdir()
        cfg = CanaryConfig(
            directories=[canary_dir],
            file_types=[".txt"],
            files_per_directory=1,
        )
        system = CanaryDeploymentSystem(cfg)
        deployed = system.deploy_all()
        assert len(deployed) >= 1

        deployed[0].path.unlink()
        triggered = system.verify_all()
        events = system.to_events(triggered)

        assert len(events) >= 1
        assert events[0].severity == Severity.CRITICAL
        assert events[0].event_type == "canary_triggered"
        assert events[0].sensor == SensorType.FILE
        assert "canary_id" in events[0].data


# ------------------------------------------------------------------ #
# TestCoordinatorLifecycle
# ------------------------------------------------------------------ #


class TestCoordinatorLifecycle:
    """Full coordinator setup / start / stop cycle."""

    def test_coordinator_setup_all_components(
        self, config: AegisConfig,
    ) -> None:
        """setup() creates all core components."""
        coordinator = AegisCoordinator(config)
        coordinator.setup()

        assert coordinator.db is not None
        assert coordinator.enricher is not None
        assert coordinator.scheduler is not None

    def test_coordinator_scheduled_tasks_registered(
        self, config: AegisConfig,
    ) -> None:
        """After setup, scheduler has tasks."""
        coordinator = AegisCoordinator(config)
        coordinator.setup()

        tasks = coordinator.scheduler.list_tasks()
        assert len(tasks) >= 1
        task_names = [t.name for t in tasks]
        assert "retention_cleanup" in task_names

    def test_coordinator_db_has_incident_tables(
        self, config: AegisConfig,
    ) -> None:
        """After setup, DB tables include incidents."""
        coordinator = AegisCoordinator(config)
        coordinator.setup()

        tables = coordinator.db.list_tables()
        assert "incidents" in tables
        assert "incident_alerts" in tables

    def test_coordinator_stop_is_clean(
        self, config: AegisConfig,
    ) -> None:
        """stop() does not raise."""
        coordinator = AegisCoordinator(config)
        coordinator.setup()

        with patch.object(coordinator._engine, "start"):
            with patch.object(coordinator._engine, "stop"):
                coordinator.start()
                coordinator.stop()

    def test_coordinator_double_stop(
        self, config: AegisConfig,
    ) -> None:
        """Calling stop() twice is safe."""
        coordinator = AegisCoordinator(config)
        coordinator.setup()

        with patch.object(coordinator._engine, "start"):
            with patch.object(coordinator._engine, "stop"):
                coordinator.start()
                coordinator.stop()
                coordinator.stop()


# ------------------------------------------------------------------ #
# TestDatabaseIncidentCRUD
# ------------------------------------------------------------------ #


class TestDatabaseIncidentCRUD:
    """Direct incident DB method tests."""

    def test_insert_and_get_incident(
        self, db: AegisDatabase,
    ) -> None:
        """Insert then get verifies all fields."""
        now = time.time()
        db.insert_incident(
            incident_id="inc-abc123",
            title="Test Incident",
            severity="high",
            status="open",
            mitre_chain=["T1059"],
            entities=["ip:10.0.0.1"],
            first_seen=now,
            last_seen=now,
        )
        row = db.get_incident("inc-abc123")

        assert row is not None
        assert row["incident_id"] == "inc-abc123"
        assert row["title"] == "Test Incident"
        assert row["severity"] == "high"
        assert row["status"] == "open"
        assert row["mitre_chain"] == ["T1059"]
        assert row["entities"] == ["ip:10.0.0.1"]

    def test_update_incident(self, db: AegisDatabase) -> None:
        """Insert, update title + severity, verify."""
        now = time.time()
        db.insert_incident(
            incident_id="inc-upd001",
            title="Original",
            severity="low",
            status="open",
            mitre_chain=[],
            entities=[],
            first_seen=now,
            last_seen=now,
        )
        ok = db.update_incident(
            "inc-upd001",
            title="Updated Title",
            severity="critical",
        )
        assert ok is True

        row = db.get_incident("inc-upd001")
        assert row is not None
        assert row["title"] == "Updated Title"
        assert row["severity"] == "critical"

    def test_query_incidents_by_status(
        self, db: AegisDatabase,
    ) -> None:
        """Insert 3 with different statuses, query by status."""
        now = time.time()
        for iid, status in [
            ("inc-s1", "open"),
            ("inc-s2", "open"),
            ("inc-s3", "closed"),
        ]:
            db.insert_incident(
                incident_id=iid,
                title=f"Incident {iid}",
                severity="medium",
                status=status,
                mitre_chain=[],
                entities=[],
                first_seen=now,
                last_seen=now,
            )

        open_list = db.query_incidents(status="open")
        closed_list = db.query_incidents(status="closed")

        assert len(open_list) == 2
        assert len(closed_list) == 1
        assert closed_list[0]["incident_id"] == "inc-s3"
