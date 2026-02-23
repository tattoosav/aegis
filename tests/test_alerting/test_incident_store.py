"""Tests for the IncidentStore persistence layer.

Validates that IncidentStore correctly wraps the CorrelationEngine
with AegisDatabase persistence, handles graceful degradation when
no database is available, and maintains correct incident lifecycle
through process_alert, close, sync, and stats operations.
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import patch

import pytest

from aegis.alerting.correlation_engine import (
    CorrelationEngine,
    Incident,
    IncidentStatus,
)
from aegis.alerting.incident_store import IncidentStore
from aegis.core.database import AegisDatabase
from aegis.core.models import Alert, SensorType, Severity

# ------------------------------------------------------------------ #
#  Helper
# ------------------------------------------------------------------ #

def _make_alert(
    alert_type: str = "test.alert",
    severity: Severity = Severity.MEDIUM,
    sensor: SensorType = SensorType.PROCESS,
    data: dict | None = None,
    mitre_ids: list[str] | None = None,
) -> Alert:
    """Create a test Alert with sensible defaults."""
    return Alert(
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        sensor=sensor,
        alert_type=alert_type,
        severity=severity,
        title=f"Test alert: {alert_type}",
        description="Test alert description",
        confidence=0.9,
        data=data or {},
        mitre_ids=mitre_ids or [],
    )


# ------------------------------------------------------------------ #
#  Fixtures
# ------------------------------------------------------------------ #

@pytest.fixture()
def db(tmp_path) -> AegisDatabase:
    """Create a temporary AegisDatabase for testing."""
    return AegisDatabase(tmp_path / "test.db")


@pytest.fixture()
def engine() -> CorrelationEngine:
    """Create a CorrelationEngine with default time window."""
    return CorrelationEngine(time_window=300)


@pytest.fixture()
def store(engine: CorrelationEngine, db: AegisDatabase) -> IncidentStore:
    """Create an IncidentStore backed by engine and database."""
    return IncidentStore(engine, db)


@pytest.fixture()
def store_no_db(engine: CorrelationEngine) -> IncidentStore:
    """Create an IncidentStore without database persistence."""
    return IncidentStore(engine)


# ------------------------------------------------------------------ #
#  TestIncidentStoreInit
# ------------------------------------------------------------------ #

class TestIncidentStoreInit:
    """Verify initial state of a newly-created IncidentStore."""

    def test_init_with_db(
        self, engine: CorrelationEngine, db: AegisDatabase,
    ) -> None:
        """IncidentStore(engine, db) sets both engine and db."""
        store = IncidentStore(engine, db)
        assert store._engine is engine
        assert store._db is db

    def test_init_without_db(
        self, engine: CorrelationEngine,
    ) -> None:
        """IncidentStore(engine) works with db defaulting to None."""
        store = IncidentStore(engine)
        assert store._engine is engine
        assert store._db is None

    def test_known_incidents_empty(
        self, store: IncidentStore,
    ) -> None:
        """_known_incidents starts as an empty set."""
        assert store._known_incidents == set()
        assert len(store._known_incidents) == 0


# ------------------------------------------------------------------ #
#  TestProcessAlert
# ------------------------------------------------------------------ #

class TestProcessAlert:
    """Tests for IncidentStore.process_alert()."""

    def test_process_alert_creates_incident(
        self, store: IncidentStore,
    ) -> None:
        """Ingesting a single alert returns an Incident."""
        alert = _make_alert(data={"pid": 1001})
        incident = store.process_alert(alert)

        assert incident is not None
        assert isinstance(incident, Incident)
        assert incident.alert_count == 1
        assert incident.status == IncidentStatus.OPEN

    def test_process_alert_persists_to_db(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """After process_alert, the incident exists in the database."""
        alert = _make_alert(data={"pid": 2002})
        incident = store.process_alert(alert)

        assert incident is not None
        row = db.get_incident(incident.incident_id)
        assert row is not None
        assert row["incident_id"] == incident.incident_id
        assert row["status"] == "open"

    def test_process_alert_links_alert_to_incident(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """The alert_id is linked to the incident in the DB."""
        alert = _make_alert(data={"pid": 3003})
        incident = store.process_alert(alert)

        assert incident is not None
        linked = db.get_incident_alerts(incident.incident_id)
        assert alert.alert_id in linked

    def test_process_alert_updates_existing_incident(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """Two related alerts go into the same incident; DB updated."""
        now = time.time()
        a1 = _make_alert(data={"pid": 4004}, severity=Severity.LOW)
        a1.timestamp = now
        a2 = _make_alert(data={"pid": 4004}, severity=Severity.HIGH)
        a2.timestamp = now + 1

        inc1 = store.process_alert(a1)
        inc2 = store.process_alert(a2)

        assert inc1 is not None and inc2 is not None
        assert inc1.incident_id == inc2.incident_id
        assert inc1.alert_count == 2

        row = db.get_incident(inc1.incident_id)
        assert row is not None
        assert row["severity"] == "high"

    def test_process_alert_without_db(
        self, store_no_db: IncidentStore,
    ) -> None:
        """process_alert works in-memory when no DB is configured."""
        alert = _make_alert(data={"pid": 5005})
        incident = store_no_db.process_alert(alert)

        assert incident is not None
        assert incident.alert_count == 1

    def test_process_alert_returns_none_when_engine_returns_none(
        self, store: IncidentStore,
    ) -> None:
        """When engine.ingest_alert returns None, process_alert does too."""
        with patch.object(
            store._engine, "ingest_alert", return_value=None,
        ):
            alert = _make_alert()
            result = store.process_alert(alert)
            assert result is None

    def test_process_multiple_alerts(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """Processing 3 related alerts creates one incident with all linked."""
        now = time.time()
        alerts = []
        for i in range(3):
            a = _make_alert(data={"pid": 6006})
            a.timestamp = now + i
            alerts.append(a)

        incidents = [store.process_alert(a) for a in alerts]

        # All should return the same incident
        assert all(inc is not None for inc in incidents)
        assert incidents[0].incident_id == incidents[1].incident_id
        assert incidents[1].incident_id == incidents[2].incident_id

        linked = db.get_incident_alerts(incidents[0].incident_id)
        for a in alerts:
            assert a.alert_id in linked

    def test_process_alert_db_insert_failure(
        self, engine: CorrelationEngine, db: AegisDatabase,
    ) -> None:
        """If DB insert raises, process_alert still returns the incident."""
        store = IncidentStore(engine, db)
        alert = _make_alert(data={"pid": 7007})

        with patch.object(
            db, "insert_incident", side_effect=RuntimeError("DB error"),
        ):
            incident = store.process_alert(alert)

        # Incident returned despite DB failure (graceful degradation)
        assert incident is not None
        assert incident.alert_count == 1

    def test_process_alert_tracks_known_incidents(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """Second call for same incident triggers update, not insert."""
        now = time.time()
        a1 = _make_alert(data={"pid": 8008})
        a1.timestamp = now
        a2 = _make_alert(data={"pid": 8008})
        a2.timestamp = now + 1

        store.process_alert(a1)
        assert len(store._known_incidents) == 1

        # Second alert for same incident: should update, not insert
        with patch.object(db, "insert_incident") as mock_insert:
            store.process_alert(a2)
            mock_insert.assert_not_called()

    def test_process_alert_mitre_chain_persisted(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """MITRE technique IDs are persisted to the database."""
        alert = _make_alert(
            data={"pid": 8888},
            mitre_ids=["T1059", "T1547"],
        )
        incident = store.process_alert(alert)

        assert incident is not None
        row = db.get_incident(incident.incident_id)
        assert row is not None
        assert "T1059" in row["mitre_chain"]
        assert "T1547" in row["mitre_chain"]

    def test_process_alert_severity_escalation(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """When second alert has higher severity, incident is updated."""
        now = time.time()
        a1 = _make_alert(
            data={"pid": 9009}, severity=Severity.LOW,
        )
        a1.timestamp = now
        a2 = _make_alert(
            data={"pid": 9009}, severity=Severity.CRITICAL,
        )
        a2.timestamp = now + 1

        inc = store.process_alert(a1)
        store.process_alert(a2)

        assert inc is not None
        assert inc.severity == Severity.CRITICAL

        row = db.get_incident(inc.incident_id)
        assert row is not None
        assert row["severity"] == "critical"


# ------------------------------------------------------------------ #
#  TestGetIncident
# ------------------------------------------------------------------ #

class TestGetIncident:
    """Tests for IncidentStore.get_incident()."""

    def test_get_existing_incident(
        self, store: IncidentStore,
    ) -> None:
        """get_incident returns a previously processed incident."""
        alert = _make_alert(data={"pid": 1100})
        incident = store.process_alert(alert)

        assert incident is not None
        fetched = store.get_incident(incident.incident_id)
        assert fetched is incident

    def test_get_nonexistent_incident(
        self, store: IncidentStore,
    ) -> None:
        """get_incident returns None for unknown ID."""
        result = store.get_incident("inc-does-not-exist")
        assert result is None

    def test_get_incident_delegates_to_engine(
        self, store: IncidentStore,
    ) -> None:
        """get_incident calls engine.get_incident with the ID."""
        with patch.object(
            store._engine,
            "get_incident",
            return_value=None,
        ) as mock_get:
            store.get_incident("inc-test123")
            mock_get.assert_called_once_with("inc-test123")


# ------------------------------------------------------------------ #
#  TestGetActiveIncidents
# ------------------------------------------------------------------ #

class TestGetActiveIncidents:
    """Tests for IncidentStore.get_active_incidents()."""

    def test_get_active_incidents_empty(
        self, store: IncidentStore,
    ) -> None:
        """No alerts processed means empty active list."""
        result = store.get_active_incidents()
        assert result == []

    def test_get_active_incidents_after_alerts(
        self, store: IncidentStore,
    ) -> None:
        """After processing alerts, active incidents are returned."""
        now = time.time()
        a1 = _make_alert(
            data={"pid": 2200}, sensor=SensorType.FILE,
        )
        a1.timestamp = now
        a2 = _make_alert(
            data={"pid": 3300}, sensor=SensorType.NETWORK,
        )
        a2.timestamp = now + 1

        store.process_alert(a1)
        store.process_alert(a2)

        active = store.get_active_incidents()
        assert len(active) == 2
        assert all(
            inc.status == IncidentStatus.OPEN for inc in active
        )

    def test_get_active_excludes_closed(
        self, store: IncidentStore,
    ) -> None:
        """Closed incidents are excluded from active list."""
        now = time.time()
        a1 = _make_alert(
            data={"pid": 4400}, sensor=SensorType.FILE,
        )
        a1.timestamp = now
        a2 = _make_alert(
            data={"pid": 5500}, sensor=SensorType.NETWORK,
        )
        a2.timestamp = now + 1

        inc1 = store.process_alert(a1)
        inc2 = store.process_alert(a2)

        assert inc1 is not None and inc2 is not None
        store.close_incident(inc1.incident_id)

        active = store.get_active_incidents()
        active_ids = [i.incident_id for i in active]
        assert inc1.incident_id not in active_ids
        assert inc2.incident_id in active_ids

    def test_get_active_returns_incident_objects(
        self, store: IncidentStore,
    ) -> None:
        """Returned items are Incident instances with OPEN status."""
        alert = _make_alert(data={"pid": 6600})
        store.process_alert(alert)

        active = store.get_active_incidents()
        assert len(active) == 1
        assert isinstance(active[0], Incident)
        assert active[0].status == IncidentStatus.OPEN


# ------------------------------------------------------------------ #
#  TestCloseIncident
# ------------------------------------------------------------------ #

class TestCloseIncident:
    """Tests for IncidentStore.close_incident()."""

    def test_close_incident_success(
        self, store: IncidentStore,
    ) -> None:
        """Closing an open incident returns True."""
        alert = _make_alert(data={"pid": 1010})
        incident = store.process_alert(alert)
        assert incident is not None

        result = store.close_incident(incident.incident_id)
        assert result is True
        assert incident.status == IncidentStatus.CLOSED

    def test_close_incident_updates_db(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """After close, the DB shows status='closed'."""
        alert = _make_alert(data={"pid": 2020})
        incident = store.process_alert(alert)
        assert incident is not None

        store.close_incident(incident.incident_id)

        row = db.get_incident(incident.incident_id)
        assert row is not None
        assert row["status"] == "closed"

    def test_close_incident_nonexistent(
        self, store: IncidentStore,
    ) -> None:
        """Closing a non-existent incident returns False."""
        result = store.close_incident("inc-nonexistent")
        assert result is False

    def test_close_without_db(
        self, store_no_db: IncidentStore,
    ) -> None:
        """Closing works in engine-only mode (no DB)."""
        alert = _make_alert(data={"pid": 3030})
        incident = store_no_db.process_alert(alert)
        assert incident is not None

        result = store_no_db.close_incident(incident.incident_id)
        assert result is True
        assert incident.status == IncidentStatus.CLOSED

    def test_close_already_closed_returns_false(
        self, store: IncidentStore,
    ) -> None:
        """Closing an already-closed incident returns False."""
        alert = _make_alert(data={"pid": 5050})
        incident = store.process_alert(alert)
        assert incident is not None

        store.close_incident(incident.incident_id)
        result = store.close_incident(incident.incident_id)
        assert result is False

    def test_close_incident_db_failure(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """If db.update_incident raises, close still returns True."""
        alert = _make_alert(data={"pid": 4040})
        incident = store.process_alert(alert)
        assert incident is not None

        with patch.object(
            db, "update_incident",
            side_effect=RuntimeError("DB write error"),
        ):
            result = store.close_incident(incident.incident_id)

        assert result is True
        assert incident.status == IncidentStatus.CLOSED


# ------------------------------------------------------------------ #
#  TestSyncFromEngine
# ------------------------------------------------------------------ #

class TestSyncFromEngine:
    """Tests for IncidentStore.sync_from_engine()."""

    def test_sync_persists_all_incidents(
        self,
        engine: CorrelationEngine,
        db: AegisDatabase,
    ) -> None:
        """All in-memory incidents are persisted after sync."""
        # Build incidents directly in the engine first
        now = time.time()
        for i, sensor in enumerate(
            [SensorType.PROCESS, SensorType.FILE, SensorType.NETWORK],
        ):
            a = _make_alert(data={"pid": 100 + i}, sensor=sensor)
            a.timestamp = now + i
            engine.ingest_alert(a)

        assert engine.incident_count == 3

        # Create store fresh (nothing in _known_incidents)
        store = IncidentStore(engine, db)
        synced = store.sync_from_engine()

        assert synced == 3
        assert db.incident_count() == 3

    def test_sync_persists_alert_linkages(
        self,
        engine: CorrelationEngine,
        db: AegisDatabase,
    ) -> None:
        """Alert-to-incident links are persisted during sync."""
        now = time.time()
        a1 = _make_alert(data={"pid": 200})
        a1.timestamp = now
        a2 = _make_alert(data={"pid": 200})
        a2.timestamp = now + 1

        engine.ingest_alert(a1)
        engine.ingest_alert(a2)

        store = IncidentStore(engine, db)
        store.sync_from_engine()

        incidents = engine.get_all_incidents()
        assert len(incidents) == 1
        linked = db.get_incident_alerts(incidents[0].incident_id)
        assert a1.alert_id in linked
        assert a2.alert_id in linked

    def test_sync_returns_count(
        self,
        engine: CorrelationEngine,
        db: AegisDatabase,
    ) -> None:
        """sync_from_engine returns the number of incidents synced."""
        now = time.time()
        for i, sensor in enumerate(
            [SensorType.FILE, SensorType.NETWORK],
        ):
            a = _make_alert(data={"pid": 300 + i}, sensor=sensor)
            a.timestamp = now + i
            engine.ingest_alert(a)

        store = IncidentStore(engine, db)
        count = store.sync_from_engine()
        assert count == engine.incident_count

    def test_sync_without_db_returns_zero(
        self, store_no_db: IncidentStore,
    ) -> None:
        """sync_from_engine returns 0 when no DB is configured."""
        alert = _make_alert(data={"pid": 400})
        store_no_db.process_alert(alert)

        result = store_no_db.sync_from_engine()
        assert result == 0

    def test_sync_handles_db_errors(
        self,
        engine: CorrelationEngine,
        db: AegisDatabase,
    ) -> None:
        """If one incident fails to persist, others still sync."""
        now = time.time()
        for i, sensor in enumerate(
            [SensorType.PROCESS, SensorType.FILE, SensorType.NETWORK],
        ):
            a = _make_alert(data={"pid": 500 + i}, sensor=sensor)
            a.timestamp = now + i
            engine.ingest_alert(a)

        store = IncidentStore(engine, db)

        original_persist = store._persist_incident
        call_count = 0

        def failing_persist(incident):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise RuntimeError("Persist error on second")
            return original_persist(incident)

        with patch.object(
            store, "_persist_incident", side_effect=failing_persist,
        ):
            synced = store.sync_from_engine()

        # One failed, two succeeded
        assert synced == 2

    def test_sync_idempotent(
        self,
        engine: CorrelationEngine,
        db: AegisDatabase,
    ) -> None:
        """Syncing twice does not create duplicate DB rows."""
        now = time.time()
        a = _make_alert(data={"pid": 600})
        a.timestamp = now
        engine.ingest_alert(a)

        store = IncidentStore(engine, db)
        store.sync_from_engine()
        count_after_first = db.incident_count()

        store.sync_from_engine()
        count_after_second = db.incident_count()

        assert count_after_first == count_after_second == 1


# ------------------------------------------------------------------ #
#  TestGetStats
# ------------------------------------------------------------------ #

class TestGetStats:
    """Tests for IncidentStore.get_stats()."""

    def test_stats_empty(self, store: IncidentStore) -> None:
        """All counts are zero when no alerts have been processed."""
        stats = store.get_stats()
        assert stats["total_incidents"] == 0
        assert stats["active_incidents"] == 0
        assert stats["db_incidents"] == 0

    def test_stats_after_alerts(
        self, store: IncidentStore,
    ) -> None:
        """Counts are correct after processing several alerts."""
        now = time.time()
        a1 = _make_alert(
            data={"pid": 7001}, sensor=SensorType.FILE,
        )
        a1.timestamp = now
        a2 = _make_alert(
            data={"pid": 7002}, sensor=SensorType.NETWORK,
        )
        a2.timestamp = now + 1

        store.process_alert(a1)
        store.process_alert(a2)

        stats = store.get_stats()
        assert stats["total_incidents"] == 2
        assert stats["active_incidents"] == 2

    def test_stats_db_count(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """db_incidents matches the actual database count."""
        now = time.time()
        a = _make_alert(data={"pid": 8001})
        a.timestamp = now
        store.process_alert(a)

        stats = store.get_stats()
        assert stats["db_incidents"] == db.incident_count()
        assert stats["db_incidents"] == 1

    def test_stats_without_db(
        self, store_no_db: IncidentStore,
    ) -> None:
        """db_incidents is -1 when no database is available."""
        stats = store_no_db.get_stats()
        assert stats["db_incidents"] == -1

    def test_stats_after_close(
        self, store: IncidentStore,
    ) -> None:
        """Active count decreases after closing an incident."""
        now = time.time()
        a1 = _make_alert(
            data={"pid": 9901}, sensor=SensorType.FILE,
        )
        a1.timestamp = now
        a2 = _make_alert(
            data={"pid": 9902}, sensor=SensorType.NETWORK,
        )
        a2.timestamp = now + 1

        inc1 = store.process_alert(a1)
        store.process_alert(a2)

        assert inc1 is not None
        store.close_incident(inc1.incident_id)

        stats = store.get_stats()
        assert stats["total_incidents"] == 2
        assert stats["active_incidents"] == 1


# ------------------------------------------------------------------ #
#  TestIncidentStoreIntegration
# ------------------------------------------------------------------ #

class TestIncidentStoreIntegration:
    """End-to-end integration tests for IncidentStore."""

    def test_full_lifecycle(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """Full lifecycle: process -> get -> close -> sync -> verify DB."""
        now = time.time()

        # Process alerts
        a1 = _make_alert(data={"pid": 9001})
        a1.timestamp = now
        a2 = _make_alert(data={"pid": 9001})
        a2.timestamp = now + 1
        inc = store.process_alert(a1)
        store.process_alert(a2)

        assert inc is not None
        assert inc.alert_count == 2

        # Get incident
        fetched = store.get_incident(inc.incident_id)
        assert fetched is inc

        # Active incidents
        active = store.get_active_incidents()
        assert len(active) == 1

        # Close
        result = store.close_incident(inc.incident_id)
        assert result is True
        assert len(store.get_active_incidents()) == 0

        # Sync (should update closed status)
        synced = store.sync_from_engine()
        assert synced == 1

        # Verify DB
        row = db.get_incident(inc.incident_id)
        assert row is not None
        assert row["status"] == "closed"

        linked = db.get_incident_alerts(inc.incident_id)
        assert a1.alert_id in linked
        assert a2.alert_id in linked

        # Stats
        stats = store.get_stats()
        assert stats["total_incidents"] == 1
        assert stats["active_incidents"] == 0
        assert stats["db_incidents"] == 1

    def test_multi_incident_flow(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """Alerts creating separate incidents are tracked independently."""
        now = time.time()

        a1 = _make_alert(
            data={"pid": 1111}, sensor=SensorType.FILE,
        )
        a1.timestamp = now
        a2 = _make_alert(
            data={"pid": 2222}, sensor=SensorType.NETWORK,
        )
        a2.timestamp = now + 1
        a3 = _make_alert(
            data={"pid": 3333}, sensor=SensorType.REGISTRY,
        )
        a3.timestamp = now + 2

        inc1 = store.process_alert(a1)
        inc2 = store.process_alert(a2)
        inc3 = store.process_alert(a3)

        assert inc1 is not None
        assert inc2 is not None
        assert inc3 is not None

        # All are different incidents
        ids = {
            inc1.incident_id, inc2.incident_id, inc3.incident_id,
        }
        assert len(ids) == 3

        assert db.incident_count() == 3
        assert len(store.get_active_incidents()) == 3

    def test_reopen_scenario(
        self, store: IncidentStore,
    ) -> None:
        """Closing an already-closed incident returns False."""
        alert = _make_alert(data={"pid": 4444})
        incident = store.process_alert(alert)
        assert incident is not None

        # Close once
        assert store.close_incident(incident.incident_id) is True

        # Try to close again -- engine returns False
        assert store.close_incident(incident.incident_id) is False
        assert incident.status == IncidentStatus.CLOSED

    def test_concurrent_alert_types(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """Different alert types from different sensors create separate incidents."""
        now = time.time()

        a_proc = _make_alert(
            alert_type="process.suspicious",
            sensor=SensorType.PROCESS,
            data={"pid": 5555},
        )
        a_proc.timestamp = now
        a_net = _make_alert(
            alert_type="network.anomaly",
            sensor=SensorType.NETWORK,
            data={"dst_ip": "192.168.1.100"},
        )
        a_net.timestamp = now + 1
        a_file = _make_alert(
            alert_type="file.modification",
            sensor=SensorType.FILE,
            data={"path": "C:\\Windows\\System32\\evil.dll"},
        )
        a_file.timestamp = now + 2

        inc_proc = store.process_alert(a_proc)
        inc_net = store.process_alert(a_net)
        inc_file = store.process_alert(a_file)

        assert inc_proc is not None
        assert inc_net is not None
        assert inc_file is not None

        # Verify all are separate (different entities, sensors)
        ids = {
            inc_proc.incident_id,
            inc_net.incident_id,
            inc_file.incident_id,
        }
        assert len(ids) == 3

        # All persisted to DB
        for iid in ids:
            assert db.get_incident(iid) is not None

    def test_entity_based_correlation_persisted(
        self, store: IncidentStore, db: AegisDatabase,
    ) -> None:
        """Alerts sharing entities are grouped and persisted correctly."""
        now = time.time()

        # Three alerts sharing the same IP entity
        a1 = _make_alert(
            alert_type="scan.detected",
            sensor=SensorType.NETWORK,
            data={"dst_ip": "10.0.0.50"},
        )
        a1.timestamp = now
        a2 = _make_alert(
            alert_type="c2.beacon",
            sensor=SensorType.NETWORK,
            data={"dst_ip": "10.0.0.50"},
        )
        a2.timestamp = now + 5
        a3 = _make_alert(
            alert_type="exfil.attempt",
            sensor=SensorType.NETWORK,
            data={"dst_ip": "10.0.0.50"},
        )
        a3.timestamp = now + 10

        inc1 = store.process_alert(a1)
        inc2 = store.process_alert(a2)
        inc3 = store.process_alert(a3)

        assert inc1 is not None
        assert inc2 is not None
        assert inc3 is not None

        # All correlated into one incident
        assert inc1.incident_id == inc2.incident_id
        assert inc2.incident_id == inc3.incident_id
        assert inc1.alert_count == 3
        assert "ip:10.0.0.50" in inc1.entities

        # DB has the single incident with all alerts linked
        assert db.incident_count() == 1
        linked = db.get_incident_alerts(inc1.incident_id)
        assert len(linked) == 3
        assert a1.alert_id in linked
        assert a2.alert_id in linked
        assert a3.alert_id in linked

        # Entities persisted
        row = db.get_incident(inc1.incident_id)
        assert row is not None
        assert "ip:10.0.0.50" in row["entities"]

    def test_sync_after_engine_only_operations(
        self, engine: CorrelationEngine, db: AegisDatabase,
    ) -> None:
        """Incidents created directly in engine are synced to DB."""
        now = time.time()
        # Create incidents directly in the engine (bypassing store)
        a1 = _make_alert(data={"pid": 7777})
        a1.timestamp = now
        a2 = _make_alert(data={"pid": 8888}, sensor=SensorType.FILE)
        a2.timestamp = now + 1

        engine.ingest_alert(a1)
        engine.ingest_alert(a2)

        assert engine.incident_count == 2
        assert db.incident_count() == 0  # Nothing in DB yet

        store = IncidentStore(engine, db)
        synced = store.sync_from_engine()

        assert synced == 2
        assert db.incident_count() == 2

    def test_stats_keys_always_present(
        self, store: IncidentStore,
    ) -> None:
        """get_stats always returns all three expected keys."""
        stats = store.get_stats()
        assert "total_incidents" in stats
        assert "active_incidents" in stats
        assert "db_incidents" in stats
        assert isinstance(stats["total_incidents"], int)
        assert isinstance(stats["active_incidents"], int)
        assert isinstance(stats["db_incidents"], int)
