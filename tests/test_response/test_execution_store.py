"""Tests for ExecutionStore — playbook execution persistence layer."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import patch

import pytest

from aegis.core.database import AegisDatabase
from aegis.core.models import Alert, SensorType, Severity
from aegis.response.execution_store import ExecutionStore
from aegis.response.playbook_engine import (
    Playbook,
    PlaybookEngine,
    PlaybookExecution,
    PlaybookStep,
    PlaybookTrigger,
)

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _make_playbook() -> Playbook:
    """Create a minimal Playbook with two steps."""
    return Playbook(
        playbook_id="pb-test",
        name="Test Playbook",
        trigger=PlaybookTrigger(
            alert_type="test.alert",
            min_severity="medium",
        ),
        steps=[
            PlaybookStep(
                step_id="s1",
                action="quarantine_file",
                target="/tmp/test",
            ),
            PlaybookStep(
                step_id="s2",
                action="block_ip",
                target="1.2.3.4",
            ),
        ],
    )


def _make_alert() -> Alert:
    """Create a minimal Alert for testing."""
    return Alert(
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        sensor=SensorType.PROCESS,
        alert_type="test.alert",
        severity=Severity.HIGH,
        title="Test alert",
        description="Test",
        confidence=0.9,
        data={},
        mitre_ids=[],
    )


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture()
def db(tmp_path) -> AegisDatabase:
    """Return a fresh AegisDatabase backed by a temp file."""
    return AegisDatabase(tmp_path / "test.db")


@pytest.fixture()
def engine() -> PlaybookEngine:
    """Return a fresh PlaybookEngine with no playbooks dir."""
    return PlaybookEngine(playbooks_dir=None)


@pytest.fixture()
def store(engine: PlaybookEngine, db: AegisDatabase) -> ExecutionStore:
    """Return an ExecutionStore with a real database."""
    return ExecutionStore(engine, db)


@pytest.fixture()
def store_no_db(engine: PlaybookEngine) -> ExecutionStore:
    """Return an ExecutionStore without a database."""
    return ExecutionStore(engine)


# ------------------------------------------------------------------ #
# TestExecutionStoreInit
# ------------------------------------------------------------------ #


class TestExecutionStoreInit:
    """ExecutionStore construction."""

    def test_init_with_db(
        self, engine: PlaybookEngine, db: AegisDatabase,
    ) -> None:
        """Store initialises with engine and database references."""
        s = ExecutionStore(engine, db)
        assert s._engine is engine
        assert s._db is db

    def test_init_without_db(
        self, engine: PlaybookEngine,
    ) -> None:
        """Store can be created without a database."""
        s = ExecutionStore(engine)
        assert s._engine is engine
        assert s._db is None

    def test_known_executions_empty(
        self, store: ExecutionStore,
    ) -> None:
        """Freshly created store has no known executions."""
        assert store._known_executions == set()


# ------------------------------------------------------------------ #
# TestPersistExecution
# ------------------------------------------------------------------ #


class TestPersistExecution:
    """ExecutionStore.persist_execution."""

    def test_persist_new_execution(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """Persisting an execution inserts it into the database."""
        pb = _make_playbook()
        engine.add_playbook(pb)
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)

        store.persist_execution(exe)

        row = db.get_execution(exe.execution_id)
        assert row is not None
        assert row["execution_id"] == exe.execution_id
        assert row["playbook_id"] == "pb-test"
        assert row["status"] == "running"

    def test_persist_execution_steps(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """All execution steps are persisted to the database."""
        pb = _make_playbook()
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)

        store.persist_execution(exe)

        steps = db.get_execution_steps(exe.execution_id)
        assert len(steps) == 2
        assert steps[0]["action"] == "quarantine_file"
        assert steps[1]["action"] == "block_ip"

    def test_persist_updates_existing(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """Persisting the same execution twice updates instead of inserting."""
        pb = _make_playbook()
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)

        store.persist_execution(exe)
        exe.status = "completed"
        store.persist_execution(exe)

        row = db.get_execution(exe.execution_id)
        assert row is not None
        assert row["status"] == "completed"

    def test_persist_completed_sets_completed_at(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """A completed execution gets a completed_at timestamp on update."""
        pb = _make_playbook()
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)

        store.persist_execution(exe)
        exe.status = "completed"
        store.persist_execution(exe)

        row = db.get_execution(exe.execution_id)
        assert row is not None
        assert row["completed_at"] is not None
        assert row["completed_at"] > 0

    def test_persist_without_db(
        self, store_no_db: ExecutionStore, engine: PlaybookEngine,
    ) -> None:
        """Persisting without a DB does not crash."""
        pb = _make_playbook()
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)
        # Should not raise
        store_no_db.persist_execution(exe)

    def test_persist_db_error_graceful(
        self, store: ExecutionStore, engine: PlaybookEngine,
    ) -> None:
        """A database error during persist is caught gracefully."""
        pb = _make_playbook()
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)

        with patch.object(
            store._db, "insert_execution",
            side_effect=RuntimeError("DB broke"),
        ):
            # Should not raise
            store.persist_execution(exe)

    def test_persist_tracks_known(
        self, store: ExecutionStore, engine: PlaybookEngine,
    ) -> None:
        """Persisted execution IDs are added to _known_executions."""
        pb = _make_playbook()
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)

        store.persist_execution(exe)
        assert exe.execution_id in store._known_executions

    def test_persist_step_count(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """The correct number of steps is persisted for the execution."""
        pb = _make_playbook()
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)

        store.persist_execution(exe)
        steps = db.get_execution_steps(exe.execution_id)
        assert len(steps) == len(exe.steps)


# ------------------------------------------------------------------ #
# TestUpdateStepStatus
# ------------------------------------------------------------------ #


class TestUpdateStepStatus:
    """ExecutionStore.update_step_status."""

    def _persist_and_get_exe(
        self,
        store: ExecutionStore,
        engine: PlaybookEngine,
    ) -> PlaybookExecution:
        """Helper: create, start, and persist an execution."""
        pb = _make_playbook()
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)
        store.persist_execution(exe)
        return exe

    def test_update_step_status(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """Updating a step status reflects in the database."""
        exe = self._persist_and_get_exe(store, engine)

        store.update_step_status(exe.execution_id, 0, "executed")

        steps = db.get_execution_steps(exe.execution_id)
        assert steps[0]["status"] == "executed"

    def test_update_step_with_message(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """A result_message is persisted along with the status update."""
        exe = self._persist_and_get_exe(store, engine)

        store.update_step_status(
            exe.execution_id, 0, "failed", message="Permission denied",
        )

        steps = db.get_execution_steps(exe.execution_id)
        assert steps[0]["result_message"] == "Permission denied"

    def test_update_step_without_db(
        self, store_no_db: ExecutionStore, engine: PlaybookEngine,
    ) -> None:
        """Updating step status without a DB does not crash."""
        pb = _make_playbook()
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)
        # Should not raise
        store_no_db.update_step_status(exe.execution_id, 0, "executed")

    def test_update_approved_sets_started_at(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """Setting status to 'approved' records a started_at timestamp."""
        exe = self._persist_and_get_exe(store, engine)

        store.update_step_status(exe.execution_id, 0, "approved")

        steps = db.get_execution_steps(exe.execution_id)
        assert steps[0]["started_at"] is not None
        assert steps[0]["started_at"] > 0

    def test_update_executed_sets_completed_at(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """Setting status to 'executed' records a completed_at timestamp."""
        exe = self._persist_and_get_exe(store, engine)

        store.update_step_status(exe.execution_id, 0, "executed")

        steps = db.get_execution_steps(exe.execution_id)
        assert steps[0]["completed_at"] is not None
        assert steps[0]["completed_at"] > 0


# ------------------------------------------------------------------ #
# TestSyncFromEngine
# ------------------------------------------------------------------ #


class TestSyncFromEngine:
    """ExecutionStore.sync_from_engine."""

    def test_sync_persists_all(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """sync_from_engine persists all in-memory executions."""
        pb = _make_playbook()
        exe1 = engine.start_execution(pb, _make_alert())
        exe2 = engine.start_execution(pb, _make_alert())

        store.sync_from_engine()

        assert db.get_execution(exe1.execution_id) is not None
        assert db.get_execution(exe2.execution_id) is not None

    def test_sync_returns_count(
        self, store: ExecutionStore, engine: PlaybookEngine,
    ) -> None:
        """sync_from_engine returns the number of executions synced."""
        pb = _make_playbook()
        engine.start_execution(pb, _make_alert())
        engine.start_execution(pb, _make_alert())

        count = store.sync_from_engine()
        assert count == 2

    def test_sync_without_db_returns_zero(
        self, store_no_db: ExecutionStore, engine: PlaybookEngine,
    ) -> None:
        """sync_from_engine returns 0 when no database is configured."""
        pb = _make_playbook()
        engine.start_execution(pb, _make_alert())

        count = store_no_db.sync_from_engine()
        assert count == 0

    def test_sync_handles_errors(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """If one execution fails to persist, others are still synced."""
        pb = _make_playbook()
        engine.start_execution(pb, _make_alert())
        engine.start_execution(pb, _make_alert())

        original_insert = db.insert_execution
        call_count = 0

        def failing_insert(*args: Any, **kwargs: Any) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Simulated DB failure")
            return original_insert(*args, **kwargs)

        with patch.object(db, "insert_execution", side_effect=failing_insert):
            count = store.sync_from_engine()

        # At least one should have succeeded
        assert count >= 1

    def test_sync_idempotent(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """Calling sync_from_engine twice does not cause errors."""
        pb = _make_playbook()
        engine.start_execution(pb, _make_alert())

        count1 = store.sync_from_engine()
        count2 = store.sync_from_engine()
        assert count1 == 1
        assert count2 == 1

    def test_sync_includes_steps(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """sync_from_engine also persists execution steps."""
        pb = _make_playbook()
        exe = engine.start_execution(pb, _make_alert())

        store.sync_from_engine()

        steps = db.get_execution_steps(exe.execution_id)
        assert len(steps) == 2


# ------------------------------------------------------------------ #
# TestGetStats
# ------------------------------------------------------------------ #


class TestGetStats:
    """ExecutionStore.get_stats."""

    def test_stats_empty(self, store: ExecutionStore) -> None:
        """Stats are all zeros when no executions exist."""
        stats = store.get_stats()
        assert stats["active_executions"] == 0
        assert stats["total_executions"] == 0
        assert stats["db_executions"] == 0

    def test_stats_after_execution(
        self, store: ExecutionStore, engine: PlaybookEngine,
    ) -> None:
        """Stats reflect running executions in the engine."""
        pb = _make_playbook()
        engine.start_execution(pb, _make_alert())

        stats = store.get_stats()
        assert stats["active_executions"] == 1
        assert stats["total_executions"] == 1

    def test_stats_db_count(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """db_executions matches the number of rows in the database."""
        pb = _make_playbook()
        engine.start_execution(pb, _make_alert())
        engine.start_execution(pb, _make_alert())
        store.sync_from_engine()

        stats = store.get_stats()
        assert stats["db_executions"] == 2

    def test_stats_without_db(
        self, store_no_db: ExecutionStore, engine: PlaybookEngine,
    ) -> None:
        """db_executions is -1 when no database is available."""
        pb = _make_playbook()
        engine.start_execution(pb, _make_alert())

        stats = store_no_db.get_stats()
        assert stats["db_executions"] == -1
        assert stats["active_executions"] == 1
        assert stats["total_executions"] == 1


# ------------------------------------------------------------------ #
# TestDatabaseExecutionCRUD
# ------------------------------------------------------------------ #


class TestDatabaseExecutionCRUD:
    """Direct AegisDatabase execution CRUD operations."""

    def test_insert_and_get_execution(
        self, db: AegisDatabase,
    ) -> None:
        """Insert an execution and retrieve it by ID."""
        db.insert_execution(
            execution_id="exec-abc",
            playbook_id="pb-1",
            playbook_name="My Playbook",
            alert_id="alt-xyz",
            status="running",
            started_at=1000.0,
            current_step=0,
        )

        row = db.get_execution("exec-abc")
        assert row is not None
        assert row["execution_id"] == "exec-abc"
        assert row["playbook_id"] == "pb-1"
        assert row["playbook_name"] == "My Playbook"
        assert row["alert_id"] == "alt-xyz"
        assert row["status"] == "running"

    def test_update_execution_status(
        self, db: AegisDatabase,
    ) -> None:
        """Updating execution status is reflected in retrieval."""
        db.insert_execution(
            execution_id="exec-upd",
            playbook_id="pb-1",
            playbook_name="PB",
            alert_id="alt-1",
            status="running",
            started_at=1000.0,
            current_step=0,
        )

        result = db.update_execution(
            "exec-upd", status="completed", completed_at=2000.0,
        )
        assert result is True

        row = db.get_execution("exec-upd")
        assert row is not None
        assert row["status"] == "completed"
        assert row["completed_at"] == 2000.0

    def test_query_by_status(self, db: AegisDatabase) -> None:
        """query_executions can filter by status."""
        db.insert_execution(
            execution_id="exec-r1",
            playbook_id="pb-1",
            playbook_name="PB",
            alert_id="alt-1",
            status="running",
            started_at=1000.0,
            current_step=0,
        )
        db.insert_execution(
            execution_id="exec-c1",
            playbook_id="pb-2",
            playbook_name="PB2",
            alert_id="alt-2",
            status="completed",
            started_at=1001.0,
            current_step=1,
        )

        running = db.query_executions(status="running")
        assert len(running) == 1
        assert running[0]["execution_id"] == "exec-r1"

        completed = db.query_executions(status="completed")
        assert len(completed) == 1
        assert completed[0]["execution_id"] == "exec-c1"

    def test_step_insert_and_get(self, db: AegisDatabase) -> None:
        """Insert execution steps and retrieve them."""
        db.insert_execution(
            execution_id="exec-steps",
            playbook_id="pb-1",
            playbook_name="PB",
            alert_id="alt-1",
            status="running",
            started_at=1000.0,
            current_step=0,
        )
        db.insert_execution_step(
            execution_id="exec-steps",
            step_index=0,
            step_id="s0",
            action="quarantine_file",
            target="/tmp/f",
            status="pending",
        )
        db.insert_execution_step(
            execution_id="exec-steps",
            step_index=1,
            step_id="s1",
            action="block_ip",
            target="10.0.0.1",
            status="pending",
        )

        steps = db.get_execution_steps("exec-steps")
        assert len(steps) == 2
        assert steps[0]["step_id"] == "s0"
        assert steps[0]["action"] == "quarantine_file"
        assert steps[1]["step_id"] == "s1"
        assert steps[1]["target"] == "10.0.0.1"

    def test_execution_count(self, db: AegisDatabase) -> None:
        """execution_count returns the correct total."""
        assert db.execution_count() == 0

        db.insert_execution(
            execution_id="exec-cnt1",
            playbook_id="pb-1",
            playbook_name="PB",
            alert_id="alt-1",
            status="running",
            started_at=1000.0,
            current_step=0,
        )
        db.insert_execution(
            execution_id="exec-cnt2",
            playbook_id="pb-2",
            playbook_name="PB2",
            alert_id="alt-2",
            status="completed",
            started_at=1001.0,
            current_step=0,
        )

        assert db.execution_count() == 2
        assert db.execution_count(status="running") == 1
        assert db.execution_count(status="completed") == 1


# ------------------------------------------------------------------ #
# TestExecutionStoreIntegration
# ------------------------------------------------------------------ #


class TestExecutionStoreIntegration:
    """End-to-end integration tests for ExecutionStore."""

    def test_full_lifecycle(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """Full lifecycle: start -> persist -> update steps -> complete."""
        pb = _make_playbook()
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)

        # Persist initial state
        store.persist_execution(exe)
        row = db.get_execution(exe.execution_id)
        assert row is not None
        assert row["status"] == "running"

        # Approve and execute step 0
        store.update_step_status(
            exe.execution_id, 0, "approved",
        )
        store.update_step_status(
            exe.execution_id, 0, "executed", message="File quarantined",
        )

        # Approve and execute step 1
        store.update_step_status(
            exe.execution_id, 1, "approved",
        )
        store.update_step_status(
            exe.execution_id, 1, "executed", message="IP blocked",
        )

        # Mark execution completed and persist again
        exe.status = "completed"
        store.persist_execution(exe)

        row = db.get_execution(exe.execution_id)
        assert row is not None
        assert row["status"] == "completed"
        assert row["completed_at"] is not None

        steps = db.get_execution_steps(exe.execution_id)
        assert steps[0]["status"] == "executed"
        assert steps[0]["result_message"] == "File quarantined"
        assert steps[1]["status"] == "executed"
        assert steps[1]["result_message"] == "IP blocked"

    def test_multiple_executions(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """Three different executions are all independently persisted."""
        pb = _make_playbook()
        exes = []
        for _ in range(3):
            exe = engine.start_execution(pb, _make_alert())
            store.persist_execution(exe)
            exes.append(exe)

        for exe in exes:
            row = db.get_execution(exe.execution_id)
            assert row is not None
            assert row["playbook_id"] == "pb-test"

        assert db.execution_count() == 3

    def test_sync_after_step_changes(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """Modifying in-memory steps and syncing updates the database."""
        pb = _make_playbook()
        alert = _make_alert()
        exe = engine.start_execution(pb, alert)

        # First sync — inserts
        store.sync_from_engine()

        # Modify steps in memory (simulating engine marking them)
        exe.steps[0].status = "executed"
        exe.steps[0].result_message = "Done"

        # Second sync — updates step statuses
        store.sync_from_engine()

        steps = db.get_execution_steps(exe.execution_id)
        assert steps[0]["status"] == "executed"
        assert steps[0]["result_message"] == "Done"

    def test_stats_reflect_actual_state(
        self, store: ExecutionStore, engine: PlaybookEngine,
        db: AegisDatabase,
    ) -> None:
        """get_stats accurately reflects both engine and DB state."""
        pb = _make_playbook()

        # Start two executions
        exe1 = engine.start_execution(pb, _make_alert())
        engine.start_execution(pb, _make_alert())
        store.sync_from_engine()

        stats = store.get_stats()
        assert stats["active_executions"] == 2
        assert stats["total_executions"] == 2
        assert stats["db_executions"] == 2

        # Complete one execution
        exe1.status = "completed"
        store.persist_execution(exe1)

        stats = store.get_stats()
        assert stats["active_executions"] == 1
        assert stats["total_executions"] == 2
        assert stats["db_executions"] == 2
