"""Tests for Aegis task scheduler.

Covers TaskScheduler init, add/remove, tick execution,
enable/disable, task results, and stats reporting.
All tick tests use explicit ``now`` for determinism.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from aegis.core.scheduler import ScheduledTask, TaskResult, TaskScheduler


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _noop() -> None:
    """No-op callback for tasks that don't need side effects."""


def _failing() -> None:
    """Callback that always raises."""
    raise RuntimeError("simulated failure")


# ===================================================================
# TestTaskSchedulerInit
# ===================================================================


class TestTaskSchedulerInit:
    """Initialization of TaskScheduler."""

    def test_default_tick_interval(self) -> None:
        """Default tick interval is 1.0 second."""
        scheduler = TaskScheduler()
        assert scheduler._tick_interval == 1.0

    def test_custom_tick_interval(self) -> None:
        """Custom tick interval is stored correctly."""
        scheduler = TaskScheduler(tick_interval=5.0)
        assert scheduler._tick_interval == 5.0

    def test_empty_task_list_on_init(self) -> None:
        """Scheduler starts with no tasks."""
        scheduler = TaskScheduler()
        assert scheduler.task_count == 0
        assert scheduler.list_tasks() == []


# ===================================================================
# TestAddRemoveTask
# ===================================================================


class TestAddRemoveTask:
    """Adding and removing tasks from the scheduler."""

    def test_add_single_task(self) -> None:
        """Adding one task increases task_count to 1."""
        scheduler = TaskScheduler()
        task = scheduler.add_task("scan", _noop, 60.0)
        assert scheduler.task_count == 1
        assert isinstance(task, ScheduledTask)

    def test_add_multiple_tasks(self) -> None:
        """Adding several tasks tracks all of them."""
        scheduler = TaskScheduler()
        scheduler.add_task("task_a", _noop, 10.0)
        scheduler.add_task("task_b", _noop, 20.0)
        scheduler.add_task("task_c", _noop, 30.0)
        assert scheduler.task_count == 3

    def test_remove_existing_task(self) -> None:
        """Removing an existing task returns True and decrements count."""
        scheduler = TaskScheduler()
        task = scheduler.add_task("scan", _noop, 60.0)
        assert scheduler.remove_task(task.task_id) is True
        assert scheduler.task_count == 0

    def test_remove_nonexistent_task(self) -> None:
        """Removing a non-existent task returns False."""
        scheduler = TaskScheduler()
        assert scheduler.remove_task("does-not-exist") is False

    def test_task_properties_set_correctly(self) -> None:
        """Returned ScheduledTask has correct initial properties."""
        cb = MagicMock()
        scheduler = TaskScheduler()
        task = scheduler.add_task(
            "cleanup", cb, interval_seconds=120.0, enabled=True,
        )
        assert task.name == "cleanup"
        assert task.callback is cb
        assert task.interval_seconds == 120.0
        assert task.enabled is True
        assert task.next_run_at == 0.0
        assert task.last_run_at == 0.0
        assert task.last_result == "pending"
        assert task.run_count == 0
        assert task.error_count == 0
        assert task.task_id.startswith("task-")

    def test_task_count_property(self) -> None:
        """task_count reflects adds and removes."""
        scheduler = TaskScheduler()
        t1 = scheduler.add_task("a", _noop, 10.0)
        t2 = scheduler.add_task("b", _noop, 10.0)
        assert scheduler.task_count == 2
        scheduler.remove_task(t1.task_id)
        assert scheduler.task_count == 1
        scheduler.remove_task(t2.task_id)
        assert scheduler.task_count == 0

    def test_list_tasks_returns_all(self) -> None:
        """list_tasks returns a separate list of all registered tasks."""
        scheduler = TaskScheduler()
        scheduler.add_task("a", _noop, 10.0)
        scheduler.add_task("b", _noop, 20.0)
        tasks = scheduler.list_tasks()
        assert len(tasks) == 2
        names = {t.name for t in tasks}
        assert names == {"a", "b"}
        # Mutating the returned list must not affect the scheduler.
        tasks.clear()
        assert scheduler.task_count == 2


# ===================================================================
# TestTickExecution
# ===================================================================


class TestTickExecution:
    """Core tick() execution logic."""

    def test_task_runs_when_due(self) -> None:
        """A task whose next_run_at <= now is executed."""
        cb = MagicMock()
        scheduler = TaskScheduler()
        scheduler.add_task("work", cb, 60.0)
        results = scheduler.tick(now=100.0)
        assert len(results) == 1
        cb.assert_called_once()

    def test_task_skipped_when_not_due(self) -> None:
        """A task is skipped if now < next_run_at."""
        cb = MagicMock()
        scheduler = TaskScheduler()
        task = scheduler.add_task("work", cb, 60.0)
        # Manually set next_run_at into the future.
        task.next_run_at = 200.0
        results = scheduler.tick(now=100.0)
        assert results == []
        cb.assert_not_called()

    def test_multiple_tasks_run_same_tick(self) -> None:
        """All due tasks execute within a single tick."""
        cb_a = MagicMock()
        cb_b = MagicMock()
        scheduler = TaskScheduler()
        scheduler.add_task("a", cb_a, 10.0)
        scheduler.add_task("b", cb_b, 20.0)
        results = scheduler.tick(now=100.0)
        assert len(results) == 2
        cb_a.assert_called_once()
        cb_b.assert_called_once()

    def test_callback_exception_handled(self) -> None:
        """An exception in a callback does not crash tick()."""
        scheduler = TaskScheduler()
        scheduler.add_task("bad", _failing, 10.0)
        results = scheduler.tick(now=100.0)
        assert len(results) == 1
        assert results[0].success is False

    def test_result_success(self) -> None:
        """Successful callback produces a success result."""
        scheduler = TaskScheduler()
        scheduler.add_task("ok", _noop, 10.0)
        results = scheduler.tick(now=100.0)
        assert results[0].success is True
        assert results[0].message == "OK"

    def test_result_failure(self) -> None:
        """Failed callback produces a failure result."""
        scheduler = TaskScheduler()
        scheduler.add_task("bad", _failing, 10.0)
        results = scheduler.tick(now=100.0)
        assert results[0].success is False
        assert "simulated failure" in results[0].message

    def test_run_count_incremented(self) -> None:
        """run_count increments on each execution."""
        scheduler = TaskScheduler()
        task = scheduler.add_task("counter", _noop, 10.0)
        scheduler.tick(now=100.0)
        assert task.run_count == 1
        scheduler.tick(now=200.0)
        assert task.run_count == 2

    def test_error_count_incremented_on_failure(self) -> None:
        """error_count increments for each failed execution."""
        scheduler = TaskScheduler()
        task = scheduler.add_task("err", _failing, 10.0)
        scheduler.tick(now=100.0)
        assert task.error_count == 1
        assert task.run_count == 1
        scheduler.tick(now=200.0)
        assert task.error_count == 2
        assert task.run_count == 2

    def test_next_run_at_updated_after_execution(self) -> None:
        """next_run_at is set to now + interval after execution."""
        scheduler = TaskScheduler()
        task = scheduler.add_task("update", _noop, 60.0)
        scheduler.tick(now=1000.0)
        assert task.next_run_at == 1060.0
        assert task.last_run_at == 1000.0

    def test_explicit_now_parameter(self) -> None:
        """Passing an explicit now makes tick fully deterministic."""
        scheduler = TaskScheduler()
        task = scheduler.add_task("det", _noop, 30.0)
        results = scheduler.tick(now=500.0)
        assert results[0].timestamp == 500.0
        assert task.last_run_at == 500.0
        assert task.next_run_at == 530.0

    def test_task_with_future_next_run_at_skipped(self) -> None:
        """A task with next_run_at far in the future is not executed."""
        cb = MagicMock()
        scheduler = TaskScheduler()
        task = scheduler.add_task("future", cb, 10.0)
        task.next_run_at = 9999.0
        results = scheduler.tick(now=100.0)
        assert results == []
        cb.assert_not_called()


# ===================================================================
# TestTaskEnableDisable
# ===================================================================


class TestTaskEnableDisable:
    """Enabling and disabling tasks."""

    def test_enable_existing_task(self) -> None:
        """enable_task returns True for a known task."""
        scheduler = TaskScheduler()
        task = scheduler.add_task("t", _noop, 10.0, enabled=False)
        assert scheduler.enable_task(task.task_id) is True
        assert scheduler.get_task(task.task_id).enabled is True

    def test_disable_existing_task(self) -> None:
        """disable_task returns True for a known task."""
        scheduler = TaskScheduler()
        task = scheduler.add_task("t", _noop, 10.0, enabled=True)
        assert scheduler.disable_task(task.task_id) is True
        assert scheduler.get_task(task.task_id).enabled is False

    def test_disabled_task_skipped_in_tick(self) -> None:
        """A disabled task is not executed even when due."""
        cb = MagicMock()
        scheduler = TaskScheduler()
        task = scheduler.add_task("skip", cb, 10.0, enabled=False)
        results = scheduler.tick(now=100.0)
        assert results == []
        cb.assert_not_called()

    def test_re_enable_runs_again(self) -> None:
        """Re-enabling a previously disabled task lets it run."""
        cb = MagicMock()
        scheduler = TaskScheduler()
        task = scheduler.add_task("toggle", cb, 10.0, enabled=False)
        # Disabled -- should not run.
        scheduler.tick(now=100.0)
        cb.assert_not_called()
        # Re-enable -- should run on next tick.
        scheduler.enable_task(task.task_id)
        results = scheduler.tick(now=200.0)
        assert len(results) == 1
        cb.assert_called_once()

    def test_enable_disable_nonexistent_returns_false(self) -> None:
        """enable/disable on a missing task_id returns False."""
        scheduler = TaskScheduler()
        assert scheduler.enable_task("no-such-id") is False
        assert scheduler.disable_task("no-such-id") is False


# ===================================================================
# TestTaskResults
# ===================================================================


class TestTaskResults:
    """Inspection of TaskResult objects."""

    def test_success_result_fields(self) -> None:
        """Successful result has correct task_id, success=True."""
        scheduler = TaskScheduler()
        task = scheduler.add_task("ok", _noop, 10.0)
        results = scheduler.tick(now=100.0)
        r = results[0]
        assert r.task_id == task.task_id
        assert r.success is True
        assert r.message == "OK"
        assert r.timestamp == 100.0

    def test_failure_result_fields(self) -> None:
        """Failed result has success=False and error message."""
        scheduler = TaskScheduler()
        task = scheduler.add_task("bad", _failing, 10.0)
        results = scheduler.tick(now=100.0)
        r = results[0]
        assert r.task_id == task.task_id
        assert r.success is False
        assert "simulated failure" in r.message

    def test_task_name_in_result(self) -> None:
        """Result carries the human-readable task name."""
        scheduler = TaskScheduler()
        scheduler.add_task("my-scan", _noop, 10.0)
        results = scheduler.tick(now=100.0)
        assert results[0].task_name == "my-scan"

    def test_duration_seconds_positive(self) -> None:
        """Duration is a non-negative float."""
        scheduler = TaskScheduler()
        scheduler.add_task("dur", _noop, 10.0)
        results = scheduler.tick(now=100.0)
        assert results[0].duration_seconds >= 0.0

    def test_failure_message_contains_error_text(self) -> None:
        """Failure message includes the original exception text."""
        def _raise_value_error() -> None:
            raise ValueError("bad input value")

        scheduler = TaskScheduler()
        scheduler.add_task("val", _raise_value_error, 10.0)
        results = scheduler.tick(now=100.0)
        assert "bad input value" in results[0].message


# ===================================================================
# TestSchedulerStats
# ===================================================================


class TestSchedulerStats:
    """get_stats() reporting."""

    def test_stats_with_no_tasks(self) -> None:
        """Empty scheduler returns zeroed stats."""
        scheduler = TaskScheduler()
        stats = scheduler.get_stats()
        assert stats["task_count"] == 0
        assert stats["enabled_count"] == 0
        assert stats["total_runs"] == 0
        assert stats["total_errors"] == 0
        assert stats["tasks"] == []

    def test_stats_after_adding_tasks(self) -> None:
        """Stats reflect newly added tasks."""
        scheduler = TaskScheduler()
        scheduler.add_task("a", _noop, 10.0)
        scheduler.add_task("b", _noop, 20.0)
        stats = scheduler.get_stats()
        assert stats["task_count"] == 2
        assert stats["enabled_count"] == 2
        assert stats["total_runs"] == 0

    def test_stats_after_running_tasks(self) -> None:
        """total_runs and total_errors update after tick."""
        scheduler = TaskScheduler()
        scheduler.add_task("ok", _noop, 10.0)
        scheduler.add_task("bad", _failing, 10.0)
        scheduler.tick(now=100.0)
        stats = scheduler.get_stats()
        assert stats["total_runs"] == 2
        assert stats["total_errors"] == 1

    def test_enabled_count(self) -> None:
        """enabled_count only counts enabled tasks."""
        scheduler = TaskScheduler()
        scheduler.add_task("on", _noop, 10.0, enabled=True)
        scheduler.add_task("off", _noop, 10.0, enabled=False)
        stats = scheduler.get_stats()
        assert stats["enabled_count"] == 1
        assert stats["task_count"] == 2

    def test_per_task_stats(self) -> None:
        """Each task entry in stats has the expected keys."""
        scheduler = TaskScheduler()
        scheduler.add_task("scan", _noop, 60.0)
        scheduler.tick(now=100.0)
        stats = scheduler.get_stats()
        assert len(stats["tasks"]) == 1
        entry = stats["tasks"][0]
        assert entry["name"] == "scan"
        assert entry["interval_seconds"] == 60.0
        assert entry["enabled"] is True
        assert entry["run_count"] == 1
        assert entry["error_count"] == 0
        assert entry["last_result"] == "success"
        assert "task_id" in entry
