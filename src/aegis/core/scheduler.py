"""Centralized task scheduler for Aegis.

Provides a lightweight, testable scheduler for periodic operations
such as threat feed updates, retention cleanup, Bloom filter rebuilds,
and baseline snapshots.  The core ``tick()`` method is deterministic
and synchronous — it accepts an explicit *now* timestamp and returns
results, making the scheduler fully testable without threads.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class TaskResult:
    """Result of a single scheduled task execution."""

    task_id: str
    task_name: str
    success: bool
    duration_seconds: float
    message: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class ScheduledTask:
    """Definition of a periodic scheduled task."""

    task_id: str
    name: str
    callback: Callable[[], Any]
    interval_seconds: float
    next_run_at: float = 0.0
    last_run_at: float = 0.0
    last_result: str = "pending"  # "pending", "success", "error"
    enabled: bool = True
    run_count: int = 0
    error_count: int = 0


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


class TaskScheduler:
    """Lightweight task scheduler with deterministic tick().

    Parameters
    ----------
    tick_interval:
        How often the background thread calls tick() (seconds).
        Only used when running via start()/stop().
    """

    def __init__(self, tick_interval: float = 1.0) -> None:
        self._tasks: dict[str, ScheduledTask] = {}
        self._tick_interval = tick_interval
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # --- Task management ------------------------------------------------

    def add_task(
        self,
        name: str,
        callback: Callable[[], Any],
        interval_seconds: float,
        enabled: bool = True,
    ) -> ScheduledTask:
        """Register a new periodic task. Returns the created task."""
        task_id = f"task-{uuid.uuid4().hex[:8]}"
        task = ScheduledTask(
            task_id=task_id,
            name=name,
            callback=callback,
            interval_seconds=interval_seconds,
            enabled=enabled,
        )
        with self._lock:
            self._tasks[task_id] = task
        logger.info(
            "Scheduled task '%s' every %.0fs", name, interval_seconds,
        )
        return task

    def remove_task(self, task_id: str) -> bool:
        """Remove a task by ID. Returns True if found and removed."""
        with self._lock:
            return self._tasks.pop(task_id, None) is not None

    def enable_task(self, task_id: str) -> bool:
        """Enable a task. Returns True if found."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.enabled = True
                return True
            return False

    def disable_task(self, task_id: str) -> bool:
        """Disable a task. Returns True if found."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.enabled = False
                return True
            return False

    def get_task(self, task_id: str) -> ScheduledTask | None:
        """Get a task by ID."""
        with self._lock:
            return self._tasks.get(task_id)

    def list_tasks(self) -> list[ScheduledTask]:
        """Return all registered tasks."""
        with self._lock:
            return list(self._tasks.values())

    @property
    def task_count(self) -> int:
        """Number of registered tasks."""
        return len(self._tasks)

    # --- Core tick ------------------------------------------------------

    def tick(self, now: float | None = None) -> list[TaskResult]:
        """Execute all tasks that are due.

        This is the core scheduling method. It is deterministic
        and synchronous -- pass an explicit *now* for testing.

        Parameters
        ----------
        now:
            Current timestamp. Defaults to time.time().

        Returns
        -------
        List of TaskResult for tasks that were executed this tick.
        """
        if now is None:
            now = time.time()

        results: list[TaskResult] = []
        with self._lock:
            tasks_snapshot = list(self._tasks.values())

        for task in tasks_snapshot:
            if not task.enabled:
                continue
            if now < task.next_run_at:
                continue

            # Task is due -- execute it
            start = time.monotonic()
            try:
                task.callback()
                duration = time.monotonic() - start
                task.last_result = "success"
                task.run_count += 1
                result = TaskResult(
                    task_id=task.task_id,
                    task_name=task.name,
                    success=True,
                    duration_seconds=duration,
                    message="OK",
                    timestamp=now,
                )
            except Exception as exc:
                duration = time.monotonic() - start
                task.last_result = "error"
                task.run_count += 1
                task.error_count += 1
                result = TaskResult(
                    task_id=task.task_id,
                    task_name=task.name,
                    success=False,
                    duration_seconds=duration,
                    message=str(exc)[:200],
                    timestamp=now,
                )
                logger.warning(
                    "Scheduled task '%s' failed: %s",
                    task.name,
                    exc,
                )

            task.last_run_at = now
            task.next_run_at = now + task.interval_seconds
            results.append(result)

        return results

    # --- Background thread ----------------------------------------------

    def start(self) -> None:
        """Start the background scheduler thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="aegis-scheduler",
        )
        self._thread.start()
        logger.info(
            "Task scheduler started (tick=%.1fs)", self._tick_interval,
        )

    def stop(self) -> None:
        """Stop the background scheduler thread."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("Task scheduler stopped")

    @property
    def is_running(self) -> bool:
        """Whether the background thread is active."""
        return self._running

    def _run_loop(self) -> None:
        """Background loop that calls tick() periodically."""
        while self._running:
            try:
                self.tick()
            except Exception:
                logger.exception("Scheduler tick failed")
            time.sleep(self._tick_interval)

    # --- Stats ----------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return scheduler statistics."""
        with self._lock:
            tasks = list(self._tasks.values())
        total_runs = sum(t.run_count for t in tasks)
        total_errors = sum(t.error_count for t in tasks)
        return {
            "task_count": len(tasks),
            "enabled_count": sum(1 for t in tasks if t.enabled),
            "total_runs": total_runs,
            "total_errors": total_errors,
            "tasks": [
                {
                    "task_id": t.task_id,
                    "name": t.name,
                    "interval_seconds": t.interval_seconds,
                    "enabled": t.enabled,
                    "run_count": t.run_count,
                    "error_count": t.error_count,
                    "last_result": t.last_result,
                }
                for t in tasks
            ],
        }
