"""Playbook execution persistence layer for Aegis.

Wraps the in-memory PlaybookEngine with AegisDatabase persistence
so that execution state survives process restarts.  All database
operations are wrapped in try/except for graceful degradation.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase
    from aegis.response.playbook_engine import (
        PlaybookEngine,
        PlaybookExecution,
    )

logger = logging.getLogger(__name__)


class ExecutionStore:
    """Persistence layer for PlaybookEngine executions.

    Wraps PlaybookEngine (in-memory execution tracking) with
    AegisDatabase persistence so playbook execution state
    survives process restarts.
    """

    def __init__(
        self,
        playbook_engine: PlaybookEngine,
        db: AegisDatabase | None = None,
    ) -> None:
        self._engine = playbook_engine
        self._db = db
        self._known_executions: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def persist_execution(
        self, execution: PlaybookExecution,
    ) -> None:
        """Persist a PlaybookExecution to the database.

        On first call for a given execution the full record (header
        plus all steps) is inserted.  On subsequent calls only the
        mutable fields (status, current_step, completed_at) are
        updated.
        """
        if self._db is None:
            return

        eid = execution.execution_id
        try:
            if eid not in self._known_executions:
                self._db.insert_execution(
                    execution_id=eid,
                    playbook_id=execution.playbook.playbook_id,
                    playbook_name=execution.playbook.name,
                    alert_id=execution.alert.alert_id,
                    status=execution.status,
                    started_at=time.time(),
                    current_step=execution.current_step,
                )
                for i, step in enumerate(execution.steps):
                    self._db.insert_execution_step(
                        execution_id=eid,
                        step_index=i,
                        step_id=step.step_id,
                        action=step.action,
                        target=step.target,
                        status=step.status,
                    )
                self._known_executions.add(eid)
                logger.debug("Inserted execution %s", eid)
            else:
                completed_at: float | None = None
                if execution.status in ("completed", "aborted"):
                    completed_at = time.time()
                self._db.update_execution(
                    execution_id=eid,
                    status=execution.status,
                    current_step=execution.current_step,
                    completed_at=completed_at,
                )
                logger.debug("Updated execution %s", eid)
        except Exception:
            logger.exception(
                "Failed to persist execution %s", eid,
            )

    def update_step_status(
        self,
        execution_id: str,
        step_index: int,
        status: str,
        message: str = "",
    ) -> None:
        """Update a single execution step in the database.

        Sets ``started_at`` when the step is approved and
        ``completed_at`` when it reaches a terminal status.
        """
        if self._db is None:
            return

        try:
            started_at: float | None = None
            completed_at: float | None = None

            if status == "approved":
                started_at = time.time()
            elif status == "executed":
                completed_at = time.time()

            self._db.update_execution_step(
                execution_id=execution_id,
                step_index=step_index,
                status=status,
                started_at=started_at,
                completed_at=completed_at,
                result_message=message or None,
            )
        except Exception:
            logger.exception(
                "Failed to update step %d of execution %s",
                step_index,
                execution_id,
            )

    def sync_from_engine(self) -> int:
        """Persist all in-memory executions to the database.

        Useful at startup (after replaying events) or before a
        graceful shutdown.  Returns the number of executions synced.
        """
        if self._db is None:
            logger.debug(
                "sync_from_engine called without a database",
            )
            return 0

        executions = list(self._engine._executions.values())
        synced = 0

        for execution in executions:
            try:
                self.persist_execution(execution)
                # Also persist current step statuses
                for i, step in enumerate(execution.steps):
                    self._db.update_execution_step(
                        execution_id=execution.execution_id,
                        step_index=i,
                        status=step.status,
                        result_message=step.result_message or None,
                    )
                synced += 1
            except Exception:
                logger.exception(
                    "Failed to sync execution %s",
                    execution.execution_id,
                )

        logger.info(
            "Synced %d executions to database", synced,
        )
        return synced

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics about executions.

        Keys returned:
        - ``active_executions``: running executions in engine
        - ``total_executions``: all executions in engine
        - ``db_executions``: rows in the executions table
          (``-1`` when no database is available)
        """
        active = len(self._engine.active_executions)
        total = len(self._engine._executions)

        db_count: int = -1
        if self._db is not None:
            try:
                db_count = self._db.execution_count()
            except Exception:
                logger.exception(
                    "Failed to query execution count from DB",
                )

        return {
            "active_executions": active,
            "total_executions": total,
            "db_executions": db_count,
        }
