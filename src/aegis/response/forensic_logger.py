"""Forensic Logger — immutable audit trail for all security actions.

Records alerts, user decisions (approve/dismiss), and action results
in the ``audit_log`` table.  Provides query and timeline export for
incident investigation and compliance.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

logger = logging.getLogger(__name__)

# 1-year retention in seconds (design doc Section 8.2)
RETENTION_SECONDS = 365 * 24 * 60 * 60


@dataclass
class LogEntry:
    """A single audit-log record, returned by query methods."""

    log_id: int
    timestamp: float
    log_type: str
    source: str
    severity: str
    details: dict[str, Any]


class ForensicLogger:
    """Write and query the forensic audit trail.

    Parameters
    ----------
    db:
        An :class:`AegisDatabase` instance (uses the ``audit_log`` table).
    """

    def __init__(self, db: AegisDatabase) -> None:
        self._db = db

    # ------------------------------------------------------------------ #
    # Write methods
    # ------------------------------------------------------------------ #

    def log_alert(
        self,
        alert_id: str,
        alert_type: str,
        severity: str,
        title: str,
        confidence: float,
        sensor: str = "",
        mitre_ids: list[str] | None = None,
    ) -> None:
        """Record that an alert was raised."""
        detail = json.dumps({
            "log_type": "alert",
            "alert_id": alert_id,
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "confidence": confidence,
            "sensor": sensor,
            "mitre_ids": mitre_ids or [],
        })
        self._db.audit(
            component="detection",
            action="alert_raised",
            detail=detail,
        )

    def log_user_action(
        self,
        alert_id: str,
        action: str,
        user: str = "user",
        reason: str = "",
    ) -> None:
        """Record a user decision (approve, dismiss, escalate)."""
        detail = json.dumps({
            "log_type": "user_action",
            "alert_id": alert_id,
            "action": action,
            "user": user,
            "reason": reason,
        })
        self._db.audit(
            component="response",
            action=f"user_{action}",
            detail=detail,
        )

    def log_action_result(
        self,
        action_id: str,
        action_type: str,
        success: bool,
        message: str,
        target: str = "",
        approved_by: str = "user",
    ) -> None:
        """Record the outcome of an executed response action."""
        detail = json.dumps({
            "log_type": "action_result",
            "action_id": action_id,
            "action_type": action_type,
            "success": success,
            "message": message,
            "target": target,
            "approved_by": approved_by,
        })
        self._db.audit(
            component="response",
            action="action_executed",
            detail=detail,
        )

    # ------------------------------------------------------------------ #
    # Query methods
    # ------------------------------------------------------------------ #

    def query_logs(
        self,
        log_type: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[LogEntry]:
        """Query audit-log entries with optional filters.

        Parameters
        ----------
        log_type:
            Filter to a specific type (``"alert"``, ``"user_action"``,
            ``"action_result"``).
        since:
            Only return entries newer than this Unix timestamp.
        limit:
            Maximum number of entries to return.
        """
        raw = self._db.get_audit_log(limit=limit * 5)
        entries: list[LogEntry] = []
        for row in raw:
            try:
                details = json.loads(row["detail"]) if row["detail"] else {}
            except (json.JSONDecodeError, TypeError):
                details = {"raw": row["detail"]}

            entry_type = details.get("log_type", row.get("action", ""))
            severity = details.get("severity", "info")

            if log_type is not None and entry_type != log_type:
                continue
            if since is not None and row["timestamp"] < since:
                continue

            entries.append(LogEntry(
                log_id=row["id"],
                timestamp=row["timestamp"],
                log_type=entry_type,
                source=row["component"],
                severity=severity,
                details=details,
            ))
            if len(entries) >= limit:
                break

        return entries

    def export_timeline(
        self, since: float | None = None, limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Export a chronological timeline suitable for JSON serialization.

        Returns dicts with ``timestamp``, ``type``, ``source``,
        ``severity``, and ``details`` keys, sorted oldest-first.
        """
        entries = self.query_logs(since=since, limit=limit)
        timeline = [
            {
                "timestamp": e.timestamp,
                "type": e.log_type,
                "source": e.source,
                "severity": e.severity,
                "details": e.details,
            }
            for e in entries
        ]
        timeline.sort(key=lambda x: x["timestamp"])
        return timeline

    # ------------------------------------------------------------------ #
    # Retention management
    # ------------------------------------------------------------------ #

    def purge_old_entries(self) -> int:
        """Delete audit-log entries older than the retention period.

        Returns the number of rows deleted.
        """
        cutoff = time.time() - RETENTION_SECONDS
        cursor = self._db._conn.execute(
            "DELETE FROM audit_log WHERE timestamp < ?", (cutoff,),
        )
        self._db._conn.commit()
        return cursor.rowcount
