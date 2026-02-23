"""Incident persistence layer for Aegis.

Wraps the in-memory CorrelationEngine with AegisDatabase persistence
so that incidents and their alert linkages survive process restarts.
All database operations are wrapped in try/except so the store
degrades gracefully to in-memory-only mode when no DB is available.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from aegis.alerting.correlation_engine import (
    CorrelationEngine,
    Incident,
    IncidentStatus,
)
from aegis.core.models import Alert

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

logger = logging.getLogger(__name__)


class IncidentStore:
    """Persistence layer for the correlation engine.

    Wraps CorrelationEngine (in-memory correlation) and AegisDatabase
    (persistence) to ensure incidents survive restarts.
    """

    def __init__(
        self,
        correlation_engine: CorrelationEngine,
        db: AegisDatabase | None = None,
    ) -> None:
        self._engine = correlation_engine
        self._db = db
        self._known_incidents: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_alert(self, alert: Alert) -> Incident | None:
        """Ingest an alert, correlate it, and persist the result.

        Returns the incident the alert was assigned to, or ``None``
        if the engine did not produce one.
        """
        incident = self._engine.ingest_alert(alert)
        if incident is None:
            return None

        self._persist_incident(incident)
        self._link_alert(incident.incident_id, alert.alert_id)
        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        """Return an incident by ID from the in-memory engine.

        The correlation engine is the authoritative source; the DB
        is used only for crash recovery, not for runtime lookups.
        """
        return self._engine.get_incident(incident_id)

    def get_active_incidents(self) -> list[Incident]:
        """Return all open incidents from the correlation engine."""
        return self._engine.get_active_incidents()

    def close_incident(self, incident_id: str) -> bool:
        """Close an incident in both the engine and the database.

        Returns ``True`` if the engine successfully closed it.
        """
        closed = self._engine.close_incident(incident_id)
        if closed and self._db is not None:
            try:
                self._db.update_incident(
                    incident_id,
                    status=IncidentStatus.CLOSED.value,
                )
            except Exception:
                logger.exception(
                    "Failed to persist incident close for %s",
                    incident_id,
                )
        return closed

    def sync_from_engine(self) -> int:
        """Persist every in-memory incident to the database.

        Useful at startup (after replaying events) or before a
        graceful shutdown.  Returns the number of incidents synced.
        """
        if self._db is None:
            logger.debug(
                "sync_from_engine called without a database"
            )
            return 0

        incidents = self._engine.get_all_incidents()
        synced = 0

        for incident in incidents:
            try:
                self._persist_incident(incident)
                # Also persist alert linkages
                for alert in incident.alerts:
                    self._link_alert(
                        incident.incident_id, alert.alert_id,
                    )
                synced += 1
            except Exception:
                logger.exception(
                    "Failed to sync incident %s",
                    incident.incident_id,
                )

        logger.info("Synced %d incidents to database", synced)
        return synced

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics about incidents.

        Keys returned:
        - ``total_incidents``: count of all incidents in engine
        - ``active_incidents``: count of OPEN incidents in engine
        - ``db_incidents``: count of rows in the incidents table
          (``-1`` when no database is available)
        """
        total = len(self._engine.get_all_incidents())
        active = len(self._engine.get_active_incidents())

        db_count: int = -1
        if self._db is not None:
            try:
                db_count = self._db.incident_count()
            except Exception:
                logger.exception(
                    "Failed to query incident count from DB"
                )

        return {
            "total_incidents": total,
            "active_incidents": active,
            "db_incidents": db_count,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _persist_incident(self, incident: Incident) -> None:
        """Insert or update a single incident in the database."""
        if self._db is None:
            return

        iid = incident.incident_id
        entities_list = sorted(incident.entities)

        try:
            if iid not in self._known_incidents:
                self._db.insert_incident(
                    incident_id=iid,
                    title=incident.title,
                    severity=incident.severity.value,
                    status=incident.status.value,
                    mitre_chain=list(incident.mitre_chain),
                    entities=entities_list,
                    first_seen=incident.first_seen,
                    last_seen=incident.last_seen,
                )
                self._known_incidents.add(iid)
                logger.debug("Inserted incident %s", iid)
            else:
                self._db.update_incident(
                    incident_id=iid,
                    title=incident.title,
                    severity=incident.severity.value,
                    status=incident.status.value,
                    mitre_chain=list(incident.mitre_chain),
                    entities=entities_list,
                    last_seen=incident.last_seen,
                )
                logger.debug("Updated incident %s", iid)
        except Exception:
            logger.exception(
                "Failed to persist incident %s", iid,
            )

    def _link_alert(
        self, incident_id: str, alert_id: str,
    ) -> None:
        """Link an alert to an incident in the database."""
        if self._db is None:
            return
        try:
            self._db.add_alert_to_incident(
                incident_id, alert_id,
            )
        except Exception:
            logger.exception(
                "Failed to link alert %s to incident %s",
                alert_id,
                incident_id,
            )
