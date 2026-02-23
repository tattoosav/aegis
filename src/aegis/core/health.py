"""System health aggregator for Aegis.

Collects performance and status metrics from all subsystems via
the :class:`AegisCoordinator`, suitable for dashboard display
and monitoring integrations.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class SystemHealth:
    """Aggregate health and performance stats from all subsystems.

    Parameters
    ----------
    coordinator:
        The AegisCoordinator instance to collect stats from.
        Typed as Any to avoid circular imports.
    """

    def __init__(self, coordinator: Any) -> None:
        self._coordinator = coordinator

    def collect(self) -> dict[str, Any]:
        """Collect stats from every subsystem.

        Each section is wrapped in try/except so a single failing
        component never breaks the entire health report.
        """
        result: dict[str, Any] = {}
        for section, collector in [
            ("engine", self._collect_engine),
            ("enricher", self._collect_enricher),
            ("correlation", self._collect_correlation),
            ("scheduler", self._collect_scheduler),
            ("canary", self._collect_canary),
            ("whitelist", self._collect_whitelist),
            ("database", self._collect_database),
            ("playbooks", self._collect_playbooks),
            ("response_router", self._collect_response_router),
        ]:
            try:
                result[section] = collector()
            except Exception:
                logger.debug(
                    "Health collection failed for %s",
                    section,
                    exc_info=True,
                )
                result[section] = {}
        return result

    # ------------------------------------------------------------------
    # Private collectors (one per subsystem)
    # ------------------------------------------------------------------

    def _collect_engine(self) -> dict[str, Any]:
        engine = self._coordinator.engine
        if engine is None:
            return {}
        return {
            "events_processed": engine.events_processed,
            "alerts_generated": engine.alerts_generated,
            "is_running": engine.is_running,
        }

    def _collect_enricher(self) -> dict[str, Any]:
        enricher = self._coordinator.enricher
        if enricher is None:
            return {}
        return enricher.get_stats()

    def _collect_correlation(self) -> dict[str, Any]:
        store = self._coordinator.incident_store
        if store is None:
            return {}
        return store.get_stats()

    def _collect_scheduler(self) -> dict[str, Any]:
        scheduler = self._coordinator.scheduler
        if scheduler is None:
            return {}
        stats = scheduler.get_stats()
        return {
            "task_count": stats.get("task_count", 0),
            "total_runs": stats.get("total_runs", 0),
            "total_errors": stats.get("total_errors", 0),
        }

    def _collect_canary(self) -> dict[str, Any]:
        canary = self._coordinator.canary_system
        if canary is None:
            return {}
        status = canary.get_status()
        return {
            "total_deployed": status.get("total_deployed", 0),
            "healthy": status.get("healthy", 0),
            "triggered": status.get("triggered", 0),
        }

    def _collect_whitelist(self) -> dict[str, Any]:
        wm = self._coordinator.whitelist_manager
        if wm is None:
            return {}
        entries = wm.list_entries()
        by_type: dict[str, int] = {}
        for entry in entries:
            t = entry.entry_type.value
            by_type[t] = by_type.get(t, 0) + 1
        return {
            "total_entries": len(entries),
            "by_type": by_type,
        }

    def _collect_database(self) -> dict[str, Any]:
        db = self._coordinator.db
        if db is None:
            return {}
        return {
            "event_count": db.event_count(),
            "alert_count": db.alert_count(),
            "incident_count": db.incident_count(),
        }

    def _collect_playbooks(self) -> dict[str, Any]:
        pe = self._coordinator.playbook_engine
        if pe is None:
            return {}
        return {
            "loaded": pe.playbook_count,
            "active_executions": len(pe.active_executions),
        }

    def _collect_response_router(self) -> dict[str, Any]:
        rr = self._coordinator.response_router
        if rr is None:
            return {}
        return rr.get_stats()
