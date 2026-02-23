"""Dashboard data aggregation service for Aegis.

Sits between the :class:`AegisCoordinator` and the desktop dashboard
UI, enriching raw subsystem data with cross-references between alerts,
incidents, and playbook executions.  Every public method returns a
plain ``dict`` ready for direct consumption by Qt widgets.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from aegis.core.models import AlertStatus, Severity

logger = logging.getLogger(__name__)

# Key sensor names surfaced on the home dashboard.
_KEY_SENSORS = [
    "process",
    "network",
    "file",
    "event_log",
    "registry",
    "clipboard",
    "dns",
    "hardware",
]


class DashboardDataService:
    """Aggregate and enrich data from all Aegis subsystems for the UI.

    Each public method wraps every subsystem access in ``try/except``
    so that a single failing component never breaks the dashboard.
    The coordinator is typed as ``Any`` to avoid circular imports
    (same pattern used by :class:`SystemHealth`).

    Parameters
    ----------
    coordinator:
        The :class:`AegisCoordinator` instance that owns all
        subsystem references.
    """

    def __init__(self, coordinator: Any) -> None:
        self._coordinator = coordinator

    # ------------------------------------------------------------------
    # 1. Home page
    # ------------------------------------------------------------------

    def get_home_data(self) -> dict[str, Any]:
        """Return the data payload for the home / overview page.

        Returns
        -------
        dict
            Keys: ``health_summary``, ``sensor_status``,
            ``recent_alerts``, ``stats``, ``canary_overview``,
            ``scheduler_overview``.
        """
        if self._coordinator is None:
            return {
                "health_summary": {},
                "sensor_status": [],
                "recent_alerts": [],
                "stats": self._empty_home_stats(),
                "canary_overview": {},
                "scheduler_overview": {
                    "task_count": 0,
                    "total_runs": 0,
                    "total_errors": 0,
                },
            }
        return {
            "health_summary": self._collect_health_summary(),
            "sensor_status": self._collect_sensor_status(),
            "recent_alerts": self._collect_recent_alerts(),
            "stats": self._collect_home_stats(),
            "canary_overview": self._collect_canary_overview(),
            "scheduler_overview": self._collect_scheduler_overview(),
        }

    # ------------------------------------------------------------------
    # 2. Alerts page
    # ------------------------------------------------------------------

    def get_alerts_data(
        self,
        severity: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Return alert list with cross-referenced incident/response data.

        Parameters
        ----------
        severity:
            Filter by severity string (e.g. ``"critical"``), or
            ``None`` for all.
        status:
            Filter by status string (e.g. ``"new"``), or ``None``
            for all.
        limit:
            Maximum number of alerts to return.

        Returns
        -------
        dict
            Keys: ``alerts``, ``severity_counts``,
            ``status_counts``, ``total_count``.
        """
        alerts_list: list[dict[str, Any]] = []
        severity_counts = {s.value: 0 for s in Severity}
        status_counts = {s.value: 0 for s in AlertStatus}
        total_count = 0

        db = (
            self._coordinator.db
            if self._coordinator is not None
            else None
        )
        if db is None:
            return {
                "alerts": alerts_list,
                "severity_counts": severity_counts,
                "status_counts": status_counts,
                "total_count": total_count,
            }

        # Convert string filters to enums.
        sev_enum: Severity | None = None
        stat_enum: AlertStatus | None = None
        try:
            if severity is not None:
                sev_enum = Severity(severity.lower())
        except (ValueError, AttributeError):
            pass
        try:
            if status is not None:
                stat_enum = AlertStatus(status.lower())
        except (ValueError, AttributeError):
            pass

        # Fetch alerts from DB.
        try:
            raw_alerts = db.query_alerts(
                status=stat_enum,
                severity=sev_enum,
                limit=limit,
            )
        except Exception:
            logger.debug(
                "Failed to query alerts", exc_info=True,
            )
            raw_alerts = []

        # Build incident reverse-lookup: {alert_id: incident_id}.
        alert_to_incident = self._build_alert_incident_map()

        # Build response status lookup: {alert_id: status}.
        alert_to_response = self._build_alert_response_map()

        for alert in raw_alerts:
            try:
                d = alert.to_dict()
                d["incident_id"] = alert_to_incident.get(
                    alert.alert_id,
                )
                d["response_status"] = alert_to_response.get(
                    alert.alert_id,
                )
                alerts_list.append(d)
            except Exception:
                logger.debug(
                    "Failed to serialise alert", exc_info=True,
                )

        # Severity counts (all alerts, unfiltered).
        for sev in Severity:
            try:
                severity_counts[sev.value] = db.alert_count(
                    severity=sev,
                )
            except Exception:
                pass

        # Status counts (all alerts, unfiltered).
        for st in AlertStatus:
            try:
                count = len(db.query_alerts(status=st, limit=10000))
                status_counts[st.value] = count
            except Exception:
                pass

        try:
            total_count = db.alert_count()
        except Exception:
            pass

        return {
            "alerts": alerts_list,
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "total_count": total_count,
        }

    # ------------------------------------------------------------------
    # 3. Incidents page
    # ------------------------------------------------------------------

    def get_incidents_data(
        self,
        status: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Return incidents enriched with alert and response details.

        Parameters
        ----------
        status:
            Filter by incident status string (e.g. ``"open"``), or
            ``None`` for all.
        limit:
            Maximum number of incidents to return.

        Returns
        -------
        dict
            Keys: ``incidents``, ``status_counts``, ``total_count``.
        """
        incidents_list: list[dict[str, Any]] = []
        status_counts = {"open": 0, "closed": 0, "merged": 0}
        total_count = 0

        db = (
            self._coordinator.db
            if self._coordinator is not None
            else None
        )
        if db is None:
            return {
                "incidents": incidents_list,
                "status_counts": status_counts,
                "total_count": total_count,
            }

        try:
            raw_incidents = db.query_incidents(
                status=status, limit=limit,
            )
        except Exception:
            logger.debug(
                "Failed to query incidents", exc_info=True,
            )
            raw_incidents = []

        # Collect active responses for cross-reference.
        active_responses: list[dict[str, Any]] = []
        try:
            rr = self._coordinator.response_router
            if rr is not None:
                active_responses = rr.get_active_responses()
        except Exception:
            logger.debug(
                "Failed to get active responses",
                exc_info=True,
            )

        for inc in raw_incidents:
            try:
                incident_id = inc.get("incident_id", "")
                alert_ids: list[str] = []
                try:
                    alert_ids = db.get_incident_alerts(incident_id)
                except Exception:
                    pass

                # Filter active responses matching this incident.
                inc_responses = [
                    r for r in active_responses
                    if r.get("alert_id") in alert_ids
                ]

                first_seen = inc.get("first_seen", 0.0)
                last_seen = inc.get("last_seen", 0.0)
                duration = max(0.0, last_seen - first_seen)

                enriched = dict(inc)
                enriched["alert_count"] = len(alert_ids)
                enriched["alert_ids"] = alert_ids
                enriched["active_responses"] = inc_responses
                enriched["duration_seconds"] = duration
                incidents_list.append(enriched)
            except Exception:
                logger.debug(
                    "Failed to enrich incident", exc_info=True,
                )

        # Status counts (unfiltered).
        for st in ("open", "closed", "merged"):
            try:
                status_counts[st] = db.incident_count(status=st)
            except Exception:
                pass

        try:
            total_count = db.incident_count()
        except Exception:
            pass

        return {
            "incidents": incidents_list,
            "status_counts": status_counts,
            "total_count": total_count,
        }

    # ------------------------------------------------------------------
    # 4. Executions page
    # ------------------------------------------------------------------

    def get_executions_data(
        self,
        status: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Return playbook executions enriched with steps and alert titles.

        Parameters
        ----------
        status:
            Filter by execution status string (e.g. ``"running"``),
            or ``None`` for all.
        limit:
            Maximum number of executions to return.

        Returns
        -------
        dict
            Keys: ``executions``, ``status_counts``,
            ``total_count``, ``playbooks_loaded``.
        """
        executions_list: list[dict[str, Any]] = []
        status_counts = {
            "running": 0, "completed": 0, "aborted": 0,
        }
        total_count = 0
        playbooks_loaded = 0

        # Playbooks loaded (independent of DB).
        try:
            if self._coordinator is not None:
                pe = self._coordinator.playbook_engine
                if pe is not None:
                    playbooks_loaded = pe.playbook_count
        except Exception:
            pass

        db = (
            self._coordinator.db
            if self._coordinator is not None
            else None
        )
        if db is None:
            return {
                "executions": executions_list,
                "status_counts": status_counts,
                "total_count": total_count,
                "playbooks_loaded": playbooks_loaded,
            }

        try:
            raw_execs = db.query_executions(
                status=status, limit=limit,
            )
        except Exception:
            logger.debug(
                "Failed to query executions", exc_info=True,
            )
            raw_execs = []

        for ex in raw_execs:
            try:
                enriched = dict(ex)

                # Attach execution steps.
                exec_id = ex.get("execution_id", "")
                try:
                    enriched["steps"] = db.get_execution_steps(
                        exec_id,
                    )
                except Exception:
                    enriched["steps"] = []

                # Attach alert title.
                alert_id = ex.get("alert_id", "")
                alert_title = ""
                if alert_id:
                    try:
                        alert_obj = db.get_alert(alert_id)
                        if alert_obj is not None:
                            alert_title = alert_obj.title
                    except Exception:
                        pass
                enriched["alert_title"] = alert_title

                executions_list.append(enriched)
            except Exception:
                logger.debug(
                    "Failed to enrich execution", exc_info=True,
                )

        # Status counts (unfiltered).
        for st in ("running", "completed", "aborted"):
            try:
                status_counts[st] = db.execution_count(status=st)
            except Exception:
                pass

        try:
            total_count = db.execution_count()
        except Exception:
            pass

        return {
            "executions": executions_list,
            "status_counts": status_counts,
            "total_count": total_count,
            "playbooks_loaded": playbooks_loaded,
        }

    # ------------------------------------------------------------------
    # 5. System status page
    # ------------------------------------------------------------------

    def get_system_status(self) -> dict[str, Any]:
        """Return full system health and operational status.

        Returns
        -------
        dict
            Keys: ``health``, ``scheduler_tasks``,
            ``whitelist_entries``, ``baseline_progress``,
            ``uptime_stats``.
        """
        if self._coordinator is None:
            return {
                "health": {},
                "scheduler_tasks": [],
                "whitelist_entries": 0,
                "baseline_progress": None,
                "uptime_stats": {
                    "events_processed": 0,
                    "alerts_generated": 0,
                    "is_running": False,
                },
            }

        # Health
        health: dict[str, Any] = {}
        try:
            sh = self._coordinator.system_health
            if sh is not None:
                health = sh.collect()
        except Exception:
            logger.debug(
                "Failed to collect health", exc_info=True,
            )

        # Scheduler tasks
        scheduler_tasks: list[dict[str, Any]] = []
        try:
            sched = self._coordinator.scheduler
            if sched is not None:
                stats = sched.get_stats()
                scheduler_tasks = stats.get("tasks", [])
        except Exception:
            logger.debug(
                "Failed to get scheduler tasks", exc_info=True,
            )

        # Whitelist entries
        whitelist_entries = 0
        try:
            wm = self._coordinator.whitelist_manager
            if wm is not None:
                whitelist_entries = wm.entry_count
        except Exception:
            logger.debug(
                "Failed to get whitelist count", exc_info=True,
            )

        # Baseline / learning progress
        baseline_progress: dict[str, Any] | None = None
        try:
            wm = self._coordinator.whitelist_manager
            if wm is not None and hasattr(wm, "get_learning_progress"):
                baseline_progress = wm.get_learning_progress()
        except Exception:
            logger.debug(
                "Failed to get baseline progress", exc_info=True,
            )

        # Uptime stats from the event engine.
        uptime_stats: dict[str, Any] = {
            "events_processed": 0,
            "alerts_generated": 0,
            "is_running": False,
        }
        try:
            engine = self._coordinator.engine
            if engine is not None:
                uptime_stats = {
                    "events_processed": engine.events_processed,
                    "alerts_generated": engine.alerts_generated,
                    "is_running": engine.is_running,
                }
        except Exception:
            logger.debug(
                "Failed to get engine stats", exc_info=True,
            )

        return {
            "health": health,
            "scheduler_tasks": scheduler_tasks,
            "whitelist_entries": whitelist_entries,
            "baseline_progress": baseline_progress,
            "uptime_stats": uptime_stats,
        }

    # ------------------------------------------------------------------
    # 6. Canary status page
    # ------------------------------------------------------------------

    def get_canary_status(self) -> dict[str, Any]:
        """Return canary deployment overview and per-canary details.

        Returns
        -------
        dict
            Keys: ``overview``, ``canaries``,
            ``last_verification``.
        """
        if self._coordinator is None:
            return {
                "overview": {
                    "total_deployed": 0,
                    "healthy": 0,
                    "triggered": 0,
                    "errors": 0,
                },
                "canaries": [],
                "last_verification": None,
            }

        default_overview: dict[str, Any] = {
            "total_deployed": 0,
            "healthy": 0,
            "triggered": 0,
            "errors": 0,
        }

        canary_sys = self._coordinator.canary_system

        # Overview
        overview = dict(default_overview)
        try:
            if canary_sys is not None:
                overview = canary_sys.get_status()
        except Exception:
            logger.debug(
                "Failed to get canary status", exc_info=True,
            )

        # Individual canaries
        canaries_list: list[dict[str, Any]] = []
        last_verification: float | None = None
        try:
            if canary_sys is not None:
                raw_canaries = canary_sys.canaries
                for c in raw_canaries:
                    canaries_list.append({
                        "canary_id": c.canary_id,
                        "path": str(c.path),
                        "file_type": c.file_type,
                        "status": c.status,
                        "last_verified": c.last_verified,
                        "trigger_reason": c.trigger_reason,
                    })
                    if c.last_verified is not None:
                        if (
                            last_verification is None
                            or c.last_verified > last_verification
                        ):
                            last_verification = c.last_verified
        except Exception:
            logger.debug(
                "Failed to enumerate canaries", exc_info=True,
            )

        return {
            "overview": overview,
            "canaries": canaries_list,
            "last_verification": last_verification,
        }

    # ------------------------------------------------------------------
    # 7. Threat intel page
    # ------------------------------------------------------------------

    def get_threat_intel_data(self) -> dict[str, Any]:
        """Return threat intelligence feed health and IOC statistics.

        Returns
        -------
        dict
            Keys: ``feed_health``, ``ioc_count``, ``bloom_stats``.
        """
        default: dict[str, Any] = {
            "feed_health": {
                "total_feeds": 0,
                "healthy": 0,
                "stale": 0,
                "errored": 0,
                "feeds": [],
            },
            "ioc_count": 0,
            "bloom_stats": None,
        }
        if self._coordinator is None:
            return default

        # Feed health
        feed_health = dict(default["feed_health"])
        try:
            fht = self._coordinator.feed_health_tracker
            if fht is not None:
                feed_health = fht.get_status()
        except Exception:
            logger.debug(
                "Failed to get feed health", exc_info=True,
            )

        # IOC count
        ioc_count = 0
        try:
            tfm = self._coordinator.threat_feed_manager
            if tfm is not None:
                ioc_count = tfm.ioc_count
        except Exception:
            logger.debug(
                "Failed to get IOC count", exc_info=True,
            )

        # Bloom filter stats
        bloom_stats: dict[str, Any] | None = None
        try:
            tfm = self._coordinator.threat_feed_manager
            if tfm is not None:
                bloom = getattr(tfm, "_bloom", None)
                if bloom is not None:
                    bloom_stats = {
                        "size": bloom.size,
                        "count": bloom.item_count,
                    }
        except Exception:
            logger.debug(
                "Failed to get bloom stats", exc_info=True,
            )

        return {
            "feed_health": feed_health,
            "ioc_count": ioc_count,
            "bloom_stats": bloom_stats,
        }

    # ==================================================================
    # Private helpers
    # ==================================================================

    def _collect_health_summary(self) -> dict[str, Any]:
        """Collect full health summary via SystemHealth."""
        try:
            sh = self._coordinator.system_health
            if sh is not None:
                return sh.collect()
        except Exception:
            logger.debug(
                "Health summary collection failed",
                exc_info=True,
            )
        return {}

    def _collect_sensor_status(self) -> list[dict[str, Any]]:
        """Build sensor status list for the home page."""
        db = self._coordinator.db
        sm = getattr(self._coordinator, "sensor_manager", None)
        live_health: dict[str, Any] = {}
        if sm is not None:
            try:
                for name, h in sm.get_all_health().items():
                    live_health[name] = h.to_dict()
            except Exception:
                pass

        result: list[dict[str, Any]] = []
        for name in _KEY_SENSORS:
            entry: dict[str, Any] = {
                "name": name,
                "status": "unknown",
                "event_count": 0,
            }
            # Live health from SensorManager
            if name in live_health:
                lh = live_health[name]
                entry["is_running"] = lh.get("is_running", False)
                entry["events_emitted"] = lh.get(
                    "events_emitted", 0,
                )
                entry["errors"] = lh.get("errors", 0)
                if lh.get("is_running"):
                    entry["status"] = "active"
                elif lh.get("enabled"):
                    entry["status"] = "idle"
            # DB event count
            if db is not None:
                try:
                    from aegis.core.models import SensorType

                    sensor_enum = SensorType(name)
                    count = db.event_count(sensor=sensor_enum)
                    entry["event_count"] = count
                    if entry["status"] == "unknown":
                        entry["status"] = (
                            "active" if count > 0 else "idle"
                        )
                except (ValueError, Exception):
                    pass
            result.append(entry)
        return result

    def _collect_recent_alerts(self) -> list[dict[str, Any]]:
        """Fetch the 10 most recent alerts as lightweight dicts."""
        db = self._coordinator.db
        if db is None:
            return []
        try:
            alerts = db.query_alerts(limit=10)
            return [
                {
                    "alert_id": a.alert_id,
                    "timestamp": a.timestamp,
                    "severity": a.severity.value,
                    "title": a.title,
                    "sensor": a.sensor.value,
                    "confidence": a.confidence,
                    "status": a.status.value,
                }
                for a in alerts
            ]
        except Exception:
            logger.debug(
                "Failed to fetch recent alerts", exc_info=True,
            )
            return []

    @staticmethod
    def _empty_home_stats() -> dict[str, Any]:
        """Return zero-valued home stats."""
        return {
            "events_24h": 0,
            "alerts_24h": 0,
            "incidents_open": 0,
            "responses_total": 0,
        }

    def _collect_home_stats(self) -> dict[str, Any]:
        """Build the aggregated stats block for the home page."""
        stats: dict[str, Any] = {
            "events_24h": 0,
            "alerts_24h": 0,
            "incidents_open": 0,
            "responses_total": 0,
        }
        db = self._coordinator.db
        cutoff = time.time() - 86400

        # Events in last 24 hours.
        if db is not None:
            try:
                events = db.query_events(since=cutoff)
                stats["events_24h"] = len(events)
            except Exception:
                logger.debug(
                    "Failed to count events_24h", exc_info=True,
                )

        # Alerts in last 24 hours.
        if db is not None:
            try:
                all_alerts = db.query_alerts(limit=10000)
                stats["alerts_24h"] = len(
                    [a for a in all_alerts if a.timestamp >= cutoff],
                )
            except Exception:
                logger.debug(
                    "Failed to count alerts_24h", exc_info=True,
                )

        # Open incidents.
        if db is not None:
            try:
                stats["incidents_open"] = db.incident_count(
                    status="open",
                )
            except Exception:
                logger.debug(
                    "Failed to count open incidents",
                    exc_info=True,
                )

        # Total responses.
        try:
            rr = self._coordinator.response_router
            if rr is not None:
                rr_stats = rr.get_stats()
                stats["responses_total"] = rr_stats.get(
                    "responses_total", 0,
                )
        except Exception:
            logger.debug(
                "Failed to get response stats", exc_info=True,
            )

        return stats

    def _collect_canary_overview(self) -> dict[str, Any]:
        """Collect canary overview for the home page."""
        try:
            cs = self._coordinator.canary_system
            if cs is not None:
                return cs.get_status()
        except Exception:
            logger.debug(
                "Failed to get canary overview", exc_info=True,
            )
        return {}

    def _collect_scheduler_overview(self) -> dict[str, Any]:
        """Collect scheduler summary for the home page."""
        defaults: dict[str, Any] = {
            "task_count": 0,
            "total_runs": 0,
            "total_errors": 0,
        }
        try:
            sched = self._coordinator.scheduler
            if sched is not None:
                stats = sched.get_stats()
                return {
                    "task_count": stats.get("task_count", 0),
                    "total_runs": stats.get("total_runs", 0),
                    "total_errors": stats.get("total_errors", 0),
                }
        except Exception:
            logger.debug(
                "Failed to get scheduler overview",
                exc_info=True,
            )
        return defaults

    def _build_alert_incident_map(self) -> dict[str, str]:
        """Build a reverse lookup from alert_id to incident_id."""
        mapping: dict[str, str] = {}
        db = self._coordinator.db
        if db is None:
            return mapping
        try:
            incidents = db.query_incidents(limit=1000)
            for inc in incidents:
                incident_id = inc.get("incident_id", "")
                try:
                    alert_ids = db.get_incident_alerts(incident_id)
                    for aid in alert_ids:
                        mapping[aid] = incident_id
                except Exception:
                    pass
        except Exception:
            logger.debug(
                "Failed to build alert-incident map",
                exc_info=True,
            )
        return mapping

    def _build_alert_response_map(self) -> dict[str, str]:
        """Build a lookup from alert_id to response status."""
        mapping: dict[str, str] = {}
        try:
            rr = self._coordinator.response_router
            if rr is not None:
                active = rr.get_active_responses()
                for resp in active:
                    aid = resp.get("alert_id")
                    st = resp.get("status")
                    if aid and st:
                        mapping[aid] = st
        except Exception:
            logger.debug(
                "Failed to build alert-response map",
                exc_info=True,
            )
        return mapping
