"""Alert-to-response routing for Aegis.

Routes alerts through the playbook engine and triggers incident
reports when significance thresholds are met.  Acts as the single
integration point between detection and response subsystems.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.alerting.correlation_engine import Incident
    from aegis.response.forensic_logger import ForensicLogger
    from aegis.response.playbook_engine import PlaybookEngine
    from aegis.response.report_generator import ReportGenerator

from aegis.core.models import Alert, Severity

logger = logging.getLogger(__name__)


@dataclass
class ResponseResult:
    """Outcome of routing an alert through the response pipeline."""

    alert_id: str
    playbooks_triggered: list[str] = field(default_factory=list)
    executions_started: list[str] = field(default_factory=list)
    report_generated: bool = False
    report_title: str = ""
    errors: list[str] = field(default_factory=list)


class ResponseRouter:
    """Route alerts and incidents through the response pipeline.

    Orchestrates:
    1. PlaybookEngine trigger evaluation + execution start
    2. Incident-threshold report generation
    3. Forensic logging of response actions
    """

    def __init__(
        self,
        playbook_engine: PlaybookEngine | None = None,
        report_generator: ReportGenerator | None = None,
        forensic_logger: ForensicLogger | None = None,
        min_alerts_for_report: int = 3,
    ) -> None:
        self._playbook_engine = playbook_engine
        self._report_generator = report_generator
        self._forensic_logger = forensic_logger
        self._min_alerts_for_report = min_alerts_for_report
        self._lock = threading.Lock()
        self._playbooks_triggered: int = 0
        self._reports_generated: int = 0
        self._responses_total: int = 0

    # ------------------------------------------------------------------ #
    # Public routing methods
    # ------------------------------------------------------------------ #

    def route_alert(
        self,
        alert: Alert,
        incident: Incident | None = None,
    ) -> ResponseResult:
        """Route an alert through playbooks and optionally generate a report.

        Parameters
        ----------
        alert:
            The alert to process.
        incident:
            Optional correlated incident.  If provided and the
            significance threshold is met, a report is generated.

        Returns
        -------
        ResponseResult
            Summary of playbooks triggered, executions started,
            and whether a report was generated.
        """
        result = ResponseResult(alert_id=alert.alert_id)

        # Step 1 -- evaluate playbook triggers
        if self._playbook_engine is not None:
            try:
                matches = self._playbook_engine.evaluate_trigger(alert)
                for playbook in matches:
                    execution = self._playbook_engine.start_execution(
                        playbook, alert,
                    )
                    result.playbooks_triggered.append(playbook.name)
                    result.executions_started.append(
                        execution.execution_id,
                    )
                if matches:
                    with self._lock:
                        self._playbooks_triggered += len(matches)
                    logger.info(
                        "Alert %s triggered %d playbook(s): %s",
                        alert.alert_id,
                        len(matches),
                        ", ".join(result.playbooks_triggered),
                    )
            except Exception as exc:  # noqa: BLE001
                msg = f"Playbook evaluation failed: {exc}"
                result.errors.append(msg)
                logger.error(msg, exc_info=True)

        # Step 2 -- generate report if incident crosses threshold
        if incident is not None and self._check_report_threshold(
            incident,
        ):
            self._generate_incident_report(result, incident)

        # Step 3 -- increment total counter
        with self._lock:
            self._responses_total += 1

        return result

    def route_incident(self, incident: Incident) -> ResponseResult:
        """Route a standalone incident for report generation.

        Use this when an incident reaches the significance threshold
        without a specific new alert (e.g. after pruning or campaign
        detection).
        """
        result = ResponseResult(alert_id="")

        if self._check_report_threshold(incident):
            self._generate_incident_report(result, incident)

        with self._lock:
            self._responses_total += 1

        return result

    # ------------------------------------------------------------------ #
    # Active-response introspection
    # ------------------------------------------------------------------ #

    def get_active_responses(self) -> list[dict[str, Any]]:
        """Return currently running playbook executions as dicts."""
        if self._playbook_engine is None:
            return []

        responses: list[dict[str, Any]] = []
        for execution in self._playbook_engine.active_executions:
            responses.append({
                "execution_id": execution.execution_id,
                "playbook_name": execution.playbook.name,
                "alert_id": execution.alert.alert_id,
                "status": execution.status,
                "current_step": execution.current_step,
            })
        return responses

    def get_stats(self) -> dict[str, Any]:
        """Return thread-safe snapshot of routing statistics."""
        with self._lock:
            return {
                "playbooks_triggered": self._playbooks_triggered,
                "reports_generated": self._reports_generated,
                "responses_total": self._responses_total,
            }

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    def _check_report_threshold(self, incident: Any) -> bool:
        """Decide whether an incident warrants a report.

        Returns ``True`` when:
        * The incident contains at least *min_alerts_for_report* alerts, OR
        * The incident severity is HIGH or CRITICAL.
        """
        if incident.alert_count >= self._min_alerts_for_report:
            return True
        try:
            if incident.severity.weight >= Severity.HIGH.weight:
                return True
        except AttributeError:
            pass
        return False

    def _generate_incident_report(
        self,
        result: ResponseResult,
        incident: Any,
    ) -> None:
        """Attempt to generate a report and update *result* in place."""
        title = f"Incident Report: {incident.title}"
        try:
            if self._report_generator is not None:
                self._report_generator.generate_report(
                    title=title,
                    since=incident.first_seen,
                )
            result.report_generated = True
            result.report_title = title
            with self._lock:
                self._reports_generated += 1
            logger.info("Generated report: %s", title)
        except Exception as exc:  # noqa: BLE001
            msg = f"Report generation failed: {exc}"
            result.errors.append(msg)
            logger.error(msg, exc_info=True)
