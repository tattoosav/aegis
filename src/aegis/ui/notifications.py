"""Notification Manager — routes alerts to the appropriate UI channel.

Routing rules (from design doc):
  Critical (80-100): Full-screen alert overlay + sound
  High (60-79): Toast / tray balloon notification
  Medium (30-59): Tray icon colour change
  Low (0-29): Silent log entry (daily digest)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.core.models import Alert

logger = logging.getLogger(__name__)


class NotificationManager:
    """Route alerts to the correct notification channel.

    Parameters
    ----------
    tray:
        Tray widget with ``set_status(str)`` and
        ``show_notification(title, message, severity)``.
    on_fullscreen:
        Callback ``(alert) -> None`` invoked for critical alerts.
    """

    def __init__(
        self,
        tray: Any = None,
        on_fullscreen: Any = None,
    ) -> None:
        self._tray = tray
        self._on_fullscreen = on_fullscreen
        self._notification_count = 0

    @property
    def notification_count(self) -> int:
        return self._notification_count

    def notify(self, alert: Alert) -> str:
        """Route *alert* to the appropriate channel.

        Returns the channel name: ``"fullscreen"``, ``"toast"``,
        ``"tray"``, or ``"log"``.
        """
        score = alert.priority_score
        channel = self._route(score)

        if channel == "fullscreen":
            self._show_fullscreen(alert)
        elif channel == "toast":
            self._show_toast(alert)
        elif channel == "tray":
            self._update_tray(alert)
        else:
            logger.info(
                "Alert %s routed to log (score=%.1f)",
                alert.alert_id, score,
            )

        self._notification_count += 1
        return channel

    @staticmethod
    def _route(score: float) -> str:
        if score >= 80:
            return "fullscreen"
        elif score >= 60:
            return "toast"
        elif score >= 30:
            return "tray"
        return "log"

    def _show_fullscreen(self, alert: Alert) -> None:
        """Display a full-screen critical alert overlay."""
        logger.warning(
            "CRITICAL ALERT: %s (score=%.1f)",
            alert.title, alert.priority_score,
        )
        if self._tray:
            self._tray.set_status("critical")
        if self._on_fullscreen:
            try:
                self._on_fullscreen(alert)
            except Exception as exc:
                logger.error("Fullscreen callback failed: %s", exc)

    def _show_toast(self, alert: Alert) -> None:
        """Display a tray balloon / toast notification."""
        logger.info(
            "Toast alert: %s (score=%.1f)",
            alert.title, alert.priority_score,
        )
        if self._tray:
            self._tray.set_status("warning")
            try:
                self._tray.show_notification(
                    title=f"Aegis Alert: {alert.severity.value.upper()}",
                    message=alert.title,
                    severity=alert.severity.value,
                )
            except Exception as exc:
                logger.error("Toast notification failed: %s", exc)

    def _update_tray(self, alert: Alert) -> None:
        """Change the tray icon colour for medium-severity alerts."""
        logger.info(
            "Tray update for alert: %s (score=%.1f)",
            alert.title, alert.priority_score,
        )
        if self._tray:
            self._tray.set_status("warning")
