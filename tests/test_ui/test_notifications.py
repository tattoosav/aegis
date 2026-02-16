"""Tests for the NotificationManager."""

from __future__ import annotations

from unittest.mock import MagicMock

from aegis.core.models import Alert, SensorType, Severity
from aegis.ui.notifications import NotificationManager


def _make_alert(severity: Severity, confidence: float) -> Alert:
    return Alert(
        event_id="evt-test",
        sensor=SensorType.PROCESS,
        alert_type="test",
        severity=severity,
        title="Test alert",
        description="Test",
        confidence=confidence,
        data={},
    )


class TestNotificationManager:
    def test_critical_routes_fullscreen(self):
        mgr = NotificationManager()
        alert = _make_alert(Severity.CRITICAL, 0.95)
        channel = mgr.notify(alert)
        assert channel == "fullscreen"

    def test_high_routes_toast(self):
        mgr = NotificationManager()
        alert = _make_alert(Severity.HIGH, 0.85)
        channel = mgr.notify(alert)
        assert channel == "toast"

    def test_medium_routes_tray(self):
        mgr = NotificationManager()
        alert = _make_alert(Severity.MEDIUM, 0.7)
        channel = mgr.notify(alert)
        assert channel == "tray"

    def test_low_routes_log(self):
        mgr = NotificationManager()
        alert = _make_alert(Severity.LOW, 0.5)
        channel = mgr.notify(alert)
        assert channel == "log"

    def test_info_routes_log(self):
        mgr = NotificationManager()
        alert = _make_alert(Severity.INFO, 0.3)
        channel = mgr.notify(alert)
        assert channel == "log"

    def test_fullscreen_callback_invoked(self):
        cb = MagicMock()
        mgr = NotificationManager(on_fullscreen=cb)
        alert = _make_alert(Severity.CRITICAL, 0.95)
        mgr.notify(alert)
        cb.assert_called_once_with(alert)

    def test_tray_set_status_called(self):
        tray = MagicMock()
        mgr = NotificationManager(tray=tray)
        alert = _make_alert(Severity.CRITICAL, 0.95)
        mgr.notify(alert)
        tray.set_status.assert_called_with("critical")

    def test_toast_shows_notification(self):
        tray = MagicMock()
        mgr = NotificationManager(tray=tray)
        alert = _make_alert(Severity.HIGH, 0.85)
        mgr.notify(alert)
        tray.show_notification.assert_called_once()

    def test_notification_count_increments(self):
        mgr = NotificationManager()
        assert mgr.notification_count == 0
        mgr.notify(_make_alert(Severity.LOW, 0.3))
        mgr.notify(_make_alert(Severity.HIGH, 0.8))
        assert mgr.notification_count == 2

    def test_callback_error_does_not_crash(self):
        cb = MagicMock(side_effect=RuntimeError("boom"))
        mgr = NotificationManager(on_fullscreen=cb)
        alert = _make_alert(Severity.CRITICAL, 0.95)
        channel = mgr.notify(alert)
        assert channel == "fullscreen"
        assert mgr.notification_count == 1
