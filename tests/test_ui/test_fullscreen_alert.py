"""Tests for the FullscreenAlert widget."""

from __future__ import annotations

import pytest

PySide6 = pytest.importorskip("PySide6")

from aegis.core.models import Alert, SensorType, Severity  # noqa: E402
from aegis.ui.widgets.fullscreen_alert import FullscreenAlert  # noqa: E402


def _make_alert() -> Alert:
    return Alert(
        event_id="evt-test",
        sensor=SensorType.PROCESS,
        alert_type="chain_ransomware",
        severity=Severity.CRITICAL,
        title="Ransomware detected",
        description="Process encrypting files rapidly",
        confidence=0.95,
        data={},
        mitre_ids=["T1486"],
    )


class TestFullscreenAlert:
    def test_creates_widget(self, qtbot):
        widget = FullscreenAlert()
        qtbot.addWidget(widget)
        assert widget.objectName() == "fullscreenAlert"

    def test_starts_hidden(self, qtbot):
        widget = FullscreenAlert()
        qtbot.addWidget(widget)
        assert not widget.isVisible()

    def test_show_alert_populates_title(self, qtbot):
        widget = FullscreenAlert()
        qtbot.addWidget(widget)
        alert = _make_alert()
        widget.show_alert(alert)
        assert "Ransomware" in widget._title_label.text()

    def test_show_alert_populates_mitre(self, qtbot):
        widget = FullscreenAlert()
        qtbot.addWidget(widget)
        alert = _make_alert()
        widget.show_alert(alert)
        assert "T1486" in widget._mitre_label.text()

    def test_show_alert_populates_confidence(self, qtbot):
        widget = FullscreenAlert()
        qtbot.addWidget(widget)
        alert = _make_alert()
        widget.show_alert(alert)
        assert "95%" in widget._confidence_label.text()

    def test_investigate_emits_signal(self, qtbot):
        widget = FullscreenAlert()
        qtbot.addWidget(widget)
        alert = _make_alert()
        widget.show_alert(alert)

        with qtbot.waitSignal(widget.investigate_clicked):
            widget._on_investigate()

    def test_dismiss_emits_signal(self, qtbot):
        widget = FullscreenAlert()
        qtbot.addWidget(widget)
        alert = _make_alert()
        widget.show_alert(alert)

        with qtbot.waitSignal(widget.dismiss_clicked):
            widget._on_dismiss()

    def test_approve_emits_signal(self, qtbot):
        widget = FullscreenAlert()
        qtbot.addWidget(widget)
        alert = _make_alert()
        widget.show_alert(alert)

        with qtbot.waitSignal(widget.approve_action_clicked):
            widget._on_approve()

    def test_buttons_exist(self, qtbot):
        widget = FullscreenAlert()
        qtbot.addWidget(widget)
        btn_investigate = widget.findChild(
            PySide6.QtWidgets.QPushButton, "btnInvestigate"
        )
        btn_dismiss = widget.findChild(
            PySide6.QtWidgets.QPushButton, "btnDismiss"
        )
        btn_approve = widget.findChild(
            PySide6.QtWidgets.QPushButton, "btnApproveAction"
        )
        assert btn_investigate is not None
        assert btn_dismiss is not None
        assert btn_approve is not None
