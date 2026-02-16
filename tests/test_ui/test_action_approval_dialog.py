"""Tests for the ActionApprovalDialog."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

PySide6 = pytest.importorskip("PySide6")

from aegis.ui.widgets.action_approval_dialog import (  # noqa: E402
    ActionApprovalDialog,
)


@dataclass
class FakePreview:
    action_type: str = "kill_process"
    description: str = "Terminate malicious process"
    impact: str = "Process will be killed immediately"
    reversible: bool = False
    requires_approval: bool = True


class TestActionApprovalDialog:
    def test_creates_dialog(self, qtbot):
        dialog = ActionApprovalDialog()
        qtbot.addWidget(dialog)
        assert dialog.windowTitle().startswith("Aegis")

    def test_is_modal(self, qtbot):
        dialog = ActionApprovalDialog()
        qtbot.addWidget(dialog)
        assert dialog.isModal()

    def test_buttons_exist(self, qtbot):
        dialog = ActionApprovalDialog()
        qtbot.addWidget(dialog)
        approve = dialog.findChild(
            PySide6.QtWidgets.QPushButton, "btnApprove"
        )
        reject = dialog.findChild(
            PySide6.QtWidgets.QPushButton, "btnReject"
        )
        assert approve is not None
        assert reject is not None

    def test_approve_emits_signal(self, qtbot):
        dialog = ActionApprovalDialog()
        qtbot.addWidget(dialog)
        dialog._alert_id = "alt-abc"
        dialog._action_type = "kill_process"

        with qtbot.waitSignal(dialog.action_approved):
            dialog._on_approve()

    def test_reject_emits_signal(self, qtbot):
        dialog = ActionApprovalDialog()
        qtbot.addWidget(dialog)
        dialog._alert_id = "alt-abc"
        dialog._action_type = "kill_process"

        with qtbot.waitSignal(dialog.action_rejected):
            dialog._on_reject()

    def test_reason_property_empty_by_default(self, qtbot):
        dialog = ActionApprovalDialog()
        qtbot.addWidget(dialog)
        assert dialog.reason == ""

    def test_minimum_width(self, qtbot):
        dialog = ActionApprovalDialog()
        qtbot.addWidget(dialog)
        assert dialog.minimumWidth() >= 500
