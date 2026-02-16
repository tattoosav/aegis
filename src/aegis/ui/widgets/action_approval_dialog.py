"""Action Approval Dialog — user must explicitly approve every response action.

This is the critical gate that prevents Aegis from auto-executing any
response action.  Every detected threat presents recommended actions;
the user must review and click "Approve & Execute" before anything happens.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aegis.response.action_executor import ActionPreview

logger = logging.getLogger(__name__)


class ActionApprovalDialog(QDialog):
    """Modal dialog requiring user approval before executing an action.

    Signals
    -------
    action_approved(str, str)
        Emitted with (alert_id, action_type) when the user approves.
    action_rejected(str, str)
        Emitted with (alert_id, action_type) when the user rejects.
    """

    action_approved = Signal(str, str)
    action_rejected = Signal(str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._alert_id: str = ""
        self._action_type: str = ""
        self._build_ui()

    def _build_ui(self) -> None:
        self.setWindowTitle("Aegis \u2014 Action Approval Required")
        self.setMinimumWidth(500)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # Warning header
        header = QLabel(
            "\u26a0  Action Requires Your Approval"
        )
        header_font = QFont()
        header_font.setPointSize(14)
        header_font.setBold(True)
        header.setFont(header_font)
        header.setStyleSheet("color: #fb8c00;")
        layout.addWidget(header)

        # Action type
        self._action_label = QLabel()
        self._action_label.setStyleSheet(
            "font-size: 13px; font-weight: bold; color: #ffffff;"
        )
        layout.addWidget(self._action_label)

        # Description
        self._desc_label = QLabel()
        self._desc_label.setWordWrap(True)
        self._desc_label.setStyleSheet("color: #cccccc;")
        layout.addWidget(self._desc_label)

        # Impact warning
        impact_frame = QFrame()
        impact_frame.setStyleSheet(
            "background-color: #2d1b1b; border: 1px solid #e53935; "
            "border-radius: 6px; padding: 8px;"
        )
        impact_layout = QVBoxLayout(impact_frame)
        self._impact_label = QLabel()
        self._impact_label.setWordWrap(True)
        self._impact_label.setStyleSheet("color: #ef9a9a;")
        impact_layout.addWidget(self._impact_label)
        layout.addWidget(impact_frame)

        # Reversible indicator
        self._reversible_label = QLabel()
        self._reversible_label.setStyleSheet("color: #a5d6a7;")
        layout.addWidget(self._reversible_label)

        # Reason input (optional)
        reason_label = QLabel("Reason (optional):")
        reason_label.setStyleSheet("color: #999999;")
        layout.addWidget(reason_label)

        self._reason_edit = QTextEdit()
        self._reason_edit.setMaximumHeight(60)
        self._reason_edit.setPlaceholderText(
            "Why are you approving this action?"
        )
        layout.addWidget(self._reason_edit)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        approve_btn = QPushButton("Approve & Execute")
        approve_btn.setObjectName("btnApprove")
        approve_btn.setStyleSheet(
            "background-color: #e53935; color: white; "
            "padding: 10px 24px; border-radius: 6px; font-weight: bold;"
        )
        approve_btn.clicked.connect(self._on_approve)

        reject_btn = QPushButton("Reject")
        reject_btn.setObjectName("btnReject")
        reject_btn.setStyleSheet(
            "background-color: #424242; color: white; "
            "padding: 10px 24px; border-radius: 6px;"
        )
        reject_btn.clicked.connect(self._on_reject)

        btn_row.addStretch()
        btn_row.addWidget(reject_btn)
        btn_row.addWidget(approve_btn)
        layout.addLayout(btn_row)

    def show_preview(
        self,
        alert_id: str,
        preview: ActionPreview,
    ) -> None:
        """Populate the dialog with action details and show it.

        Parameters
        ----------
        alert_id:
            The alert this action relates to.
        preview:
            The :class:`ActionPreview` describing the proposed action.
        """
        self._alert_id = alert_id
        self._action_type = preview.action_type

        self._action_label.setText(
            f"Action: {preview.action_type.replace('_', ' ').title()}"
        )
        self._desc_label.setText(preview.description)
        self._impact_label.setText(
            f"Impact: {preview.impact}"
        )
        self._reversible_label.setText(
            "Reversible: Yes" if preview.reversible
            else "Reversible: No \u2014 this action cannot be undone!"
        )
        self._reason_edit.clear()
        self.exec()

    @property
    def reason(self) -> str:
        """Return the user-provided reason text."""
        return self._reason_edit.toPlainText().strip()

    def _on_approve(self) -> None:
        logger.info(
            "User APPROVED action %s for alert %s",
            self._action_type, self._alert_id,
        )
        self.action_approved.emit(
            self._alert_id, self._action_type
        )
        self.accept()

    def _on_reject(self) -> None:
        logger.info(
            "User REJECTED action %s for alert %s",
            self._action_type, self._alert_id,
        )
        self.action_rejected.emit(
            self._alert_id, self._action_type
        )
        self.reject()
