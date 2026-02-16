"""Full-screen alert overlay for critical security events.

Displayed when a CRITICAL-severity alert is raised, blocking
the UI until the user acknowledges and chooses an action.
Requires explicit user approval before any response action.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aegis.core.models import Alert

logger = logging.getLogger(__name__)


class FullscreenAlert(QWidget):
    """Overlay widget for critical alerts requiring immediate attention.

    Signals
    -------
    investigate_clicked(str)
        Emitted with alert_id when user clicks Investigate.
    dismiss_clicked(str)
        Emitted with alert_id when user clicks Dismiss.
    approve_action_clicked(str)
        Emitted with alert_id when user wants to approve an action.
    """

    investigate_clicked = Signal(str)
    dismiss_clicked = Signal(str)
    approve_action_clicked = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._alert_id: str = ""
        self._build_ui()
        self.hide()

    def _build_ui(self) -> None:
        self.setObjectName("fullscreenAlert")
        self.setStyleSheet(
            "#fullscreenAlert {"
            "  background-color: rgba(20, 20, 20, 230);"
            "}"
        )

        root = QVBoxLayout(self)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Card container
        card = QFrame()
        card.setObjectName("alertCard")
        card.setFixedWidth(600)
        card.setStyleSheet(
            "#alertCard {"
            "  background-color: #1a1a2e;"
            "  border: 2px solid #e53935;"
            "  border-radius: 12px;"
            "  padding: 24px;"
            "}"
        )

        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(16)

        # Severity banner
        self._severity_label = QLabel("CRITICAL ALERT")
        self._severity_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self._severity_label.setStyleSheet(
            "color: #e53935; font-size: 20px; font-weight: bold;"
        )
        card_layout.addWidget(self._severity_label)

        # Title
        self._title_label = QLabel()
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        self._title_label.setFont(title_font)
        self._title_label.setWordWrap(True)
        self._title_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self._title_label.setStyleSheet("color: #ffffff;")
        card_layout.addWidget(self._title_label)

        # Description
        self._desc_label = QLabel()
        self._desc_label.setWordWrap(True)
        self._desc_label.setStyleSheet("color: #cccccc;")
        card_layout.addWidget(self._desc_label)

        # MITRE line
        self._mitre_label = QLabel()
        self._mitre_label.setStyleSheet("color: #90caf9;")
        card_layout.addWidget(self._mitre_label)

        # Confidence
        self._confidence_label = QLabel()
        self._confidence_label.setStyleSheet("color: #a5d6a7;")
        card_layout.addWidget(self._confidence_label)

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        investigate_btn = QPushButton("Investigate")
        investigate_btn.setObjectName("btnInvestigate")
        investigate_btn.setStyleSheet(
            "background-color: #1565c0; color: white; "
            "padding: 10px 24px; border-radius: 6px; font-weight: bold;"
        )
        investigate_btn.clicked.connect(self._on_investigate)

        approve_btn = QPushButton("Approve Action")
        approve_btn.setObjectName("btnApproveAction")
        approve_btn.setStyleSheet(
            "background-color: #e53935; color: white; "
            "padding: 10px 24px; border-radius: 6px; font-weight: bold;"
        )
        approve_btn.clicked.connect(self._on_approve)

        dismiss_btn = QPushButton("Dismiss")
        dismiss_btn.setObjectName("btnDismiss")
        dismiss_btn.setStyleSheet(
            "background-color: #424242; color: white; "
            "padding: 10px 24px; border-radius: 6px;"
        )
        dismiss_btn.clicked.connect(self._on_dismiss)

        btn_row.addWidget(investigate_btn)
        btn_row.addWidget(approve_btn)
        btn_row.addWidget(dismiss_btn)
        card_layout.addLayout(btn_row)

        root.addWidget(card)

    def show_alert(self, alert: Alert) -> None:
        """Populate and display the overlay for *alert*."""
        self._alert_id = alert.alert_id
        self._title_label.setText(alert.title)
        self._desc_label.setText(alert.description)
        self._confidence_label.setText(
            f"Confidence: {alert.confidence * 100:.0f}%"
        )
        if alert.mitre_ids:
            self._mitre_label.setText(
                f"MITRE: {', '.join(alert.mitre_ids)}"
            )
        else:
            self._mitre_label.setText("")

        self.show()
        self.raise_()
        logger.info(
            "Fullscreen alert shown for %s", alert.alert_id
        )

    def _on_investigate(self) -> None:
        self.investigate_clicked.emit(self._alert_id)
        self.hide()

    def _on_approve(self) -> None:
        self.approve_action_clicked.emit(self._alert_id)
        self.hide()

    def _on_dismiss(self) -> None:
        self.dismiss_clicked.emit(self._alert_id)
        self.hide()
