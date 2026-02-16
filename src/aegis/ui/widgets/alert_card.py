"""Alert Card widget — displays a single alert with action buttons.

Shows severity badge, title, confidence bar, MITRE badges, and
action buttons (Investigate, Dismiss, Execute Action).  All response
actions require explicit user approval via button click.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

_SEVERITY_COLORS = {
    "critical": "#f44336",
    "high": "#ff9800",
    "medium": "#ffeb3b",
    "low": "#4caf50",
    "info": "#2196f3",
}


class AlertCard(QFrame):
    """A card widget representing a single security alert.

    Signals
    -------
    investigate_clicked(str)
        Emitted with the alert_id when "Investigate" is clicked.
    dismiss_clicked(str)
        Emitted with the alert_id when "Dismiss" is clicked.
    execute_action_clicked(str, str)
        Emitted with (alert_id, action_type) when "Execute" is clicked.
    """

    investigate_clicked = Signal(str)
    dismiss_clicked = Signal(str)
    execute_action_clicked = Signal(str, str)

    def __init__(
        self,
        alert_id: str,
        title: str,
        severity: str,
        confidence: float,
        description: str = "",
        mitre_ids: list[str] | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._alert_id = alert_id
        self._title = title
        self._severity = severity.lower()
        self._confidence = confidence
        self._description = description
        self._mitre_ids = mitre_ids or []
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._setup_ui()

    @property
    def alert_id(self) -> str:
        return self._alert_id

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Top row: severity badge + title
        top = QHBoxLayout()
        badge = QLabel(self._severity.upper())
        badge.setFixedWidth(80)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        color = _SEVERITY_COLORS.get(self._severity, "#9e9e9e")
        badge.setStyleSheet(
            f"background-color: {color}; color: #fff; "
            f"border-radius: 4px; padding: 4px;"
        )
        badge_font = QFont()
        badge_font.setBold(True)
        badge.setFont(badge_font)

        title_label = QLabel(self._title)
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title_label.setFont(title_font)

        top.addWidget(badge)
        top.addWidget(title_label, stretch=1)
        layout.addLayout(top)

        # Description
        if self._description:
            desc = QLabel(self._description)
            desc.setWordWrap(True)
            desc.setStyleSheet("color: #aaa;")
            layout.addWidget(desc)

        # Confidence bar
        conf_row = QHBoxLayout()
        conf_label = QLabel(f"Confidence: {self._confidence:.0%}")
        conf_bar = QProgressBar()
        conf_bar.setRange(0, 100)
        conf_bar.setValue(int(self._confidence * 100))
        conf_bar.setFixedHeight(16)
        conf_bar.setTextVisible(False)
        conf_row.addWidget(conf_label)
        conf_row.addWidget(conf_bar, stretch=1)
        layout.addLayout(conf_row)

        # MITRE badges
        if self._mitre_ids:
            mitre_row = QHBoxLayout()
            for mid in self._mitre_ids:
                badge_label = QLabel(mid)
                badge_label.setStyleSheet(
                    "background-color: #333; color: #4fc3f7; "
                    "border-radius: 3px; padding: 2px 6px;"
                )
                mitre_row.addWidget(badge_label)
            mitre_row.addStretch()
            layout.addLayout(mitre_row)

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        investigate_btn = QPushButton("Investigate")
        investigate_btn.clicked.connect(
            lambda: self.investigate_clicked.emit(self._alert_id)
        )
        dismiss_btn = QPushButton("Dismiss")
        dismiss_btn.clicked.connect(
            lambda: self.dismiss_clicked.emit(self._alert_id)
        )
        execute_btn = QPushButton("Execute Action")
        execute_btn.clicked.connect(
            lambda: self.execute_action_clicked.emit(
                self._alert_id, "default"
            )
        )

        btn_row.addWidget(investigate_btn)
        btn_row.addWidget(dismiss_btn)
        btn_row.addWidget(execute_btn)
        layout.addLayout(btn_row)
