"""File monitoring dashboard — recent changes, canaries, quarantine.

Displays a table of recent file-system events, canary-file status
cards, and a quarantine manager showing isolated files with restore
options (user-approved only).
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

_CHANGE_COLUMNS = ["Time", "Path", "Action", "Sensor", "Severity"]
_QUARANTINE_COLUMNS = ["File", "Original Path", "Quarantined At", "Actions"]


class FilesPage(QWidget):
    """File monitoring dashboard page.

    Shows recent file-system changes, canary status, and quarantine.
    """

    restore_requested = Signal(str)  # action_id

    def __init__(
        self,
        parent: QWidget | None = None,
        db: AegisDatabase | None = None,
    ) -> None:
        super().__init__(parent)
        self._db = db
        self._setup_ui()
        self.refresh()

    # ------------------------------------------------------------------ #
    # UI construction
    # ------------------------------------------------------------------ #

    def _setup_ui(self) -> None:
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        layout.addWidget(self._build_header())
        layout.addLayout(self._build_canary_cards())
        layout.addWidget(self._build_changes_section())
        layout.addWidget(self._build_quarantine_section())
        layout.addStretch()

        scroll.setWidget(container)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    def _build_header(self) -> QLabel:
        title = QLabel("File Monitoring")
        font = QFont()
        font.setPointSize(18)
        font.setBold(True)
        title.setFont(font)
        return title

    def _build_canary_cards(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(16)
        self._canary_labels: dict[str, QLabel] = {}
        for name in ["System Files", "Config Files", "Application Files"]:
            card, status_label = self._create_canary_card(name)
            self._canary_labels[name] = status_label
            row.addWidget(card)
        return row

    def _create_canary_card(
        self, name: str,
    ) -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setFrameShape(QFrame.Shape.StyledPanel)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(8)

        title = QLabel(name)
        title_font = QFont()
        title_font.setBold(True)
        title.setFont(title_font)

        status = QLabel("\u25cf Healthy")
        status.setStyleSheet("color: #4caf50;")

        card_layout.addWidget(title)
        card_layout.addWidget(status)
        return card, status

    def _build_changes_section(self) -> QWidget:
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        header = QLabel("Recent File Changes")
        header_font = QFont()
        header_font.setPointSize(14)
        header_font.setBold(True)
        header.setFont(header_font)

        self._changes_table = QTableWidget(0, len(_CHANGE_COLUMNS))
        self._changes_table.setHorizontalHeaderLabels(_CHANGE_COLUMNS)
        self._changes_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._changes_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._changes_table.verticalHeader().setVisible(False)
        h = self._changes_table.horizontalHeader()
        h.setStretchLastSection(True)
        h.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

        layout.addWidget(header)
        layout.addWidget(self._changes_table)
        return section

    def _build_quarantine_section(self) -> QWidget:
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        header = QLabel("Quarantined Files")
        header_font = QFont()
        header_font.setPointSize(14)
        header_font.setBold(True)
        header.setFont(header_font)

        self._quarantine_table = QTableWidget(
            0, len(_QUARANTINE_COLUMNS),
        )
        self._quarantine_table.setHorizontalHeaderLabels(
            _QUARANTINE_COLUMNS
        )
        self._quarantine_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._quarantine_table.verticalHeader().setVisible(False)
        h = self._quarantine_table.horizontalHeader()
        h.setStretchLastSection(True)
        h.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

        layout.addWidget(header)
        layout.addWidget(self._quarantine_table)
        return section

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def refresh(self) -> None:
        """Reload file monitoring data from the database."""
        self._populate_changes()

    def update_canary_status(
        self, name: str, healthy: bool,
    ) -> None:
        """Update a canary card's status indicator."""
        label = self._canary_labels.get(name)
        if label is None:
            return
        if healthy:
            label.setText("\u25cf Healthy")
            label.setStyleSheet("color: #4caf50;")
        else:
            label.setText("\u25cf TAMPERED")
            label.setStyleSheet("color: #f44336;")

    def load_quarantine(
        self, items: list[dict],
    ) -> None:
        """Load quarantine entries into the table.

        Each item should have ``filename``, ``original_path``,
        ``quarantined_at`` (epoch), and ``action_id`` keys.
        """
        self._quarantine_table.setRowCount(len(items))
        for row, item in enumerate(items):
            ts = datetime.fromtimestamp(
                item.get("quarantined_at", 0)
            ).strftime("%Y-%m-%d %H:%M")
            vals = [
                item.get("filename", ""),
                item.get("original_path", ""),
                ts,
            ]
            for col, text in enumerate(vals):
                cell = QTableWidgetItem(text)
                cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._quarantine_table.setItem(row, col, cell)

            btn = QPushButton("Restore")
            aid = item.get("action_id", "")
            btn.clicked.connect(
                lambda checked, a=aid: self.restore_requested.emit(a)
            )
            self._quarantine_table.setCellWidget(row, 3, btn)

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _populate_changes(self) -> None:
        self._changes_table.setRowCount(0)
        if self._db is None:
            return
        try:
            from aegis.core.models import SensorType
            events = self._db.query_events(
                sensor=SensorType.FILE, limit=50,
            )
        except Exception:
            return

        self._changes_table.setRowCount(len(events))
        for row, evt in enumerate(events):
            ts = datetime.fromtimestamp(evt.timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            items = [
                ts,
                evt.data.get("path", ""),
                evt.data.get("action", evt.event_type),
                evt.sensor.value,
                evt.severity.value.upper(),
            ]
            for col, text in enumerate(items):
                cell = QTableWidgetItem(str(text))
                cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._changes_table.setItem(row, col, cell)
