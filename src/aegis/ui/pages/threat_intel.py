"""Threat Intelligence dashboard — IOC stats, matches, manual lookup.

Displays IOC database statistics, recent match history, a manual
lookup widget, and feed-health status cards.
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
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

_IOC_COLUMNS = ["Type", "Value", "Source", "Severity", "Last Updated"]
_MATCH_COLUMNS = ["Time", "IOC Value", "Matched In", "Severity"]


class ThreatIntelPage(QWidget):
    """Threat Intelligence dashboard page."""

    lookup_requested = Signal(str)  # query text

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
        layout.addLayout(self._build_stats_row())
        layout.addWidget(self._build_lookup_widget())
        layout.addWidget(self._build_results_section())
        layout.addLayout(self._build_feed_health())
        layout.addStretch()

        scroll.setWidget(container)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    def _build_header(self) -> QLabel:
        title = QLabel("Threat Intelligence")
        font = QFont()
        font.setPointSize(18)
        font.setBold(True)
        title.setFont(font)
        return title

    def _build_stats_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(16)
        self._stat_labels: dict[str, QLabel] = {}
        for label_text, key in [
            ("Total IOCs", "total_iocs"),
            ("IP Indicators", "ip_count"),
            ("Domain Indicators", "domain_count"),
            ("Hash Indicators", "hash_count"),
        ]:
            box, val_label = self._create_stat_box(label_text)
            self._stat_labels[key] = val_label
            row.addWidget(box)
        return row

    def _create_stat_box(
        self, label: str,
    ) -> tuple[QFrame, QLabel]:
        box = QFrame()
        box.setFrameShape(QFrame.Shape.StyledPanel)
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(16, 16, 16, 16)
        box_layout.setSpacing(4)
        box_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        val = QLabel("0")
        val_font = QFont()
        val_font.setPointSize(20)
        val_font.setBold(True)
        val.setFont(val_font)
        val.setAlignment(Qt.AlignmentFlag.AlignCenter)

        desc = QLabel(label)
        desc.setStyleSheet("color: #888;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)

        box_layout.addWidget(val)
        box_layout.addWidget(desc)
        return box, val

    def _build_lookup_widget(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._lookup_input = QLineEdit()
        self._lookup_input.setPlaceholderText(
            "Search IOC (IP, domain, hash)..."
        )
        self._lookup_btn = QPushButton("Search")
        self._lookup_btn.clicked.connect(self._on_lookup_clicked)

        layout.addWidget(self._lookup_input, stretch=1)
        layout.addWidget(self._lookup_btn)
        return widget

    def _build_results_section(self) -> QWidget:
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        header = QLabel("IOC Lookup Results")
        header_font = QFont()
        header_font.setPointSize(14)
        header_font.setBold(True)
        header.setFont(header_font)

        self._results_table = QTableWidget(0, len(_IOC_COLUMNS))
        self._results_table.setHorizontalHeaderLabels(_IOC_COLUMNS)
        self._results_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._results_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._results_table.verticalHeader().setVisible(False)
        h = self._results_table.horizontalHeader()
        h.setStretchLastSection(True)
        h.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

        layout.addWidget(header)
        layout.addWidget(self._results_table)
        return section

    def _build_feed_health(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(16)
        self._feed_labels: dict[str, QLabel] = {}
        for name in ["AbuseIPDB", "PhishTank", "Local IOCs"]:
            card, status_label = self._create_feed_card(name)
            self._feed_labels[name] = status_label
            row.addWidget(card)
        return row

    def _create_feed_card(
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

        status = QLabel("\u25cf Unknown")
        status.setStyleSheet("color: #9e9e9e;")

        card_layout.addWidget(title)
        card_layout.addWidget(status)
        return card, status

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def refresh(self) -> None:
        """Reload statistics from the database."""
        self._load_stats()

    def update_feed_status(
        self, name: str, healthy: bool,
    ) -> None:
        """Update a feed-health card."""
        label = self._feed_labels.get(name)
        if label is None:
            return
        if healthy:
            label.setText("\u25cf Active")
            label.setStyleSheet("color: #4caf50;")
        else:
            label.setText("\u25cf Offline")
            label.setStyleSheet("color: #f44336;")

    def show_results(
        self, results: list[dict],
    ) -> None:
        """Populate the results table with IOC lookup data."""
        self._results_table.setRowCount(len(results))
        for row, item in enumerate(results):
            ts = ""
            if item.get("last_updated"):
                ts = datetime.fromtimestamp(
                    item["last_updated"]
                ).strftime("%Y-%m-%d %H:%M")
            vals = [
                item.get("ioc_type", ""),
                item.get("value", ""),
                item.get("source", ""),
                item.get("severity", ""),
                ts,
            ]
            for col, text in enumerate(vals):
                cell = QTableWidgetItem(str(text))
                cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._results_table.setItem(row, col, cell)

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _on_lookup_clicked(self) -> None:
        query = self._lookup_input.text().strip()
        if not query:
            return
        self.lookup_requested.emit(query)
        if self._db is not None:
            results = self._db.lookup_ioc_by_value(query)
            self.show_results(results)

    def _load_stats(self) -> None:
        if self._db is None:
            return
        try:
            total = self._db.ioc_count()
            self._stat_labels["total_iocs"].setText(str(total))
            # Count by type
            for ioc_type, key in [
                ("ip", "ip_count"),
                ("domain", "domain_count"),
                ("hash", "hash_count"),
            ]:
                cursor = self._db._conn.execute(
                    "SELECT COUNT(*) FROM ioc_indicators "
                    "WHERE ioc_type = ?",
                    (ioc_type,),
                )
                count = cursor.fetchone()[0]
                self._stat_labels[key].setText(str(count))
        except Exception:
            pass
