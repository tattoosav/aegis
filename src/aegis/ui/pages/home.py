"""Home page — main overview dashboard for Aegis.

Displays system overview with sensor status cards, statistics,
recent alerts table, and an activity chart placeholder.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

_SENSOR_NAMES = ["Network", "Process", "File", "Event Log"]

_STATUS_COLORS = {
    "Active": "#4caf50",
    "Inactive": "#9e9e9e",
    "Error": "#f44336",
}

_ALERT_COLUMNS = [
    "Severity",
    "Time",
    "Title",
    "Source",
    "Confidence",
    "Status",
]


class HomePage(QWidget):
    """Main overview / home page for the Aegis dashboard.

    Shows sensor status cards, aggregate statistics, recent alerts,
    and a placeholder for an activity chart.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        db: AegisDatabase | None = None,
    ) -> None:
        super().__init__(parent)
        self._db = db

        # Track mutable sub-widgets for later updates
        self._sensor_cards: dict[str, dict[str, QLabel]] = {}
        self._stat_labels: dict[str, QLabel] = {}

        self._build_ui()
        self.refresh()

    # ------------------------------------------------------------------ #
    #  UI construction
    # ------------------------------------------------------------------ #

    def _build_ui(self) -> None:
        """Assemble all sections inside a scrollable layout."""
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        layout.addLayout(self._build_header())
        layout.addLayout(self._build_sensor_cards())
        layout.addLayout(self._build_stats_row())
        layout.addWidget(self._build_alerts_section())
        layout.addWidget(self._build_chart_placeholder())
        layout.addStretch()

        scroll.setWidget(container)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    # -- 1. Header ---------------------------------------------------- #

    def _build_header(self) -> QVBoxLayout:
        """Create the 'System Overview' header with timestamp."""
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)

        title = QLabel("System Overview")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)

        self._datetime_label = QLabel()
        self._datetime_label.setStyleSheet("color: #888;")
        self._update_datetime()

        header_layout.addWidget(title)
        header_layout.addWidget(self._datetime_label)
        return header_layout

    # -- 2. Sensor cards ---------------------------------------------- #

    def _build_sensor_cards(self) -> QHBoxLayout:
        """Create the horizontal row of four sensor status cards."""
        row = QHBoxLayout()
        row.setSpacing(16)
        for name in _SENSOR_NAMES:
            card = self._create_sensor_card(name, "Inactive", 0)
            row.addWidget(card)
        return row

    def _create_sensor_card(
        self,
        name: str,
        status: str,
        count: int,
    ) -> QFrame:
        """Build a single sensor status card.

        Args:
            name: Display name of the sensor.
            status: One of 'Active', 'Inactive', or 'Error'.
            count: Event count to display.

        Returns:
            A styled QFrame containing the card widgets.
        """
        card = QFrame()
        card.setObjectName("sensorCard")
        card.setFrameShape(QFrame.Shape.StyledPanel)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(8)

        # Sensor name
        name_label = QLabel(name)
        name_font = QFont()
        name_font.setPointSize(12)
        name_font.setBold(True)
        name_label.setFont(name_font)

        # Status indicator
        color = _STATUS_COLORS.get(status, "#9e9e9e")
        status_label = QLabel(f"\u25cf {status}")
        status_label.setStyleSheet(f"color: {color};")

        # Event count
        count_label = QLabel(str(count))
        count_font = QFont()
        count_font.setPointSize(20)
        count_font.setBold(True)
        count_label.setFont(count_font)
        count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        count_desc = QLabel("events")
        count_desc.setStyleSheet("color: #888;")
        count_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card_layout.addWidget(name_label)
        card_layout.addWidget(status_label)
        card_layout.addStretch()
        card_layout.addWidget(count_label)
        card_layout.addWidget(count_desc)

        # Store references for live updates
        self._sensor_cards[name] = {
            "status": status_label,
            "count": count_label,
        }

        return card

    # -- 3. Statistics row -------------------------------------------- #

    def _build_stats_row(self) -> QHBoxLayout:
        """Create the three aggregate statistic boxes."""
        row = QHBoxLayout()
        row.setSpacing(16)

        for label, key in [
            ("Events (24h)", "events_24h"),
            ("Alerts (24h)", "alerts_24h"),
            ("Threats Blocked", "threats"),
        ]:
            box = self._create_stat_box(label, "0")
            self._stat_labels[key] = box.findChild(
                QLabel, f"statValue_{label}"
            )
            row.addWidget(box)

        return row

    def _create_stat_box(
        self,
        label: str,
        value: str,
    ) -> QFrame:
        """Build a single statistic display box.

        Args:
            label: Description text shown beneath the number.
            value: The numeric string to display prominently.

        Returns:
            A styled QFrame containing the stat widgets.
        """
        box = QFrame()
        box.setObjectName("statBox")
        box.setFrameShape(QFrame.Shape.StyledPanel)
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(16, 16, 16, 16)
        box_layout.setSpacing(4)
        box_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        value_label = QLabel(value)
        value_label.setObjectName(f"statValue_{label}")
        value_font = QFont()
        value_font.setPointSize(24)
        value_font.setBold(True)
        value_label.setFont(value_font)
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        desc_label = QLabel(label)
        desc_label.setStyleSheet("color: #888;")
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        box_layout.addWidget(value_label)
        box_layout.addWidget(desc_label)
        return box

    # -- 4. Recent alerts table --------------------------------------- #

    def _build_alerts_section(self) -> QWidget:
        """Create the Recent Alerts header and table."""
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        header = QLabel("Recent Alerts")
        header_font = QFont()
        header_font.setPointSize(14)
        header_font.setBold(True)
        header.setFont(header_font)

        self._alert_table = QTableWidget(0, len(_ALERT_COLUMNS))
        self._alert_table.setObjectName("alertTable")
        self._alert_table.setHorizontalHeaderLabels(_ALERT_COLUMNS)
        self._alert_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._alert_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._alert_table.verticalHeader().setVisible(False)

        h_header = self._alert_table.horizontalHeader()
        h_header.setStretchLastSection(True)
        h_header.setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )

        layout.addWidget(header)
        layout.addWidget(self._alert_table)
        return section

    # -- 5. Activity chart placeholder -------------------------------- #

    def _build_chart_placeholder(self) -> QFrame:
        """Create a placeholder frame for the future activity chart."""
        frame = QFrame()
        frame.setObjectName("chartPlaceholder")
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        frame.setFixedHeight(200)

        layout = QVBoxLayout(frame)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        label = QLabel("Activity Chart \u2014 Events per minute")
        label.setStyleSheet("color: #888;")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        chart_font = QFont()
        chart_font.setPointSize(12)
        label.setFont(chart_font)

        layout.addWidget(label)
        return frame

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def refresh(self) -> None:
        """Reload all dashboard data from the database."""
        self._update_datetime()
        self._populate_alerts()
        self._load_stats_from_db()

    def update_sensor_status(
        self,
        sensor: str,
        status: str,
        count: int,
    ) -> None:
        """Update a specific sensor card's status and count.

        Args:
            sensor: Sensor display name (e.g. 'Network').
            status: One of 'Active', 'Inactive', or 'Error'.
            count: Current event count for this sensor.
        """
        refs = self._sensor_cards.get(sensor)
        if refs is None:
            return
        color = _STATUS_COLORS.get(status, "#9e9e9e")
        refs["status"].setText(f"\u25cf {status}")
        refs["status"].setStyleSheet(f"color: {color};")
        refs["count"].setText(str(count))

    def update_stats(
        self,
        events_24h: int,
        alerts_24h: int,
        threats: int,
    ) -> None:
        """Update the three aggregate statistic boxes.

        Args:
            events_24h: Total events in the last 24 hours.
            alerts_24h: Total alerts in the last 24 hours.
            threats: Total threats blocked.
        """
        mapping = {
            "events_24h": events_24h,
            "alerts_24h": alerts_24h,
            "threats": threats,
        }
        for key, val in mapping.items():
            label = self._stat_labels.get(key)
            if label is not None:
                label.setText(str(val))

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #

    def _update_datetime(self) -> None:
        """Refresh the header date/time label."""
        now = datetime.now().strftime("%A, %B %d, %Y  %H:%M:%S")
        self._datetime_label.setText(now)

    def _populate_alerts(self) -> None:
        """Fill the alert table from the database (if available)."""
        self._alert_table.setRowCount(0)

        if self._db is None:
            return

        try:
            alerts = self._db.query_alerts(limit=10)
        except Exception:
            return

        self._alert_table.setRowCount(len(alerts))
        for row_idx, alert in enumerate(alerts):
            ts = datetime.fromtimestamp(alert.timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            items = [
                alert.severity.value.upper(),
                ts,
                alert.title,
                alert.sensor.value,
                f"{alert.confidence:.0%}",
                alert.status.value,
            ]
            for col_idx, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setTextAlignment(
                    Qt.AlignmentFlag.AlignCenter
                )
                self._alert_table.setItem(
                    row_idx, col_idx, item
                )

    def _load_stats_from_db(self) -> None:
        """Query aggregate stats from the database."""
        if self._db is None:
            return

        try:
            cutoff = time.time() - 86400  # 24 hours
            events = self._db.query_events(since=cutoff)
            alerts = self._db.query_alerts(limit=10000)
            recent_alerts = [
                a for a in alerts if a.timestamp >= cutoff
            ]
            self.update_stats(
                events_24h=len(events),
                alerts_24h=len(recent_alerts),
                threats=0,
            )
        except Exception:
            pass
