"""Alerts page — filterable, sortable alert feed for the dashboard."""

from __future__ import annotations

import datetime
import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from aegis.core.models import (
    Alert,
    AlertStatus,
    Severity,
)

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

logger = logging.getLogger(__name__)

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#e53935",
    Severity.HIGH: "#fb8c00",
    Severity.MEDIUM: "#fdd835",
    Severity.LOW: "#42a5f5",
    Severity.INFO: "#78909c",
}

_TABLE_COLUMNS = [
    "Severity",
    "Time",
    "Title",
    "Type",
    "Source",
    "Confidence",
    "MITRE",
    "Status",
]


class AlertsPage(QWidget):
    """Filterable, sortable alert feed page.

    Displays all alerts from the Aegis database in a table
    with severity/status filters, count badges, and a
    collapsible detail panel.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        db: AegisDatabase | None = None,
    ) -> None:
        super().__init__(parent)
        self._db = db
        self._alerts: list[Alert] = []
        self._selected_alert: Alert | None = None
        self._setup_ui()
        self.refresh()

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        """Build the full page layout."""
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        root.addLayout(self._build_header())
        root.addLayout(self._build_badges())
        root.addWidget(self._build_table(), stretch=1)
        root.addWidget(self._build_detail_panel())

    # -- Header row ----------------------------------------------------

    def _build_header(self) -> QHBoxLayout:
        header = QHBoxLayout()

        title = QLabel("Alerts")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        header.addWidget(title)

        header.addStretch()

        self._severity_filter = QComboBox()
        self._severity_filter.setObjectName("severityFilter")
        self._severity_filter.addItems(
            ["All", "Critical", "High", "Medium", "Low", "Info"]
        )
        self._severity_filter.currentIndexChanged.connect(
            self._on_filter_changed
        )
        header.addWidget(QLabel("Severity:"))
        header.addWidget(self._severity_filter)

        self._status_filter = QComboBox()
        self._status_filter.setObjectName("statusFilter")
        self._status_filter.addItems(
            ["All", "New", "Investigating", "Resolved", "Dismissed"]
        )
        self._status_filter.currentIndexChanged.connect(
            self._on_filter_changed
        )
        header.addWidget(QLabel("Status:"))
        header.addWidget(self._status_filter)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)

        return header

    # -- Severity badges -----------------------------------------------

    def _build_badges(self) -> QHBoxLayout:
        row = QHBoxLayout()
        self._badge_critical = self._create_severity_badge(
            "Critical", 0, "#e53935"
        )
        self._badge_high = self._create_severity_badge(
            "High", 0, "#fb8c00"
        )
        self._badge_medium = self._create_severity_badge(
            "Medium", 0, "#fdd835"
        )
        self._badge_low = self._create_severity_badge(
            "Low+Info", 0, "#42a5f5"
        )
        row.addWidget(self._badge_critical)
        row.addWidget(self._badge_high)
        row.addWidget(self._badge_medium)
        row.addWidget(self._badge_low)
        row.addStretch()
        return row

    @staticmethod
    def _create_severity_badge(
        label: str, count: int, color: str
    ) -> QFrame:
        """Return a small coloured badge showing *label*: *count*."""
        frame = QFrame()
        frame.setObjectName("severityBadge")
        frame.setStyleSheet(
            f"background-color: {color}; border-radius: 6px; "
            f"padding: 4px 10px;"
        )
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(8, 4, 8, 4)

        lbl = QLabel(f"{label}: {count}")
        lbl.setObjectName("badgeLabel")
        lbl.setStyleSheet("color: #fff; font-weight: bold;")
        layout.addWidget(lbl)

        return frame

    # -- Alert table ---------------------------------------------------

    def _build_table(self) -> QTableWidget:
        self._table = QTableWidget(0, len(_TABLE_COLUMNS))
        self._table.setObjectName("alertTable")
        self._table.setHorizontalHeaderLabels(_TABLE_COLUMNS)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self._table.cellClicked.connect(self._on_row_selected)
        return self._table

    # -- Detail panel --------------------------------------------------

    def _build_detail_panel(self) -> QFrame:
        self._detail_frame = QFrame()
        self._detail_frame.setObjectName("alertDetail")
        self._detail_frame.setFrameShape(QFrame.Shape.StyledPanel)
        self._detail_frame.setVisible(False)

        layout = QVBoxLayout(self._detail_frame)
        layout.setContentsMargins(12, 12, 12, 12)

        self._detail_title = QLabel()
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(13)
        self._detail_title.setFont(title_font)
        layout.addWidget(self._detail_title)

        self._detail_description = QLabel()
        self._detail_description.setWordWrap(True)
        layout.addWidget(self._detail_description)

        self._detail_mitre = QLabel()
        layout.addWidget(self._detail_mitre)

        self._detail_actions = QLabel()
        self._detail_actions.setWordWrap(True)
        layout.addWidget(self._detail_actions)

        btn_row = QHBoxLayout()
        investigate_btn = QPushButton("Investigate")
        investigate_btn.clicked.connect(self._on_investigate)
        dismiss_btn = QPushButton("Dismiss")
        dismiss_btn.clicked.connect(self._on_dismiss)
        resolve_btn = QPushButton("Resolve")
        resolve_btn.clicked.connect(self._on_resolve)
        btn_row.addWidget(investigate_btn)
        btn_row.addWidget(dismiss_btn)
        btn_row.addWidget(resolve_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return self._detail_frame

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Reload all alerts from the database using current filters."""
        if self._db is None:
            self._alerts = []
            self._populate_table([])
            self._update_badges([])
            return

        severity_text = self._severity_filter.currentText()
        status_text = self._status_filter.currentText()

        sev: Severity | None = None
        if severity_text != "All":
            sev = Severity.from_string(severity_text.lower())

        status: AlertStatus | None = None
        if status_text != "All":
            status = AlertStatus(status_text.lower())

        self._alerts = self._db.query_alerts(
            severity=sev, status=status
        )
        self._populate_table(self._alerts)
        self._update_badges(self._alerts)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _populate_table(self, alerts: list[Alert]) -> None:
        """Fill the table widget from a list of Alert objects."""
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)

        if self._db is None and not alerts:
            self._table.setRowCount(1)
            item = QTableWidgetItem("No database connected")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self._table.setItem(0, 0, item)
            self._table.setSpan(0, 0, 1, len(_TABLE_COLUMNS))
            self._table.setSortingEnabled(True)
            return

        for row_idx, alert in enumerate(alerts):
            self._table.insertRow(row_idx)
            self._set_table_row(row_idx, alert)

        self._table.setSortingEnabled(True)

    def _set_table_row(
        self, row: int, alert: Alert
    ) -> None:
        """Write a single Alert into *row* of the table."""
        # Severity
        sev_item = QTableWidgetItem(alert.severity.value.upper())
        color = _SEVERITY_COLORS.get(alert.severity, "#78909c")
        sev_item.setForeground(QColor(color))
        sev_font = QFont()
        sev_font.setBold(True)
        sev_item.setFont(sev_font)
        self._table.setItem(row, 0, sev_item)

        # Time
        dt = datetime.datetime.fromtimestamp(alert.timestamp)
        now = datetime.datetime.now()
        if dt.date() == now.date():
            time_str = dt.strftime("%H:%M:%S")
        else:
            time_str = dt.strftime("%Y-%m-%d %H:%M")
        time_item = QTableWidgetItem(time_str)
        time_item.setData(
            Qt.ItemDataRole.UserRole, alert.timestamp
        )
        self._table.setItem(row, 1, time_item)

        # Title
        self._table.setItem(
            row, 2, QTableWidgetItem(alert.title)
        )

        # Type
        self._table.setItem(
            row, 3, QTableWidgetItem(alert.alert_type)
        )

        # Source (sensor)
        self._table.setItem(
            row, 4, QTableWidgetItem(alert.sensor.value)
        )

        # Confidence
        conf_item = QTableWidgetItem(
            f"{alert.confidence * 100:.0f}%"
        )
        conf_item.setData(
            Qt.ItemDataRole.UserRole, alert.confidence
        )
        self._table.setItem(row, 5, conf_item)

        # MITRE
        mitre_text = ", ".join(alert.mitre_ids) if alert.mitre_ids else ""
        self._table.setItem(
            row, 6, QTableWidgetItem(mitre_text)
        )

        # Status
        self._table.setItem(
            row, 7, QTableWidgetItem(alert.status.value)
        )

    def _update_badges(self, alerts: list[Alert]) -> None:
        """Refresh the four severity-count badges."""
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low_info": 0,
        }
        for a in alerts:
            if a.severity == Severity.CRITICAL:
                counts["critical"] += 1
            elif a.severity == Severity.HIGH:
                counts["high"] += 1
            elif a.severity == Severity.MEDIUM:
                counts["medium"] += 1
            else:
                counts["low_info"] += 1

        self._set_badge_count(
            self._badge_critical, "Critical", counts["critical"]
        )
        self._set_badge_count(
            self._badge_high, "High", counts["high"]
        )
        self._set_badge_count(
            self._badge_medium, "Medium", counts["medium"]
        )
        self._set_badge_count(
            self._badge_low, "Low+Info", counts["low_info"]
        )

    @staticmethod
    def _set_badge_count(
        badge: QFrame, label: str, count: int
    ) -> None:
        lbl = badge.findChild(QLabel, "badgeLabel")
        if lbl is not None:
            lbl.setText(f"{label}: {count}")

    # -- Slots ---------------------------------------------------------

    def _on_row_selected(self, row: int, col: int) -> None:
        """Show the detail panel for the alert in *row*."""
        if row < 0 or row >= len(self._alerts):
            self._detail_frame.setVisible(False)
            return

        alert = self._alerts[row]
        self._selected_alert = alert

        self._detail_title.setText(alert.title)
        self._detail_description.setText(alert.description)

        if alert.mitre_ids:
            mitre_str = ", ".join(alert.mitre_ids)
            self._detail_mitre.setText(
                f"MITRE Techniques: {mitre_str}"
            )
        else:
            self._detail_mitre.setText("MITRE Techniques: n/a")

        if alert.recommended_actions:
            actions_str = "\n".join(
                f"  \u2022 {a}" for a in alert.recommended_actions
            )
            self._detail_actions.setText(
                f"Recommended Actions:\n{actions_str}"
            )
        else:
            self._detail_actions.setText(
                "Recommended Actions: none"
            )

        self._detail_frame.setVisible(True)

    def _on_filter_changed(self) -> None:
        """Re-query the database when a filter combo changes."""
        self.refresh()

    def _on_investigate(self) -> None:
        """Mark the selected alert as Investigating."""
        self._update_selected_status(AlertStatus.INVESTIGATING)

    def _on_dismiss(self) -> None:
        """Mark the selected alert as Dismissed."""
        self._update_selected_status(AlertStatus.DISMISSED)

    def _on_resolve(self) -> None:
        """Mark the selected alert as Resolved."""
        self._update_selected_status(AlertStatus.RESOLVED)

    def _update_selected_status(
        self, new_status: AlertStatus
    ) -> None:
        """Persist *new_status* for the currently selected alert."""
        if self._selected_alert is None or self._db is None:
            return
        self._db.update_alert_status(
            self._selected_alert.alert_id, new_status
        )
        logger.info(
            "Alert %s -> %s",
            self._selected_alert.alert_id,
            new_status.value,
        )
        self.refresh()
