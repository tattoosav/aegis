"""Network Monitor page for the Aegis security dashboard.

Displays active network connections, connection statistics,
and flow analysis in a PySide6 QWidget layout.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

logger = logging.getLogger(__name__)

# Column definitions for the connection table
_COLUMNS = [
    "Status",
    "Local Address",
    "Remote Address",
    "Remote Port",
    "Protocol",
    "PID",
    "Process",
    "Duration",
]

# Status colors
_STATUS_COLORS: dict[str, str] = {
    "ESTABLISHED": "#4caf50",  # green
    "LISTEN": "#ffeb3b",       # yellow
    "CLOSE_WAIT": "#f44336",   # red
}


class NetworkPage(QWidget):
    """Network monitoring page showing connections and flow stats.

    Provides a real-time view of active network connections,
    summary statistics, and traffic flow analysis.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        db: AegisDatabase | None = None,
    ) -> None:
        super().__init__(parent)
        self._db = db
        self.setObjectName("networkPage")

        # Stat label references for live updates
        self._stat_labels: dict[str, QLabel] = {}
        # Flow stat label references
        self._flow_labels: dict[str, QLabel] = {}

        self._build_ui()
        self.refresh()

    # ----------------------------------------------------------
    # UI Construction
    # ----------------------------------------------------------

    def _build_ui(self) -> None:
        """Assemble the full page layout."""
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        root.addWidget(self._build_header())
        root.addLayout(self._build_stats_row())
        root.addWidget(self._build_connection_table(), stretch=1)
        root.addWidget(self._build_flow_stats_panel())

    def _build_header(self) -> QLabel:
        """Create the page title label."""
        title = QLabel("Network Monitor")
        title.setObjectName("pageTitle")
        font = QFont()
        font.setPointSize(18)
        font.setBold(True)
        title.setFont(font)
        return title

    def _build_stats_row(self) -> QHBoxLayout:
        """Create the horizontal row of four stat boxes."""
        row = QHBoxLayout()
        row.setSpacing(12)

        active_box = self._create_stat_box(
            "Active Connections", "0",
        )
        self._stat_labels["active"] = (
            active_box.findChild(QLabel, "statValue")  # type: ignore[assignment]
        )

        unique_box = self._create_stat_box("Unique Remote IPs", "0")
        self._stat_labels["unique_ips"] = (
            unique_box.findChild(QLabel, "statValue")  # type: ignore[assignment]
        )

        dns_box = self._create_stat_box("DNS Queries", "0")
        self._stat_labels["dns"] = (
            dns_box.findChild(QLabel, "statValue")  # type: ignore[assignment]
        )

        flagged_box = self._create_stat_box(
            "Flagged Connections", "0", value_color="#f44336",
        )
        self._stat_labels["flagged"] = (
            flagged_box.findChild(QLabel, "statValue")  # type: ignore[assignment]
        )

        for box in (active_box, unique_box, dns_box, flagged_box):
            row.addWidget(box)

        return row

    def _build_connection_table(self) -> QTableWidget:
        """Create and configure the connection table widget."""
        table = QTableWidget(0, len(_COLUMNS))
        table.setObjectName("connectionTable")
        table.setHorizontalHeaderLabels(_COLUMNS)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers,
        )
        table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows,
        )
        table.verticalHeader().setVisible(False)

        header = table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive,
        )

        self._table = table
        return table

    def _build_flow_stats_panel(self) -> QFrame:
        """Create the bottom flow-statistics panel."""
        frame = QFrame()
        frame.setObjectName("flowStats")
        frame.setFrameShape(QFrame.Shape.StyledPanel)

        outer = QVBoxLayout(frame)
        outer.setContentsMargins(12, 8, 12, 8)
        outer.setSpacing(8)

        title = QLabel("Flow Statistics")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)
        outer.addWidget(title)

        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(6)

        # Row 0 — packet / byte counters
        flow_fields: list[tuple[int, int, str, str]] = [
            (0, 0, "total_packets", "Total Packets"),
            (0, 1, "bytes_in", "Bytes In"),
            (0, 2, "bytes_out", "Bytes Out"),
            # Row 1 — entropy / rate
            (1, 0, "port_entropy", "Port Entropy"),
            (1, 1, "new_dest_rate", "New Destination Rate"),
        ]

        for row, col, key, label_text in flow_fields:
            lbl = QLabel(f"{label_text}:")
            lbl_font = QFont()
            lbl_font.setBold(True)
            lbl.setFont(lbl_font)
            grid.addWidget(lbl, row, col * 2)

            val = QLabel("--")
            val.setObjectName(f"flow_{key}")
            grid.addWidget(val, row, col * 2 + 1)
            self._flow_labels[key] = val

        outer.addLayout(grid)

        # Top talkers section
        talker_title = QLabel("Top Talker Processes:")
        talker_font = QFont()
        talker_font.setBold(True)
        talker_title.setFont(talker_font)
        outer.addWidget(talker_title)

        self._top_talkers_label = QLabel("--")
        self._top_talkers_label.setObjectName("flow_top_talkers")
        self._top_talkers_label.setWordWrap(True)
        outer.addWidget(self._top_talkers_label)

        self._flow_frame = frame
        return frame

    # ----------------------------------------------------------
    # Public helpers
    # ----------------------------------------------------------

    @staticmethod
    def _create_stat_box(
        label: str,
        value: str,
        value_color: str | None = None,
    ) -> QFrame:
        """Build a single stat box frame.

        Parameters
        ----------
        label : str
            Descriptive label shown above the number.
        value : str
            Initial numeric value string.
        value_color : str | None
            Optional CSS colour for the value text.

        Returns
        -------
        QFrame
            The assembled stat box widget.
        """
        frame = QFrame()
        frame.setObjectName("statBox")
        frame.setFrameShape(QFrame.Shape.StyledPanel)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        val_label = QLabel(value)
        val_label.setObjectName("statValue")
        val_font = QFont()
        val_font.setPointSize(22)
        val_font.setBold(True)
        val_label.setFont(val_font)
        val_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if value_color:
            val_label.setStyleSheet(f"color: {value_color};")

        desc_label = QLabel(label)
        desc_label.setObjectName("statLabel")
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(val_label)
        layout.addWidget(desc_label)

        return frame

    # ----------------------------------------------------------
    # Public API — data updates
    # ----------------------------------------------------------

    def refresh(self) -> None:
        """Reload data from the database.

        When a database is available, queries recent network events
        and populates the table.  Otherwise the table stays empty.
        """
        if self._db is None:
            return

        try:
            from aegis.core.models import SensorType

            events = self._db.query_events(
                sensor=SensorType.NETWORK, limit=50,
            )
            connections: list[dict[str, Any]] = []
            for evt in events:
                data = evt.data
                connections.append({
                    "status": data.get("status", "UNKNOWN"),
                    "local_addr": data.get(
                        "local_addr", "",
                    ),
                    "remote_addr": data.get(
                        "remote_addr", "",
                    ),
                    "remote_port": data.get(
                        "remote_port", 0,
                    ),
                    "protocol": data.get("protocol", ""),
                    "pid": data.get("pid", 0),
                    "process": data.get("process", ""),
                })
            self.update_connections(connections)
        except Exception:
            logger.debug(
                "Could not load network events from database",
                exc_info=True,
            )

    def update_connections(
        self, connections: list[dict[str, Any]],
    ) -> None:
        """Replace the connection table contents.

        Parameters
        ----------
        connections : list[dict]
            Each dict must contain the keys: status, local_addr,
            remote_addr, remote_port, protocol, pid, process.
        """
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)

        for conn in connections:
            row_idx = self._table.rowCount()
            self._table.insertRow(row_idx)

            status = str(conn.get("status", ""))
            local_addr = str(conn.get("local_addr", ""))
            remote_addr = str(conn.get("remote_addr", ""))
            remote_port = str(conn.get("remote_port", ""))
            protocol = str(conn.get("protocol", ""))
            pid = str(conn.get("pid", ""))
            process = str(conn.get("process", ""))
            duration = str(conn.get("duration", ""))

            # Build row items
            items = [
                status,
                local_addr,
                remote_addr,
                remote_port,
                protocol,
                pid,
                process,
                duration,
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                if col == 0:
                    color = _STATUS_COLORS.get(
                        status.upper(), "#9e9e9e",
                    )
                    item.setForeground(
                        QBrush(QColor(color)),
                    )
                self._table.setItem(row_idx, col, item)

        self._table.setSortingEnabled(True)

    def update_stats(
        self,
        active: int,
        unique_ips: int,
        dns: int,
        flagged: int,
    ) -> None:
        """Update the four stat boxes with new counts.

        Parameters
        ----------
        active : int
            Number of active connections.
        unique_ips : int
            Number of unique remote IP addresses.
        dns : int
            Number of DNS queries observed.
        flagged : int
            Number of flagged / suspicious connections.
        """
        mapping: dict[str, int] = {
            "active": active,
            "unique_ips": unique_ips,
            "dns": dns,
            "flagged": flagged,
        }
        for key, val in mapping.items():
            lbl = self._stat_labels.get(key)
            if lbl is not None:
                lbl.setText(str(val))

    def update_flow_stats(
        self, stats: dict[str, Any],
    ) -> None:
        """Update the flow statistics panel.

        Parameters
        ----------
        stats : dict
            Expected keys (all optional):
            - total_packets : int
            - bytes_in : int | str
            - bytes_out : int | str
            - port_entropy : float | str
            - new_dest_rate : float | str
            - top_talkers : list[str]  (up to 5 process names)
        """
        for key in (
            "total_packets",
            "bytes_in",
            "bytes_out",
            "port_entropy",
            "new_dest_rate",
        ):
            lbl = self._flow_labels.get(key)
            if lbl is not None and key in stats:
                lbl.setText(str(stats[key]))

        talkers = stats.get("top_talkers", [])
        if isinstance(talkers, list):
            display = ", ".join(
                str(t) for t in talkers[:5]
            ) or "--"
        else:
            display = str(talkers)
        self._top_talkers_label.setText(display)
