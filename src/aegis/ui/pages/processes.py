"""Process Monitor page for the Aegis security dashboard.

Displays a searchable, sortable process table with per-process
detail panel, risk colouring, and action buttons.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

logger = logging.getLogger(__name__)

# Column definitions for the process table
_COLUMNS: list[str] = [
    "PID",
    "Name",
    "Status",
    "CPU%",
    "Memory (MB)",
    "Threads",
    "User",
    "Executable Path",
    "Risk",
]

# Risk-level colour mapping
_RISK_COLORS: dict[str, str] = {
    "none": "#4caf50",
    "low": "#ffeb3b",
    "medium": "#ff9800",
    "high": "#f44336",
}


class ProcessesPage(QWidget):
    """Process Monitor dashboard page.

    Shows a live process table with search, stats, and a
    collapsible detail panel for the selected row.

    Parameters
    ----------
    parent : QWidget | None
        Optional parent widget.
    db : AegisDatabase | None
        Optional database handle used to load the most recent
        process-sensor snapshot.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        db: AegisDatabase | None = None,
    ) -> None:
        super().__init__(parent)
        self._db = db
        self._processes: list[dict] = []
        self._selected_process: dict | None = None

        self._build_ui()
        self.refresh()

    # ----------------------------------------------------------------
    # UI construction
    # ----------------------------------------------------------------

    def _build_ui(self) -> None:
        """Assemble every section of the page."""
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        root.addLayout(self._build_header())
        root.addLayout(self._build_stats_row())

        body = QHBoxLayout()
        body.setSpacing(12)
        body.addWidget(self._build_process_table(), stretch=3)
        body.addWidget(self._build_detail_panel(), stretch=1)
        root.addLayout(body, stretch=1)

    # -- header ------------------------------------------------------

    def _build_header(self) -> QHBoxLayout:
        header = QHBoxLayout()
        title = QLabel("Process Monitor")
        title.setStyleSheet(
            "font-size: 20px; font-weight: bold;"
        )
        header.addWidget(title)

        header.addStretch()

        self._search = QLineEdit()
        self._search.setObjectName("processSearch")
        self._search.setPlaceholderText("Filter processes...")
        self._search.setMinimumWidth(220)
        self._search.textChanged.connect(self._on_search_changed)
        header.addWidget(self._search)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)

        return header

    # -- stats row ---------------------------------------------------

    def _build_stats_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)

        self._stat_total = self._create_stat_box(
            "Total Processes", "0",
        )
        self._stat_suspicious = self._create_stat_box(
            "Suspicious", "0", color="#ff9800",
        )
        self._stat_unsigned = self._create_stat_box(
            "Unsigned", "0",
        )
        self._stat_high_cpu = self._create_stat_box(
            "High CPU", "0",
        )

        row.addWidget(self._stat_total)
        row.addWidget(self._stat_suspicious)
        row.addWidget(self._stat_unsigned)
        row.addWidget(self._stat_high_cpu)
        return row

    @staticmethod
    def _create_stat_box(
        label: str,
        value: str,
        color: str = "",
    ) -> QFrame:
        """Build a compact stat card.

        Parameters
        ----------
        label : str
            Descriptive label shown above the number.
        value : str
            Numeric string displayed prominently.
        color : str
            Optional CSS colour applied to the value text.

        Returns
        -------
        QFrame
            A styled stat-box widget.
        """
        frame = QFrame()
        frame.setObjectName("statBox")
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        frame.setMinimumHeight(70)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("font-size: 11px; opacity: 0.8;")
        layout.addWidget(lbl)

        val = QLabel(value)
        val.setObjectName("statValue")
        val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        style = "font-size: 22px; font-weight: bold;"
        if color:
            style += f" color: {color};"
        val.setStyleSheet(style)
        layout.addWidget(val)

        return frame

    # -- process table -----------------------------------------------

    def _build_process_table(self) -> QTableWidget:
        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setObjectName("processTable")
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows,
        )
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers,
        )
        self._table.verticalHeader().setVisible(False)

        hdr = self._table.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive,
        )

        self._table.cellClicked.connect(self._on_row_selected)
        return self._table

    # -- detail panel ------------------------------------------------

    def _build_detail_panel(self) -> QFrame:
        self._detail = QFrame()
        self._detail.setObjectName("processDetail")
        self._detail.setFrameShape(QFrame.Shape.StyledPanel)
        self._detail.setVisible(False)
        self._detail.setMinimumWidth(280)

        layout = QVBoxLayout(self._detail)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(6)

        heading = QLabel("Process Details")
        heading.setStyleSheet(
            "font-size: 16px; font-weight: bold;"
        )
        layout.addWidget(heading)

        self._detail_labels: dict[str, QLabel] = {}
        fields = [
            "PID", "Name", "Full path", "Command line",
            "Parent PID", "User", "CPU%", "Memory",
            "Network Connections", "Open Files", "Threads",
        ]
        for f in fields:
            lbl = QLabel(f"{f}: —")
            lbl.setWordWrap(True)
            self._detail_labels[f] = lbl
            layout.addWidget(lbl)

        self._risk_label = QLabel("Risk: —")
        self._risk_label.setWordWrap(True)
        layout.addWidget(self._risk_label)

        layout.addStretch()

        btn_row = QHBoxLayout()
        kill_btn = QPushButton("Kill Process")
        kill_btn.clicked.connect(self._on_kill_process)
        btn_row.addWidget(kill_btn)

        whitelist_btn = QPushButton("Whitelist")
        whitelist_btn.clicked.connect(self._on_whitelist)
        btn_row.addWidget(whitelist_btn)

        investigate_btn = QPushButton("Investigate")
        investigate_btn.clicked.connect(self._on_investigate)
        btn_row.addWidget(investigate_btn)

        layout.addLayout(btn_row)
        return self._detail

    # ----------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------

    def refresh(self) -> None:
        """Reload process data from the database.

        If no database is available the table is left empty.
        """
        if self._db is None:
            self.update_processes([])
            return

        try:
            from aegis.core.models import SensorType

            events = self._db.query_events(
                sensor=SensorType.PROCESS, limit=1,
            )
            if events:
                data = events[0].data
                procs = data.get("processes", [])
                self.update_processes(procs)
            else:
                self.update_processes([])
        except Exception:
            logger.exception("Failed to load process data")
            self.update_processes([])

    def update_processes(self, processes: list[dict]) -> None:
        """Populate the table with the supplied process dicts.

        Each dict should contain the keys: pid, name, status,
        cpu_percent, memory_mb, num_threads, username, exe,
        risk_level.

        Parameters
        ----------
        processes : list[dict]
            Process snapshot to display.
        """
        self._processes = list(processes)
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)

        total = len(processes)
        suspicious = 0
        unsigned = 0
        high_cpu = 0

        for proc in processes:
            row = self._table.rowCount()
            self._table.insertRow(row)

            risk = str(proc.get("risk_level", "none")).lower()
            if risk in ("medium", "high"):
                suspicious += 1
            if not proc.get("exe"):
                unsigned += 1
            if float(proc.get("cpu_percent", 0)) > 80:
                high_cpu += 1

            values = [
                str(proc.get("pid", "")),
                str(proc.get("name", "")),
                str(proc.get("status", "")),
                f"{float(proc.get('cpu_percent', 0)):.1f}",
                f"{float(proc.get('memory_mb', 0)):.1f}",
                str(proc.get("num_threads", "")),
                str(proc.get("username", "")),
                str(proc.get("exe", "")),
                risk.capitalize() if risk != "none" else "None",
            ]

            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                # Make PID, CPU%, Memory, Threads sort numerically
                if col in (0, 3, 4, 5):
                    try:
                        item.setData(
                            Qt.ItemDataRole.UserRole,
                            float(text),
                        )
                    except ValueError:
                        pass

                # Colour the Risk column
                if col == len(_COLUMNS) - 1:
                    clr = _RISK_COLORS.get(risk, "")
                    if clr:
                        item.setForeground(QColor(clr))

                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)
        self._update_stats(total, suspicious, unsigned, high_cpu)

    # ----------------------------------------------------------------
    # Slots
    # ----------------------------------------------------------------

    def _on_row_selected(self, row: int, col: int) -> None:
        """Display the detail panel for the clicked row.

        Parameters
        ----------
        row : int
            Row index in the table.
        col : int
            Column index (unused, kept for signal signature).
        """
        if row < 0 or row >= len(self._processes):
            return

        proc = self._processes[row]
        self._selected_process = proc

        self._detail_labels["PID"].setText(
            f"PID: {proc.get('pid', '—')}"
        )
        self._detail_labels["Name"].setText(
            f"Name: {proc.get('name', '—')}"
        )
        self._detail_labels["Full path"].setText(
            f"Full path: {proc.get('exe', '—')}"
        )
        self._detail_labels["Command line"].setText(
            f"Command line: {proc.get('cmdline', '—')}"
        )
        self._detail_labels["Parent PID"].setText(
            f"Parent PID: {proc.get('ppid', '—')}"
        )
        self._detail_labels["User"].setText(
            f"User: {proc.get('username', '—')}"
        )
        self._detail_labels["CPU%"].setText(
            f"CPU%: {proc.get('cpu_percent', '—')}"
        )
        self._detail_labels["Memory"].setText(
            f"Memory: {proc.get('memory_mb', '—')} MB"
        )
        self._detail_labels["Network Connections"].setText(
            f"Network Connections: "
            f"{proc.get('net_connections', 0)}"
        )
        self._detail_labels["Open Files"].setText(
            f"Open Files: {proc.get('open_files', 0)}"
        )
        self._detail_labels["Threads"].setText(
            f"Threads: {proc.get('num_threads', 0)}"
        )

        risk = str(proc.get("risk_level", "none")).lower()
        risk_color = _RISK_COLORS.get(risk, "")
        risk_display = risk.capitalize() if risk != "none" else "None"
        style = ""
        if risk_color:
            style = f"color: {risk_color}; font-weight: bold;"
        self._risk_label.setText(
            f"Risk: {risk_display}"
        )
        self._risk_label.setStyleSheet(style)

        self._detail.setVisible(True)

    def _on_search_changed(self, text: str) -> None:
        """Filter visible table rows by *text*.

        Matches against PID, Name, User, and Executable Path
        columns (case-insensitive).

        Parameters
        ----------
        text : str
            Current contents of the search field.
        """
        needle = text.lower()
        for row in range(self._table.rowCount()):
            match = False
            # Check PID(0), Name(1), User(6), Executable(7)
            for col in (0, 1, 6, 7):
                item = self._table.item(row, col)
                if item and needle in item.text().lower():
                    match = True
                    break
            self._table.setRowHidden(row, not match)

    def _on_kill_process(self) -> None:
        """Stub: kill the selected process."""
        if self._selected_process:
            logger.info(
                "Kill requested for PID %s",
                self._selected_process.get("pid"),
            )

    def _on_whitelist(self) -> None:
        """Stub: whitelist the selected process."""
        if self._selected_process:
            logger.info(
                "Whitelist requested for %s",
                self._selected_process.get("name"),
            )

    def _on_investigate(self) -> None:
        """Stub: open investigation for the selected process."""
        if self._selected_process:
            logger.info(
                "Investigate requested for PID %s",
                self._selected_process.get("pid"),
            )

    # ----------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------

    def _update_stats(
        self,
        total: int,
        suspicious: int,
        unsigned: int,
        high_cpu: int,
    ) -> None:
        """Refresh the four stat boxes with current counts."""
        self._set_stat_value(self._stat_total, str(total))
        self._set_stat_value(
            self._stat_suspicious, str(suspicious),
        )
        self._set_stat_value(
            self._stat_unsigned, str(unsigned),
        )
        self._set_stat_value(
            self._stat_high_cpu, str(high_cpu),
        )

    @staticmethod
    def _set_stat_value(frame: QFrame, value: str) -> None:
        """Set the value label inside a stat-box *frame*."""
        for child in frame.findChildren(QLabel, "statValue"):
            child.setText(value)
            break
