"""Threat Hunt page -- SQL-based query interface for threat hunting.

Provides a text editor for SQL queries, pre-built saved queries,
a results table, and CSV export capability.
"""

from __future__ import annotations

import csv
import logging
import re
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

logger = logging.getLogger(__name__)

_SAVED_QUERIES: dict[str, str] = {
    "Recent high-severity alerts": (
        "SELECT * FROM alerts"
        " WHERE severity IN ('high','critical')"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
    "Events by sensor type": (
        "SELECT sensor, COUNT(*) as count"
        " FROM events GROUP BY sensor"
    ),
    "Connection reputation scores": (
        "SELECT * FROM connection_reputation"
        " WHERE score > 70"
        " ORDER BY score DESC LIMIT 50"
    ),
    "Recent IOC matches": (
        "SELECT * FROM ioc_indicators"
        " ORDER BY last_updated DESC LIMIT 50"
    ),
    "User feedback summary": (
        "SELECT alert_type, sensor, action, COUNT(*) as count"
        " FROM user_feedback"
        " GROUP BY alert_type, sensor, action"
    ),
}

_SELECT_PATTERN = re.compile(r"^\s*SELECT\b", re.IGNORECASE)


class ThreatHuntPage(QWidget):
    """SQL-based threat hunting page.

    Allows analysts to run read-only SELECT queries against the
    Aegis database, choose from saved queries, view results in a
    table, and export to CSV.
    """

    def __init__(
        self,
        db: AegisDatabase | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._db = db
        self._results: list[dict[str, Any]] = []
        self._columns: list[str] = []
        self._setup_ui()

    # ------------------------------------------------------------------ #
    #  UI construction
    # ------------------------------------------------------------------ #

    def _setup_ui(self) -> None:
        """Build the full page layout."""
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # 1. Header
        title = QLabel("Threat Hunt")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        root.addWidget(title)

        # 2. Saved queries combo
        combo_row = QHBoxLayout()
        combo_row.addWidget(QLabel("Saved Queries:"))
        self._query_combo = QComboBox()
        self._query_combo.setObjectName("savedQueries")
        self._query_combo.addItems(list(_SAVED_QUERIES.keys()))
        self._query_combo.currentIndexChanged.connect(
            self._load_saved_query
        )
        combo_row.addWidget(self._query_combo, stretch=1)
        root.addLayout(combo_row)

        # 3. SQL text editor
        self._query_edit = QTextEdit()
        self._query_edit.setObjectName("queryEdit")
        self._query_edit.setPlaceholderText(
            "Enter a SELECT query..."
        )
        self._query_edit.setMaximumHeight(120)
        root.addWidget(self._query_edit)

        # Load the first saved query into the editor
        self._load_saved_query()

        # 4. Buttons row
        btn_row = QHBoxLayout()
        self._execute_btn = QPushButton("Execute Query")
        self._execute_btn.setObjectName("executeBtn")
        self._execute_btn.clicked.connect(self._on_execute)
        btn_row.addWidget(self._execute_btn)

        self._export_btn = QPushButton("Export CSV")
        self._export_btn.setObjectName("exportBtn")
        self._export_btn.clicked.connect(self._on_export)
        btn_row.addWidget(self._export_btn)

        btn_row.addStretch()
        root.addLayout(btn_row)

        # 5. Results table
        self._table = QTableWidget(0, 0)
        self._table.setObjectName("resultsTable")
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        root.addWidget(self._table, stretch=1)

        # 6. Status label
        self._status_label = QLabel("")
        self._status_label.setStyleSheet("color: #888;")
        root.addWidget(self._status_label)

    # ------------------------------------------------------------------ #
    #  Public interface
    # ------------------------------------------------------------------ #

    def refresh(self) -> None:
        """Clear results and reset the page."""
        self._results = []
        self._columns = []
        self._table.setRowCount(0)
        self._table.setColumnCount(0)
        self._status_label.setText("")

    def execute_query(self, sql: str) -> list[dict[str, Any]]:
        """Validate and execute a read-only SQL query.

        Args:
            sql: A SQL SELECT statement to execute.

        Returns:
            Query results as a list of dicts.

        Raises:
            ValueError: If the query is not a SELECT statement or
                no database is connected.
        """
        if not _SELECT_PATTERN.match(sql):
            raise ValueError(
                "Only SELECT queries are allowed."
            )
        if self._db is None:
            raise ValueError("No database connected.")

        cursor = self._db._conn.execute(sql)
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        return [
            dict(zip(columns, row))
            for row in rows
        ]

    def export_csv(self, filepath: str) -> None:
        """Write current results to a CSV file.

        Args:
            filepath: Destination path for the CSV file.
        """
        if not self._results or not self._columns:
            return
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self._columns)
            writer.writeheader()
            writer.writerows(self._results)
        logger.info("Exported %d rows to %s", len(self._results), filepath)

    # ------------------------------------------------------------------ #
    #  Internal slots
    # ------------------------------------------------------------------ #

    def _load_saved_query(self) -> None:
        """Fill the query text box from the combo box selection."""
        name = self._query_combo.currentText()
        sql = _SAVED_QUERIES.get(name, "")
        self._query_edit.setPlainText(sql)

    def _on_execute(self) -> None:
        """Execute the current query and display results."""
        sql = self._query_edit.toPlainText().strip()
        if not sql:
            return
        try:
            self._results = self.execute_query(sql)
        except ValueError as exc:
            QMessageBox.warning(self, "Query Error", str(exc))
            self._status_label.setText(f"Error: {exc}")
            return
        except Exception as exc:
            QMessageBox.warning(self, "Query Error", str(exc))
            self._status_label.setText(f"Error: {exc}")
            return
        self._populate_table()

    def _on_export(self) -> None:
        """Prompt for a filepath and export results to CSV."""
        from PySide6.QtWidgets import QFileDialog

        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "threat_hunt_results.csv",
            "CSV Files (*.csv)",
        )
        if filepath:
            self.export_csv(filepath)

    def _populate_table(self) -> None:
        """Fill the table widget with current results."""
        if not self._results:
            self._table.setRowCount(0)
            self._table.setColumnCount(0)
            self._status_label.setText("Query returned 0 rows.")
            self._columns = []
            return

        self._columns = list(self._results[0].keys())
        self._table.setColumnCount(len(self._columns))
        self._table.setHorizontalHeaderLabels(self._columns)
        self._table.setRowCount(len(self._results))

        for row_idx, row_data in enumerate(self._results):
            for col_idx, col_name in enumerate(self._columns):
                value = row_data.get(col_name, "")
                item = QTableWidgetItem(str(value))
                item.setTextAlignment(
                    Qt.AlignmentFlag.AlignLeft
                    | Qt.AlignmentFlag.AlignVCenter
                )
                self._table.setItem(row_idx, col_idx, item)

        self._status_label.setText(
            f"Returned {len(self._results)} row(s)."
        )
