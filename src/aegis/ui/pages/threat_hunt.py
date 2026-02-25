"""Threat Hunt page -- SQL-based query interface for threat hunting.

Provides a text editor for SQL queries, pre-built saved queries,
a results table, CSV export, bookmarked queries, and query history.

The pure-logic helpers (``PRE_BUILT_QUERIES``, ``validate_query``,
``QueryBookmarks``, ``QueryHistory``) are importable without PySide6
so that they can be unit-tested in headless environments.
"""

from __future__ import annotations

import csv
import logging
import re
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
#  Pure-logic helpers  (no Qt dependency)
# ------------------------------------------------------------------ #

PRE_BUILT_QUERIES: dict[str, str] = {
    "Recent high-severity alerts": (
        "SELECT * FROM alerts"
        " WHERE severity IN ('high','critical')"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
    "Events by sensor type": (
        "SELECT sensor, COUNT(*) AS count"
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
        "SELECT alert_type, sensor, action, COUNT(*) AS count"
        " FROM user_feedback"
        " GROUP BY alert_type, sensor, action"
    ),
    "Suspicious outbound connections": (
        "SELECT * FROM events"
        " WHERE event_type = 'connection'"
        " AND direction = 'outbound'"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
    "PowerShell execution events": (
        "SELECT * FROM events"
        " WHERE data LIKE '%powershell%'"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
    "Failed login attempts": (
        "SELECT * FROM events"
        " WHERE event_type = 'auth'"
        " AND status = 'failed'"
        " ORDER BY timestamp DESC LIMIT 100"
    ),
    "Lateral movement indicators": (
        "SELECT * FROM events"
        " WHERE event_type IN ('smb','rdp','wmi')"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
    "DNS queries to rare domains": (
        "SELECT * FROM events"
        " WHERE event_type = 'dns'"
        " AND domain_frequency < 10"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
    "Process creation with suspicious parents": (
        "SELECT * FROM events"
        " WHERE event_type = 'process_create'"
        " AND parent_name IN ('cmd.exe','powershell.exe',"
        "'wscript.exe','cscript.exe','mshta.exe')"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
    "Large data transfers": (
        "SELECT * FROM events"
        " WHERE event_type = 'connection'"
        " AND bytes_sent > 10485760"
        " ORDER BY bytes_sent DESC LIMIT 50"
    ),
    "Registry modification events": (
        "SELECT * FROM events"
        " WHERE event_type = 'registry'"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
    "Alerts resolved in last 24 hours": (
        "SELECT * FROM alerts"
        " WHERE status = 'resolved'"
        " AND timestamp > datetime('now', '-1 day')"
        " ORDER BY timestamp DESC"
    ),
    "Top talkers by connection count": (
        "SELECT remote_ip, COUNT(*) AS conn_count"
        " FROM events"
        " WHERE event_type = 'connection'"
        " GROUP BY remote_ip"
        " ORDER BY conn_count DESC LIMIT 20"
    ),
    "File creation in temp directories": (
        "SELECT * FROM events"
        " WHERE event_type = 'file_create'"
        " AND path LIKE '%\\Temp\\%'"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
    "Scheduled task creation events": (
        "SELECT * FROM events"
        " WHERE event_type = 'scheduled_task'"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
    "Service installation events": (
        "SELECT * FROM events"
        " WHERE event_type = 'service_install'"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
    "Alerts grouped by severity": (
        "SELECT severity, COUNT(*) AS count"
        " FROM alerts"
        " GROUP BY severity"
        " ORDER BY count DESC"
    ),
    "Unsigned binary execution": (
        "SELECT * FROM events"
        " WHERE event_type = 'process_create'"
        " AND is_signed = 0"
        " ORDER BY timestamp DESC LIMIT 50"
    ),
}

_SELECT_PATTERN = re.compile(r"^\s*SELECT\b", re.IGNORECASE)
_BLOCKED_KEYWORDS = re.compile(
    r"^\s*("
    r"DELETE|DROP|INSERT|UPDATE|ALTER|CREATE|"
    r"TRUNCATE|EXEC|GRANT|REVOKE"
    r")\b",
    re.IGNORECASE,
)


def validate_query(sql: str) -> bool:
    """Return True only for SELECT statements.

    Blocks DELETE, DROP, INSERT, UPDATE, ALTER, CREATE,
    TRUNCATE, EXEC, GRANT, and REVOKE (case-insensitive).
    Empty / whitespace-only strings return False.
    """
    stripped = sql.strip()
    if not stripped:
        return False
    if _BLOCKED_KEYWORDS.match(stripped):
        return False
    if _SELECT_PATTERN.match(stripped):
        return True
    return False


class QueryBookmarks:
    """In-memory bookmark store for saved queries."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def save(self, name: str, sql: str) -> None:
        """Save a query under *name*."""
        self._store[name] = sql

    def remove(self, name: str) -> None:
        """Remove a bookmark by *name*.  No-op if missing."""
        self._store.pop(name, None)

    def get(self, name: str) -> str | None:
        """Return the SQL for *name*, or ``None``."""
        return self._store.get(name)

    def list_names(self) -> list[str]:
        """Return all bookmark names in insertion order."""
        return list(self._store.keys())


class QueryHistory:
    """Fixed-size, most-recent-first query history.

    Duplicates are de-duplicated and moved to the front.
    """

    def __init__(self, max_size: int = 50) -> None:
        self._max = max_size
        self._items: list[str] = []

    def add(self, sql: str) -> None:
        """Record *sql*.  Moves to front if already present."""
        if sql in self._items:
            self._items.remove(sql)
        self._items.insert(0, sql)
        if len(self._items) > self._max:
            self._items = self._items[: self._max]

    def entries(self) -> list[str]:
        """Return history entries, most recent first."""
        return list(self._items)

    def clear(self) -> None:
        """Clear all history entries."""
        self._items.clear()


# ------------------------------------------------------------------ #
#  Qt UI  (guarded import so pure-logic is testable without PySide6)
# ------------------------------------------------------------------ #

try:
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

    _HAS_QT = True
except ImportError:  # pragma: no cover
    _HAS_QT = False

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase


# Keep back-compat alias used by the combo-box
_SAVED_QUERIES = PRE_BUILT_QUERIES


if _HAS_QT:

    class ThreatHuntPage(QWidget):  # type: ignore[misc]
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
            self._bookmarks = QueryBookmarks()
            self._history = QueryHistory()
            self._setup_ui()

        # -------------------------------------------------------------- #
        #  UI construction
        # -------------------------------------------------------------- #

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
            self._query_combo.addItems(
                list(PRE_BUILT_QUERIES.keys())
            )
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

            self._bookmark_btn = QPushButton("Bookmark")
            self._bookmark_btn.setObjectName("bookmarkBtn")
            self._bookmark_btn.clicked.connect(
                self._on_bookmark
            )
            btn_row.addWidget(self._bookmark_btn)

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
            self._table.horizontalHeader().setStretchLastSection(
                True
            )
            self._table.horizontalHeader().setSectionResizeMode(
                QHeaderView.ResizeMode.Interactive
            )
            root.addWidget(self._table, stretch=1)

            # 6. Status label
            self._status_label = QLabel("")
            self._status_label.setStyleSheet("color: #888;")
            root.addWidget(self._status_label)

        # -------------------------------------------------------------- #
        #  Public interface
        # -------------------------------------------------------------- #

        def refresh(self) -> None:
            """Clear results and reset the page."""
            self._results = []
            self._columns = []
            self._table.setRowCount(0)
            self._table.setColumnCount(0)
            self._status_label.setText("")

        def execute_query(
            self, sql: str,
        ) -> list[dict[str, Any]]:
            """Validate and execute a read-only SQL query.

            Args:
                sql: A SQL SELECT statement to execute.

            Returns:
                Query results as a list of dicts.

            Raises:
                ValueError: If the query is not a SELECT
                    statement or no database is connected.
            """
            if not validate_query(sql):
                raise ValueError(
                    "Only SELECT queries are allowed."
                )
            if self._db is None:
                raise ValueError("No database connected.")

            cursor = self._db._conn.execute(sql)
            columns = [
                desc[0] for desc in cursor.description
            ]
            rows = cursor.fetchall()
            self._history.add(sql)
            return [
                dict(zip(columns, row)) for row in rows
            ]

        def export_csv(self, filepath: str) -> None:
            """Write current results to a CSV file.

            Args:
                filepath: Destination path for the CSV file.
            """
            if not self._results or not self._columns:
                return
            with open(
                filepath, "w", newline="", encoding="utf-8",
            ) as f:
                writer = csv.DictWriter(
                    f, fieldnames=self._columns,
                )
                writer.writeheader()
                writer.writerows(self._results)
            logger.info(
                "Exported %d rows to %s",
                len(self._results),
                filepath,
            )

        # -------------------------------------------------------------- #
        #  Internal slots
        # -------------------------------------------------------------- #

        def _load_saved_query(self) -> None:
            """Fill query text box from the combo selection."""
            name = self._query_combo.currentText()
            sql = PRE_BUILT_QUERIES.get(name, "")
            self._query_edit.setPlainText(sql)

        def _on_execute(self) -> None:
            """Execute the current query and display results."""
            sql = self._query_edit.toPlainText().strip()
            if not sql:
                return
            try:
                self._results = self.execute_query(sql)
            except ValueError as exc:
                QMessageBox.warning(
                    self, "Query Error", str(exc),
                )
                self._status_label.setText(
                    f"Error: {exc}"
                )
                return
            except Exception as exc:
                QMessageBox.warning(
                    self, "Query Error", str(exc),
                )
                self._status_label.setText(
                    f"Error: {exc}"
                )
                return
            self._populate_table()

        def _on_bookmark(self) -> None:
            """Bookmark the current query."""
            from PySide6.QtWidgets import QInputDialog

            sql = self._query_edit.toPlainText().strip()
            if not sql:
                return
            name, ok = QInputDialog.getText(
                self, "Bookmark Query", "Name:",
            )
            if ok and name:
                self._bookmarks.save(name, sql)
                logger.info("Bookmarked query: %s", name)

        def _on_export(self) -> None:
            """Prompt for filepath and export results."""
            from PySide6.QtWidgets import QFileDialog

            filepath, _ = QFileDialog.getSaveFileName(
                self,
                "Export CSV",
                "threat_hunt_results.csv",
                "CSV Files (*.csv)",
            )
            if filepath:
                self.export_csv(filepath)

        def _populate_table(self) -> None:
            """Fill the table widget with current results."""
            if not self._results:
                self._table.setRowCount(0)
                self._table.setColumnCount(0)
                self._status_label.setText(
                    "Query returned 0 rows."
                )
                self._columns = []
                return

            self._columns = list(self._results[0].keys())
            self._table.setColumnCount(len(self._columns))
            self._table.setHorizontalHeaderLabels(
                self._columns,
            )
            self._table.setRowCount(len(self._results))

            for row_idx, row_data in enumerate(
                self._results,
            ):
                for col_idx, col_name in enumerate(
                    self._columns,
                ):
                    value = row_data.get(col_name, "")
                    item = QTableWidgetItem(str(value))
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignLeft
                        | Qt.AlignmentFlag.AlignVCenter
                    )
                    self._table.setItem(
                        row_idx, col_idx, item,
                    )

            self._status_label.setText(
                f"Returned {len(self._results)} row(s)."
            )
