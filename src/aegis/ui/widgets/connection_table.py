"""Connection Table widget — sortable network connections display.

Shows active connections with process, IP, port, protocol, and
reputation columns.  Includes protocol filter and context menu.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

_COLUMNS = ["Process", "Remote IP", "Port", "Protocol", "Reputation"]


class ConnectionTable(QWidget):
    """Sortable table of active network connections.

    Signals
    -------
    block_ip_requested(str)
        Emitted when "Block IP" is chosen from the context menu.
        Actual blocking requires user approval.
    """

    block_ip_requested = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._all_connections: list[dict] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Filter row
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Protocol:"))
        self._protocol_filter = QComboBox()
        self._protocol_filter.addItems(["All", "TCP", "UDP"])
        self._protocol_filter.currentTextChanged.connect(
            self._apply_filter
        )
        filter_row.addWidget(self._protocol_filter)
        filter_row.addStretch()
        layout.addLayout(filter_row)

        # Table
        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setSortingEnabled(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        self._table.customContextMenuRequested.connect(
            self._show_context_menu
        )
        h = self._table.horizontalHeader()
        h.setStretchLastSection(True)
        h.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

        layout.addWidget(self._table)

    def load_connections(self, connections: list[dict]) -> None:
        """Load connection data into the table.

        Each dict should have ``process``, ``remote_ip``, ``port``,
        ``protocol``, and ``reputation`` keys.
        """
        self._all_connections = connections
        self._apply_filter(self._protocol_filter.currentText())

    def _apply_filter(self, protocol: str) -> None:
        if protocol == "All":
            filtered = self._all_connections
        else:
            filtered = [
                c for c in self._all_connections
                if c.get("protocol", "").upper() == protocol.upper()
            ]
        self._populate(filtered)

    def _populate(self, connections: list[dict]) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(connections))
        for row, conn in enumerate(connections):
            vals = [
                conn.get("process", ""),
                conn.get("remote_ip", ""),
                str(conn.get("port", "")),
                conn.get("protocol", ""),
                str(conn.get("reputation", "")),
            ]
            for col, text in enumerate(vals):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._table.setItem(row, col, item)
        self._table.setSortingEnabled(True)

    def _show_context_menu(self, pos) -> None:
        item = self._table.itemAt(pos)
        if item is None:
            return
        row = item.row()
        ip_item = self._table.item(row, 1)
        if ip_item is None:
            return
        ip = ip_item.text()

        menu = QMenu(self)
        block = QAction(f"Block IP: {ip}", self)
        block.triggered.connect(
            lambda: self.block_ip_requested.emit(ip)
        )
        copy = QAction("Copy IP", self)
        copy.triggered.connect(
            lambda: self._copy_to_clipboard(ip)
        )
        menu.addAction(block)
        menu.addAction(copy)
        menu.exec(self._table.viewport().mapToGlobal(pos))

    @staticmethod
    def _copy_to_clipboard(text: str) -> None:
        from PySide6.QtWidgets import QApplication

        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)
