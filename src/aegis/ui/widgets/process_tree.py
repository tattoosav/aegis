"""Process Tree widget — hierarchical process display.

Shows parent-child process relationships with risk-level color coding
and a context menu for process actions (kill requires user approval).
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QColor
from PySide6.QtWidgets import (
    QMenu,
    QTreeWidget,
    QTreeWidgetItem,
)

_RISK_COLORS = {
    "critical": QColor("#f44336"),
    "high": QColor("#ff9800"),
    "medium": QColor("#ffeb3b"),
    "low": QColor("#4caf50"),
    "normal": QColor("#ffffff"),
}

_COLUMNS = ["PID", "Name", "CPU %", "Memory MB", "Risk"]


class ProcessTree(QTreeWidget):
    """Tree widget displaying running processes in a hierarchy.

    Signals
    -------
    process_selected(int)
        Emitted with the PID when a process row is clicked.
    kill_requested(int)
        Emitted with the PID when "Kill Process" is chosen from
        the context menu.  Actual kill requires user approval.
    """

    process_selected = Signal(int)
    kill_requested = Signal(int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setColumnCount(len(_COLUMNS))
        self.setHeaderLabels(_COLUMNS)
        self.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        self.customContextMenuRequested.connect(self._show_context_menu)
        self.itemClicked.connect(self._on_item_clicked)

    def load_processes(self, processes: list[dict]) -> None:
        """Load processes into the tree.

        Each dict should have ``pid``, ``name``, ``cpu``, ``memory_mb``,
        ``risk`` (str), and optionally ``parent_pid`` keys.
        """
        self.clear()
        items_by_pid: dict[int, QTreeWidgetItem] = {}

        # First pass — create all items
        for proc in processes:
            pid = proc.get("pid", 0)
            item = QTreeWidgetItem([
                str(pid),
                proc.get("name", ""),
                f"{proc.get('cpu', 0):.1f}",
                f"{proc.get('memory_mb', 0):.1f}",
                proc.get("risk", "normal"),
            ])
            risk = proc.get("risk", "normal").lower()
            color = _RISK_COLORS.get(risk, QColor("#ffffff"))
            item.setForeground(4, color)
            item.setData(0, Qt.ItemDataRole.UserRole, pid)
            items_by_pid[pid] = item

        # Second pass — build hierarchy
        for proc in processes:
            pid = proc.get("pid", 0)
            ppid = proc.get("parent_pid")
            item = items_by_pid[pid]
            if ppid and ppid in items_by_pid:
                items_by_pid[ppid].addChild(item)
            else:
                self.addTopLevelItem(item)

        self.expandAll()

    def _on_item_clicked(
        self, item: QTreeWidgetItem, column: int,
    ) -> None:
        pid = item.data(0, Qt.ItemDataRole.UserRole)
        if pid is not None:
            self.process_selected.emit(int(pid))

    def _show_context_menu(self, pos) -> None:
        item = self.itemAt(pos)
        if item is None:
            return
        pid = item.data(0, Qt.ItemDataRole.UserRole)
        if pid is None:
            return

        menu = QMenu(self)
        kill_action = QAction(f"Kill Process (PID {pid})", self)
        kill_action.triggered.connect(
            lambda: self.kill_requested.emit(int(pid))
        )
        menu.addAction(kill_action)
        menu.exec(self.viewport().mapToGlobal(pos))
