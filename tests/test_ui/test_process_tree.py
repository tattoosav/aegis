"""Tests for ProcessTree widget."""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from aegis.ui.widgets.process_tree import ProcessTree  # noqa: E402

_app = QApplication.instance() or QApplication([])


_SAMPLE_PROCS = [
    {"pid": 1, "name": "init", "cpu": 0.1, "memory_mb": 10.0, "risk": "normal"},
    {"pid": 100, "name": "svchost", "cpu": 2.5, "memory_mb": 50.0,
     "risk": "low", "parent_pid": 1},
    {"pid": 200, "name": "suspicious.exe", "cpu": 90.0, "memory_mb": 500.0,
     "risk": "critical", "parent_pid": 100},
]


class TestProcessTreeInit:
    """Basic construction tests."""

    def test_creates(self) -> None:
        tree = ProcessTree()
        assert tree is not None

    def test_has_columns(self) -> None:
        tree = ProcessTree()
        assert tree.columnCount() == 5


class TestLoadProcesses:
    """Tests for load_processes."""

    def test_loads_flat_list(self) -> None:
        tree = ProcessTree()
        tree.load_processes([
            {"pid": 1, "name": "a", "cpu": 0, "memory_mb": 0, "risk": "normal"},
            {"pid": 2, "name": "b", "cpu": 0, "memory_mb": 0, "risk": "normal"},
        ])
        assert tree.topLevelItemCount() == 2

    def test_builds_hierarchy(self) -> None:
        tree = ProcessTree()
        tree.load_processes(_SAMPLE_PROCS)
        assert tree.topLevelItemCount() == 1  # only "init" at top level
        init_item = tree.topLevelItem(0)
        assert init_item.childCount() == 1  # svchost is child of init

    def test_empty_list(self) -> None:
        tree = ProcessTree()
        tree.load_processes([])
        assert tree.topLevelItemCount() == 0


class TestProcessTreeSignals:
    """Signal tests."""

    def test_process_selected_signal(self) -> None:
        tree = ProcessTree()
        received = []
        tree.process_selected.connect(received.append)
        tree.process_selected.emit(123)
        assert received == [123]

    def test_kill_requested_signal(self) -> None:
        tree = ProcessTree()
        received = []
        tree.kill_requested.connect(received.append)
        tree.kill_requested.emit(456)
        assert received == [456]


class TestRiskColors:
    """Processes with different risk levels should load without error."""

    @pytest.mark.parametrize("risk", [
        "critical", "high", "medium", "low", "normal",
    ])
    def test_risk_level(self, risk: str) -> None:
        tree = ProcessTree()
        tree.load_processes([
            {"pid": 1, "name": "test", "cpu": 0, "memory_mb": 0, "risk": risk},
        ])
        assert tree.topLevelItemCount() == 1
