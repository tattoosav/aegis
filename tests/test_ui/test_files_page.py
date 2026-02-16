"""Tests for FilesPage UI component."""

from __future__ import annotations

import pytest

PySide6 = pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QTableWidget  # noqa: E402

from aegis.ui.pages.files import FilesPage  # noqa: E402

# Ensure a QApplication exists for widget tests
_app = QApplication.instance() or QApplication([])


class TestFilesPageInit:
    """Basic construction tests."""

    def test_creates_without_db(self) -> None:
        page = FilesPage()
        assert page is not None

    def test_has_changes_table(self) -> None:
        page = FilesPage()
        assert hasattr(page, "_changes_table")
        assert isinstance(page._changes_table, QTableWidget)

    def test_has_quarantine_table(self) -> None:
        page = FilesPage()
        assert hasattr(page, "_quarantine_table")
        assert isinstance(page._quarantine_table, QTableWidget)

    def test_changes_table_has_columns(self) -> None:
        page = FilesPage()
        assert page._changes_table.columnCount() == 5

    def test_quarantine_table_has_columns(self) -> None:
        page = FilesPage()
        assert page._quarantine_table.columnCount() == 4


class TestCanaryStatus:
    """Tests for update_canary_status."""

    def test_set_healthy(self) -> None:
        page = FilesPage()
        page.update_canary_status("System Files", True)
        label = page._canary_labels["System Files"]
        assert "Healthy" in label.text()

    def test_set_tampered(self) -> None:
        page = FilesPage()
        page.update_canary_status("Config Files", False)
        label = page._canary_labels["Config Files"]
        assert "TAMPERED" in label.text()

    def test_unknown_name_ignored(self) -> None:
        page = FilesPage()
        page.update_canary_status("Nonexistent", True)  # no crash


class TestLoadQuarantine:
    """Tests for load_quarantine."""

    def test_populates_table(self) -> None:
        page = FilesPage()
        items = [
            {
                "filename": "malware.exe",
                "original_path": r"C:\temp\malware.exe",
                "quarantined_at": 1700000000.0,
                "action_id": "act-001",
            },
        ]
        page.load_quarantine(items)
        assert page._quarantine_table.rowCount() == 1

    def test_empty_list_clears_table(self) -> None:
        page = FilesPage()
        page.load_quarantine([{"filename": "x", "original_path": "y",
                               "quarantined_at": 0, "action_id": "a"}])
        page.load_quarantine([])
        assert page._quarantine_table.rowCount() == 0
