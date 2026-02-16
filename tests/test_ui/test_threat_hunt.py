"""Tests for ThreatHuntPage — query execution, validation, and export."""

from __future__ import annotations

import os
import tempfile

import pytest

pytest.importorskip("PySide6")

_app = None


def get_app():
    """Get or create a QApplication instance for testing."""
    global _app
    if _app is None:
        from PySide6.QtWidgets import QApplication
        _app = QApplication.instance() or QApplication([])
    return _app


class TestThreatHuntImport:
    """Verify the module can be imported."""

    def test_import(self) -> None:
        from aegis.ui.pages.threat_hunt import ThreatHuntPage
        assert ThreatHuntPage is not None


class TestThreatHuntInstantiation:
    """Verify the widget can be created without a database."""

    def test_instantiate_without_db(self) -> None:
        get_app()
        from aegis.ui.pages.threat_hunt import ThreatHuntPage
        page = ThreatHuntPage(db=None)
        assert page is not None

    def test_has_refresh_method(self) -> None:
        from aegis.ui.pages.threat_hunt import ThreatHuntPage
        assert callable(getattr(ThreatHuntPage, "refresh", None))


class TestThreatHuntSavedQueries:
    """Verify the saved queries combo box."""

    def test_saved_query_count(self) -> None:
        get_app()
        from aegis.ui.pages.threat_hunt import ThreatHuntPage
        page = ThreatHuntPage(db=None)
        assert page._query_combo.count() == 5

    def test_load_saved_query_populates_editor(self) -> None:
        get_app()
        from aegis.ui.pages.threat_hunt import ThreatHuntPage
        page = ThreatHuntPage(db=None)
        page._query_combo.setCurrentIndex(1)
        text = page._query_edit.toPlainText()
        assert "SELECT" in text.upper()


class TestThreatHuntQueryExecution:
    """Verify query validation and execution."""

    def test_reject_non_select_query(self) -> None:
        get_app()
        from aegis.core.database import AegisDatabase
        from aegis.ui.pages.threat_hunt import ThreatHuntPage

        db = AegisDatabase(":memory:")
        page = ThreatHuntPage(db=db)
        with pytest.raises(ValueError, match="SELECT"):
            page.execute_query("DROP TABLE events")

    def test_reject_update_query(self) -> None:
        get_app()
        from aegis.core.database import AegisDatabase
        from aegis.ui.pages.threat_hunt import ThreatHuntPage

        db = AegisDatabase(":memory:")
        page = ThreatHuntPage(db=db)
        with pytest.raises(ValueError, match="SELECT"):
            page.execute_query(
                "UPDATE alerts SET status='resolved'"
            )

    def test_execute_valid_select(self) -> None:
        get_app()
        from aegis.core.database import AegisDatabase
        from aegis.ui.pages.threat_hunt import ThreatHuntPage

        db = AegisDatabase(":memory:")
        page = ThreatHuntPage(db=db)
        results = page.execute_query(
            "SELECT COUNT(*) as cnt FROM events"
        )
        assert len(results) == 1
        assert results[0]["cnt"] == 0

    def test_execute_without_db_raises(self) -> None:
        get_app()
        from aegis.ui.pages.threat_hunt import ThreatHuntPage

        page = ThreatHuntPage(db=None)
        with pytest.raises(ValueError, match="No database"):
            page.execute_query("SELECT 1")


class TestThreatHuntExport:
    """Verify CSV export."""

    def test_export_csv_writes_file(self) -> None:
        get_app()
        from aegis.core.database import AegisDatabase
        from aegis.ui.pages.threat_hunt import ThreatHuntPage

        db = AegisDatabase(":memory:")
        page = ThreatHuntPage(db=db)
        page._results = [
            {"col_a": "val1", "col_b": "val2"},
            {"col_a": "val3", "col_b": "val4"},
        ]
        page._columns = ["col_a", "col_b"]

        with tempfile.NamedTemporaryFile(
            suffix=".csv", delete=False, mode="w"
        ) as tmp:
            tmp_path = tmp.name

        try:
            page.export_csv(tmp_path)
            with open(tmp_path, encoding="utf-8") as f:
                content = f.read()
            assert "col_a" in content
            assert "val1" in content
            lines = content.strip().splitlines()
            # Header + 2 data rows
            assert len(lines) == 3
        finally:
            os.unlink(tmp_path)
