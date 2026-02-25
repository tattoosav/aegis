"""Tests for ThreatHuntPage -- query execution, validation, and export.

Includes tests for NL threat hunting: PRE_BUILT_QUERIES, validate_query,
saved/bookmarked queries, and query history.
"""

from __future__ import annotations

import os
import tempfile

import pytest

# ------------------------------------------------------------------ #
#  Pure-logic tests (no Qt required)
# ------------------------------------------------------------------ #


class TestNLHunting:
    """Validate pre-built queries and query validation (no Qt)."""

    def test_pre_built_queries_loaded(self) -> None:
        from aegis.ui.pages.threat_hunt import PRE_BUILT_QUERIES

        assert len(PRE_BUILT_QUERIES) >= 10

    def test_pre_built_queries_has_at_least_20(self) -> None:
        from aegis.ui.pages.threat_hunt import PRE_BUILT_QUERIES

        assert len(PRE_BUILT_QUERIES) >= 20

    def test_pre_built_queries_all_select(self) -> None:
        from aegis.ui.pages.threat_hunt import PRE_BUILT_QUERIES

        for label, sql in PRE_BUILT_QUERIES.items():
            assert sql.strip().upper().startswith("SELECT"), (
                f"Query '{label}' does not start with SELECT"
            )

    def test_query_validation_blocks_delete(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("DELETE FROM events") is False

    def test_query_validation_blocks_drop(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("DROP TABLE events") is False

    def test_query_validation_blocks_insert(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("INSERT INTO events VALUES (1)") is False

    def test_query_validation_blocks_update(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("UPDATE alerts SET status='x'") is False

    def test_query_validation_blocks_alter(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("ALTER TABLE events ADD col TEXT") is False

    def test_query_validation_blocks_create(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("CREATE TABLE evil (id INT)") is False

    def test_query_validation_blocks_truncate(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("TRUNCATE TABLE events") is False

    def test_query_validation_blocks_exec(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("EXEC sp_configure") is False

    def test_query_validation_blocks_grant(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("GRANT ALL ON events TO user") is False

    def test_query_validation_blocks_revoke(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("REVOKE ALL ON events FROM user") is False

    def test_query_validation_case_insensitive(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("delete FROM events") is False
        assert validate_query("Delete FROM events") is False
        assert validate_query("DELETE from events") is False

    def test_query_validation_allows_select(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("SELECT * FROM alerts") is True

    def test_query_validation_allows_select_case_insensitive(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("select * from events") is True
        assert validate_query("Select count(*) from events") is True

    def test_query_validation_allows_select_with_whitespace(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("  SELECT * FROM events") is True
        assert validate_query("\n SELECT * FROM events") is True

    def test_query_validation_blocks_empty(self) -> None:
        from aegis.ui.pages.threat_hunt import validate_query

        assert validate_query("") is False
        assert validate_query("   ") is False


class TestSavedQueriesLogic:
    """Test bookmark / saved-queries support (no Qt)."""

    def test_save_and_list_bookmarks(self) -> None:
        from aegis.ui.pages.threat_hunt import QueryBookmarks

        bm = QueryBookmarks()
        bm.save("My Query", "SELECT * FROM events")
        assert "My Query" in bm.list_names()
        assert bm.get("My Query") == "SELECT * FROM events"

    def test_remove_bookmark(self) -> None:
        from aegis.ui.pages.threat_hunt import QueryBookmarks

        bm = QueryBookmarks()
        bm.save("temp", "SELECT 1")
        bm.remove("temp")
        assert "temp" not in bm.list_names()

    def test_remove_nonexistent_is_safe(self) -> None:
        from aegis.ui.pages.threat_hunt import QueryBookmarks

        bm = QueryBookmarks()
        bm.remove("does_not_exist")  # should not raise

    def test_get_nonexistent_returns_none(self) -> None:
        from aegis.ui.pages.threat_hunt import QueryBookmarks

        bm = QueryBookmarks()
        assert bm.get("nope") is None


class TestQueryHistory:
    """Test query history tracking (no Qt)."""

    def test_add_and_retrieve(self) -> None:
        from aegis.ui.pages.threat_hunt import QueryHistory

        hist = QueryHistory(max_size=5)
        hist.add("SELECT 1")
        hist.add("SELECT 2")
        entries = hist.entries()
        assert len(entries) == 2
        assert entries[0] == "SELECT 2"  # most recent first

    def test_max_size_enforced(self) -> None:
        from aegis.ui.pages.threat_hunt import QueryHistory

        hist = QueryHistory(max_size=3)
        for i in range(5):
            hist.add(f"SELECT {i}")
        entries = hist.entries()
        assert len(entries) == 3
        # oldest queries trimmed
        assert entries[-1] == "SELECT 2"

    def test_duplicate_moves_to_top(self) -> None:
        from aegis.ui.pages.threat_hunt import QueryHistory

        hist = QueryHistory(max_size=10)
        hist.add("SELECT 1")
        hist.add("SELECT 2")
        hist.add("SELECT 1")  # re-run same query
        entries = hist.entries()
        assert entries[0] == "SELECT 1"
        assert entries.count("SELECT 1") == 1  # no duplicates

    def test_clear(self) -> None:
        from aegis.ui.pages.threat_hunt import QueryHistory

        hist = QueryHistory(max_size=10)
        hist.add("SELECT 1")
        hist.clear()
        assert hist.entries() == []


# ------------------------------------------------------------------ #
#  Qt-dependent tests
# ------------------------------------------------------------------ #

_HAS_PYSIDE6 = True
try:
    import PySide6  # noqa: F401
except ImportError:
    _HAS_PYSIDE6 = False

_skip_no_qt = pytest.mark.skipif(
    not _HAS_PYSIDE6, reason="PySide6 not installed"
)

_app = None


def get_app():
    """Get or create a QApplication instance for testing."""
    global _app
    if _app is None:
        from PySide6.QtWidgets import QApplication
        _app = QApplication.instance() or QApplication([])
    return _app


@_skip_no_qt
class TestThreatHuntImport:
    """Verify the module can be imported."""

    def test_import(self) -> None:
        from aegis.ui.pages.threat_hunt import ThreatHuntPage
        assert ThreatHuntPage is not None


@_skip_no_qt
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


@_skip_no_qt
class TestThreatHuntSavedQueries:
    """Verify the saved queries combo box."""

    def test_saved_query_count_at_least_20(self) -> None:
        get_app()
        from aegis.ui.pages.threat_hunt import ThreatHuntPage
        page = ThreatHuntPage(db=None)
        assert page._query_combo.count() >= 20

    def test_load_saved_query_populates_editor(self) -> None:
        get_app()
        from aegis.ui.pages.threat_hunt import ThreatHuntPage
        page = ThreatHuntPage(db=None)
        page._query_combo.setCurrentIndex(1)
        text = page._query_edit.toPlainText()
        assert "SELECT" in text.upper()


@_skip_no_qt
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


@_skip_no_qt
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
