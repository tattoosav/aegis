"""Tests for ThreatIntelPage UI component."""

from __future__ import annotations

import pytest

PySide6 = pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QTableWidget  # noqa: E402

from aegis.ui.pages.threat_intel import ThreatIntelPage  # noqa: E402

_app = QApplication.instance() or QApplication([])


class TestThreatIntelPageInit:
    """Basic construction tests."""

    def test_creates_without_db(self) -> None:
        page = ThreatIntelPage()
        assert page is not None

    def test_has_results_table(self) -> None:
        page = ThreatIntelPage()
        assert isinstance(page._results_table, QTableWidget)

    def test_results_table_has_columns(self) -> None:
        page = ThreatIntelPage()
        assert page._results_table.columnCount() == 5

    def test_has_lookup_input(self) -> None:
        page = ThreatIntelPage()
        assert hasattr(page, "_lookup_input")

    def test_has_stat_labels(self) -> None:
        page = ThreatIntelPage()
        assert "total_iocs" in page._stat_labels


class TestFeedStatus:
    """Tests for update_feed_status."""

    def test_set_active(self) -> None:
        page = ThreatIntelPage()
        page.update_feed_status("AbuseIPDB", True)
        assert "Active" in page._feed_labels["AbuseIPDB"].text()

    def test_set_offline(self) -> None:
        page = ThreatIntelPage()
        page.update_feed_status("PhishTank", False)
        assert "Offline" in page._feed_labels["PhishTank"].text()

    def test_unknown_feed_ignored(self) -> None:
        page = ThreatIntelPage()
        page.update_feed_status("Nonexistent", True)  # no crash


class TestShowResults:
    """Tests for show_results."""

    def test_populates_table(self) -> None:
        page = ThreatIntelPage()
        page.show_results([
            {
                "ioc_type": "ip",
                "value": "10.0.0.1",
                "source": "AbuseIPDB",
                "severity": "high",
                "last_updated": 1700000000.0,
            },
        ])
        assert page._results_table.rowCount() == 1

    def test_empty_results_clears_table(self) -> None:
        page = ThreatIntelPage()
        page.show_results([{"ioc_type": "ip", "value": "x",
                            "source": "s", "severity": "low",
                            "last_updated": 0}])
        page.show_results([])
        assert page._results_table.rowCount() == 0
