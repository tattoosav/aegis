"""Tests for RealTimeChart widget."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from aegis.ui.widgets.real_time_chart import RealTimeChart  # noqa: E402

_app = QApplication.instance() or QApplication([])


class TestRealTimeChartInit:
    """Construction tests."""

    def test_creates(self) -> None:
        chart = RealTimeChart()
        assert chart is not None

    def test_minimum_height(self) -> None:
        chart = RealTimeChart()
        assert chart.minimumHeight() >= 180


class TestAddSeries:
    """Tests for add_series and update_data."""

    def test_add_series(self) -> None:
        chart = RealTimeChart()
        chart.add_series("events", "#ff0000")
        assert "events" in chart._series

    def test_update_data(self) -> None:
        chart = RealTimeChart()
        chart.add_series("events")
        now = time.time()
        chart.update_data("events", now, 42.0)
        assert len(chart._series["events"]["data"]) == 1

    def test_update_unknown_series_ignored(self) -> None:
        chart = RealTimeChart()
        chart.update_data("nonexistent", time.time(), 1.0)
        # Should not crash

    def test_multiple_data_points(self) -> None:
        chart = RealTimeChart()
        chart.add_series("cpu")
        now = time.time()
        for i in range(10):
            chart.update_data("cpu", now + i, float(i))
        assert len(chart._series["cpu"]["data"]) == 10

    def test_old_data_pruned(self) -> None:
        chart = RealTimeChart()
        chart.add_series("test")
        old = time.time() - 700  # older than 10-minute window
        chart.update_data("test", old, 1.0)
        chart._prune("test")
        assert len(chart._series["test"]["data"]) == 0
