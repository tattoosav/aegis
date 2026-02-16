"""Real-time Chart widget — rolling line chart using QPainter.

Displays a rolling 10-minute window line chart with custom paint.
Uses PySide6-native drawing (no pyqtgraph dependency).
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from PySide6.QtCore import QTimer
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QWidget

_WINDOW_SECONDS = 600  # 10-minute rolling window
_REFRESH_MS = 1000  # 1-second refresh


class RealTimeChart(QWidget):
    """A rolling line chart rendered with QPainter.

    Supports multiple named series with distinct colors.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(180)
        self._series: dict[str, dict[str, Any]] = {}
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.update)
        self._timer.start(_REFRESH_MS)

    def add_series(self, name: str, color: str = "#4fc3f7") -> None:
        """Register a named data series with a color."""
        self._series[name] = {
            "color": QColor(color),
            "data": deque(),  # (timestamp, value) tuples
        }

    def update_data(
        self, series: str, timestamp: float, value: float,
    ) -> None:
        """Append a data point to a series."""
        if series not in self._series:
            return
        self._series[series]["data"].append((timestamp, value))
        self._prune(series)

    def _prune(self, series: str) -> None:
        """Remove data older than the rolling window."""
        cutoff = time.time() - _WINDOW_SECONDS
        data = self._series[series]["data"]
        while data and data[0][0] < cutoff:
            data.popleft()

    def paintEvent(self, event) -> None:  # noqa: N802
        """Render all series as line charts."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width()
        h = self.height()

        # Background
        painter.fillRect(0, 0, w, h, QColor("#1e1e1e"))

        # Grid lines
        painter.setPen(QPen(QColor("#333333"), 1))
        for i in range(1, 4):
            y = int(h * i / 4)
            painter.drawLine(0, y, w, y)

        now = time.time()
        t_start = now - _WINDOW_SECONDS

        for info in self._series.values():
            data = info["data"]
            if len(data) < 2:
                continue

            color = info["color"]
            painter.setPen(QPen(color, 2))

            # Find y range
            values = [v for _, v in data]
            y_min = min(values)
            y_max = max(values)
            y_range = y_max - y_min if y_max != y_min else 1.0

            points = []
            for ts, val in data:
                x = int((ts - t_start) / _WINDOW_SECONDS * w)
                y = int(h - (val - y_min) / y_range * (h - 20) - 10)
                points.append((x, y))

            for i in range(1, len(points)):
                painter.drawLine(
                    points[i - 1][0], points[i - 1][1],
                    points[i][0], points[i][1],
                )

        painter.end()
