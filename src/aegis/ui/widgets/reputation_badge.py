"""Reputation Badge widget — color-coded score indicator.

Small widget that displays a reputation score (0-100) with color
coding: red (0-30), yellow (31-60), blue (61-80), green (81-100).
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QLabel


def _score_color(score: float) -> str:
    """Return a hex color based on the reputation score."""
    if score <= 30:
        return "#f44336"
    if score <= 60:
        return "#ffeb3b"
    if score <= 80:
        return "#2196f3"
    return "#4caf50"


def _score_label(score: float) -> str:
    """Return a human-readable risk label."""
    if score <= 30:
        return "Malicious"
    if score <= 60:
        return "Suspicious"
    if score <= 80:
        return "Neutral"
    return "Clean"


class ReputationBadge(QLabel):
    """A small badge displaying a reputation score with color coding.

    The badge background color changes based on the score range:
      - 0-30: Red (Malicious)
      - 31-60: Yellow (Suspicious)
      - 61-80: Blue (Neutral)
      - 81-100: Green (Clean)
    """

    def __init__(self, score: float = 50.0, parent=None) -> None:
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedSize(80, 28)
        font = QFont()
        font.setBold(True)
        self.setFont(font)
        self.set_score(score)

    def set_score(self, score: float) -> None:
        """Update the displayed score and re-color the badge."""
        self._score = max(0.0, min(100.0, score))
        color = _score_color(self._score)
        label = _score_label(self._score)
        self.setText(f"{self._score:.0f}")
        self.setStyleSheet(
            f"background-color: {color}; color: #fff; "
            f"border-radius: 4px; padding: 2px 8px;"
        )
        self.setToolTip(
            f"Reputation: {self._score:.1f}/100 ({label})"
        )

    @property
    def score(self) -> float:
        """Return the current score."""
        return self._score
