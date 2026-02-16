"""Tests for ReputationBadge widget."""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from aegis.ui.widgets.reputation_badge import ReputationBadge  # noqa: E402

_app = QApplication.instance() or QApplication([])


class TestReputationBadgeInit:
    """Construction tests."""

    def test_creates_with_default_score(self) -> None:
        badge = ReputationBadge()
        assert badge.score == 50.0

    def test_creates_with_custom_score(self) -> None:
        badge = ReputationBadge(score=85.0)
        assert badge.score == 85.0


class TestSetScore:
    """Tests for set_score."""

    def test_updates_score(self) -> None:
        badge = ReputationBadge()
        badge.set_score(25.0)
        assert badge.score == 25.0

    def test_clamps_to_zero(self) -> None:
        badge = ReputationBadge()
        badge.set_score(-10.0)
        assert badge.score == 0.0

    def test_clamps_to_hundred(self) -> None:
        badge = ReputationBadge()
        badge.set_score(150.0)
        assert badge.score == 100.0

    def test_tooltip_contains_label(self) -> None:
        badge = ReputationBadge(score=10.0)
        assert "Malicious" in badge.toolTip()

    def test_tooltip_suspicious(self) -> None:
        badge = ReputationBadge(score=50.0)
        assert "Suspicious" in badge.toolTip()

    def test_tooltip_clean(self) -> None:
        badge = ReputationBadge(score=95.0)
        assert "Clean" in badge.toolTip()
