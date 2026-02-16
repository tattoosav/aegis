"""Tests for AlertCard widget."""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from aegis.ui.widgets.alert_card import AlertCard  # noqa: E402

_app = QApplication.instance() or QApplication([])


class TestAlertCardInit:
    """Construction and basic property tests."""

    def test_creates_with_required_fields(self) -> None:
        card = AlertCard(
            alert_id="alt-001",
            title="Suspicious connection",
            severity="high",
            confidence=0.85,
        )
        assert card is not None

    def test_alert_id_property(self) -> None:
        card = AlertCard("alt-002", "T", "medium", 0.5)
        assert card.alert_id == "alt-002"

    def test_with_mitre_ids(self) -> None:
        card = AlertCard(
            alert_id="alt-003",
            title="Test",
            severity="critical",
            confidence=0.9,
            mitre_ids=["T1059", "T1071"],
        )
        assert card is not None

    def test_with_description(self) -> None:
        card = AlertCard(
            alert_id="alt-004",
            title="Test",
            severity="low",
            confidence=0.3,
            description="Detailed description here",
        )
        assert card is not None


class TestAlertCardSignals:
    """Signal emission tests."""

    def test_investigate_signal(self, qtbot=None) -> None:
        card = AlertCard("alt-010", "T", "high", 0.8)
        received = []
        card.investigate_clicked.connect(received.append)
        card.investigate_clicked.emit("alt-010")
        assert received == ["alt-010"]

    def test_dismiss_signal(self) -> None:
        card = AlertCard("alt-011", "T", "high", 0.8)
        received = []
        card.dismiss_clicked.connect(received.append)
        card.dismiss_clicked.emit("alt-011")
        assert received == ["alt-011"]

    def test_execute_action_signal(self) -> None:
        card = AlertCard("alt-012", "T", "high", 0.8)
        received = []
        card.execute_action_clicked.connect(
            lambda aid, atype: received.append((aid, atype))
        )
        card.execute_action_clicked.emit("alt-012", "block_ip")
        assert received == [("alt-012", "block_ip")]


class TestSeverityColors:
    """Test that different severity levels don't crash."""

    @pytest.mark.parametrize("sev", [
        "critical", "high", "medium", "low", "info", "unknown",
    ])
    def test_severity_level(self, sev: str) -> None:
        card = AlertCard("a", "T", sev, 0.5)
        assert card is not None
