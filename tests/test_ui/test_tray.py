"""Tests for Aegis system tray and app (non-GUI unit tests)."""

import pytest
from aegis.ui.tray import TrayState, AegisTrayManager


class TestTrayState:
    def test_all_states_defined(self):
        assert TrayState.ALL_CLEAR is not None
        assert TrayState.WARNING is not None
        assert TrayState.CRITICAL is not None
        assert TrayState.LEARNING is not None

    def test_state_has_tooltip(self):
        assert "clear" in TrayState.ALL_CLEAR.tooltip.lower()
        assert "alert" in TrayState.WARNING.tooltip.lower()
        assert "critical" in TrayState.CRITICAL.tooltip.lower()
        assert "learning" in TrayState.LEARNING.tooltip.lower()

    def test_state_has_color(self):
        assert TrayState.ALL_CLEAR.color == "green"
        assert TrayState.WARNING.color == "yellow"
        assert TrayState.CRITICAL.color == "red"
        assert TrayState.LEARNING.color == "grey"


class TestTrayManager:
    def test_initial_state_is_learning(self):
        manager = AegisTrayManager(headless=True)
        assert manager.state == TrayState.LEARNING

    def test_set_state(self):
        manager = AegisTrayManager(headless=True)
        manager.set_state(TrayState.ALL_CLEAR)
        assert manager.state == TrayState.ALL_CLEAR

    def test_set_state_to_critical(self):
        manager = AegisTrayManager(headless=True)
        manager.set_state(TrayState.CRITICAL)
        assert manager.state == TrayState.CRITICAL

    def test_sensor_status_tracking(self):
        manager = AegisTrayManager(headless=True)
        manager.update_sensor_status("network", running=True)
        manager.update_sensor_status("process", running=True)
        manager.update_sensor_status("fim", running=False)
        statuses = manager.sensor_statuses
        assert statuses["network"] is True
        assert statuses["process"] is True
        assert statuses["fim"] is False
