"""Tests for the headless tray manager and tray state."""

from aegis.ui.tray import AegisTrayManager, TrayState, STATUS_COLORS


class TestTrayState:
    def test_all_states_have_color(self):
        for state in TrayState:
            assert state.color in ("green", "yellow", "red", "grey")

    def test_all_states_have_tooltip(self):
        for state in TrayState:
            assert "Aegis" in state.tooltip

    def test_all_clear_state(self):
        assert TrayState.ALL_CLEAR.color == "green"

    def test_warning_state(self):
        assert TrayState.WARNING.color == "yellow"

    def test_critical_state(self):
        assert TrayState.CRITICAL.color == "red"

    def test_learning_state(self):
        assert TrayState.LEARNING.color == "grey"


class TestStatusColors:
    def test_has_four_statuses(self):
        assert len(STATUS_COLORS) == 4

    def test_clear_is_green(self):
        assert STATUS_COLORS["clear"] == "#2ecc71"

    def test_warning_is_yellow(self):
        assert STATUS_COLORS["warning"] == "#f39c12"

    def test_critical_is_red(self):
        assert STATUS_COLORS["critical"] == "#e74c3c"

    def test_learning_is_grey(self):
        assert STATUS_COLORS["learning"] == "#95a5a6"


class TestAegisTrayManager:
    def test_default_state_is_learning(self):
        mgr = AegisTrayManager(headless=True)
        assert mgr.state == TrayState.LEARNING

    def test_set_state(self):
        mgr = AegisTrayManager(headless=True)
        mgr.set_state(TrayState.ALL_CLEAR)
        assert mgr.state == TrayState.ALL_CLEAR

    def test_set_state_warning(self):
        mgr = AegisTrayManager(headless=True)
        mgr.set_state(TrayState.WARNING)
        assert mgr.state == TrayState.WARNING

    def test_set_state_critical(self):
        mgr = AegisTrayManager(headless=True)
        mgr.set_state(TrayState.CRITICAL)
        assert mgr.state == TrayState.CRITICAL

    def test_sensor_status_empty_by_default(self):
        mgr = AegisTrayManager(headless=True)
        assert mgr.sensor_statuses == {}

    def test_update_sensor_status(self):
        mgr = AegisTrayManager(headless=True)
        mgr.update_sensor_status("network", True)
        assert mgr.sensor_statuses["network"] is True

    def test_multiple_sensor_statuses(self):
        mgr = AegisTrayManager(headless=True)
        mgr.update_sensor_status("network", True)
        mgr.update_sensor_status("process", False)
        mgr.update_sensor_status("file", True)
        statuses = mgr.sensor_statuses
        assert statuses["network"] is True
        assert statuses["process"] is False
        assert statuses["file"] is True

    def test_sensor_status_update(self):
        mgr = AegisTrayManager(headless=True)
        mgr.update_sensor_status("network", False)
        assert mgr.sensor_statuses["network"] is False
        mgr.update_sensor_status("network", True)
        assert mgr.sensor_statuses["network"] is True

    def test_sensor_statuses_returns_copy(self):
        mgr = AegisTrayManager(headless=True)
        mgr.update_sensor_status("network", True)
        statuses = mgr.sensor_statuses
        statuses["network"] = False
        # Original should be unchanged
        assert mgr.sensor_statuses["network"] is True
