"""Tests for AegisServiceFramework — Windows Service wrapper."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from aegis.core.service import AegisServiceFramework

# ------------------------------------------------------------------ #
# Construction
# ------------------------------------------------------------------ #

class TestServiceInit:
    """Basic construction tests."""

    def test_creates(self) -> None:
        svc = AegisServiceFramework()
        assert svc is not None

    def test_not_running_initially(self) -> None:
        svc = AegisServiceFramework()
        assert svc.running is False

    def test_no_coordinator_initially(self) -> None:
        svc = AegisServiceFramework()
        assert svc.coordinator is None

    def test_service_name(self) -> None:
        assert AegisServiceFramework._svc_name_ == "AegisDefense"

    def test_svc_display_name(self) -> None:
        assert (
            AegisServiceFramework._svc_display_name_
            == "Aegis Security Defense System"
        )


# ------------------------------------------------------------------ #
# Coordinator integration
# ------------------------------------------------------------------ #

class TestServiceCoordinatorIntegration:
    """Tests for start/stop with AegisCoordinator."""

    @patch("aegis.core.service.AegisCoordinator")
    @patch("aegis.core.service.AegisConfig")
    def test_start_creates_coordinator(
        self,
        mock_config_cls: MagicMock,
        mock_coord_cls: MagicMock,
    ) -> None:
        mock_config_cls.load.return_value = MagicMock()
        mock_instance = MagicMock()
        mock_coord_cls.return_value = mock_instance

        svc = AegisServiceFramework()
        svc.start()

        mock_coord_cls.assert_called_once()
        mock_instance.setup.assert_called_once()
        mock_instance.start.assert_called_once()

    @patch("aegis.core.service.AegisCoordinator")
    @patch("aegis.core.service.AegisConfig")
    def test_event_log_on_start(
        self,
        mock_config_cls: MagicMock,
        mock_coord_cls: MagicMock,
    ) -> None:
        mock_config_cls.load.return_value = MagicMock()

        svc = AegisServiceFramework()
        with patch("aegis.core.service.logger") as mock_log:
            svc.start()
            mock_log.info.assert_any_call("Aegis service starting")

    @patch("aegis.core.service.AegisCoordinator")
    @patch("aegis.core.service.AegisConfig")
    def test_coordinator_set_after_start(
        self,
        mock_config_cls: MagicMock,
        mock_coord_cls: MagicMock,
    ) -> None:
        mock_config_cls.load.return_value = MagicMock()
        mock_instance = MagicMock()
        mock_coord_cls.return_value = mock_instance

        svc = AegisServiceFramework()
        svc.start()

        assert svc.coordinator is mock_instance
        assert svc.running is True

    def test_stop_calls_coordinator_stop(self) -> None:
        svc = AegisServiceFramework()
        svc._coordinator = MagicMock()
        svc._running = True

        svc.stop()

        svc._coordinator.stop.assert_called_once()
        assert svc.running is False

    def test_stop_without_coordinator(self) -> None:
        svc = AegisServiceFramework()
        svc._running = True
        svc.stop()
        assert svc.running is False


# ------------------------------------------------------------------ #
# Mode detection
# ------------------------------------------------------------------ #

class TestModeDetection:
    """Tests for _is_service_mode."""

    def test_is_service_mode_returns_bool(self) -> None:
        svc = AegisServiceFramework()
        result = svc._is_service_mode()
        assert isinstance(result, bool)
