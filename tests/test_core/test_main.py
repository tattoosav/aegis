"""Tests for dual-mode entry point."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from aegis.__main__ import detect_run_mode, main


class TestRunModeDetection:
    """detect_run_mode returns the correct mode string."""

    def test_returns_gui_or_service(self) -> None:
        mode = detect_run_mode()
        assert mode in ("gui", "service", "headless")

    def test_cli_flag_service(self) -> None:
        with patch("sys.argv", ["aegis", "--service"]):
            assert detect_run_mode() == "service"

    def test_cli_flag_headless(self) -> None:
        with patch("sys.argv", ["aegis", "--headless"]):
            assert detect_run_mode() == "headless"

    def test_default_is_gui(self) -> None:
        with patch("sys.argv", ["aegis"]):
            assert detect_run_mode() == "gui"


class TestMainServiceMode:
    """main() in service mode delegates to AegisServiceFramework."""

    def test_service_mode_delegates(self) -> None:
        mock_framework = MagicMock()
        with (
            patch("sys.argv", ["aegis", "--service"]),
            patch(
                "aegis.core.service.AegisServiceFramework",
                return_value=mock_framework,
            ),
            patch("aegis.__main__._setup_logging"),
        ):
            result = main()
            mock_framework.start.assert_called_once()
            assert result == 0


class TestMainHeadlessMode:
    """main() in headless mode runs coordinator without UI."""

    def test_headless_starts_coordinator(self) -> None:
        mock_coordinator = MagicMock()
        mock_config = MagicMock()
        mock_stop_event = MagicMock()
        mock_stop_event.wait = MagicMock()
        with (
            patch("sys.argv", ["aegis", "--headless"]),
            patch("aegis.__main__._setup_logging"),
            patch(
                "aegis.__main__.AegisConfig.load",
                return_value=mock_config,
            ),
            patch(
                "aegis.__main__.AegisCoordinator",
                return_value=mock_coordinator,
            ),
            patch("aegis.__main__.signal.signal"),
            patch(
                "aegis.__main__.threading.Event",
                return_value=mock_stop_event,
            ),
        ):
            result = main()
            mock_coordinator.setup.assert_called_once()
            mock_coordinator.start.assert_called_once()
            mock_coordinator.stop.assert_called_once()
            assert result == 0


class TestMainGuiMode:
    """main() in gui mode launches UI (existing behaviour)."""

    def test_gui_mode_launches_ui(self) -> None:
        mock_coordinator = MagicMock()
        mock_config = MagicMock()
        mock_app = MagicMock()
        mock_app.run.return_value = 0
        with (
            patch("sys.argv", ["aegis"]),
            patch("aegis.__main__._setup_logging"),
            patch(
                "aegis.__main__.AegisConfig.load",
                return_value=mock_config,
            ),
            patch(
                "aegis.__main__.AegisCoordinator",
                return_value=mock_coordinator,
            ),
            patch(
                "aegis.ui.app.create_app",
                return_value=mock_app,
            ),
            patch("aegis.__main__.signal.signal"),
        ):
            result = main()
            mock_app.run.assert_called_once()
            mock_coordinator.stop.assert_called_once()
            assert result == 0
