"""Tests for Windows Service -- Coordinator integration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from aegis.core.service import AegisServiceFramework

# ------------------------------------------------------------------ #
# Service metadata
# ------------------------------------------------------------------ #


class TestServiceMetadata:
    """Service name and display name."""

    def test_svc_name_is_aegis_defense(self) -> None:
        svc = AegisServiceFramework()
        assert svc._svc_name_ == "AegisDefense"

    def test_svc_display_name(self) -> None:
        svc = AegisServiceFramework()
        assert svc._svc_display_name_ == "Aegis Security Defense System"


# ------------------------------------------------------------------ #
# Coordinator integration
# ------------------------------------------------------------------ #


class TestServiceCoordinatorIntegration:
    """start/stop delegate to AegisCoordinator."""

    def test_start_creates_coordinator(self) -> None:
        svc = AegisServiceFramework()
        with patch("aegis.core.service.AegisCoordinator") as mock_coord:
            mock_instance = MagicMock()
            mock_coord.return_value = mock_instance
            svc._running = False  # prevent monitor loop
            svc.start()
            mock_coord.assert_called_once()
            mock_instance.setup.assert_called_once()
            mock_instance.start.assert_called_once()

    def test_stop_calls_coordinator_stop(self) -> None:
        svc = AegisServiceFramework()
        svc._coordinator = MagicMock()
        svc._running = True
        svc.stop()
        svc._coordinator.stop.assert_called_once()
        assert svc._running is False

    def test_event_log_on_start(self) -> None:
        svc = AegisServiceFramework()
        with patch("aegis.core.service.AegisCoordinator"):
            with patch("aegis.core.service.logger") as mock_log:
                svc._running = False
                svc.start()
                mock_log.info.assert_any_call("Aegis service starting")

    def test_event_log_on_stop(self) -> None:
        svc = AegisServiceFramework()
        svc._coordinator = MagicMock()
        svc._running = True
        with patch("aegis.core.service.logger") as mock_log:
            svc.stop()
            mock_log.info.assert_any_call("Aegis service stopping")


# ------------------------------------------------------------------ #
# Dual-mode detection
# ------------------------------------------------------------------ #


class TestDualMode:
    """Service mode detection."""

    def test_is_service_mode_exists(self) -> None:
        svc = AegisServiceFramework()
        result = svc._is_service_mode()
        assert isinstance(result, bool)


# ------------------------------------------------------------------ #
# Properties
# ------------------------------------------------------------------ #


class TestServiceProperties:
    """Read-only properties."""

    def test_running_initially_false(self) -> None:
        svc = AegisServiceFramework()
        assert svc.running is False

    def test_coordinator_initially_none(self) -> None:
        svc = AegisServiceFramework()
        assert svc.coordinator is None

    def test_coordinator_set_after_start(self) -> None:
        svc = AegisServiceFramework()
        with patch("aegis.core.service.AegisCoordinator") as mock_coord:
            mock_instance = MagicMock()
            mock_coord.return_value = mock_instance
            svc._running = False
            svc.start()
            assert svc.coordinator is mock_instance


# ------------------------------------------------------------------ #
# Error handling
# ------------------------------------------------------------------ #


class TestServiceErrorHandling:
    """Coordinator errors are logged, not raised."""

    def test_start_logs_coordinator_error(self) -> None:
        svc = AegisServiceFramework()
        with patch("aegis.core.service.AegisCoordinator") as mock_coord:
            mock_coord.side_effect = RuntimeError("boom")
            with patch("aegis.core.service.logger") as mock_log:
                svc._running = False
                svc.start()
                mock_log.exception.assert_called()

    def test_stop_logs_coordinator_error(self) -> None:
        svc = AegisServiceFramework()
        mock_c = MagicMock()
        mock_c.stop.side_effect = RuntimeError("boom")
        svc._coordinator = mock_c
        svc._running = True
        with patch("aegis.core.service.logger") as mock_log:
            svc.stop()
            mock_log.exception.assert_called()
            assert svc._running is False
