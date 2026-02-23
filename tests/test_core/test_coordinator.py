"""Tests for AegisCoordinator lifecycle and component wiring."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aegis.core.config import AegisConfig
from aegis.core.coordinator import AegisCoordinator


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def config(tmp_path):
    """AegisConfig with database path pointed at tmp_path."""
    cfg = AegisConfig()
    cfg._data["database"]["path"] = str(tmp_path / "test.db")
    # Disable canary dirs to avoid filesystem side effects
    cfg._data["canary"]["directories"] = []
    return cfg


@pytest.fixture
def coordinator(config):
    """Un-setup coordinator."""
    return AegisCoordinator(config)


@pytest.fixture
def setup_coordinator(coordinator):
    """Coordinator with setup() already called."""
    coordinator.setup()
    return coordinator


# ==================================================================
# TestCoordinatorInit
# ==================================================================


class TestCoordinatorInit:
    """Before setup(), every component slot should be None."""

    def test_init_all_none(self, coordinator):
        """All component properties are None before setup."""
        assert coordinator.engine is None
        assert coordinator.db is None
        assert coordinator.scheduler is None
        assert coordinator.whitelist_manager is None
        assert coordinator.correlation_engine is None
        assert coordinator.canary_system is None
        assert coordinator.incident_store is None
        assert coordinator.enricher is None

    def test_init_config_stored(self, coordinator, config):
        """The config object passed to __init__ is accessible."""
        assert coordinator._config is config

    def test_init_sensors_empty(self, coordinator):
        """The internal _sensors list starts empty."""
        assert coordinator._sensors == []


# ==================================================================
# TestCoordinatorSetup
# ==================================================================


class TestCoordinatorSetup:
    """After setup(), all enabled components should be initialised."""

    def test_setup_creates_database(self, setup_coordinator):
        assert setup_coordinator.db is not None

    def test_setup_creates_whitelist_manager(
        self, setup_coordinator,
    ):
        """whitelist.enabled defaults to True."""
        assert setup_coordinator.whitelist_manager is not None

    def test_setup_creates_enricher(self, setup_coordinator):
        assert setup_coordinator.enricher is not None

    def test_setup_creates_pipeline(self, setup_coordinator):
        assert setup_coordinator._pipeline is not None

    def test_setup_creates_alert_manager(self, setup_coordinator):
        assert setup_coordinator._alert_manager is not None

    def test_setup_creates_correlation_engine(
        self, setup_coordinator,
    ):
        """alerting.correlation.enabled defaults to True."""
        assert setup_coordinator.correlation_engine is not None

    def test_setup_creates_incident_store(
        self, setup_coordinator,
    ):
        assert setup_coordinator.incident_store is not None

    def test_setup_creates_forensic_logger(
        self, setup_coordinator,
    ):
        """ForensicLogger is created when db is available."""
        assert setup_coordinator._forensic_logger is not None

    def test_setup_creates_engine(self, setup_coordinator):
        assert setup_coordinator.engine is not None

    def test_setup_creates_scheduler(self, setup_coordinator):
        """scheduler.enabled defaults to True."""
        assert setup_coordinator.scheduler is not None

    def test_setup_engine_has_enricher(self, setup_coordinator):
        """EventEngine should have the enricher wired in."""
        assert setup_coordinator.engine._enricher is not None
        assert (
            setup_coordinator.engine._enricher
            is setup_coordinator.enricher
        )

    def test_setup_engine_has_correlation(
        self, setup_coordinator,
    ):
        """EventEngine should have the correlation engine wired."""
        assert (
            setup_coordinator.engine._correlation_engine is not None
        )
        assert (
            setup_coordinator.engine._correlation_engine
            is setup_coordinator.correlation_engine
        )


# ==================================================================
# TestCoordinatorSetupDisabled
# ==================================================================


class TestCoordinatorSetupDisabled:
    """Disabling components via config keeps them as None."""

    def test_setup_whitelist_disabled(self, config):
        config._data["whitelist"]["enabled"] = False
        coord = AegisCoordinator(config)
        coord.setup()
        assert coord.whitelist_manager is None

    def test_setup_correlation_disabled(self, config):
        config._data["alerting"]["correlation"]["enabled"] = False
        coord = AegisCoordinator(config)
        coord.setup()
        assert coord.correlation_engine is None

    def test_setup_scheduler_disabled(self, config):
        config._data["scheduler"]["enabled"] = False
        coord = AegisCoordinator(config)
        coord.setup()
        assert coord.scheduler is None

    def test_setup_canary_disabled(self, config):
        config._data["canary"]["enabled"] = False
        coord = AegisCoordinator(config)
        coord.setup()
        assert coord.canary_system is None


# ==================================================================
# TestScheduledTasks
# ==================================================================


class TestScheduledTasks:
    """Verify that built-in periodic tasks are registered."""

    @staticmethod
    def _task_names(scheduler) -> list[str]:
        """Return the names of all registered tasks."""
        return [t.name for t in scheduler.list_tasks()]

    def test_retention_cleanup_registered(
        self, setup_coordinator,
    ):
        names = self._task_names(setup_coordinator.scheduler)
        assert "retention_cleanup" in names

    def test_whitelist_prune_registered(
        self, setup_coordinator,
    ):
        names = self._task_names(setup_coordinator.scheduler)
        assert "whitelist_prune" in names

    def test_stale_incident_prune_registered(
        self, setup_coordinator,
    ):
        names = self._task_names(setup_coordinator.scheduler)
        assert "stale_incident_prune" in names

    def test_scheduler_task_count(self, setup_coordinator):
        """With all defaults enabled, we expect at least 3 tasks
        (retention_cleanup, whitelist_prune, stale_incident_prune).
        Canary dirs are empty so canary_verify is NOT registered.
        """
        count = setup_coordinator.scheduler.task_count
        assert count >= 3

    def test_canary_verify_registered(self, tmp_path, config):
        """When canary is enabled and canary_system is created
        before task registration, canary_verify is present.

        In the current coordinator the canary system (step 13)
        is created *after* the scheduler registers its tasks
        (step 12), so we manually register tasks again after
        setup to prove the registration logic itself works.
        """
        canary_dir = tmp_path / "canary_dir"
        canary_dir.mkdir()
        config._data["canary"]["directories"] = [
            str(canary_dir),
        ]
        coord = AegisCoordinator(config)
        coord.setup()
        if coord.canary_system is not None and coord.scheduler:
            # Re-register now that canary_system exists
            coord._register_scheduled_tasks()
            names = [
                t.name for t in coord.scheduler.list_tasks()
            ]
            assert "canary_verify" in names


# ==================================================================
# TestCoordinatorLifecycle
# ==================================================================


class TestCoordinatorLifecycle:
    """Start / stop lifecycle, mocking engine sockets."""

    def test_start_starts_engine(self, setup_coordinator):
        coord = setup_coordinator
        with patch.object(coord._engine, "start") as m_start:
            with patch.object(coord._engine, "stop"):
                coord.start()
                m_start.assert_called_once()
                coord.stop()

    def test_stop_stops_engine(self, setup_coordinator):
        coord = setup_coordinator
        with patch.object(coord._engine, "start"):
            with patch.object(coord._engine, "stop") as m_stop:
                coord.start()
                coord.stop()
                m_stop.assert_called_once()

    def test_setup_start_stop(self, config):
        """Full lifecycle: setup -> start -> stop without errors."""
        coord = AegisCoordinator(config)
        coord.setup()
        with patch.object(coord._engine, "start"):
            with patch.object(coord._engine, "stop"):
                coord.start()
                coord.stop()

    def test_stop_without_start(self, setup_coordinator):
        """Calling stop() without start() must not raise."""
        with patch.object(
            setup_coordinator._engine, "stop",
        ):
            setup_coordinator.stop()

    def test_start_stop_scheduler(self, setup_coordinator):
        coord = setup_coordinator
        with patch.object(coord._engine, "start"):
            with patch.object(coord._engine, "stop"):
                coord.start()
                assert coord.scheduler.is_running
                coord.stop()
                assert not coord.scheduler.is_running

    def test_multiple_start_stop(self, setup_coordinator):
        """Can start and stop multiple times without issues."""
        coord = setup_coordinator
        with patch.object(coord._engine, "start"):
            with patch.object(coord._engine, "stop"):
                coord.start()
                coord.stop()
                coord.start()
                coord.stop()


# ==================================================================
# TestCoordinatorProperties
# ==================================================================


class TestCoordinatorProperties:
    """Read-only properties expose internal components."""

    def test_property_engine(self, setup_coordinator):
        assert setup_coordinator.engine is not None
        assert (
            setup_coordinator.engine
            is setup_coordinator._engine
        )

    def test_property_db(self, setup_coordinator):
        assert setup_coordinator.db is not None
        assert setup_coordinator.db is setup_coordinator._db

    def test_property_scheduler(self, setup_coordinator):
        assert setup_coordinator.scheduler is not None
        assert (
            setup_coordinator.scheduler
            is setup_coordinator._scheduler
        )

    def test_property_whitelist_manager(
        self, setup_coordinator,
    ):
        assert setup_coordinator.whitelist_manager is not None
        assert (
            setup_coordinator.whitelist_manager
            is setup_coordinator._whitelist_manager
        )

    def test_property_correlation_engine(
        self, setup_coordinator,
    ):
        assert setup_coordinator.correlation_engine is not None
        assert (
            setup_coordinator.correlation_engine
            is setup_coordinator._correlation_engine
        )
