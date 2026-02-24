"""Windows Service wrapper for Aegis.

Runs Aegis as a Windows Service via ``pywin32``.  The service creates
an :class:`AegisCoordinator` that manages all subsystems (database,
detection, alerting, response, scheduler, sensors) within a single
process.  All ``pywin32`` calls are accessed through module-level
attributes to facilitate mocking in tests.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from aegis.core.config import AegisConfig
from aegis.core.coordinator import AegisCoordinator

logger = logging.getLogger(__name__)

# Default config path
_DEFAULT_CONFIG_PATH = (
    Path.home() / "AppData" / "Roaming" / "Aegis" / "config.yaml"
)


class AegisServiceFramework:
    """Service framework that delegates to :class:`AegisCoordinator`.

    On real deployments this subclasses
    ``win32serviceutil.ServiceFramework``.  For testability the class
    is kept independent of ``pywin32`` imports -- the actual Windows
    service entry point calls :meth:`start` and :meth:`stop`.
    """

    _svc_name_ = "AegisDefense"
    _svc_display_name_ = "Aegis Security Defense System"
    _svc_description_ = (
        "Autonomous AI-powered security defense system for Windows."
    )

    def __init__(self) -> None:
        self._running = False
        self._coordinator: AegisCoordinator | None = None

    # -------------------------------------------------------------- #
    # Service lifecycle
    # -------------------------------------------------------------- #

    def start(self) -> None:
        """Start the service: create coordinator, setup, and start."""
        logger.info("Aegis service starting")
        try:
            config = AegisConfig.load(_DEFAULT_CONFIG_PATH)
            self._coordinator = AegisCoordinator(config)
            self._coordinator.setup()
            self._coordinator.start()
            self._running = True
            logger.info("Aegis service started successfully")
        except Exception:
            logger.exception("Aegis service failed to start")

    def stop(self) -> None:
        """Signal the service to stop and shut down the coordinator."""
        logger.info("Aegis service stopping")
        self._running = False
        if self._coordinator is not None:
            try:
                self._coordinator.stop()
                logger.info("Aegis service stopped successfully")
            except Exception:
                logger.exception(
                    "Error during coordinator shutdown"
                )

    # -------------------------------------------------------------- #
    # Mode detection
    # -------------------------------------------------------------- #

    def _is_service_mode(self) -> bool:
        """Return ``True`` when running as a Windows service.

        Heuristic: if there is no console window attached we are
        likely running headless as a service.
        """
        try:
            return os.getenv("AEGIS_SERVICE") == "1" or not sys.stdin.isatty()
        except Exception:
            return True

    # -------------------------------------------------------------- #
    # Read-only properties
    # -------------------------------------------------------------- #

    @property
    def running(self) -> bool:
        """Whether the service is running."""
        return self._running

    @property
    def coordinator(self) -> AegisCoordinator | None:
        """The :class:`AegisCoordinator`, or ``None``."""
        return self._coordinator


# ------------------------------------------------------------------ #
# Service install / uninstall helpers
# ------------------------------------------------------------------ #


def install_service() -> None:
    """Install the Aegis Windows service (requires admin)."""
    try:
        import win32serviceutil
        win32serviceutil.InstallService(
            None,
            AegisServiceFramework._svc_name_,
            AegisServiceFramework._svc_display_name_,
            description=AegisServiceFramework._svc_description_,
            startType=2,  # SERVICE_AUTO_START
            exeName=sys.executable,
            exeArgs="-m aegis.core.service",
        )
        logger.info("Service installed successfully")
    except ImportError:
        logger.error(
            "pywin32 not installed -- cannot install service",
        )
    except Exception:
        logger.exception("Failed to install service")


def uninstall_service() -> None:
    """Uninstall the Aegis Windows service."""
    try:
        import win32serviceutil
        win32serviceutil.RemoveService(
            AegisServiceFramework._svc_name_,
        )
        logger.info("Service uninstalled successfully")
    except ImportError:
        logger.error(
            "pywin32 not installed -- cannot uninstall service",
        )
    except Exception:
        logger.exception("Failed to uninstall service")
