"""Windows Service wrapper for Aegis.

Runs Aegis as a Windows Service via ``pywin32``.  The service launches
and monitors child sensor/engine processes, restarting them if they
crash.  All ``pywin32`` calls are accessed through module-level
attributes to facilitate mocking in tests.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from typing import Any

logger = logging.getLogger(__name__)

# Monitoring interval (seconds)
CHECK_INTERVAL = 5

# Child process definitions: name -> module path
_CHILD_PROCESSES: dict[str, str] = {
    "event_engine": "aegis.core.engine",
    "network_sensor": "aegis.sensors.network",
    "process_sensor": "aegis.sensors.process_monitor",
    "file_sensor": "aegis.sensors.file_integrity",
    "eventlog_sensor": "aegis.sensors.eventlog",
}


class AegisServiceFramework:
    """A service framework that manages Aegis child processes.

    On real deployments this subclasses
    ``win32serviceutil.ServiceFramework``.  For testability the class
    is kept independent of ``pywin32`` imports — the actual Windows
    service entry point calls :meth:`start` and :meth:`stop`.
    """

    _svc_name_ = "AegisSecurity"
    _svc_display_name_ = "Aegis AI Security Defense"
    _svc_description_ = (
        "Autonomous AI-powered security defense system for Windows."
    )

    def __init__(self) -> None:
        self._running = False
        self._children: dict[str, subprocess.Popen[bytes]] = {}

    # ------------------------------------------------------------------ #
    # Service lifecycle
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        """Start the service: launch all children and enter monitor loop."""
        logger.info("Aegis service starting")
        self._running = True
        self._launch_all()
        self._monitor_loop()

    def stop(self) -> None:
        """Signal the service to stop and terminate all children."""
        logger.info("Aegis service stopping")
        self._running = False
        self._terminate_all()

    # ------------------------------------------------------------------ #
    # Child process management
    # ------------------------------------------------------------------ #

    def _launch_all(self) -> None:
        """Launch every configured child process."""
        for name, module in _CHILD_PROCESSES.items():
            self._launch_child(name, module)

    def _launch_child(self, name: str, module: str) -> None:
        """Launch a single child process."""
        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", module],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._children[name] = proc
            logger.info(
                "Launched %s (PID %d)", name, proc.pid,
            )
        except Exception:
            logger.exception("Failed to launch %s", name)

    def _monitor_loop(self) -> None:
        """Check child processes periodically, restarting crashed ones."""
        while self._running:
            for name, module in _CHILD_PROCESSES.items():
                proc = self._children.get(name)
                if proc is None or proc.poll() is not None:
                    logger.warning(
                        "Child %s exited, restarting", name,
                    )
                    self._launch_child(name, module)
            time.sleep(CHECK_INTERVAL)

    def _terminate_all(self) -> None:
        """Terminate all child processes."""
        for name, proc in self._children.items():
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                    logger.info("Terminated %s", name)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    logger.warning(
                        "Force-killed %s", name,
                    )
                except Exception:
                    logger.exception(
                        "Error terminating %s", name,
                    )
        self._children.clear()

    @property
    def running(self) -> bool:
        """Whether the service is running."""
        return self._running

    @property
    def children(self) -> dict[str, Any]:
        """Child processes keyed by name."""
        return dict(self._children)


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
            exeArgs='-m aegis.core.service',
        )
        logger.info("Service installed successfully")
    except ImportError:
        logger.error(
            "pywin32 not installed — cannot install service"
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
            "pywin32 not installed — cannot uninstall service"
        )
    except Exception:
        logger.exception("Failed to uninstall service")
