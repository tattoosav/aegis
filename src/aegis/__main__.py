"""Entry point for Aegis — the AI Security Defense System.

Supports three run modes via CLI flags:

  * **gui** (default): full PySide6 dashboard + system tray
  * **service** (``--service``): delegates to :class:`AegisServiceFramework`
  * **headless** (``--headless``): coordinator only, no UI

Usage::

    python -m aegis              # GUI mode
    python -m aegis --service    # Windows service mode
    python -m aegis --headless   # headless / coordinator-only mode
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

from aegis import __version__
from aegis.core.config import AegisConfig
from aegis.core.coordinator import AegisCoordinator

logger = logging.getLogger("aegis")


# ------------------------------------------------------------------
# Logging setup
# ------------------------------------------------------------------

def _setup_logging() -> None:
    """Configure logging with console and rotating file handler."""
    root_logger = logging.getLogger()
    if root_logger.handlers:
        return  # Already configured

    log_dir = Path.home() / "AppData" / "Roaming" / "Aegis" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    root_logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root_logger.addHandler(console)

    # Rotating file handler (10 MB, keep 5)
    file_handler = RotatingFileHandler(
        log_dir / "aegis.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    root_logger.addHandler(file_handler)


# ------------------------------------------------------------------
# Mode detection
# ------------------------------------------------------------------

def detect_run_mode() -> str:
    """Determine the run mode from CLI flags.

    Returns:
        ``"service"`` if ``--service`` is present,
        ``"headless"`` if ``--headless`` is present,
        ``"gui"`` otherwise.
    """
    if "--service" in sys.argv:
        return "service"
    if "--headless" in sys.argv:
        return "headless"
    return "gui"


# ------------------------------------------------------------------
# Mode-specific launchers
# ------------------------------------------------------------------

def _run_service() -> int:
    """Run Aegis as a Windows service via :class:`AegisServiceFramework`."""
    from aegis.core.service import AegisServiceFramework

    framework = AegisServiceFramework()
    framework.start()
    return 0


def _run_headless(config: AegisConfig) -> int:
    """Run Aegis in headless mode (coordinator only, no UI).

    Blocks on a ``threading.Event`` until SIGINT / SIGTERM is received.
    """
    coordinator = AegisCoordinator(config)
    coordinator.setup()
    coordinator.start()
    try:
        stop_event = threading.Event()

        def _signal_handler(*_args: object) -> None:
            logger.info("Shutdown signal received")
            stop_event.set()

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        logger.info("Aegis running in headless mode (Ctrl-C to stop)")
        stop_event.wait()
    finally:
        coordinator.stop()
        logger.info("Aegis headless shutdown complete")
    return 0


def _run_gui(config: AegisConfig) -> int:
    """Run Aegis with the full PySide6 dashboard."""
    coordinator = AegisCoordinator(config)
    coordinator.setup()
    coordinator.start()

    engine = coordinator.engine

    exit_code = 1  # default; overwritten on success
    try:
        from aegis.ui.app import create_app

        app = create_app(db=coordinator.db, engine=engine)
        logger.info("UI ready — launching dashboard")

        # Wire action executor to alerts page
        try:
            from aegis.response.action_executor import ActionExecutor

            action_executor = ActionExecutor()
            alerts_page = app.window._stack.widget(1)
            if hasattr(alerts_page, "set_action_executor"):
                alerts_page.set_action_executor(
                    action_executor, coordinator.forensic_logger,
                )
                logger.info("Action executor wired to alerts page")
        except Exception as exc:
            logger.warning("Could not wire action executor: %s", exc)

        # Wire notification system
        try:
            from aegis.ui.notifications import NotificationManager
            from aegis.ui.widgets.fullscreen_alert import (
                FullscreenAlert,
            )

            fullscreen_widget = FullscreenAlert(parent=app.window)
            notification_manager = NotificationManager(
                tray=app.tray,
                on_fullscreen=fullscreen_widget.show_alert,
            )
            engine._notification_manager = notification_manager
            logger.info("Notification system wired")
        except Exception as exc:
            logger.warning("Could not wire notifications: %s", exc)

        # Graceful shutdown on Ctrl-C
        signal.signal(
            signal.SIGINT,
            lambda *_: app.qt_app.quit(),
        )

        exit_code = app.run()
    except ImportError:
        logger.error(
            "PySide6 not installed — cannot launch UI. "
            "Running in headless mode.",
        )
        exit_code = 0
    finally:
        coordinator.stop()
        logger.info("Aegis shutdown complete")

    return exit_code


# ------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------

def main() -> int:
    """Launch Aegis in the detected run mode."""
    _setup_logging()
    mode = detect_run_mode()
    logger.info("Aegis v%s starting in %s mode...", __version__, mode)

    if mode == "service":
        return _run_service()

    config_path = (
        Path.home() / "AppData" / "Roaming" / "Aegis" / "config.yaml"
    )
    config = AegisConfig.load(config_path)
    logger.info("Config loaded from %s", config_path)

    if mode == "headless":
        return _run_headless(config)

    return _run_gui(config)


if __name__ == "__main__":
    sys.exit(main())
