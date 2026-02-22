"""Entry point for Aegis — the AI Security Defense System.

Launches the full stack:
  1. Configuration
  2. Event Engine (ZeroMQ bus + database)
  3. Detection Pipeline (rule engine, anomaly, graph analyzer)
  4. Alert Manager + Forensic Logger
  5. PySide6 dashboard + system tray

Usage:
    python -m aegis
"""

from __future__ import annotations

import logging
import signal
import sys

from aegis import __version__


def _start_sensors(config, engine) -> list:
    """Start enabled sensors and connect to the event engine."""
    sensors = []

    # Process sensor (always enabled — core functionality)
    try:
        from aegis.sensors.process import ProcessSensor

        proc = ProcessSensor(
            interval=config.get("sensors.process.interval", 5.0),
            on_event=engine._on_event,
        )
        proc.start()
        sensors.append(proc)
        logger.info("Process sensor started")
    except Exception:
        logger.warning("Process sensor not available")

    # Network sensor
    if config.get("sensors.network.enabled", True):
        try:
            from aegis.sensors.network import NetworkSensor

            net = NetworkSensor(
                interval=config.get("sensors.network.interval", 10.0),
                on_event=engine._on_event,
            )
            net.start()
            sensors.append(net)
            logger.info("Network sensor started")
        except Exception:
            logger.warning("Network sensor not available")

    # File integrity sensor
    if config.get("sensors.fim.enabled", False):
        try:
            from aegis.sensors.file_integrity import FileIntegritySensor

            fim = FileIntegritySensor(
                interval=config.get("sensors.fim.interval", 30.0),
                on_event=engine._on_event,
            )
            fim.start()
            sensors.append(fim)
            logger.info("File integrity sensor started")
        except Exception:
            logger.warning("File integrity sensor not available")

    return sensors


logger = logging.getLogger("aegis")


def _setup_logging() -> None:
    """Configure logging with console and rotating file handler."""
    from logging.handlers import RotatingFileHandler
    from pathlib import Path

    log_dir = Path.home() / "AppData" / "Roaming" / "Aegis" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
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


def main() -> int:
    """Launch Aegis."""
    _setup_logging()
    logger.info("Aegis v%s starting...", __version__)

    # 1. Configuration — load from file if it exists
    from aegis.core.config import AegisConfig
    from pathlib import Path

    config_path = Path.home() / "AppData" / "Roaming" / "Aegis" / "config.yaml"
    config = AegisConfig.load(config_path)
    logger.info("Config loaded from %s", config_path)

    # 2. Detection Pipeline
    from aegis.detection.pipeline import DetectionPipeline

    pipeline_kwargs: dict = {}

    # Wire in available engines (graceful if any are missing)
    try:
        from aegis.detection.rule_engine import RuleEngine

        rule_engine = RuleEngine()
        rule_engine.load_builtin_rules()
        pipeline_kwargs["rule_engine"] = rule_engine
        logger.info("Rule engine loaded (%d rules)", rule_engine.rule_count)
    except Exception:
        logger.warning("Rule engine not available")

    try:
        from aegis.detection.anomaly import AnomalyDetector

        pipeline_kwargs["anomaly_detector"] = AnomalyDetector()
        logger.info("Anomaly detector loaded")
    except Exception:
        logger.warning("Anomaly detector not available")

    try:
        from aegis.detection.graph_analyzer import (
            ContextGraph,
            GraphAnalyzer,
        )

        graph = ContextGraph()
        pipeline_kwargs["graph_analyzer"] = GraphAnalyzer(graph=graph)
        logger.info("Graph analyzer loaded")
    except Exception:
        logger.warning("Graph analyzer not available")

    pipeline = DetectionPipeline(**pipeline_kwargs)

    # 3. Alert Manager + Forensic Logger
    from aegis.alerting.manager import AlertManager

    alert_manager = AlertManager()

    # 4. Event Engine
    from aegis.core.engine import EventEngine

    engine = EventEngine(
        config=config,
        detection_pipeline=pipeline,
        alert_manager=alert_manager,
    )
    engine.start()

    # Wire forensic logger after engine starts (needs db)
    forensic_logger = None
    if engine.db:
        from aegis.response.forensic_logger import ForensicLogger

        forensic_logger = ForensicLogger(engine.db)
        engine._forensic_logger = forensic_logger
        logger.info("Forensic logger attached")

    # Start sensors
    sensors = _start_sensors(config, engine)
    engine._active_sensors = sensors
    logger.info(
        "Engine started. sensors=%d active, pipeline=active",
        len(sensors),
    )

    # 5. Launch UI
    try:
        from aegis.ui.app import create_app

        app = create_app(db=engine.db, engine=engine)
        logger.info("UI ready — launching dashboard")

        # Wire action executor to alerts page
        try:
            from aegis.response.action_executor import ActionExecutor

            action_executor = ActionExecutor()
            alerts_page = app.window._stack.widget(1)  # AlertsPage is index 1
            if hasattr(alerts_page, "set_action_executor"):
                alerts_page.set_action_executor(
                    action_executor, forensic_logger
                )
                logger.info("Action executor wired to alerts page")
        except Exception as exc:
            logger.warning("Could not wire action executor: %s", exc)

        # Wire notification system
        try:
            from aegis.ui.notifications import NotificationManager
            from aegis.ui.widgets.fullscreen_alert import FullscreenAlert

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
            "Running in headless mode."
        )
        exit_code = 0
    finally:
        for s in sensors:
            try:
                s.stop()
            except Exception:
                pass
        engine.stop()
        logger.info("Aegis shutdown complete")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
