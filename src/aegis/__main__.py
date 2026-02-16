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


def main() -> int:
    """Launch Aegis."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logger = logging.getLogger("aegis")
    logger.info("Aegis v%s starting...", __version__)

    # 1. Configuration
    from aegis.core.config import AegisConfig

    config = AegisConfig()

    # 2. Detection Pipeline
    from aegis.detection.pipeline import DetectionPipeline

    pipeline_kwargs: dict = {}

    # Wire in available engines (graceful if any are missing)
    try:
        from aegis.detection.rule_engine import RuleEngine

        pipeline_kwargs["rule_engine"] = RuleEngine()
        logger.info("Rule engine loaded")
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

    logger.info(
        "Engine started. sensors=%s, pipeline=%s",
        config.get("sensors.network.enabled"),
        "active",
    )

    # 5. Launch UI
    try:
        from aegis.ui.app import create_app

        app = create_app(db=engine.db, engine=engine)
        logger.info("UI ready — launching dashboard")

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
        engine.stop()
        logger.info("Aegis shutdown complete")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
