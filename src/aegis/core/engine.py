"""Event Engine — the central coordinator of Aegis.

Responsibilities:
- Runs the ZeroMQ event bus
- Subscribes to all sensor events
- Stores events in the database
- Feeds events to the detection pipeline
- Routes alerts through the alert manager
- Logs to the forensic audit trail
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegis.core.bus import EventBus, EventSubscriber
from aegis.core.config import AegisConfig
from aegis.core.database import AegisDatabase
from aegis.core.models import AegisEvent

if TYPE_CHECKING:
    from aegis.alerting.manager import AlertManager
    from aegis.detection.pipeline import DetectionPipeline
    from aegis.response.forensic_logger import ForensicLogger

logger = logging.getLogger(__name__)


class EventEngine:
    """Central coordinator that ties sensors, detection, and storage together.

    Parameters
    ----------
    config:
        Application configuration.
    pub_port, sub_port:
        ZeroMQ ports for the event bus.
    detection_pipeline:
        Optional :class:`DetectionPipeline` to process each event.
    alert_manager:
        Optional :class:`AlertManager` for scoring and deduplication.
    forensic_logger:
        Optional :class:`ForensicLogger` for the immutable audit trail.
    """

    def __init__(
        self,
        config: AegisConfig,
        pub_port: int = 15555,
        sub_port: int = 15556,
        detection_pipeline: DetectionPipeline | None = None,
        alert_manager: AlertManager | None = None,
        forensic_logger: ForensicLogger | None = None,
    ) -> None:
        self._config = config
        self._pub_port = pub_port
        self._sub_port = sub_port
        self._detection_pipeline = detection_pipeline
        self._alert_manager = alert_manager
        self._forensic_logger = forensic_logger
        self._bus: EventBus | None = None
        self._subscriber: EventSubscriber | None = None
        self._db: AegisDatabase | None = None
        self._running = False
        self._events_processed = 0
        self._alerts_generated = 0
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def db(self) -> AegisDatabase | None:
        return self._db

    @property
    def events_processed(self) -> int:
        with self._lock:
            return self._events_processed

    @property
    def alerts_generated(self) -> int:
        """Number of alerts that passed dedup and were stored."""
        with self._lock:
            return self._alerts_generated

    def start(self) -> None:
        """Start the event engine, bus, and database."""
        logger.info("EventEngine starting...")

        # Initialize database
        db_path = self._config.get("database.path", "aegis.db")
        db_path = str(db_path).replace(
            "%APPDATA%", str(Path.home() / "AppData" / "Roaming")
        )
        self._db = AegisDatabase(db_path)
        self._db.audit("engine", "starting", "Event Engine initializing")

        # Start message bus
        self._bus = EventBus(pub_port=self._pub_port, sub_port=self._sub_port)
        self._bus.start()

        # Subscribe to all sensor events
        self._subscriber = EventSubscriber(
            port=self._sub_port,
            topics=["sensor."],
            callback=self._on_event,
        )
        self._subscriber.start()

        self._running = True
        self._db.audit("engine", "started", "Event Engine ready")
        logger.info("EventEngine started")

    def _on_event(self, event: AegisEvent) -> None:
        """Handle an incoming event from any sensor.

        Flow:
          1. Store event in DB
          2. Feed to detection pipeline → list of alerts
          3. Each alert → alert manager (dedup/scoring)
          4. Surviving alerts → DB + forensic log
        """
        try:
            # 1. Persist event
            if self._db:
                self._db.insert_event(event)

            # 2. Feed to detection pipeline
            if self._detection_pipeline:
                try:
                    alerts = self._detection_pipeline.process_event(event)
                except Exception as exc:
                    logger.error(
                        "Detection pipeline error for %s: %s",
                        event.event_id, exc,
                    )
                    alerts = []

                for alert in alerts:
                    self._process_alert(alert)

            with self._lock:
                self._events_processed += 1

        except Exception as e:
            logger.error(f"Error processing event {event.event_id}: {e}")

    def _process_alert(self, alert: Any) -> None:
        """Route a single alert through dedup → DB → forensic log."""
        try:
            # 3. Deduplication + scoring
            processed = alert
            if self._alert_manager:
                processed = self._alert_manager.process_alert(alert)
                if processed is None:
                    return  # suppressed by dedup

            # 4a. Persist alert to database
            if self._db:
                try:
                    self._db.insert_alert(processed)
                except Exception as exc:
                    logger.error("Failed to store alert: %s", exc)

            # 4b. Forensic log
            if self._forensic_logger:
                try:
                    self._forensic_logger.log_alert(
                        alert_id=processed.alert_id,
                        alert_type=processed.alert_type,
                        severity=processed.severity.value,
                        title=processed.title,
                        confidence=processed.confidence,
                        sensor=processed.sensor.value,
                        mitre_ids=processed.mitre_ids,
                    )
                except Exception as exc:
                    logger.error("Forensic log error: %s", exc)

            with self._lock:
                self._alerts_generated += 1

        except Exception as exc:
            logger.error("Failed to process alert: %s", exc)

    def stop(self) -> None:
        """Stop the event engine cleanly."""
        logger.info("EventEngine stopping...")
        self._running = False

        if self._subscriber:
            self._subscriber.stop()
        if self._bus:
            self._bus.stop()
        if self._db:
            self._db.audit("engine", "stopped", "Event Engine shutdown")
            self._db.close()

        logger.info("EventEngine stopped")
