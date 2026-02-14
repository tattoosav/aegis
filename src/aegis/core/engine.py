"""Event Engine — the central coordinator of Aegis.

Responsibilities:
- Runs the ZeroMQ event bus
- Subscribes to all sensor events
- Stores events in the database
- Feeds events to detection engines (future)
- Maintains the context graph (future)
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from aegis.core.bus import EventBus, EventSubscriber
from aegis.core.config import AegisConfig
from aegis.core.database import AegisDatabase
from aegis.core.models import AegisEvent

logger = logging.getLogger(__name__)


class EventEngine:
    """Central coordinator that ties sensors, detection, and storage together."""

    def __init__(
        self,
        config: AegisConfig,
        pub_port: int = 15555,
        sub_port: int = 15556,
    ):
        self._config = config
        self._pub_port = pub_port
        self._sub_port = sub_port
        self._bus: EventBus | None = None
        self._subscriber: EventSubscriber | None = None
        self._db: AegisDatabase | None = None
        self._running = False
        self._events_processed = 0
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
        """Handle an incoming event from any sensor."""
        try:
            if self._db:
                self._db.insert_event(event)

            with self._lock:
                self._events_processed += 1

        except Exception as e:
            logger.error(f"Error processing event {event.event_id}: {e}")

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
