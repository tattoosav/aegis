"""Abstract base class for all Aegis sensor modules.

Each sensor runs in its own thread (or process), collects data at a
configured interval, and emits AegisEvent objects via a callback.
"""

from __future__ import annotations

import abc
import logging
import threading
import time
from typing import Callable

from aegis.core.models import AegisEvent, SensorType

logger = logging.getLogger(__name__)


class BaseSensor(abc.ABC):
    """Abstract base class for sensor modules.

    Subclasses must implement:
      - sensor_type: SensorType class variable
      - sensor_name: human-readable name
      - setup(): one-time initialization
      - collect(): called every interval, returns list of events
      - teardown(): cleanup on stop
    """

    sensor_type: SensorType
    sensor_name: str

    def __init__(
        self,
        interval: float = 5.0,
        on_event: Callable[[AegisEvent], None] | None = None,
    ):
        self._interval = interval
        self._on_event = on_event
        self._running = False
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    @abc.abstractmethod
    def setup(self) -> None:
        """One-time initialization. Called before first collect()."""

    @abc.abstractmethod
    def collect(self) -> list[AegisEvent]:
        """Collect data and return events. Called every interval."""

    @abc.abstractmethod
    def teardown(self) -> None:
        """Cleanup resources. Called on stop."""

    def start(self) -> None:
        """Start the sensor collection loop in a background thread."""
        if self._running:
            return
        logger.info(f"Sensor '{self.sensor_name}' starting (interval={self._interval}s)")
        self._running = True
        self.setup()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self) -> None:
        while self._running:
            try:
                events = self.collect()
                for event in events:
                    if self._on_event:
                        self._on_event(event)
            except Exception as e:
                logger.error(f"Sensor '{self.sensor_name}' error in collect(): {e}")
            time.sleep(self._interval)

    def stop(self) -> None:
        """Stop the sensor."""
        logger.info(f"Sensor '{self.sensor_name}' stopping")
        self._running = False
        if self._thread:
            self._thread.join(timeout=self._interval + 2)
        self.teardown()
