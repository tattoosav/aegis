"""Sensor health tracking for Aegis.

Provides a dataclass to track per-sensor runtime health metrics
including event rates, error counts, and restart history.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from aegis.core.models import SensorType


@dataclass
class SensorHealth:
    """Runtime health metrics for a single sensor."""

    sensor_name: str
    sensor_type: SensorType
    is_running: bool = False
    enabled: bool = True
    events_emitted: int = 0
    errors: int = 0
    consecutive_errors: int = 0
    last_event_time: float | None = None
    last_error_time: float | None = None
    last_error_message: str = ""
    last_collect_duration: float = 0.0
    started_at: float | None = None
    restarts: int = 0

    @property
    def events_per_second(self) -> float:
        """Approximate events per second since start."""
        if self.started_at is None or self.events_emitted == 0:
            return 0.0
        elapsed = time.time() - self.started_at
        if elapsed <= 0:
            return 0.0
        return self.events_emitted / elapsed

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for dashboard consumption."""
        return {
            "sensor_name": self.sensor_name,
            "sensor_type": self.sensor_type.value,
            "is_running": self.is_running,
            "enabled": self.enabled,
            "events_emitted": self.events_emitted,
            "errors": self.errors,
            "consecutive_errors": self.consecutive_errors,
            "last_event_time": self.last_event_time,
            "last_error_time": self.last_error_time,
            "last_error_message": self.last_error_message,
            "last_collect_duration": self.last_collect_duration,
            "started_at": self.started_at,
            "restarts": self.restarts,
            "events_per_second": self.events_per_second,
        }
