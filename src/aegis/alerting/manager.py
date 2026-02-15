"""Alert Manager — scoring, deduplication, and notification routing.

Implements the alert processing pipeline:
  1. Deduplication — same alert type within 60s is merged
  2. Scoring — apply priority formula
  3. Routing — direct to appropriate notification channel

Priority formula:
  score = (base_severity × engine_confidence × context_multiplier
           × threat_intel_multiplier ÷ user_familiarity_dampener) × 100

Routing:
  Critical (80-100): Full-screen alert + sound
  High (60-79): Toast notification + tray flash
  Medium (30-59): Tray icon change + log entry
  Low (0-29): Log entry only, in daily digest
"""

from __future__ import annotations

import logging
import time
import threading
from typing import Any

from aegis.core.models import Alert, AlertStatus, SensorType, Severity

logger = logging.getLogger(__name__)

# Deduplication window in seconds
DEDUP_WINDOW_SECONDS = 60.0

# Severity weight mapping
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.2,
    Severity.INFO: 0.05,
}


class AlertManager:
    """Central alert processing — scoring, dedup, routing.

    Thread-safe: can be called from multiple detection engine threads.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._alert_history: list[Alert] = []
        # Dedup tracking: key -> (last_seen_time, count)
        self._dedup_tracker: dict[str, tuple[float, int]] = {}

    @property
    def alert_history(self) -> list[Alert]:
        """Read-only copy of alert history."""
        with self._lock:
            return list(self._alert_history)

    def compute_priority(
        self,
        base_severity: Severity,
        engine_confidence: float,
        context_multiplier: float = 1.0,
        threat_intel_multiplier: float = 1.0,
        user_familiarity_dampener: float = 1.0,
    ) -> float:
        """Compute alert priority score (0-100).

        Formula: (base × confidence × context × threat_intel / dampener) × 100
        Clamped to [0, 100].
        """
        base = SEVERITY_WEIGHTS.get(base_severity, 0.1)
        raw = (
            base
            * engine_confidence
            * context_multiplier
            * threat_intel_multiplier
            / max(user_familiarity_dampener, 0.01)  # Prevent division by zero
        ) * 100.0

        return min(100.0, max(0.0, round(raw, 2)))

    def _dedup_key(self, alert: Alert) -> str:
        """Generate deduplication key for an alert."""
        return f"{alert.sensor.value}:{alert.alert_type}"

    def dedup_count(self, key: str) -> int:
        """Get the deduplication count for a key."""
        with self._lock:
            entry = self._dedup_tracker.get(key)
            return entry[1] if entry else 0

    def process_alert(self, alert: Alert) -> Alert | None:
        """Process an alert through the pipeline.

        Steps:
          1. Deduplication check
          2. Score computation
          3. Store in history

        Returns:
            The alert if it passed dedup, or None if suppressed.
        """
        with self._lock:
            key = self._dedup_key(alert)
            now = time.time()

            # Deduplication check
            if key in self._dedup_tracker:
                last_time, count = self._dedup_tracker[key]
                if now - last_time < DEDUP_WINDOW_SECONDS:
                    # Duplicate within window — suppress
                    self._dedup_tracker[key] = (now, count + 1)
                    logger.debug(
                        f"Alert dedup: {key} suppressed (count={count + 1})"
                    )
                    return None

            # Not a duplicate — process
            self._dedup_tracker[key] = (now, 1)
            self._alert_history.append(alert)

            logger.info(
                f"Alert processed: [{alert.severity.value}] {alert.title} "
                f"(priority={alert.priority_score:.1f})"
            )
            return alert

    def create_alert(
        self,
        event_id: str,
        sensor: SensorType,
        alert_type: str,
        severity: Severity,
        title: str,
        description: str,
        confidence: float,
        mitre_ids: list[str] | None = None,
        recommended_actions: list[str] | None = None,
        data: dict[str, Any] | None = None,
        context_multiplier: float = 1.0,
        threat_intel_multiplier: float = 1.0,
    ) -> Alert:
        """Create a fully scored Alert from detection engine output."""
        priority = self.compute_priority(
            base_severity=severity,
            engine_confidence=confidence,
            context_multiplier=context_multiplier,
            threat_intel_multiplier=threat_intel_multiplier,
        )

        alert = Alert(
            event_id=event_id,
            sensor=sensor,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            confidence=confidence,
            data=data or {},
            mitre_ids=mitre_ids or [],
            recommended_actions=recommended_actions or [],
        )
        # Override the auto-computed priority with our formula
        # Alert.priority_score is a property, so we store in data
        alert.data["_computed_priority"] = priority

        return alert

    @staticmethod
    def route_priority(score: float) -> str:
        """Determine notification channel based on priority score.

        Returns:
            "fullscreen" (80-100), "toast" (60-79), "tray" (30-59), "log" (0-29)
        """
        if score >= 80:
            return "fullscreen"
        elif score >= 60:
            return "toast"
        elif score >= 30:
            return "tray"
        else:
            return "log"

    def clear_history(self) -> None:
        """Clear alert history and dedup tracker."""
        with self._lock:
            self._alert_history.clear()
            self._dedup_tracker.clear()
