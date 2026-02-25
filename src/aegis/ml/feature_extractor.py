"""Feature extraction from AegisEvent objects for ML model input.

Converts raw sensor events into numerical feature dictionaries suitable
for anomaly detection and classification models.  Each sensor type has a
dedicated extraction strategy; unrecognised sensors fall back to a
generic feature set.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Any

from aegis.core.models import AegisEvent, SensorType


class FeatureExtractor:
    """Extract numerical feature dictionaries from AegisEvent objects.

    Per-sensor extraction logic converts heterogeneous event data into a
    flat ``dict[str, float]`` that ML models can consume directly.
    """

    # ---- public API ------------------------------------------------

    def extract(self, event: AegisEvent) -> dict[str, float]:
        """Return a feature dictionary for a single event.

        Args:
            event: The AegisEvent to extract features from.

        Returns:
            A dictionary mapping feature names to float values.
        """
        handler = self._SENSOR_HANDLERS.get(event.sensor, _generic_features)
        features = handler(event)
        # Always include common features
        features.update(_common_features(event))
        return features

    def batch_extract(
        self, events: list[AegisEvent]
    ) -> list[dict[str, float]]:
        """Extract features for a batch of events.

        Args:
            events: A list of AegisEvent objects.

        Returns:
            A list of feature dictionaries, one per event.
        """
        return [self.extract(e) for e in events]

    # ---- private dispatch table ------------------------------------

    _SENSOR_HANDLERS: dict[
        SensorType,
        Any,  # Callable[[AegisEvent], dict[str, float]]
    ] = {}  # populated after helper definitions below


# ---- per-sensor helpers -------------------------------------------

_NETWORK_KEYS: list[str] = [
    "total_connections",
    "unique_remote_ips",
    "unique_remote_ports",
    "dns_query_count",
]


def _network_features(event: AegisEvent) -> dict[str, float]:
    """Extract features from NETWORK sensor events."""
    data = event.data
    return {
        key: float(data.get(key, 0))
        for key in _NETWORK_KEYS
    }


_PROCESS_NUMERIC_KEYS: list[str] = [
    "cpu_percent",
    "memory_mb",
    "num_threads",
]


def _process_features(event: AegisEvent) -> dict[str, float]:
    """Extract features from PROCESS sensor events."""
    data = event.data
    features: dict[str, float] = {
        key: float(data.get(key, 0))
        for key in _PROCESS_NUMERIC_KEYS
    }
    # Shannon entropy of the command line string
    cmdline: str = data.get("cmdline", "")
    features["cmdline_entropy"] = _shannon_entropy(cmdline)
    return features


_FILE_KEYS: list[str] = [
    "files_changed",
    "entropy_increase_rate",
]


def _file_features(event: AegisEvent) -> dict[str, float]:
    """Extract features from FILE sensor events."""
    data = event.data
    return {
        key: float(data.get(key, 0))
        for key in _FILE_KEYS
    }


def _generic_features(event: AegisEvent) -> dict[str, float]:
    """Fallback features for sensors without a dedicated handler."""
    return {
        "data_field_count": float(len(event.data)),
    }


# ---- common features (always appended) ----------------------------

def _common_features(event: AegisEvent) -> dict[str, float]:
    """Features appended to every extraction result."""
    return {
        "severity_ordinal": event.severity.weight,
        "timestamp": event.timestamp,
    }


# ---- utilities -----------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits) of a string.

    Returns 0.0 for empty strings.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return round(entropy, 4)


# ---- wire up dispatch table ---------------------------------------

FeatureExtractor._SENSOR_HANDLERS = {
    SensorType.NETWORK: _network_features,
    SensorType.PROCESS: _process_features,
    SensorType.FILE: _file_features,
}
