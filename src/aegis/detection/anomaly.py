"""Isolation Forest anomaly detection engine.

One model per sensor domain (network, process, file, log).
Trained during baseline period on user's normal behavior.
Outputs anomaly score 0.0 (normal) to 1.0 (extreme outlier).

Routing:
  Score < 0.4  → Normal (log and dismiss)
  Score 0.4-0.6 → Suspicious (elevated priority)
  Score > 0.6  → Anomalous (forward to deeper analysis)
"""

from __future__ import annotations

import logging

import numpy as np
from sklearn.ensemble import IsolationForest

from aegis.core.models import AegisEvent

logger = logging.getLogger(__name__)

# Feature definitions per domain — which event data fields to extract
DOMAIN_FEATURES: dict[str, list[str]] = {
    "network": [
        "total_connections",
        "unique_remote_ips",
        "unique_remote_ports",
        "port_entropy",
        "new_destination_rate",
        "dns_query_count",
    ],
    "process": [
        "cpu_percent",
        "memory_mb",
        "num_threads",
        "cmdline_entropy",
        "lineage_depth",
        "num_connections",
        "num_open_files",
    ],
    "file": [
        "files_changed_per_minute",
        "entropy_increase_rate",
        "critical_dir_changes",
        "file_types_changed",
        "canary_status",
    ],
    "log": [
        "failed_login_rate",
        "privilege_events",
        "service_installs",
        "account_changes",
        "log_clear_events",
        "new_service_events",
    ],
}

# Minimum samples required to train a reliable model
MIN_TRAINING_SAMPLES = 50


class AnomalyDetector:
    """Isolation Forest-based anomaly detector for a specific sensor domain.

    Each domain (network, process, file, log) gets its own detector
    with domain-specific feature extraction.
    """

    def __init__(
        self,
        domain: str,
        n_estimators: int = 100,
        contamination: float = 0.01,
        max_features: float = 1.0,
    ):
        self._domain = domain
        self._n_estimators = n_estimators
        self._contamination = contamination
        self._max_features = max_features
        self._model: IsolationForest | None = None
        self._is_trained = False

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def n_estimators(self) -> int:
        return self._n_estimators

    @property
    def contamination(self) -> float:
        return self._contamination

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    def train(self, data: np.ndarray) -> None:
        """Train the Isolation Forest on baseline data.

        Args:
            data: 2D numpy array of shape (n_samples, n_features).
                  Each row is a feature vector from a single observation.

        Raises:
            ValueError: If fewer than MIN_TRAINING_SAMPLES are provided.
        """
        if data.shape[0] < MIN_TRAINING_SAMPLES:
            raise ValueError(
                f"Need at least {MIN_TRAINING_SAMPLES} samples to train, "
                f"got {data.shape[0]}"
            )

        self._model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            max_features=self._max_features,
            random_state=42,
        )
        self._model.fit(data)
        self._is_trained = True
        logger.info(
            f"AnomalyDetector({self._domain}) trained on "
            f"{data.shape[0]} samples with {data.shape[1]} features"
        )

    def score(self, sample: np.ndarray) -> float:
        """Score a single sample for anomalousness.

        Args:
            sample: 2D array of shape (1, n_features).

        Returns:
            Anomaly score between 0.0 (normal) and 1.0 (extreme outlier).

        Raises:
            RuntimeError: If the model hasn't been trained yet.
        """
        if not self._is_trained or self._model is None:
            raise RuntimeError(
                f"AnomalyDetector({self._domain}) has not been trained yet"
            )

        # IsolationForest.decision_function returns negative scores for anomalies
        # and positive for normal. We invert and normalize to [0, 1].
        raw_score = self._model.decision_function(sample)[0]

        # Normalize: raw_score is typically in [-0.5, 0.5] range
        # Map to [0, 1] where 1 = most anomalous
        normalized = max(0.0, min(1.0, 0.5 - raw_score))
        return round(normalized, 4)

    def classify(self, score: float) -> str:
        """Classify an anomaly score into routing categories.

        Args:
            score: Anomaly score between 0.0 and 1.0.

        Returns:
            "normal" (< 0.4), "suspicious" (0.4-0.6), or "anomalous" (> 0.6).
        """
        if score < 0.4:
            return "normal"
        elif score < 0.6:
            return "suspicious"
        else:
            return "anomalous"

    def extract_features(self, event: AegisEvent) -> np.ndarray | None:
        """Extract a feature vector from an event based on domain config.

        Returns:
            1D numpy array of features, or None if domain not configured.
        """
        feature_names = DOMAIN_FEATURES.get(self._domain)
        if feature_names is None:
            return None

        features = []
        for fname in feature_names:
            value = event.data.get(fname, 0)
            try:
                features.append(float(value))
            except (TypeError, ValueError):
                features.append(0.0)

        return np.array(features, dtype=np.float64)
