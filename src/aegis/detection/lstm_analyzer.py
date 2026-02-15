"""LSTM-style sequence anomaly detection engine.

Analyzes ordered sequences of events to detect temporal attack patterns
such as C2 beaconing, slow brute force, multi-stage attacks, and lateral
movement.

Named "LSTM" for the interface contract, but implemented with sklearn
IsolationForest on sequence-level statistical features rather than
requiring PyTorch/ONNX at runtime.

Pipeline:
  1. Encode each AegisEvent into a fixed-size numeric feature vector.
  2. Collect a sliding window of N encoded events into a sequence.
  3. Compute sequence-level statistics (mean, std, min, max per feature,
     plus inter-event timing statistics).
  4. Score the resulting summary vector with an IsolationForest trained
     on normal event sequences.

Routing:
  Score < 0.4  -> Normal (log and dismiss)
  Score 0.4-0.6 -> Suspicious (elevated priority)
  Score > 0.6  -> Anomalous (forward to deeper analysis)
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from aegis.core.models import AegisEvent, SensorType, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEQUENCE_FEATURES_PER_EVENT = 12
MIN_TRAINING_SEQUENCES = 30
BEACONING_CV_THRESHOLD = 0.15
BRUTE_FORCE_THRESHOLD = 10

# Ordered lists used for ordinal encoding
_SENSOR_ORDER: list[str] = [st.value for st in SensorType]
_SEVERITY_ORDER: list[str] = [sv.value for sv in Severity]


class LSTMSequenceAnalyzer:
    """Sequence anomaly detector for temporal attack-pattern recognition.

    Encodes sliding windows of AegisEvents into statistical feature
    vectors and scores them with an IsolationForest trained on normal
    baseline sequences.

    Args:
        sequence_length: Number of events per analysis window.
        n_estimators: Trees in the IsolationForest ensemble.
        contamination: Expected fraction of anomalous sequences in
            the training set.
    """

    def __init__(
        self,
        sequence_length: int = 20,
        n_estimators: int = 100,
        contamination: float = 0.02,
    ) -> None:
        self._sequence_length = sequence_length
        self._n_estimators = n_estimators
        self._contamination = contamination
        self._model: IsolationForest | None = None
        self._is_trained: bool = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def sequence_length(self) -> int:
        """Number of events per analysis window."""
        return self._sequence_length

    @property
    def is_trained(self) -> bool:
        """Whether the model has been fitted on baseline data."""
        return self._is_trained

    # ------------------------------------------------------------------
    # Event encoding
    # ------------------------------------------------------------------

    def encode_event(self, event: AegisEvent) -> np.ndarray:
        """Convert a single AegisEvent into a fixed-size feature vector.

        Features (12 total):
            0  - event_type hash (deterministic numeric encoding)
            1  - sensor type ordinal
            2  - severity ordinal
            3  - severity weight
            4  - timestamp (epoch seconds)
            5  - data field count
            6  - data string-value total length
            7  - has_pid flag (1.0 / 0.0)
            8  - has_ip flag
            9  - has_port flag
            10 - has_user flag
            11 - has_path flag

        Args:
            event: The event to encode.

        Returns:
            1-D numpy array of shape ``(SEQUENCE_FEATURES_PER_EVENT,)``.
        """
        # Deterministic hash of event_type to a float in [0, 1)
        type_hash = int(
            hashlib.sha256(
                event.event_type.encode()
            ).hexdigest()[:8],
            16,
        )
        type_numeric = (type_hash % 100_000) / 100_000.0

        sensor_ordinal = float(
            _SENSOR_ORDER.index(event.sensor.value)
            if event.sensor.value in _SENSOR_ORDER
            else 0
        )
        severity_ordinal = float(
            _SEVERITY_ORDER.index(event.severity.value)
            if event.severity.value in _SEVERITY_ORDER
            else 0
        )

        data = event.data or {}
        data_field_count = float(len(data))
        str_len_total = float(
            sum(len(str(v)) for v in data.values())
        )

        has_ip = 1.0 if ("ip" in data or "remote_ip" in data) else 0.0
        has_port = (
            1.0 if ("port" in data or "remote_port" in data) else 0.0
        )
        has_user = (
            1.0 if ("user" in data or "username" in data) else 0.0
        )
        has_path = (
            1.0 if ("path" in data or "file_path" in data) else 0.0
        )

        features = np.array(
            [
                type_numeric,                                    # 0
                sensor_ordinal,                                  # 1
                severity_ordinal,                                # 2
                event.severity.weight,                           # 3
                event.timestamp,                                 # 4
                data_field_count,                                # 5
                str_len_total,                                   # 6
                1.0 if "pid" in data else 0.0,                   # 7
                has_ip,                                          # 8
                has_port,                                        # 9
                has_user,                                        # 10
                has_path,                                        # 11
            ],
            dtype=np.float64,
        )
        return features

    # ------------------------------------------------------------------
    # Sequence encoding
    # ------------------------------------------------------------------

    def encode_sequence(
        self, events: list[AegisEvent],
    ) -> np.ndarray:
        """Encode a sequence of events into a single feature vector.

        Steps:
            1. Encode each event (pad or truncate to
               *sequence_length*).
            2. Compute per-feature statistics across the window:
               mean, std, min, max
               (4 x SEQUENCE_FEATURES_PER_EVENT = 48 values).
            3. Compute inter-event timing statistics: mean delta,
               std delta, min delta, max delta, coefficient of
               variation, regularity score (6 values).
            4. Concatenate into a single 1-D vector of length 54.

        Args:
            events: Ordered list of AegisEvents.

        Returns:
            1-D numpy array suitable for sklearn scoring.
        """
        encoded: list[np.ndarray] = [
            self.encode_event(e) for e in events
        ]

        # Pad or truncate to sequence_length
        zero_vec = np.zeros(
            SEQUENCE_FEATURES_PER_EVENT, dtype=np.float64,
        )
        if len(encoded) < self._sequence_length:
            pad_count = self._sequence_length - len(encoded)
            encoded.extend([zero_vec] * pad_count)
        elif len(encoded) > self._sequence_length:
            encoded = encoded[: self._sequence_length]

        matrix = np.array(encoded, dtype=np.float64)

        # Per-feature statistics across the window
        feat_mean = np.mean(matrix, axis=0)
        feat_std = np.std(matrix, axis=0)
        feat_min = np.min(matrix, axis=0)
        feat_max = np.max(matrix, axis=0)

        # Inter-event timing statistics (timestamp is feature 4)
        timestamps = matrix[:, 4]
        deltas = np.diff(timestamps)
        if len(deltas) == 0 or np.all(deltas == 0):
            timing_stats = np.zeros(6, dtype=np.float64)
        else:
            abs_deltas = np.abs(deltas)
            delta_mean = float(np.mean(abs_deltas))
            delta_std = float(np.std(abs_deltas))
            delta_min = float(np.min(abs_deltas))
            delta_max = float(np.max(abs_deltas))
            cv = (
                delta_std / delta_mean
                if delta_mean > 0
                else 0.0
            )
            # Regularity: 1.0 = perfectly periodic, 0.0 = chaotic
            regularity = max(0.0, 1.0 - cv)
            timing_stats = np.array(
                [delta_mean, delta_std, delta_min,
                 delta_max, cv, regularity],
                dtype=np.float64,
            )

        return np.concatenate(
            [feat_mean, feat_std, feat_min, feat_max, timing_stats]
        )

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, sequences: list[list[AegisEvent]]) -> None:
        """Train the IsolationForest on baseline (normal) sequences.

        Args:
            sequences: List of event sequences.  Each inner list is
                an ordered series of AegisEvents representing normal
                behaviour.

        Raises:
            ValueError: If fewer than ``MIN_TRAINING_SEQUENCES``
                sequences are provided.
        """
        if len(sequences) < MIN_TRAINING_SEQUENCES:
            raise ValueError(
                f"Need at least {MIN_TRAINING_SEQUENCES} sequences "
                f"to train, got {len(sequences)}"
            )

        feature_matrix = np.array(
            [self.encode_sequence(seq) for seq in sequences],
            dtype=np.float64,
        )

        self._model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=42,
        )
        self._model.fit(feature_matrix)
        self._is_trained = True
        logger.info(
            "LSTMSequenceAnalyzer trained on %d sequences "
            "(%d features each)",
            feature_matrix.shape[0],
            feature_matrix.shape[1],
        )

    # ------------------------------------------------------------------
    # Scoring and classification
    # ------------------------------------------------------------------

    def score(self, events: list[AegisEvent]) -> float:
        """Compute an anomaly score for an event sequence.

        Args:
            events: Ordered list of AegisEvents to evaluate.

        Returns:
            Anomaly score between 0.0 (normal) and 1.0 (extreme
            outlier).

        Raises:
            RuntimeError: If the model has not been trained.
        """
        if not self._is_trained or self._model is None:
            raise RuntimeError(
                "LSTMSequenceAnalyzer has not been trained yet"
            )

        feature_vec = self.encode_sequence(events).reshape(1, -1)
        raw_score = self._model.decision_function(feature_vec)[0]

        # IsolationForest returns negative for outliers, positive
        # for inliers.  Invert and clamp to [0, 1].
        normalized = max(0.0, min(1.0, 0.5 - raw_score))
        return round(normalized, 4)

    def classify(self, score: float) -> str:
        """Map an anomaly score to a human-readable category.

        Args:
            score: Value between 0.0 and 1.0.

        Returns:
            ``"normal"`` (< 0.4), ``"suspicious"`` (0.4 -- 0.6),
            or ``"anomalous"`` (>= 0.6).
        """
        if score < 0.4:
            return "normal"
        elif score < 0.6:
            return "suspicious"
        return "anomalous"

    # ------------------------------------------------------------------
    # Specialised pattern detectors
    # ------------------------------------------------------------------

    def detect_beaconing(
        self, events: list[AegisEvent],
    ) -> tuple[bool, dict[str, Any]]:
        """Statistical test for periodic (C2 beaconing) timing.

        A low coefficient of variation (CV) in inter-event intervals
        indicates a highly regular cadence typical of automated
        command-and-control callbacks.

        Args:
            events: Ordered event list (at least 3 events needed
                for meaningful interval analysis).

        Returns:
            Tuple of ``(is_beaconing, details)`` where *details*
            contains ``interval_mean``, ``interval_std``, and
            ``coefficient_of_variation``.
        """
        if len(events) < 3:
            return False, {
                "interval_mean": 0.0,
                "interval_std": 0.0,
                "coefficient_of_variation": 0.0,
            }

        timestamps = np.array(
            [e.timestamp for e in events], dtype=np.float64,
        )
        deltas = np.diff(timestamps)
        abs_deltas = np.abs(deltas)

        mean_interval = float(np.mean(abs_deltas))
        std_interval = float(np.std(abs_deltas))
        cv = (
            std_interval / mean_interval
            if mean_interval > 0
            else 0.0
        )

        is_beaconing = (
            cv < BEACONING_CV_THRESHOLD and mean_interval > 0
        )

        details: dict[str, Any] = {
            "interval_mean": round(mean_interval, 4),
            "interval_std": round(std_interval, 4),
            "coefficient_of_variation": round(cv, 4),
        }

        if is_beaconing:
            logger.warning(
                "Beaconing detected: CV=%.4f "
                "(threshold=%.2f), mean_interval=%.2fs",
                cv,
                BEACONING_CV_THRESHOLD,
                mean_interval,
            )

        return is_beaconing, details

    def detect_brute_force(
        self, events: list[AegisEvent],
    ) -> tuple[bool, dict[str, Any]]:
        """Detect brute-force login attempts within an event window.

        Counts events whose ``event_type`` indicates a failed login
        and checks whether the count exceeds the threshold.

        Args:
            events: Ordered event list to scan.

        Returns:
            Tuple of ``(is_brute_force, details)`` where *details*
            contains ``failed_count``, ``window_seconds``, and
            ``rate_per_minute``.
        """
        failed_keywords = {
            "failed_login",
            "login_failure",
            "auth_fail",
        }

        failed_count = 0
        for evt in events:
            etype = evt.event_type.lower()
            if etype in failed_keywords:
                failed_count += 1
                continue
            # Also check event data for failure indicators
            status = str(evt.data.get("status", "")).lower()
            result = str(evt.data.get("result", "")).lower()
            if "fail" in status or "fail" in result:
                failed_count += 1

        # Window duration
        if len(events) >= 2:
            window_seconds = abs(
                events[-1].timestamp - events[0].timestamp
            )
        else:
            window_seconds = 0.0

        rate_per_minute = (
            (failed_count / window_seconds) * 60.0
            if window_seconds > 0
            else 0.0
        )

        is_brute_force = failed_count >= BRUTE_FORCE_THRESHOLD

        details: dict[str, Any] = {
            "failed_count": failed_count,
            "window_seconds": round(window_seconds, 2),
            "rate_per_minute": round(rate_per_minute, 2),
        }

        if is_brute_force:
            logger.warning(
                "Brute force detected: %d failed logins in "
                "%.1fs (%.1f/min)",
                failed_count,
                window_seconds,
                rate_per_minute,
            )

        return is_brute_force, details
