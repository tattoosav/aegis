"""Concept drift detection for Aegis ML pipeline.

Monitors the distribution of system-metric feature values over time
and flags when the recent window has shifted significantly from the
baseline window.  A detected drift signals that the anomaly-scoring
model may need retraining.

Algorithm
---------
For each tracked feature the detector maintains a per-feature deque of
observed values.  When :meth:`DriftDetector.check` is called the deque
is split into a *baseline* window (first ``window_size`` samples) and a
*recent* window (last ``window_size`` samples).  If the absolute
difference between the two means exceeds ``threshold * baseline_std``,
the feature is flagged as drifted.

A special case handles a zero-variance baseline: if the baseline
standard deviation is zero but the means differ, the feature is
automatically flagged.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

# -------------------------------------------------------------------
# Result container
# -------------------------------------------------------------------

@dataclass
class DriftResult:
    """Outcome of a drift check.

    Attributes:
        drift_detected: ``True`` when at least one feature drifted.
        drifted_features: Names of features whose mean shifted beyond
            the configured threshold.
        details: Per-feature statistics that motivated the decision.
    """

    drift_detected: bool = False
    drifted_features: list[str] = field(default_factory=list)
    details: dict[str, dict[str, Any]] = field(default_factory=dict)


# -------------------------------------------------------------------
# Detector
# -------------------------------------------------------------------

class DriftDetector:
    """Sliding-window concept-drift detector.

    Keeps a per-feature buffer of observed values and compares the
    baseline (earliest ``window_size`` samples) against the most
    recent ``window_size`` samples.

    Args:
        window_size: Number of samples in each comparison window.
        threshold: Number of baseline standard deviations by which the
            recent mean must shift to trigger a drift flag.  Defaults
            to ``3.0``.
    """

    def __init__(
        self,
        window_size: int = 50,
        threshold: float = 3.0,
    ) -> None:
        self._window_size = window_size
        self._threshold = threshold
        self._buffers: dict[str, list[float]] = defaultdict(list)

    # ---- properties -----------------------------------------------

    @property
    def window_size(self) -> int:
        """Return the configured window size."""
        return self._window_size

    # ---- public API ------------------------------------------------

    def update(self, features: dict[str, float]) -> None:
        """Append a new observation for every feature in *features*.

        Args:
            features: Mapping of feature names to their latest scalar
                values.
        """
        for name, value in features.items():
            self._buffers[name].append(float(value))

    def check(self) -> DriftResult:
        """Compare baseline and recent windows for all tracked features.

        Returns:
            A :class:`DriftResult` summarising which features (if any)
            have drifted.
        """
        drifted: list[str] = []
        details: dict[str, dict[str, Any]] = {}

        for name, values in self._buffers.items():
            n = len(values)
            ws = self._window_size

            # Need at least 2 * window_size samples to compare
            if n < 2 * ws:
                continue

            baseline = values[:ws]
            recent = values[-ws:]

            b_mean = _mean(baseline)
            b_std = _std(baseline)
            r_mean = _mean(recent)

            shift = abs(r_mean - b_mean)

            feature_drifted: bool
            if b_std == 0.0:
                # Zero-variance baseline: any difference is drift
                feature_drifted = shift > 0.0
            else:
                feature_drifted = shift > self._threshold * b_std

            detail: dict[str, Any] = {
                "baseline_mean": b_mean,
                "recent_mean": r_mean,
                "baseline_std": b_std,
                "shift": shift,
            }
            details[name] = detail

            if feature_drifted:
                drifted.append(name)

        return DriftResult(
            drift_detected=len(drifted) > 0,
            drifted_features=drifted,
            details=details,
        )

    def reset(self) -> None:
        """Clear all accumulated feature data."""
        self._buffers.clear()


# -------------------------------------------------------------------
# Internal helpers
# -------------------------------------------------------------------

def _mean(values: list[float]) -> float:
    """Arithmetic mean of *values*."""
    return sum(values) / len(values)


def _std(values: list[float]) -> float:
    """Population standard deviation of *values*."""
    m = _mean(values)
    variance = sum((v - m) ** 2 for v in values) / len(values)
    return math.sqrt(variance)
