"""Tests for concept drift detection."""
from __future__ import annotations

import numpy as np

from aegis.ml.drift_detector import DriftDetector, DriftResult


class TestDriftResult:
    """Tests for the DriftResult dataclass."""

    def test_drift_result_has_details(self) -> None:
        result = DriftResult(
            drift_detected=True,
            drifted_features=["f1"],
            details={"f1": {"old_mean": 0, "new_mean": 10}},
        )
        assert result.drift_detected is True
        assert result.drifted_features == ["f1"]
        assert result.details["f1"]["old_mean"] == 0
        assert result.details["f1"]["new_mean"] == 10

    def test_drift_result_no_drift(self) -> None:
        result = DriftResult(
            drift_detected=False,
            drifted_features=[],
            details={},
        )
        assert result.drift_detected is False
        assert result.drifted_features == []

    def test_drift_result_defaults(self) -> None:
        result = DriftResult()
        assert result.drift_detected is False
        assert result.drifted_features == []
        assert result.details == {}


class TestDriftDetector:
    """Tests for the DriftDetector sliding-window drift checker."""

    def test_no_drift_on_stable_data(self) -> None:
        detector = DriftDetector(window_size=50)
        rng = np.random.default_rng(42)
        for _ in range(100):
            detector.update({"f1": rng.normal(0, 1)})
        result = detector.check()
        assert result.drift_detected is False

    def test_drift_on_mean_shift(self) -> None:
        detector = DriftDetector(window_size=50)
        rng = np.random.default_rng(42)
        # Stable period
        for _ in range(100):
            detector.update({"f1": rng.normal(0, 1)})
        # Shift mean by 10 std
        for _ in range(100):
            detector.update({"f1": rng.normal(10, 1)})
        result = detector.check()
        assert result.drift_detected is True
        assert "f1" in result.drifted_features

    def test_drift_details_contain_stats(self) -> None:
        detector = DriftDetector(window_size=50)
        rng = np.random.default_rng(42)
        for _ in range(100):
            detector.update({"f1": rng.normal(0, 1)})
        for _ in range(100):
            detector.update({"f1": rng.normal(10, 1)})
        result = detector.check()
        assert "f1" in result.details
        detail = result.details["f1"]
        assert "baseline_mean" in detail
        assert "recent_mean" in detail
        assert "baseline_std" in detail
        assert "shift" in detail

    def test_multiple_features_independent(self) -> None:
        """Only the drifted feature should be flagged."""
        detector = DriftDetector(window_size=50)
        rng = np.random.default_rng(42)
        for _ in range(100):
            detector.update({
                "stable": rng.normal(0, 1),
                "shifting": rng.normal(0, 1),
            })
        for _ in range(100):
            detector.update({
                "stable": rng.normal(0, 1),
                "shifting": rng.normal(20, 1),
            })
        result = detector.check()
        assert result.drift_detected is True
        assert "shifting" in result.drifted_features
        assert "stable" not in result.drifted_features

    def test_insufficient_data_no_drift(self) -> None:
        """With fewer samples than window_size, no drift should be reported."""
        detector = DriftDetector(window_size=50)
        rng = np.random.default_rng(42)
        for _ in range(30):
            detector.update({"f1": rng.normal(0, 1)})
        result = detector.check()
        assert result.drift_detected is False

    def test_custom_threshold(self) -> None:
        """A higher threshold should require a larger shift to trigger."""
        detector = DriftDetector(window_size=50, threshold=6.0)
        rng = np.random.default_rng(42)
        for _ in range(100):
            detector.update({"f1": rng.normal(0, 1)})
        # Shift by ~4 std — below threshold of 6
        for _ in range(100):
            detector.update({"f1": rng.normal(4, 1)})
        result = detector.check()
        assert result.drift_detected is False

    def test_window_size_property(self) -> None:
        detector = DriftDetector(window_size=75)
        assert detector.window_size == 75

    def test_reset_clears_state(self) -> None:
        detector = DriftDetector(window_size=50)
        rng = np.random.default_rng(42)
        for _ in range(100):
            detector.update({"f1": rng.normal(0, 1)})
        detector.reset()
        result = detector.check()
        assert result.drift_detected is False

    def test_zero_std_baseline_no_crash(self) -> None:
        """If baseline std is zero, detector should not crash."""
        detector = DriftDetector(window_size=5)
        # All baseline values identical
        for _ in range(10):
            detector.update({"f1": 1.0})
        # Shift
        for _ in range(10):
            detector.update({"f1": 5.0})
        result = detector.check()
        # Should detect drift (constant baseline, different recent)
        assert result.drift_detected is True
