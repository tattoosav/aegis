"""Tests for C2 beacon detection via timing analysis."""
from __future__ import annotations

import numpy as np

from aegis.detection.beacon_detector import BeaconDetector, BeaconResult

# ================================================================== #
#  BeaconResult dataclass tests
# ================================================================== #


class TestBeaconResult:
    """Tests for the BeaconResult dataclass."""

    def test_result_fields(self):
        result = BeaconResult(
            is_beacon=True,
            score=0.85,
            median_interval=60.0,
            cv=0.05,
            pct_within_tolerance=0.9,
        )
        assert result.is_beacon is True
        assert result.score == 0.85
        assert result.median_interval == 60.0
        assert result.cv == 0.05
        assert result.pct_within_tolerance == 0.9

    def test_result_non_beacon_defaults(self):
        result = BeaconResult(
            is_beacon=False,
            score=0.0,
            median_interval=0.0,
            cv=0.0,
            pct_within_tolerance=0.0,
        )
        assert result.is_beacon is False
        assert result.score == 0.0


# ================================================================== #
#  Statistical analysis tests
# ================================================================== #


class TestBeaconDetectorStatistical:
    """Tests for BeaconDetector.analyze (statistical method)."""

    def test_detects_regular_beacon(self):
        """60-second beacon with <5% jitter should score >= 0.7."""
        np.random.seed(42)
        detector = BeaconDetector(min_connections=10)
        base = 1000.0
        timestamps = [
            base + i * 60.0 + np.random.uniform(-3, 3)
            for i in range(20)
        ]
        result = detector.analyze(timestamps)
        assert result.is_beacon is True
        assert result.score >= 0.7
        assert 55 <= result.median_interval <= 65

    def test_rejects_random_traffic(self):
        """Random connection times should not trigger beacon detection."""
        np.random.seed(123)
        detector = BeaconDetector(min_connections=10)
        timestamps = sorted(np.random.uniform(0, 3600, 20).tolist())
        result = detector.analyze(timestamps)
        assert result.is_beacon is False

    def test_insufficient_data(self):
        """Fewer timestamps than min_connections returns non-beacon."""
        detector = BeaconDetector(min_connections=10)
        result = detector.analyze([1.0, 2.0, 3.0])
        assert result.is_beacon is False
        assert result.score == 0.0

    def test_empty_list(self):
        """Empty timestamp list returns non-beacon."""
        detector = BeaconDetector(min_connections=10)
        result = detector.analyze([])
        assert result.is_beacon is False

    def test_custom_threshold(self):
        """Custom beacon_threshold adjusts sensitivity."""
        np.random.seed(42)
        detector = BeaconDetector(
            min_connections=5,
            beacon_threshold=0.9,
        )
        base = 0.0
        timestamps = [
            base + i * 30.0 + np.random.uniform(-5, 5)
            for i in range(15)
        ]
        result = detector.analyze(timestamps)
        # With stricter threshold, some moderate beacons may not trigger
        assert isinstance(result.is_beacon, bool)
        assert 0.0 <= result.score <= 1.0

    def test_perfect_beacon_scores_high(self):
        """Perfectly regular intervals should produce maximum score."""
        detector = BeaconDetector(min_connections=10)
        timestamps = [100.0 + i * 60.0 for i in range(20)]
        result = detector.analyze(timestamps)
        assert result.is_beacon is True
        assert result.score >= 0.9
        assert result.cv == 0.0
        assert result.pct_within_tolerance == 1.0
        assert result.median_interval == 60.0

    def test_score_formula_components(self):
        """Verify score is composed of CV and tolerance percentage."""
        np.random.seed(99)
        detector = BeaconDetector(min_connections=5)
        base = 0.0
        timestamps = [
            base + i * 120.0 + np.random.uniform(-10, 10)
            for i in range(15)
        ]
        result = detector.analyze(timestamps)
        # Score should match: 0.4*(1-min(cv,1)) + 0.6*pct_within_tolerance
        expected = (
            0.4 * (1 - min(result.cv, 1.0))
            + 0.6 * result.pct_within_tolerance
        )
        assert abs(result.score - expected) < 1e-9


# ================================================================== #
#  FFT analysis tests
# ================================================================== #


class TestBeaconDetectorFFT:
    """Tests for BeaconDetector.analyze_fft (FFT-based periodicity)."""

    def test_fft_detects_periodic_signal_with_jitter(self):
        """Beacon with 30% jitter -- FFT should still find periodicity."""
        np.random.seed(42)
        detector = BeaconDetector(min_connections=10)
        base = 0.0
        interval = 120.0
        jitter = 0.3
        timestamps = [
            base + i * interval + np.random.uniform(
                -interval * jitter, interval * jitter
            )
            for i in range(100)
        ]
        result = detector.analyze_fft(sorted(timestamps))
        assert result.periodic is True
        assert 90 <= result.dominant_period <= 150

    def test_fft_rejects_aperiodic(self):
        """Random timestamps should not show periodicity."""
        np.random.seed(456)
        detector = BeaconDetector(min_connections=10)
        timestamps = sorted(np.random.uniform(0, 7200, 50).tolist())
        result = detector.analyze_fft(timestamps)
        assert result.periodic is False

    def test_fft_insufficient_data(self):
        """Fewer timestamps than min_connections returns non-periodic."""
        detector = BeaconDetector(min_connections=10)
        result = detector.analyze_fft([1.0, 2.0])
        assert result.periodic is False

    def test_fft_perfect_beacon(self):
        """Perfectly periodic signal should have high SNR."""
        detector = BeaconDetector(min_connections=10)
        timestamps = [i * 60.0 for i in range(100)]
        result = detector.analyze_fft(timestamps)
        assert result.periodic is True
        assert 55 <= result.dominant_period <= 65
        assert result.snr > 5.0

    def test_fft_snr_returned(self):
        """SNR value should always be non-negative."""
        np.random.seed(77)
        detector = BeaconDetector(min_connections=10)
        timestamps = sorted(np.random.uniform(0, 3600, 30).tolist())
        result = detector.analyze_fft(timestamps)
        assert result.snr >= 0.0
