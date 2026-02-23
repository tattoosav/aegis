"""C2 beacon detector via timing analysis.

Detects command-and-control beaconing by analyzing connection timestamp
patterns.  Uses two complementary approaches:

1. **Statistical analysis** — coefficient of variation and tolerance-band
   scoring to identify regular intervals hidden in noisy traffic.
2. **FFT analysis** — spectral decomposition to find dominant periodic
   signals even when jitter is significant.

Typical C2 implants "phone home" at fixed intervals (30 s, 60 s, 300 s)
with optional random jitter.  Both methods are resilient to moderate
jitter (up to ~30 %).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class BeaconResult:
    """Result of statistical beacon analysis."""

    is_beacon: bool
    score: float
    median_interval: float
    cv: float  # coefficient of variation (std / median)
    pct_within_tolerance: float


@dataclass
class FFTResult:
    """Result of FFT-based periodicity analysis."""

    periodic: bool
    dominant_period: float
    snr: float


class BeaconDetector:
    """Detect C2 beaconing in connection timestamps.

    Parameters
    ----------
    min_connections : int
        Minimum number of timestamps required before analysis is
        attempted.  Fewer samples produce a non-beacon / non-periodic
        result immediately.
    beacon_threshold : float
        Score at or above which ``analyze`` declares a beacon.
    """

    def __init__(
        self,
        min_connections: int = 10,
        beacon_threshold: float = 0.5,
    ) -> None:
        self._min_connections = min_connections
        self._beacon_threshold = beacon_threshold

    # ------------------------------------------------------------------ #
    #  Statistical analysis
    # ------------------------------------------------------------------ #

    def analyze(self, timestamps: list[float]) -> BeaconResult:
        """Analyze timestamps for beacon-like regularity.

        Parameters
        ----------
        timestamps : list[float]
            Unix-epoch (or arbitrary monotonic) timestamps of
            outbound connections to a single destination.

        Returns
        -------
        BeaconResult
            Scoring result indicating whether the pattern looks like
            C2 beaconing.
        """
        if len(timestamps) < self._min_connections:
            return BeaconResult(
                is_beacon=False,
                score=0.0,
                median_interval=0.0,
                cv=0.0,
                pct_within_tolerance=0.0,
            )

        ts = np.array(sorted(timestamps))
        deltas = np.diff(ts)

        median_interval = float(np.median(deltas))
        if median_interval == 0.0:
            return BeaconResult(
                is_beacon=False,
                score=0.0,
                median_interval=0.0,
                cv=0.0,
                pct_within_tolerance=0.0,
            )

        std = float(np.std(deltas))
        cv = std / median_interval

        # Percentage of deltas within 20 % of the median
        lower = median_interval * 0.8
        upper = median_interval * 1.2
        within = np.sum((deltas >= lower) & (deltas <= upper))
        pct_within_tolerance = float(within / len(deltas))

        score = (
            0.4 * (1.0 - min(cv, 1.0))
            + 0.6 * pct_within_tolerance
        )

        is_beacon = score >= self._beacon_threshold

        return BeaconResult(
            is_beacon=is_beacon,
            score=score,
            median_interval=median_interval,
            cv=cv,
            pct_within_tolerance=pct_within_tolerance,
        )

    # ------------------------------------------------------------------ #
    #  FFT-based periodicity detection
    # ------------------------------------------------------------------ #

    def analyze_fft(self, timestamps: list[float]) -> FFTResult:
        """Detect periodicity in timestamps using FFT.

        Creates a 1-second-resolution signal from the timestamps,
        applies ``numpy.fft.rfft``, and looks for a dominant
        frequency whose magnitude stands out from the noise floor.

        Parameters
        ----------
        timestamps : list[float]
            Sorted connection timestamps.

        Returns
        -------
        FFTResult
            Periodicity detection result including dominant period
            and signal-to-noise ratio.
        """
        if len(timestamps) < self._min_connections:
            return FFTResult(periodic=False, dominant_period=0.0, snr=0.0)

        ts = np.array(sorted(timestamps))
        t_min = ts[0]
        t_max = ts[-1]
        duration = t_max - t_min

        if duration <= 0:
            return FFTResult(periodic=False, dominant_period=0.0, snr=0.0)

        # Build 1-second-bin signal
        n_bins = int(duration) + 1
        signal = np.zeros(n_bins)
        for t in ts:
            idx = int(t - t_min)
            if 0 <= idx < n_bins:
                signal[idx] += 1.0

        # Remove DC component
        signal = signal - np.mean(signal)

        # FFT
        spectrum = np.fft.rfft(signal)
        magnitudes = np.abs(spectrum)

        # Ignore DC (index 0) and very-low-frequency bins
        if len(magnitudes) < 3:
            return FFTResult(periodic=False, dominant_period=0.0, snr=0.0)

        magnitudes[0] = 0.0

        # Peak frequency
        peak_idx = int(np.argmax(magnitudes[1:])) + 1
        peak_mag = magnitudes[peak_idx]

        # Frequencies: bin k corresponds to k / n_bins Hz (1-second bins)
        freqs = np.fft.rfftfreq(n_bins, d=1.0)
        peak_freq = freqs[peak_idx]

        if peak_freq == 0.0:
            return FFTResult(periodic=False, dominant_period=0.0, snr=0.0)

        dominant_period = 1.0 / peak_freq

        # SNR: peak vs mean of non-peak magnitudes
        non_peak = np.delete(magnitudes[1:], peak_idx - 1)
        mean_noise = float(np.mean(non_peak)) if len(non_peak) > 0 else 0.0
        snr = float(peak_mag / mean_noise) if mean_noise > 0 else 0.0

        periodic = snr > 5.0

        return FFTResult(
            periodic=periodic,
            dominant_period=dominant_period,
            snr=snr,
        )
