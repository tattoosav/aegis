"""Threat prediction engine using Markov chains over MITRE ATT&CK.

Predicts the next likely ATT&CK technique(s) an adversary will use
based on a sequence of observed techniques.  Transition probabilities
are computed from a curated set of real-world attack chain patterns
stored in ``data/mitre/attack_chains.json``.

Calibration
-----------
Raw transition counts are converted to probabilities and then passed
through Platt scaling (logistic sigmoid) so the outputs sit on a well-
calibrated [0, 1] scale.
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default location of the attack-chain database (relative to project root)
_DEFAULT_CHAINS_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "mitre"
    / "attack_chains.json"
)

# Platt scaling parameters — fitted to produce well-calibrated outputs
# on the transition probability range [0, 1].
_PLATT_A: float = -4.0
_PLATT_B: float = 2.0


# ── dataclasses ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class TechniquePrediction:
    """A single predicted next-step technique."""

    technique_id: str
    name: str
    probability: float
    defense: str
    mitre_tactic: str


@dataclass
class PredictionResult:
    """Container returned by :meth:`ThreatPredictor.predict`."""

    predictions: list[TechniquePrediction] = field(default_factory=list)


# ── helpers ──────────────────────────────────────────────────────────


def _platt_scale(raw: float, a: float = _PLATT_A, b: float = _PLATT_B) -> float:
    """Apply Platt (logistic sigmoid) scaling to a raw probability.

    Returns a value in (0, 1).
    """
    return 1.0 / (1.0 + math.exp(a * raw + b))


# ── main class ───────────────────────────────────────────────────────


class ThreatPredictor:
    """Predict the next MITRE ATT&CK technique from observed activity.

    The predictor builds a first-order Markov transition matrix from
    the attack chains in *chains_path*.  Given a list of observed
    technique IDs it looks up the *last* observed technique, computes
    next-step probabilities, applies Platt scaling for calibration,
    and returns the predictions sorted by probability (descending).

    Args:
        chains_path: Path to ``attack_chains.json``.  Falls back to
            the default bundled file when *None* or missing.
        max_predictions: Maximum number of predictions to return.
    """

    def __init__(
        self,
        chains_path: Path | None = None,
        max_predictions: int = 5,
    ) -> None:
        self._max_predictions = max_predictions

        # transition_counts[from_tid][to_tid] = count
        self._transitions: dict[str, dict[str, int]] = {}
        # technique_id -> metadata dict {"name", "tactic"}
        self._metadata: dict[str, dict[str, str]] = {}
        # technique_id -> defensive recommendation string
        self._defenses: dict[str, str] = {}

        self._load(chains_path or _DEFAULT_CHAINS_PATH)

    # ── public API ───────────────────────────────────────────────────

    def predict(
        self,
        observed_techniques: list[str],
    ) -> PredictionResult:
        """Predict the next likely techniques.

        Args:
            observed_techniques: Ordered list of MITRE ATT&CK technique
                IDs already observed (e.g. ``["T1566", "T1059"]``).

        Returns:
            A :class:`PredictionResult` containing zero or more
            :class:`TechniquePrediction` entries sorted by descending
            probability.
        """
        if not observed_techniques:
            return PredictionResult()

        last_tid = observed_techniques[-1]
        next_counts = self._transitions.get(last_tid)
        if not next_counts:
            logger.debug(
                "No transitions recorded for technique %s",
                last_tid,
            )
            return PredictionResult()

        total = sum(next_counts.values())
        if total == 0:
            return PredictionResult()

        # Build raw probability distribution
        raw_probs: list[tuple[str, float]] = [
            (tid, count / total)
            for tid, count in next_counts.items()
        ]

        # Apply Platt scaling for calibration
        scaled: list[tuple[str, float]] = [
            (tid, _platt_scale(p))
            for tid, p in raw_probs
        ]

        # Sort descending by probability and truncate
        scaled.sort(key=lambda item: item[1], reverse=True)
        top = scaled[: self._max_predictions]

        predictions: list[TechniquePrediction] = []
        for tid, prob in top:
            meta = self._metadata.get(tid, {})
            predictions.append(
                TechniquePrediction(
                    technique_id=tid,
                    name=meta.get("name", "Unknown"),
                    probability=prob,
                    defense=self._defenses.get(
                        tid,
                        "Review MITRE ATT&CK mitigations for this technique.",
                    ),
                    mitre_tactic=meta.get("tactic", "unknown"),
                ),
            )

        return PredictionResult(predictions=predictions)

    # ── private ──────────────────────────────────────────────────────

    def _load(self, chains_path: Path) -> None:
        """Load attack chains and build the transition matrix."""
        if not chains_path.is_file():
            logger.warning(
                "Attack chains file not found: %s — predictor will "
                "return empty results",
                chains_path,
            )
            return

        try:
            raw: dict[str, Any] = json.loads(
                chains_path.read_text(encoding="utf-8"),
            )
        except (json.JSONDecodeError, OSError) as exc:
            logger.error(
                "Failed to load attack chains from %s: %s",
                chains_path,
                exc,
            )
            return

        # Load technique metadata
        for tid, meta in raw.get("technique_metadata", {}).items():
            self._metadata[tid] = {
                "name": meta.get("name", "Unknown"),
                "tactic": meta.get("tactic", "unknown"),
            }

        # Load defensive recommendations
        for tid, defense in raw.get("defensive_recommendations", {}).items():
            self._defenses[tid] = defense

        # Build transition matrix from chains
        chains: list[dict[str, Any]] = raw.get("chains", [])
        for chain in chains:
            techniques: list[str] = chain.get("techniques", [])
            for i in range(len(techniques) - 1):
                src = techniques[i]
                dst = techniques[i + 1]
                if src not in self._transitions:
                    self._transitions[src] = {}
                self._transitions[src][dst] = (
                    self._transitions[src].get(dst, 0) + 1
                )

        logger.info(
            "Loaded %d attack chains with %d unique transitions",
            len(chains),
            sum(
                len(dsts) for dsts in self._transitions.values()
            ),
        )
