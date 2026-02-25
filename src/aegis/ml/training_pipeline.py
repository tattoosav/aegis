"""Adaptive baseline training pipeline using Isolation Forest.

Collects feature vectors produced by the FeatureExtractor, trains an
Isolation Forest model when enough samples are gathered, and scores
new samples for anomalousness.  Supports model versioning and rollback.
"""
from __future__ import annotations

import logging
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import numpy as np

log = logging.getLogger(__name__)

# sklearn / joblib are optional at import time so the module remains
# importable even when scikit-learn is not installed.
try:
    import joblib
    from sklearn.ensemble import IsolationForest

    _HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    _HAS_SKLEARN = False


# ---- enums & dataclasses ---------------------------------------------------


class TrainingStatus(Enum):
    """Lifecycle states of the training pipeline."""

    COLLECTING = "collecting"
    TRAINING = "training"
    TRAINED = "trained"
    FAILED = "failed"


@dataclass
class ModelVersion:
    """Metadata for a single trained model snapshot.

    Attributes:
        version:    Monotonically increasing version number.
        timestamp:  Unix epoch when the model was trained.
        model_type: String identifier for the algorithm used.
        metrics:    Evaluation metrics captured at training time.
        path:       Filesystem path where the serialised model is stored.
    """

    version: int
    timestamp: float
    model_type: str
    metrics: dict[str, Any]
    path: Path | None = None


# ---- pipeline --------------------------------------------------------------


class TrainingPipeline:
    """Collect feature samples, train an Isolation Forest, score new data.

    Args:
        min_samples: Minimum number of feature vectors required before
            training is allowed.
        model_dir:   Directory for persisted model files.  Defaults to a
            temporary directory (suitable for testing).
    """

    def __init__(
        self,
        min_samples: int = 200,
        model_dir: Path | str | None = None,
    ) -> None:
        self._min_samples = min_samples
        self._model_dir = (
            Path(model_dir)
            if model_dir is not None
            else Path(tempfile.mkdtemp(prefix="aegis_ml_"))
        )
        self._model_dir.mkdir(parents=True, exist_ok=True)

        self._samples: list[dict[str, float]] = []
        self._feature_names: list[str] | None = None
        self._model: Any = None  # IsolationForest instance
        self._status = TrainingStatus.COLLECTING
        self._current_version: ModelVersion | None = None
        self._version_history: list[ModelVersion] = []
        self._version_counter = 0

    # ---- properties --------------------------------------------------------

    @property
    def status(self) -> TrainingStatus:
        """Current pipeline status."""
        return self._status

    @property
    def sample_count(self) -> int:
        """Number of feature samples currently in the buffer."""
        return len(self._samples)

    @property
    def current_version(self) -> ModelVersion | None:
        """Metadata for the active model, or *None* if untrained."""
        return self._current_version

    # ---- public API --------------------------------------------------------

    def add_sample(self, features: dict[str, float]) -> None:
        """Append a feature vector to the sample buffer.

        Args:
            features: A mapping of feature names to float values.
        """
        self._samples.append(features)

    def train(self) -> bool:
        """Fit an Isolation Forest on the collected samples.

        Returns:
            ``True`` if training succeeded, ``False`` otherwise (not
            enough samples, or sklearn unavailable).
        """
        if not _HAS_SKLEARN:
            log.warning(
                "scikit-learn is not installed; training is unavailable"
            )
            return False

        if len(self._samples) < self._min_samples:
            log.info(
                "Not enough samples to train (%d / %d)",
                len(self._samples),
                self._min_samples,
            )
            return False

        self._status = TrainingStatus.TRAINING
        try:
            matrix, names = self._build_matrix()
            self._feature_names = names

            model = IsolationForest(
                n_estimators=100,
                contamination="auto",
                random_state=42,
            )
            model.fit(matrix)

            self._version_counter += 1
            version_info = ModelVersion(
                version=self._version_counter,
                timestamp=time.time(),
                model_type="isolation_forest",
                metrics=self._compute_metrics(model, matrix),
            )

            # Persist the model to disk.
            model_path = (
                self._model_dir / f"model_v{self._version_counter}.joblib"
            )
            joblib.dump(model, model_path)
            version_info.path = model_path

            # Rotate versions: push previous to history.
            if self._current_version is not None:
                self._version_history.append(self._current_version)

            self._model = model
            self._current_version = version_info
            self._status = TrainingStatus.TRAINED
            log.info(
                "Training complete — version %d, %d samples",
                self._version_counter,
                len(self._samples),
            )
            return True

        except Exception:
            self._status = TrainingStatus.FAILED
            log.exception("Training failed")
            return False

    def score(self, features: dict[str, float]) -> float:
        """Score a single sample against the trained model.

        The returned value is normalised to the range ``[0, 1]`` where
        higher values indicate greater anomalousness.

        Args:
            features: A mapping of feature names to float values.

        Returns:
            A float anomaly score in ``[0, 1]``.

        Raises:
            RuntimeError: If no model has been trained yet.
        """
        if self._model is None or self._feature_names is None:
            raise RuntimeError(
                "Cannot score: no trained model available"
            )

        row = np.array(
            [[features.get(n, 0.0) for n in self._feature_names]]
        )
        # decision_function returns negative values for anomalies.
        # We negate and clip to [0, 1] so that higher = more anomalous.
        raw = self._model.decision_function(row)[0]
        # Raw scores from IsolationForest typically range from about
        # -0.5 (very anomalous) to +0.5 (very normal).  We shift and
        # scale into [0, 1].
        normalised = float(np.clip(0.5 - raw, 0.0, 1.0))
        return normalised

    def rollback(self) -> None:
        """Revert to the previous model version.

        Raises:
            RuntimeError: If there is no previous version to roll back to.
        """
        if not self._version_history:
            raise RuntimeError("No previous model version to roll back to")

        prev = self._version_history.pop()
        if prev.path is not None and prev.path.exists():
            self._model = joblib.load(prev.path)
        self._current_version = prev
        self._status = TrainingStatus.TRAINED
        log.info("Rolled back to model version %d", prev.version)

    # ---- internal helpers --------------------------------------------------

    def _build_matrix(self) -> tuple[np.ndarray, list[str]]:
        """Convert the sample buffer into a NumPy matrix.

        Returns:
            A tuple of (2-D array, ordered feature-name list).
        """
        # Use the union of all feature names across samples so that
        # samples with missing keys get 0.0 for those features.
        name_set: set[str] = set()
        for sample in self._samples:
            name_set.update(sample.keys())
        names = sorted(name_set)

        matrix = np.array(
            [[s.get(n, 0.0) for n in names] for s in self._samples]
        )
        return matrix, names

    @staticmethod
    def _compute_metrics(
        model: Any,
        matrix: np.ndarray,
    ) -> dict[str, Any]:
        """Compute basic evaluation metrics for the trained model.

        Args:
            model:  The fitted IsolationForest.
            matrix: The training data matrix.

        Returns:
            A dictionary of metric names to values.
        """
        scores = model.decision_function(matrix)
        return {
            "mean_score": float(np.mean(scores)),
            "std_score": float(np.std(scores)),
            "n_samples": int(matrix.shape[0]),
            "n_features": int(matrix.shape[1]),
        }
