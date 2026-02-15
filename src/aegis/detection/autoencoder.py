"""Autoencoder deep anomaly verification engine.

Serves as a verification layer for the Isolation Forest anomaly detector.
Events that scored > 0.6 from the Isolation Forest are forwarded here
to confirm whether they are true anomalies or false positives.

Architecture (symmetric autoencoder):
  Input(64) → 48 → 32 → 16 → 8 [latent] → 16 → 32 → 48 → Output(64)

Training: Trained on normal event feature vectors using an MLPRegressor
configured as an autoencoder (input == target), MSE loss, Adam optimizer
with lr=0.001, 50 epochs.

Inference: Computes reconstruction error (MSE between input and output).
  High error  → confirmed anomaly (the sample deviates from learned normal)
  Low error   → false positive (suppress the alert)

Threshold: Auto-computed from training data as mean + 2*std of
reconstruction errors on the training set.
"""

from __future__ import annotations

import logging

import numpy as np
from sklearn.neural_network import MLPRegressor

logger = logging.getLogger(__name__)

# Minimum samples required to train a reliable autoencoder
MIN_TRAINING_SAMPLES = 50


def _relu(x: np.ndarray) -> np.ndarray:
    """Element-wise ReLU activation: max(0, x).

    Args:
        x: Input array of any shape.

    Returns:
        Array with negative values clamped to zero.
    """
    return np.maximum(0, x)


class AutoencoderVerifier:
    """Autoencoder-based anomaly verification engine.

    Wraps an sklearn MLPRegressor configured as a symmetric autoencoder.
    The network learns to reconstruct normal event feature vectors;
    samples that cannot be faithfully reconstructed are confirmed anomalies.

    Architecture:
        Input(input_dim) → 48 → 32 → 16 → latent_dim → 16 → 32 → 48
        → Output(input_dim)
        All hidden layers use ReLU activation.

    Usage:
        verifier = AutoencoderVerifier()
        verifier.train(normal_data)           # train on baseline
        is_anomaly, error = verifier.verify(sample)  # verify a flagged event
    """

    def __init__(
        self,
        input_dim: int = 64,
        latent_dim: int = 8,
        threshold: float | None = None,
    ) -> None:
        """Initialize the autoencoder verifier.

        Args:
            input_dim: Dimensionality of input feature vectors.
            latent_dim: Size of the bottleneck (latent) layer.
            threshold: Fixed reconstruction error threshold. If None,
                       auto-computed from training data (mean + 2*std).
        """
        self._input_dim = input_dim
        self._latent_dim = latent_dim
        self._threshold: float | None = threshold
        self._is_trained = False
        self._model: MLPRegressor | None = None

        # Symmetric hidden layer sizes: encoder → latent → decoder
        self._hidden_layer_sizes = (48, 32, 16, latent_dim, 16, 32, 48)

        # Pure-numpy weight/bias arrays extracted after training
        # for fast inference without sklearn overhead
        self._weights: list[np.ndarray] = []
        self._biases: list[np.ndarray] = []

        logger.debug(
            f"AutoencoderVerifier initialized: "
            f"input_dim={input_dim}, latent_dim={latent_dim}, "
            f"architecture={self._hidden_layer_sizes}"
        )

    @property
    def input_dim(self) -> int:
        """Dimensionality of input feature vectors."""
        return self._input_dim

    @property
    def latent_dim(self) -> int:
        """Size of the bottleneck (latent) layer."""
        return self._latent_dim

    @property
    def threshold(self) -> float | None:
        """Reconstruction error threshold for anomaly classification.

        None if the model has not been trained and no fixed threshold
        was provided at init.
        """
        return self._threshold

    @property
    def is_trained(self) -> bool:
        """Whether the autoencoder has been trained."""
        return self._is_trained

    def train(self, data: np.ndarray) -> None:
        """Train the autoencoder on normal baseline data.

        The MLPRegressor is trained with input == target so it learns
        to reconstruct normal feature vectors. After training, weights
        are extracted to numpy arrays for fast inference.

        If no fixed threshold was provided, the threshold is auto-computed
        as mean + 2*std of reconstruction errors on the training set.

        Args:
            data: 2D numpy array of shape (n_samples, input_dim).
                  Each row is a feature vector from a normal observation.

        Raises:
            ValueError: If fewer than MIN_TRAINING_SAMPLES are provided
                        or if feature dimension doesn't match input_dim.
        """
        if data.shape[0] < MIN_TRAINING_SAMPLES:
            raise ValueError(
                f"Need at least {MIN_TRAINING_SAMPLES} samples to train, "
                f"got {data.shape[0]}"
            )

        if data.shape[1] != self._input_dim:
            raise ValueError(
                f"Expected {self._input_dim} features, "
                f"got {data.shape[1]}"
            )

        logger.info(
            f"Training autoencoder on {data.shape[0]} samples "
            f"with {data.shape[1]} features"
        )

        # Configure MLPRegressor as autoencoder: input == target
        self._model = MLPRegressor(
            hidden_layer_sizes=self._hidden_layer_sizes,
            activation="relu",
            solver="adam",
            learning_rate_init=0.001,
            max_iter=50,
            random_state=42,
            batch_size=min(32, data.shape[0]),
            verbose=False,
        )

        # Train: learn to reconstruct the input
        self._model.fit(data, data)
        self._is_trained = True

        # Extract weights and biases for pure-numpy inference
        self._weights = [w.copy() for w in self._model.coefs_]
        self._biases = [b.copy() for b in self._model.intercepts_]

        logger.info(
            f"Autoencoder trained: {len(self._weights)} layers, "
            f"loss={self._model.loss_:.6f}"
        )

        # Auto-compute threshold from training reconstruction errors
        if self._threshold is None:
            errors = np.array([
                self.score(data[i : i + 1]) for i in range(data.shape[0])
            ])
            mean_err = float(np.mean(errors))
            std_err = float(np.std(errors))
            self._threshold = mean_err + 2.0 * std_err
            logger.info(
                f"Auto-computed threshold: {self._threshold:.6f} "
                f"(mean={mean_err:.6f}, std={std_err:.6f})"
            )

    def forward(self, x: np.ndarray) -> np.ndarray:
        """Run the full encode-decode forward pass using pure numpy.

        Passes the input through all hidden layers (with ReLU activation)
        and the output layer (linear activation) to produce a
        reconstruction.

        Args:
            x: Input array of shape (1, input_dim) or (n, input_dim).

        Returns:
            Reconstructed output array of same shape as input.

        Raises:
            RuntimeError: If the model hasn't been trained yet.
        """
        if not self._is_trained:
            raise RuntimeError(
                "AutoencoderVerifier has not been trained yet"
            )

        out = x.copy().astype(np.float64)

        # Hidden layers: linear transform + ReLU
        for i in range(len(self._weights) - 1):
            out = out @ self._weights[i] + self._biases[i]
            out = _relu(out)

        # Output layer: linear (no activation)
        out = out @ self._weights[-1] + self._biases[-1]
        return out

    def score(self, sample: np.ndarray) -> float:
        """Compute the reconstruction error for a sample.

        Runs the sample through the autoencoder and returns the
        mean squared error between the input and its reconstruction.

        Args:
            sample: 2D array of shape (1, input_dim).

        Returns:
            Reconstruction error (MSE). Higher values indicate
            the sample deviates more from learned normal patterns.

        Raises:
            RuntimeError: If the model hasn't been trained yet.
        """
        if not self._is_trained:
            raise RuntimeError(
                "AutoencoderVerifier has not been trained yet"
            )

        sample = np.atleast_2d(sample).astype(np.float64)
        reconstructed = self.forward(sample)
        mse = float(np.mean((sample - reconstructed) ** 2))
        return mse

    def verify(self, sample: np.ndarray) -> tuple[bool, float]:
        """Verify whether a flagged sample is a true anomaly.

        Computes the reconstruction error and compares it against
        the learned threshold.

        Args:
            sample: 2D array of shape (1, input_dim).

        Returns:
            Tuple of (is_anomaly, reconstruction_error).
            is_anomaly is True if the error exceeds the threshold
            (confirmed anomaly), False if below (false positive).

        Raises:
            RuntimeError: If the model hasn't been trained yet or
                          no threshold has been set.
        """
        if not self._is_trained:
            raise RuntimeError(
                "AutoencoderVerifier has not been trained yet"
            )

        if self._threshold is None:
            raise RuntimeError(
                "No threshold set — train the model or provide a "
                "fixed threshold at initialization"
            )

        error = self.score(sample)
        is_anomaly = error > self._threshold
        return (is_anomaly, error)
