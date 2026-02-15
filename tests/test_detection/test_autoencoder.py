"""Tests for the Autoencoder Verifier deep anomaly detection engine."""

from __future__ import annotations

import numpy as np
import pytest

from aegis.detection.autoencoder import MIN_TRAINING_SAMPLES, AutoencoderVerifier

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def normal_data() -> np.ndarray:
    """Generate 100 normal-distribution samples with 64 features."""
    rng = np.random.default_rng(42)
    return rng.normal(loc=0.0, scale=1.0, size=(100, 64))


@pytest.fixture()
def trained_verifier(normal_data: np.ndarray) -> AutoencoderVerifier:
    """Return an AutoencoderVerifier already trained on normal data."""
    verifier = AutoencoderVerifier(input_dim=64, latent_dim=8)
    verifier.train(normal_data)
    return verifier


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestAutoencoderVerifierInit:
    """Tests for AutoencoderVerifier construction and default values."""

    def test_default_initialization(self) -> None:
        verifier = AutoencoderVerifier()
        assert verifier.input_dim == 64
        assert verifier.latent_dim == 8
        assert verifier.threshold is None
        assert verifier.is_trained is False

    def test_custom_input_dim(self) -> None:
        verifier = AutoencoderVerifier(input_dim=128)
        assert verifier.input_dim == 128

    def test_custom_latent_dim(self) -> None:
        verifier = AutoencoderVerifier(latent_dim=16)
        assert verifier.latent_dim == 16

    def test_custom_threshold(self) -> None:
        verifier = AutoencoderVerifier(threshold=0.05)
        assert verifier.threshold == 0.05

    def test_all_custom_params(self) -> None:
        verifier = AutoencoderVerifier(input_dim=32, latent_dim=4, threshold=0.1)
        assert verifier.input_dim == 32
        assert verifier.latent_dim == 4
        assert verifier.threshold == 0.1
        assert verifier.is_trained is False


# ---------------------------------------------------------------------------
# Architecture property
# ---------------------------------------------------------------------------

class TestAutoencoderArchitecture:
    """Tests for the hidden layer architecture."""

    def test_architecture_is_symmetric(self) -> None:
        verifier = AutoencoderVerifier(latent_dim=8)
        sizes = verifier._hidden_layer_sizes
        # Encoder mirrors decoder around the latent layer
        assert sizes == (48, 32, 16, 8, 16, 32, 48)

    def test_architecture_uses_custom_latent_dim(self) -> None:
        verifier = AutoencoderVerifier(latent_dim=4)
        assert verifier._hidden_layer_sizes[3] == 4

    def test_architecture_length(self) -> None:
        verifier = AutoencoderVerifier()
        # 3 encoder layers + latent + 3 decoder layers = 7
        assert len(verifier._hidden_layer_sizes) == 7


# ---------------------------------------------------------------------------
# _relu helper
# ---------------------------------------------------------------------------

class TestReluHelper:
    """Tests for the standalone _relu activation function."""

    def test_relu_positive_values(self) -> None:
        from aegis.detection.autoencoder import _relu
        x = np.array([1.0, 2.0, 3.0])
        result = _relu(x)
        np.testing.assert_array_equal(result, np.array([1.0, 2.0, 3.0]))

    def test_relu_negative_values(self) -> None:
        from aegis.detection.autoencoder import _relu
        x = np.array([-1.0, -2.0, -3.0])
        result = _relu(x)
        np.testing.assert_array_equal(result, np.array([0.0, 0.0, 0.0]))

    def test_relu_mixed_values(self) -> None:
        from aegis.detection.autoencoder import _relu
        x = np.array([-5.0, 0.0, 5.0])
        result = _relu(x)
        np.testing.assert_array_equal(result, np.array([0.0, 0.0, 5.0]))

    def test_relu_zero_vector(self) -> None:
        from aegis.detection.autoencoder import _relu
        x = np.zeros(10)
        result = _relu(x)
        np.testing.assert_array_equal(result, np.zeros(10))

    def test_relu_2d_array(self) -> None:
        from aegis.detection.autoencoder import _relu
        x = np.array([[-1.0, 2.0], [3.0, -4.0]])
        result = _relu(x)
        expected = np.array([[0.0, 2.0], [3.0, 0.0]])
        np.testing.assert_array_equal(result, expected)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

class TestAutoencoderTraining:
    """Tests for the train() method."""

    def test_train_sets_is_trained(self, normal_data: np.ndarray) -> None:
        verifier = AutoencoderVerifier()
        verifier.train(normal_data)
        assert verifier.is_trained is True

    def test_train_auto_computes_threshold(self, normal_data: np.ndarray) -> None:
        verifier = AutoencoderVerifier()
        assert verifier.threshold is None
        verifier.train(normal_data)
        assert verifier.threshold is not None
        assert isinstance(verifier.threshold, float)
        assert verifier.threshold > 0.0

    def test_train_preserves_fixed_threshold(self, normal_data: np.ndarray) -> None:
        verifier = AutoencoderVerifier(threshold=0.99)
        verifier.train(normal_data)
        assert verifier.threshold == 0.99

    def test_train_extracts_weights(self, normal_data: np.ndarray) -> None:
        verifier = AutoencoderVerifier()
        verifier.train(normal_data)
        # hidden_layer_sizes has 7 layers, plus output = 8 weight matrices
        assert len(verifier._weights) == 8
        assert len(verifier._biases) == 8

    def test_train_insufficient_samples_raises(self) -> None:
        verifier = AutoencoderVerifier()
        small_data = np.random.default_rng(0).normal(size=(MIN_TRAINING_SAMPLES - 1, 64))
        with pytest.raises(ValueError, match="samples"):
            verifier.train(small_data)

    def test_train_exactly_minimum_samples(self) -> None:
        verifier = AutoencoderVerifier()
        data = np.random.default_rng(0).normal(size=(MIN_TRAINING_SAMPLES, 64))
        verifier.train(data)
        assert verifier.is_trained is True

    def test_train_wrong_feature_dim_raises(self, normal_data: np.ndarray) -> None:
        verifier = AutoencoderVerifier(input_dim=32)
        with pytest.raises(ValueError, match="features"):
            verifier.train(normal_data)  # normal_data has 64 features, not 32


# ---------------------------------------------------------------------------
# Forward pass
# ---------------------------------------------------------------------------

class TestAutoencoderForward:
    """Tests for the forward() method."""

    def test_forward_output_shape_single(
        self, trained_verifier: AutoencoderVerifier
    ) -> None:
        sample = np.random.default_rng(99).normal(size=(1, 64))
        output = trained_verifier.forward(sample)
        assert output.shape == (1, 64)

    def test_forward_output_shape_batch(
        self, trained_verifier: AutoencoderVerifier
    ) -> None:
        batch = np.random.default_rng(99).normal(size=(10, 64))
        output = trained_verifier.forward(batch)
        assert output.shape == (10, 64)

    def test_forward_untrained_raises(self) -> None:
        verifier = AutoencoderVerifier()
        sample = np.random.default_rng(0).normal(size=(1, 64))
        with pytest.raises(RuntimeError, match="not been trained"):
            verifier.forward(sample)

    def test_forward_returns_float64(
        self, trained_verifier: AutoencoderVerifier
    ) -> None:
        sample = np.random.default_rng(99).normal(size=(1, 64)).astype(np.float32)
        output = trained_verifier.forward(sample)
        assert output.dtype == np.float64


# ---------------------------------------------------------------------------
# Score method
# ---------------------------------------------------------------------------

class TestAutoencoderScore:
    """Tests for the score() method (reconstruction error)."""

    def test_score_returns_float(
        self, trained_verifier: AutoencoderVerifier, normal_data: np.ndarray
    ) -> None:
        score = trained_verifier.score(normal_data[0:1])
        assert isinstance(score, float)

    def test_score_nonnegative(
        self, trained_verifier: AutoencoderVerifier, normal_data: np.ndarray
    ) -> None:
        score = trained_verifier.score(normal_data[0:1])
        assert score >= 0.0

    def test_score_untrained_raises(self) -> None:
        verifier = AutoencoderVerifier()
        sample = np.random.default_rng(0).normal(size=(1, 64))
        with pytest.raises(RuntimeError, match="not been trained"):
            verifier.score(sample)

    def test_score_normal_data_is_low(
        self, trained_verifier: AutoencoderVerifier, normal_data: np.ndarray
    ) -> None:
        """Reconstruction error for training-like data should be small."""
        scores = [trained_verifier.score(normal_data[i:i + 1]) for i in range(10)]
        mean_score = np.mean(scores)
        # Normal data should have low reconstruction error
        assert mean_score < trained_verifier.threshold  # type: ignore[operator]

    def test_score_anomaly_data_is_higher(
        self, trained_verifier: AutoencoderVerifier
    ) -> None:
        """Extreme outlier should have higher reconstruction error than normal."""
        rng = np.random.default_rng(42)
        normal_sample = rng.normal(loc=0.0, scale=1.0, size=(1, 64))
        anomaly_sample = rng.normal(loc=50.0, scale=20.0, size=(1, 64))
        normal_score = trained_verifier.score(normal_sample)
        anomaly_score = trained_verifier.score(anomaly_sample)
        assert anomaly_score > normal_score


# ---------------------------------------------------------------------------
# Verify method
# ---------------------------------------------------------------------------

class TestAutoencoderVerify:
    """Tests for the verify() method (anomaly decision)."""

    def test_verify_returns_tuple(
        self, trained_verifier: AutoencoderVerifier, normal_data: np.ndarray
    ) -> None:
        result = trained_verifier.verify(normal_data[0:1])
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_verify_tuple_types(
        self, trained_verifier: AutoencoderVerifier, normal_data: np.ndarray
    ) -> None:
        is_anomaly, error = trained_verifier.verify(normal_data[0:1])
        assert isinstance(is_anomaly, bool)
        assert isinstance(error, float)

    def test_verify_normal_data_not_anomalous(
        self, trained_verifier: AutoencoderVerifier, normal_data: np.ndarray
    ) -> None:
        """Data similar to training set should not be flagged as anomalous."""
        is_anomaly, error = trained_verifier.verify(normal_data[0:1])
        assert is_anomaly is False
        assert error <= trained_verifier.threshold  # type: ignore[operator]

    def test_verify_extreme_anomaly_is_anomalous(
        self, trained_verifier: AutoencoderVerifier
    ) -> None:
        """Extreme outlier should be flagged as anomalous."""
        anomaly = np.full((1, 64), fill_value=100.0)
        is_anomaly, error = trained_verifier.verify(anomaly)
        assert is_anomaly is True
        assert error > trained_verifier.threshold  # type: ignore[operator]

    def test_verify_untrained_raises(self) -> None:
        verifier = AutoencoderVerifier()
        sample = np.random.default_rng(0).normal(size=(1, 64))
        with pytest.raises(RuntimeError, match="not been trained"):
            verifier.verify(sample)

    def test_verify_no_threshold_raises(self) -> None:
        """A trained model with no threshold should raise RuntimeError.

        This can happen when a fixed threshold is set to None and
        auto-computation is somehow skipped (defensive check).
        """
        verifier = AutoencoderVerifier()
        rng = np.random.default_rng(0)
        data = rng.normal(size=(MIN_TRAINING_SAMPLES, 64))
        # Train normally (sets threshold), then force it to None
        verifier.train(data)
        verifier._threshold = None
        sample = rng.normal(size=(1, 64))
        with pytest.raises(RuntimeError, match="No threshold"):
            verifier.verify(sample)


# ---------------------------------------------------------------------------
# Threshold auto-computation
# ---------------------------------------------------------------------------

class TestThresholdComputation:
    """Tests for auto-computed threshold behaviour."""

    def test_auto_threshold_is_positive(self, normal_data: np.ndarray) -> None:
        verifier = AutoencoderVerifier()
        verifier.train(normal_data)
        assert verifier.threshold is not None
        assert verifier.threshold > 0.0

    def test_auto_threshold_uses_mean_plus_2std(
        self, normal_data: np.ndarray
    ) -> None:
        """Threshold should equal mean(errors) + 2 * std(errors)."""
        verifier = AutoencoderVerifier()
        verifier.train(normal_data)

        # Recompute errors independently
        errors = np.array([
            verifier.score(normal_data[i:i + 1])
            for i in range(normal_data.shape[0])
        ])
        expected_threshold = float(np.mean(errors) + 2.0 * np.std(errors))
        assert verifier.threshold == pytest.approx(expected_threshold, rel=1e-6)

    def test_fixed_threshold_skips_auto(self, normal_data: np.ndarray) -> None:
        verifier = AutoencoderVerifier(threshold=0.123)
        verifier.train(normal_data)
        assert verifier.threshold == 0.123


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestAutoencoderEdgeCases:
    """Edge-case tests for robustness."""

    def test_zero_vector_input(
        self, trained_verifier: AutoencoderVerifier
    ) -> None:
        """Score and verify should handle an all-zero input without error."""
        zero_sample = np.zeros((1, 64))
        score = trained_verifier.score(zero_sample)
        assert isinstance(score, float)
        assert score >= 0.0

        is_anomaly, error = trained_verifier.verify(zero_sample)
        assert isinstance(is_anomaly, bool)
        assert isinstance(error, float)

    def test_identical_training_data(self) -> None:
        """Training on identical rows should still converge and set threshold."""
        verifier = AutoencoderVerifier(input_dim=64)
        identical = np.ones((MIN_TRAINING_SAMPLES, 64)) * 3.0
        verifier.train(identical)
        assert verifier.is_trained is True
        assert verifier.threshold is not None

    def test_large_value_input(
        self, trained_verifier: AutoencoderVerifier
    ) -> None:
        """Very large feature values produce high reconstruction error."""
        big_sample = np.full((1, 64), fill_value=1e6)
        score = trained_verifier.score(big_sample)
        assert score > 0.0

    def test_min_training_samples_constant(self) -> None:
        """MIN_TRAINING_SAMPLES is a sensible positive integer."""
        assert isinstance(MIN_TRAINING_SAMPLES, int)
        assert MIN_TRAINING_SAMPLES > 0

    def test_score_with_1d_input(
        self, trained_verifier: AutoencoderVerifier
    ) -> None:
        """score() uses np.atleast_2d so 1-D input should be handled."""
        sample_1d = np.random.default_rng(7).normal(size=(64,))
        score = trained_verifier.score(sample_1d)
        assert isinstance(score, float)
        assert score >= 0.0
