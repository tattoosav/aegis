"""Tests for the Isolation Forest anomaly detection engine."""

import numpy as np
import pytest

from aegis.core.models import AegisEvent, SensorType
from aegis.detection.anomaly import AnomalyDetector


class TestAnomalyDetectorInit:
    def test_create_detector(self):
        detector = AnomalyDetector(domain="network")
        assert detector.domain == "network"
        assert detector.is_trained is False

    def test_default_config(self):
        detector = AnomalyDetector(domain="process")
        assert detector.n_estimators == 100
        assert detector.contamination == 0.01


class TestAnomalyDetectorTraining:
    def test_train_on_feature_vectors(self):
        detector = AnomalyDetector(domain="test")
        # Generate some normal data
        np.random.seed(42)
        normal_data = np.random.randn(200, 5) * 0.5 + 5.0
        detector.train(normal_data)
        assert detector.is_trained is True

    def test_train_requires_minimum_samples(self):
        detector = AnomalyDetector(domain="test")
        small_data = np.array([[1.0, 2.0, 3.0]])
        with pytest.raises(ValueError, match="samples"):
            detector.train(small_data)

    def test_score_after_training(self):
        detector = AnomalyDetector(domain="test")
        np.random.seed(42)
        normal_data = np.random.randn(200, 5) * 0.5 + 5.0
        detector.train(normal_data)

        # Score a normal sample — should be low (close to 0)
        normal_sample = np.array([[5.0, 5.1, 4.9, 5.2, 4.8]])
        score = detector.score(normal_sample)
        assert 0.0 <= score <= 1.0
        assert score < 0.5  # Should be "normal"

    def test_score_anomaly_is_high(self):
        detector = AnomalyDetector(domain="test")
        np.random.seed(42)
        normal_data = np.random.randn(200, 5) * 0.5 + 5.0
        detector.train(normal_data)

        # Score an extreme outlier — should be high (close to 1)
        anomaly_sample = np.array([[100.0, -50.0, 200.0, -100.0, 300.0]])
        score = detector.score(anomaly_sample)
        assert 0.0 <= score <= 1.0
        assert score > 0.5  # Should be "anomalous"

    def test_score_before_training_raises(self):
        detector = AnomalyDetector(domain="test")
        sample = np.array([[1.0, 2.0, 3.0]])
        with pytest.raises(RuntimeError, match="trained"):
            detector.score(sample)


class TestAnomalyDetectorRouting:
    def test_classify_normal(self):
        detector = AnomalyDetector(domain="test")
        assert detector.classify(0.2) == "normal"
        assert detector.classify(0.39) == "normal"

    def test_classify_suspicious(self):
        detector = AnomalyDetector(domain="test")
        assert detector.classify(0.4) == "suspicious"
        assert detector.classify(0.59) == "suspicious"

    def test_classify_anomalous(self):
        detector = AnomalyDetector(domain="test")
        assert detector.classify(0.6) == "anomalous"
        assert detector.classify(1.0) == "anomalous"


class TestAnomalyDetectorFeatureExtraction:
    def test_extract_network_features(self):
        """Network flow stats event can be converted to feature vector."""
        detector = AnomalyDetector(domain="network")
        event = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="network_flow_stats",
            data={
                "total_connections": 50,
                "unique_remote_ips": 10,
                "unique_remote_ports": 15,
                "port_entropy": 2.5,
                "new_destination_rate": 3,
                "dns_query_count": 5,
            },
        )
        features = detector.extract_features(event)
        assert features is not None
        assert len(features) >= 4  # At least the key numeric features

    def test_extract_process_features(self):
        """Process snapshot event can be converted to feature vector."""
        detector = AnomalyDetector(domain="process")
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={
                "cpu_percent": 5.0,
                "memory_mb": 120.5,
                "num_threads": 10,
                "cmdline_entropy": 3.2,
                "lineage_depth": 2,
                "num_connections": 3,
                "num_open_files": 10,
            },
        )
        features = detector.extract_features(event)
        assert features is not None
        assert len(features) >= 4

    def test_extract_features_unknown_domain(self):
        """Unknown domain returns None."""
        detector = AnomalyDetector(domain="unknown_domain")
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"cpu_percent": 5.0},
        )
        features = detector.extract_features(event)
        assert features is None
