"""Tests for adaptive baseline training pipeline."""
from __future__ import annotations

import numpy as np
import pytest

from aegis.ml.training_pipeline import (
    ModelVersion,
    TrainingPipeline,
    TrainingStatus,
)


class TestModelVersion:
    def test_creation(self) -> None:
        mv = ModelVersion(
            version=1,
            timestamp=1000.0,
            model_type="isolation_forest",
            metrics={"score": 0.95},
        )
        assert mv.version == 1
        assert mv.timestamp == 1000.0
        assert mv.model_type == "isolation_forest"
        assert mv.metrics == {"score": 0.95}

    def test_default_path_is_none(self) -> None:
        mv = ModelVersion(
            version=1,
            timestamp=1000.0,
            model_type="isolation_forest",
            metrics={},
        )
        assert mv.path is None


class TestTrainingPipeline:
    def test_status_starts_collecting(self) -> None:
        pipeline = TrainingPipeline()
        assert pipeline.status == TrainingStatus.COLLECTING

    def test_add_samples(self) -> None:
        pipeline = TrainingPipeline(min_samples=10)
        for i in range(5):
            pipeline.add_sample({"f1": float(i), "f2": float(i * 2)})
        assert pipeline.sample_count == 5

    def test_train_requires_min_samples(self) -> None:
        pipeline = TrainingPipeline(min_samples=50)
        pipeline.add_sample({"f1": 1.0})
        result = pipeline.train()
        assert result is False

    def test_train_succeeds_with_enough_samples(self) -> None:
        pipeline = TrainingPipeline(min_samples=10)
        rng = np.random.default_rng(42)
        for _ in range(20):
            pipeline.add_sample({
                "f1": rng.normal(0, 1),
                "f2": rng.normal(5, 2),
            })
        result = pipeline.train()
        assert result is True
        assert pipeline.status == TrainingStatus.TRAINED

    def test_score_after_training(self) -> None:
        pipeline = TrainingPipeline(min_samples=10)
        rng = np.random.default_rng(42)
        for _ in range(50):
            pipeline.add_sample({
                "f1": rng.normal(0, 1),
                "f2": rng.normal(5, 2),
            })
        pipeline.train()
        score = pipeline.score({"f1": 0.0, "f2": 5.0})
        assert 0.0 <= score <= 1.0

    def test_score_before_training_raises(self) -> None:
        pipeline = TrainingPipeline(min_samples=10)
        with pytest.raises(RuntimeError):
            pipeline.score({"f1": 0.0})

    def test_model_versioning(self) -> None:
        pipeline = TrainingPipeline(min_samples=10)
        rng = np.random.default_rng(42)
        for _ in range(20):
            pipeline.add_sample({"f1": rng.normal()})
        pipeline.train()
        assert pipeline.current_version.version == 1
        pipeline.train()
        assert pipeline.current_version.version == 2

    def test_rollback(self) -> None:
        pipeline = TrainingPipeline(min_samples=10)
        rng = np.random.default_rng(42)
        for _ in range(20):
            pipeline.add_sample({"f1": rng.normal()})
        pipeline.train()
        assert pipeline.current_version.version == 1
        pipeline.train()
        assert pipeline.current_version.version == 2
        pipeline.rollback()
        assert pipeline.current_version.version == 1

    def test_rollback_with_no_history_raises(self) -> None:
        pipeline = TrainingPipeline(min_samples=10)
        rng = np.random.default_rng(42)
        for _ in range(20):
            pipeline.add_sample({"f1": rng.normal()})
        pipeline.train()
        with pytest.raises(RuntimeError):
            pipeline.rollback()

    def test_status_during_collecting(self) -> None:
        pipeline = TrainingPipeline(min_samples=100)
        for i in range(5):
            pipeline.add_sample({"f1": float(i)})
        assert pipeline.status == TrainingStatus.COLLECTING

    def test_current_version_before_training_is_none(self) -> None:
        pipeline = TrainingPipeline()
        assert pipeline.current_version is None
