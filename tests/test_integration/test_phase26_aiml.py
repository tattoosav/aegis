"""Phase 26 integration tests — AI/ML enhancement pipeline end-to-end.

Tests the full flow: feature extraction -> training pipeline -> scoring
-> drift detection -> threat prediction -> LLM triage fallback.
All tests are fast (no real API calls, mocked where necessary).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from aegis.core.models import AegisEvent, Alert, SensorType, Severity
from aegis.detection.threat_predictor import (
    PredictionResult,
    ThreatPredictor,
)
from aegis.intelligence.llm_analyzer import (
    LLMAnalyzer,
    LLMConfig,
    TriageResult,
)
from aegis.ml.drift_detector import DriftDetector, DriftResult
from aegis.ml.feature_extractor import FeatureExtractor
from aegis.ml.training_pipeline import (
    TrainingPipeline,
    TrainingStatus,
)

# ── helpers ─────────────────────────────────────────────────────────


def _make_network_event(
    *,
    connections: int = 10,
    ips: int = 3,
    ports: int = 2,
    dns: int = 5,
    severity: Severity = Severity.INFO,
) -> AegisEvent:
    """Create a NETWORK event with realistic data fields."""
    return AegisEvent(
        sensor=SensorType.NETWORK,
        event_type="traffic_summary",
        severity=severity,
        data={
            "total_connections": connections,
            "unique_remote_ips": ips,
            "unique_remote_ports": ports,
            "dns_query_count": dns,
        },
    )


def _make_process_event(
    *,
    cpu: float = 5.0,
    mem: float = 120.0,
    threads: int = 4,
    cmdline: str = "notepad.exe",
    severity: Severity = Severity.INFO,
) -> AegisEvent:
    """Create a PROCESS event with realistic data fields."""
    return AegisEvent(
        sensor=SensorType.PROCESS,
        event_type="process_snapshot",
        severity=severity,
        data={
            "cpu_percent": cpu,
            "memory_mb": mem,
            "num_threads": threads,
            "cmdline": cmdline,
        },
    )


def _make_alert(
    severity: Severity = Severity.HIGH,
    mitre_ids: list[str] | None = None,
) -> Alert:
    """Create an Alert suitable for triage testing."""
    return Alert(
        event_id="evt-test123",
        sensor=SensorType.NETWORK,
        alert_type="anomaly",
        severity=severity,
        title="Suspicious outbound traffic",
        description="Unusual volume of outbound connections to rare IP",
        confidence=0.85,
        data={"dst_ip": "198.51.100.42", "bytes_out": 500_000},
        mitre_ids=mitre_ids or ["T1041"],
    )


def _attack_chains_file(tmp_path: Path) -> Path:
    """Write a minimal attack_chains.json and return its path."""
    chains_data: dict[str, Any] = {
        "description": "Test chains",
        "version": "1.0.0",
        "chains": [
            {
                "name": "test chain A",
                "techniques": ["T1566", "T1059", "T1082", "T1041"],
            },
            {
                "name": "test chain B",
                "techniques": ["T1566", "T1059", "T1055", "T1003"],
            },
            {
                "name": "test chain C",
                "techniques": [
                    "T1059", "T1082", "T1005", "T1041",
                ],
            },
        ],
        "technique_metadata": {
            "T1566": {"name": "Phishing", "tactic": "initial-access"},
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "execution",
            },
            "T1082": {
                "name": "System Information Discovery",
                "tactic": "discovery",
            },
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "tactic": "exfiltration",
            },
            "T1055": {
                "name": "Process Injection",
                "tactic": "defense-evasion",
            },
            "T1003": {
                "name": "OS Credential Dumping",
                "tactic": "credential-access",
            },
            "T1005": {
                "name": "Data from Local System",
                "tactic": "collection",
            },
        },
        "defensive_recommendations": {
            "T1059": "Restrict scripting engines via AppLocker.",
            "T1082": "Monitor enumeration commands.",
        },
    }
    path = tmp_path / "attack_chains.json"
    path.write_text(json.dumps(chains_data), encoding="utf-8")
    return path


# ── fixtures ────────────────────────────────────────────────────────


@pytest.fixture()
def extractor() -> FeatureExtractor:
    return FeatureExtractor()


@pytest.fixture()
def pipeline(tmp_path: Path) -> TrainingPipeline:
    return TrainingPipeline(min_samples=30, model_dir=tmp_path / "models")


@pytest.fixture()
def drift_detector() -> DriftDetector:
    return DriftDetector(window_size=20, threshold=3.0)


@pytest.fixture()
def predictor(tmp_path: Path) -> ThreatPredictor:
    chains_path = _attack_chains_file(tmp_path)
    return ThreatPredictor(chains_path=chains_path, max_predictions=5)


@pytest.fixture()
def llm_analyzer() -> LLMAnalyzer:
    """Analyzer with no API key — always falls back to templates."""
    return LLMAnalyzer(api_key=None, config=LLMConfig(api_key=None))


# ── Scenario 1: Feature extraction -> Training ─────────────────────


class TestFeatureExtractionToTraining:
    """Extract features from events, feed to pipeline, train."""

    def test_extract_and_add_samples(
        self, extractor: FeatureExtractor, pipeline: TrainingPipeline
    ) -> None:
        """Features from events can be ingested by the pipeline."""
        events = [_make_network_event() for _ in range(10)]
        features_list = extractor.batch_extract(events)

        assert len(features_list) == 10
        for feats in features_list:
            assert isinstance(feats, dict)
            assert "severity_ordinal" in feats
            assert "timestamp" in feats
            pipeline.add_sample(feats)

        assert pipeline.sample_count == 10

    def test_train_when_enough_samples(
        self, extractor: FeatureExtractor, pipeline: TrainingPipeline
    ) -> None:
        """Pipeline trains successfully after min_samples reached."""
        rng = np.random.default_rng(42)
        for _ in range(35):
            evt = _make_network_event(
                connections=int(rng.integers(5, 50)),
                ips=int(rng.integers(1, 20)),
                ports=int(rng.integers(1, 10)),
                dns=int(rng.integers(0, 30)),
            )
            feats = extractor.extract(evt)
            pipeline.add_sample(feats)

        assert pipeline.status == TrainingStatus.COLLECTING
        result = pipeline.train()
        assert result is True
        assert pipeline.status == TrainingStatus.TRAINED
        assert pipeline.current_version is not None
        assert pipeline.current_version.version == 1
        assert pipeline.current_version.model_type == "isolation_forest"

    def test_train_rejected_when_too_few(
        self, extractor: FeatureExtractor, pipeline: TrainingPipeline
    ) -> None:
        """Pipeline refuses to train with insufficient samples."""
        for _ in range(5):
            feats = extractor.extract(_make_network_event())
            pipeline.add_sample(feats)

        assert pipeline.train() is False
        assert pipeline.status == TrainingStatus.COLLECTING


# ── Scenario 2: Training -> Scoring ────────────────────────────────


class TestTrainingToScoring:
    """After training, score new events for anomalousness."""

    def _trained_pipeline(
        self,
        extractor: FeatureExtractor,
        pipeline: TrainingPipeline,
    ) -> TrainingPipeline:
        """Populate and train, returning the same pipeline."""
        rng = np.random.default_rng(99)
        for _ in range(35):
            evt = _make_network_event(
                connections=int(rng.integers(8, 15)),
                ips=int(rng.integers(2, 6)),
                ports=int(rng.integers(1, 4)),
                dns=int(rng.integers(3, 10)),
            )
            pipeline.add_sample(extractor.extract(evt))
        assert pipeline.train() is True
        return pipeline

    def test_score_normal_event(
        self, extractor: FeatureExtractor, pipeline: TrainingPipeline
    ) -> None:
        """Normal events should score low anomaly (close to 0)."""
        pipe = self._trained_pipeline(extractor, pipeline)
        normal = _make_network_event(
            connections=10, ips=3, ports=2, dns=5,
        )
        score = pipe.score(extractor.extract(normal))
        assert 0.0 <= score <= 1.0

    def test_score_anomalous_event(
        self, extractor: FeatureExtractor, pipeline: TrainingPipeline
    ) -> None:
        """Extreme events should score higher than normal ones."""
        pipe = self._trained_pipeline(extractor, pipeline)

        normal_feats = extractor.extract(
            _make_network_event(connections=10, ips=3, ports=2, dns=5)
        )
        anomalous_feats = extractor.extract(
            _make_network_event(
                connections=9999,
                ips=500,
                ports=300,
                dns=2000,
                severity=Severity.CRITICAL,
            )
        )

        normal_score = pipe.score(normal_feats)
        anomalous_score = pipe.score(anomalous_feats)

        assert 0.0 <= normal_score <= 1.0
        assert 0.0 <= anomalous_score <= 1.0
        # Anomalous event should generally score higher
        assert anomalous_score >= normal_score

    def test_score_before_training_raises(
        self,
        extractor: FeatureExtractor,
        pipeline: TrainingPipeline,
    ) -> None:
        """Scoring without a trained model raises RuntimeError."""
        feats = extractor.extract(_make_network_event())
        with pytest.raises(RuntimeError, match="no trained model"):
            pipeline.score(feats)


# ── Scenario 3: Drift detection flow ───────────────────────────────


class TestDriftDetectionFlow:
    """Feed stable data then shifted data; verify drift is detected."""

    def test_no_drift_on_stable_data(
        self,
        extractor: FeatureExtractor,
        drift_detector: DriftDetector,
    ) -> None:
        """Stable features should NOT trigger drift."""
        rng = np.random.default_rng(7)
        fixed_ts = 1_700_000_000.0
        for _ in range(50):
            evt = _make_network_event(
                connections=int(rng.integers(8, 15)),
                ips=int(rng.integers(2, 6)),
            )
            feats = extractor.extract(evt)
            # Pin timestamp to avoid natural clock drift between
            # baseline and recent windows.
            feats["timestamp"] = fixed_ts
            drift_detector.update(feats)

        result = drift_detector.check()
        assert isinstance(result, DriftResult)
        assert result.drift_detected is False

    def test_drift_detected_after_distribution_shift(
        self,
        extractor: FeatureExtractor,
        drift_detector: DriftDetector,
    ) -> None:
        """A large distribution shift in features triggers drift."""
        ws = drift_detector.window_size  # 20

        # Baseline window: low values
        for _ in range(ws):
            evt = _make_network_event(connections=10, ips=3)
            drift_detector.update(extractor.extract(evt))

        # Recent window: massively shifted values
        for _ in range(ws):
            evt = _make_network_event(connections=5000, ips=800)
            drift_detector.update(extractor.extract(evt))

        result = drift_detector.check()
        assert result.drift_detected is True
        assert len(result.drifted_features) > 0
        # At least the connection-related feature should drift
        assert any(
            "connections" in f or "ips" in f
            for f in result.drifted_features
        )

    def test_drift_reset_clears_state(
        self, drift_detector: DriftDetector
    ) -> None:
        """After reset, no drift should be detected."""
        for _ in range(50):
            drift_detector.update({"x": 1.0})
        drift_detector.reset()
        result = drift_detector.check()
        assert result.drift_detected is False
        assert result.drifted_features == []


# ── Scenario 4: Threat prediction ──────────────────────────────────


class TestThreatPrediction:
    """Predict next MITRE techniques from observed IDs."""

    def test_predict_returns_results(
        self, predictor: ThreatPredictor
    ) -> None:
        """Observed techniques yield non-empty predictions."""
        result = predictor.predict(["T1566"])
        assert isinstance(result, PredictionResult)
        assert len(result.predictions) > 0

    def test_predictions_have_required_fields(
        self, predictor: ThreatPredictor
    ) -> None:
        """Each prediction contains technique_id, name, probability."""
        result = predictor.predict(["T1566"])
        for pred in result.predictions:
            assert pred.technique_id
            assert pred.name
            assert 0.0 < pred.probability < 1.0
            assert pred.mitre_tactic

    def test_predictions_sorted_descending(
        self, predictor: ThreatPredictor
    ) -> None:
        """Predictions are sorted by probability descending."""
        result = predictor.predict(["T1566"])
        probs = [p.probability for p in result.predictions]
        assert probs == sorted(probs, reverse=True)

    def test_unknown_technique_returns_empty(
        self, predictor: ThreatPredictor
    ) -> None:
        """Unrecognised technique IDs yield an empty result."""
        result = predictor.predict(["T9999"])
        assert isinstance(result, PredictionResult)
        assert result.predictions == []

    def test_empty_observed_returns_empty(
        self, predictor: ThreatPredictor
    ) -> None:
        """Empty observed list returns empty predictions."""
        result = predictor.predict([])
        assert result.predictions == []

    def test_chain_continuation(
        self, predictor: ThreatPredictor
    ) -> None:
        """Last observed technique drives the predictions."""
        # T1059 appears as source in multiple chains
        result = predictor.predict(["T1566", "T1059"])
        assert len(result.predictions) > 0
        predicted_ids = {p.technique_id for p in result.predictions}
        # T1082 and T1055 follow T1059 in the test chains
        assert predicted_ids & {"T1082", "T1055"}


# ── Scenario 5: LLM triage fallback ───────────────────────────────


class TestLLMTriageFallback:
    """Offline triage returns template result with correct structure."""

    def test_triage_returns_template(
        self, llm_analyzer: LLMAnalyzer
    ) -> None:
        """Without API key, triage falls back to templates."""
        alert = _make_alert(severity=Severity.HIGH)
        result = llm_analyzer.triage(alert)
        assert isinstance(result, TriageResult)
        assert result.source == "template"

    def test_triage_result_structure(
        self, llm_analyzer: LLMAnalyzer
    ) -> None:
        """Template triage result has all required fields."""
        alert = _make_alert(severity=Severity.CRITICAL)
        result = llm_analyzer.triage(alert)

        assert isinstance(result.severity_assessment, str)
        assert len(result.severity_assessment) > 0
        assert isinstance(result.narrative, str)
        assert len(result.narrative) > 0
        assert isinstance(result.investigation_steps, list)
        assert len(result.investigation_steps) > 0
        assert 0.0 <= result.fp_likelihood <= 1.0

    def test_triage_severity_drives_steps(
        self, llm_analyzer: LLMAnalyzer
    ) -> None:
        """Higher severity alerts get more investigation steps."""
        critical = llm_analyzer.triage(
            _make_alert(severity=Severity.CRITICAL)
        )
        info = llm_analyzer.triage(
            _make_alert(severity=Severity.INFO)
        )
        assert len(critical.investigation_steps) > len(
            info.investigation_steps
        )

    def test_triage_fp_likelihood_varies_by_severity(
        self, llm_analyzer: LLMAnalyzer
    ) -> None:
        """Lower severity alerts have higher false-positive likelihood."""
        high = llm_analyzer.triage(_make_alert(severity=Severity.HIGH))
        low = llm_analyzer.triage(_make_alert(severity=Severity.LOW))
        assert low.fp_likelihood > high.fp_likelihood

    def test_nl_to_sql_fallback(
        self, llm_analyzer: LLMAnalyzer
    ) -> None:
        """NL-to-SQL falls back to template SQL."""
        sql = llm_analyzer.nl_to_sql("show me recent alerts")
        assert sql is not None
        assert sql.upper().startswith("SELECT")

    def test_summarize_incident_fallback(
        self, llm_analyzer: LLMAnalyzer
    ) -> None:
        """Incident summary falls back to template."""
        alert = _make_alert(severity=Severity.HIGH)
        incident: dict[str, Any] = {
            "title": "Test incident",
            "severity": Severity.HIGH,
            "alerts": [alert],
        }
        summary = llm_analyzer.summarize_incident(incident)
        assert isinstance(summary, str)
        assert "Test incident" in summary


# ── Scenario 6: Full end-to-end pipeline ───────────────────────────


class TestFullPipeline:
    """Event -> features -> training -> scoring -> drift -> prediction.

    Exercises the entire Phase 26 AI/ML stack in a single flow.
    """

    def test_end_to_end(
        self,
        extractor: FeatureExtractor,
        pipeline: TrainingPipeline,
        drift_detector: DriftDetector,
        predictor: ThreatPredictor,
        llm_analyzer: LLMAnalyzer,
        tmp_path: Path,
    ) -> None:
        """Full pipeline from raw events to triage result."""
        rng = np.random.default_rng(42)

        # Step 1: Generate baseline events and extract features
        baseline_events = [
            _make_network_event(
                connections=int(rng.integers(8, 15)),
                ips=int(rng.integers(2, 6)),
                ports=int(rng.integers(1, 4)),
                dns=int(rng.integers(3, 10)),
            )
            for _ in range(35)
        ]
        baseline_features = extractor.batch_extract(baseline_events)
        assert len(baseline_features) == 35

        # Step 2: Feed features to pipeline and train
        for feats in baseline_features:
            pipeline.add_sample(feats)
        assert pipeline.train() is True
        assert pipeline.status == TrainingStatus.TRAINED

        # Step 3: Score a new event
        new_event = _make_network_event(
            connections=10, ips=3, ports=2, dns=6,
        )
        new_feats = extractor.extract(new_event)
        score = pipeline.score(new_feats)
        assert 0.0 <= score <= 1.0

        # Step 4: Feed features to drift detector (stable window)
        ws = drift_detector.window_size
        for feats in baseline_features[:ws]:
            drift_detector.update(feats)
        # Feed more stable features for the recent window
        for feats in baseline_features[ws:2 * ws]:
            drift_detector.update(feats)
        drift_result = drift_detector.check()
        assert isinstance(drift_result, DriftResult)
        # Should NOT drift since both windows are from same dist
        assert drift_result.drift_detected is False

        # Step 5: Threat prediction from observed MITRE techniques
        prediction = predictor.predict(["T1566", "T1059"])
        assert len(prediction.predictions) > 0
        predicted_ids = {
            p.technique_id for p in prediction.predictions
        }
        assert len(predicted_ids) > 0

        # Step 6: LLM triage on a generated alert
        alert = _make_alert(
            severity=Severity.HIGH,
            mitre_ids=list(predicted_ids)[:2],
        )
        triage = llm_analyzer.triage(alert)
        assert isinstance(triage, TriageResult)
        assert triage.source == "template"
        assert len(triage.investigation_steps) > 0

    def test_drift_triggers_retrain_flow(
        self,
        extractor: FeatureExtractor,
        pipeline: TrainingPipeline,
        drift_detector: DriftDetector,
    ) -> None:
        """When drift is detected, retraining succeeds with new data."""
        rng = np.random.default_rng(123)
        ws = drift_detector.window_size  # 20

        # Phase A: train on baseline data
        for _ in range(35):
            evt = _make_network_event(
                connections=int(rng.integers(8, 15)),
                ips=int(rng.integers(2, 6)),
            )
            feats = extractor.extract(evt)
            pipeline.add_sample(feats)
            drift_detector.update(feats)

        assert pipeline.train() is True
        v1 = pipeline.current_version
        assert v1 is not None

        # Phase B: inject heavily shifted data
        for _ in range(ws):
            evt = _make_network_event(connections=9000, ips=500)
            feats = extractor.extract(evt)
            pipeline.add_sample(feats)
            drift_detector.update(feats)

        drift_result = drift_detector.check()
        assert drift_result.drift_detected is True

        # Phase C: retrain with combined data
        retrain_ok = pipeline.train()
        assert retrain_ok is True
        v2 = pipeline.current_version
        assert v2 is not None
        assert v2.version == 2

    def test_process_events_full_flow(
        self,
        extractor: FeatureExtractor,
        pipeline: TrainingPipeline,
    ) -> None:
        """Full flow also works with PROCESS sensor events."""
        rng = np.random.default_rng(55)
        for _ in range(35):
            evt = _make_process_event(
                cpu=float(rng.uniform(1, 30)),
                mem=float(rng.uniform(50, 500)),
                threads=int(rng.integers(1, 20)),
                cmdline="svchost.exe -k netsvcs",
            )
            feats = extractor.extract(evt)
            pipeline.add_sample(feats)

        assert pipeline.train() is True

        # Score a normal process
        normal_feats = extractor.extract(
            _make_process_event(
                cpu=5.0, mem=120.0, threads=4,
                cmdline="svchost.exe -k netsvcs",
            )
        )
        score_normal = pipeline.score(normal_feats)
        assert 0.0 <= score_normal <= 1.0

        # Score an unusual process
        odd_feats = extractor.extract(
            _make_process_event(
                cpu=99.0,
                mem=8000.0,
                threads=500,
                cmdline="powershell -enc QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
                severity=Severity.HIGH,
            )
        )
        score_odd = pipeline.score(odd_feats)
        assert 0.0 <= score_odd <= 1.0
