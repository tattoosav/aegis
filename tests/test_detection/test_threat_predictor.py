"""Tests for MITRE ATT&CK threat prediction."""
from __future__ import annotations

from aegis.detection.threat_predictor import (
    PredictionResult,
    ThreatPredictor,
)


class TestThreatPredictor:
    def test_predict_from_known_chain(self):
        predictor = ThreatPredictor()
        result = predictor.predict(["T1566", "T1059"])
        assert isinstance(result, PredictionResult)
        assert len(result.predictions) >= 1
        assert result.predictions[0].probability > 0

    def test_empty_sequence_returns_no_prediction(self):
        predictor = ThreatPredictor()
        result = predictor.predict([])
        assert len(result.predictions) == 0

    def test_unknown_technique_handled(self):
        predictor = ThreatPredictor()
        result = predictor.predict(["T9999"])
        assert isinstance(result, PredictionResult)

    def test_prediction_has_defensive_recommendation(self):
        predictor = ThreatPredictor()
        result = predictor.predict(["T1566", "T1059", "T1055"])
        for pred in result.predictions:
            assert pred.defense is not None

    def test_confidence_calibration(self):
        predictor = ThreatPredictor()
        result = predictor.predict(["T1566"])
        for pred in result.predictions:
            assert 0.0 <= pred.probability <= 1.0
