"""Tests for DetectionPipeline orchestrator."""

from __future__ import annotations

import time
from dataclasses import dataclass
from unittest.mock import MagicMock

from aegis.core.models import (
    AegisEvent,
    Alert,
    AlertStatus,
    SensorType,
    Severity,
)
from aegis.detection.pipeline import (
    DetectionPipeline,
)

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _make_event(**overrides) -> AegisEvent:
    defaults = {
        "sensor": SensorType.NETWORK,
        "event_type": "connection",
        "data": {"dst_ip": "10.0.0.1", "dst_port": 443},
        "severity": Severity.INFO,
        "timestamp": time.time(),
    }
    defaults.update(overrides)
    return AegisEvent(**defaults)


@dataclass
class _FakeRule:
    rule_id: str = "test_rule"
    description: str = "Test rule matched"
    severity: Severity = Severity.HIGH
    mitre_ids: list = None

    def __post_init__(self):
        if self.mitre_ids is None:
            self.mitre_ids = ["T1071"]


@dataclass
class _FakeChain:
    chain_name: str = "ransomware"
    confidence: float = 0.92
    mitre_ids: list = None
    matched_nodes: list = None
    description: str = "Chain match"
    severity: str = "CRITICAL"
    timestamp: float = 0.0

    def __post_init__(self):
        if self.mitre_ids is None:
            self.mitre_ids = ["T1486"]
        if self.matched_nodes is None:
            self.matched_nodes = ["n1", "n2"]


# ------------------------------------------------------------------ #
# No engines configured — empty results
# ------------------------------------------------------------------ #

class TestPipelineNoEngines:
    """Pipeline with no engines should produce no alerts."""

    def test_returns_empty_list(self) -> None:
        pipeline = DetectionPipeline()
        event = _make_event()
        assert pipeline.process_event(event) == []


# ------------------------------------------------------------------ #
# Rule engine stage
# ------------------------------------------------------------------ #

class TestRuleEngineStage:
    """Tests for the rule engine fast-path."""

    def test_rule_match_produces_alert(self) -> None:
        engine = MagicMock()
        engine.evaluate.return_value = [_FakeRule()]
        pipeline = DetectionPipeline(rule_engine=engine)

        alerts = pipeline.process_event(_make_event())
        assert len(alerts) == 1
        assert alerts[0].alert_type == "rule_test_rule"
        assert alerts[0].confidence == 0.95

    def test_no_rule_match_produces_no_alert(self) -> None:
        engine = MagicMock()
        engine.evaluate.return_value = []
        pipeline = DetectionPipeline(rule_engine=engine)

        alerts = pipeline.process_event(_make_event())
        assert len(alerts) == 0

    def test_rule_engine_exception_handled(self) -> None:
        engine = MagicMock()
        engine.evaluate.side_effect = RuntimeError("boom")
        pipeline = DetectionPipeline(rule_engine=engine)

        alerts = pipeline.process_event(_make_event())
        assert len(alerts) == 0

    def test_rule_alert_includes_mitre_id(self) -> None:
        engine = MagicMock()
        engine.evaluate.return_value = [_FakeRule(mitre_ids=["T1059"])]
        pipeline = DetectionPipeline(rule_engine=engine)

        alerts = pipeline.process_event(_make_event())
        assert "T1059" in alerts[0].mitre_ids


# ------------------------------------------------------------------ #
# Statistical cascade
# ------------------------------------------------------------------ #

class TestStatisticalCascade:
    """Tests for Isolation Forest -> Autoencoder cascade."""

    def test_normal_score_no_alert(self) -> None:
        ad = MagicMock()
        ad.extract_features.return_value = [1.0, 2.0]
        ad.score.return_value = 0.2
        ad.classify.return_value = "normal"
        pipeline = DetectionPipeline(anomaly_detector=ad)

        assert pipeline.process_event(_make_event()) == []

    def test_suspicious_score_produces_medium_alert(self) -> None:
        ad = MagicMock()
        ad.extract_features.return_value = [1.0, 2.0]
        ad.score.return_value = 0.45
        ad.classify.return_value = "suspicious"
        pipeline = DetectionPipeline(anomaly_detector=ad)

        alerts = pipeline.process_event(_make_event())
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.MEDIUM
        assert alerts[0].alert_type == "statistical_anomaly"

    def test_anomalous_verified_by_autoencoder(self) -> None:
        ad = MagicMock()
        ad.extract_features.return_value = [1.0, 2.0]
        ad.score.return_value = 0.75
        ad.classify.return_value = "anomalous"

        ae = MagicMock()
        ae.verify.return_value = (True, 0.85)

        pipeline = DetectionPipeline(anomaly_detector=ad, autoencoder=ae)
        alerts = pipeline.process_event(_make_event())
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH
        assert alerts[0].alert_type == "confirmed_anomaly"

    def test_autoencoder_suppresses_false_positive(self) -> None:
        ad = MagicMock()
        ad.extract_features.return_value = [1.0, 2.0]
        ad.score.return_value = 0.75
        ad.classify.return_value = "anomalous"

        ae = MagicMock()
        ae.verify.return_value = (False, 0.02)

        pipeline = DetectionPipeline(anomaly_detector=ad, autoencoder=ae)
        alerts = pipeline.process_event(_make_event())
        assert len(alerts) == 0

    def test_autoencoder_failure_falls_back_to_if(self) -> None:
        ad = MagicMock()
        ad.extract_features.return_value = [1.0, 2.0]
        ad.score.return_value = 0.75
        ad.classify.return_value = "anomalous"

        ae = MagicMock()
        ae.verify.side_effect = RuntimeError("ae crash")

        pipeline = DetectionPipeline(anomaly_detector=ad, autoencoder=ae)
        alerts = pipeline.process_event(_make_event())
        assert len(alerts) == 1
        assert alerts[0].data["_engine"] == "isolation_forest"

    def test_no_features_extracted_returns_none(self) -> None:
        ad = MagicMock()
        ad.extract_features.return_value = None
        pipeline = DetectionPipeline(anomaly_detector=ad)

        assert pipeline.process_event(_make_event()) == []


# ------------------------------------------------------------------ #
# Parallel engines — URL classifier
# ------------------------------------------------------------------ #

class TestURLClassifier:
    """Tests for URL classification in parallel engines."""

    def test_malicious_url_alert(self) -> None:
        uc = MagicMock()
        uc.predict.return_value = ("malicious", 0.9)
        pipeline = DetectionPipeline(url_classifier=uc)

        event = _make_event(data={"url": "http://evil.com/payload.exe"})
        alerts = pipeline.process_event(event)
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH
        assert "url_malicious" == alerts[0].alert_type

    def test_benign_url_no_alert(self) -> None:
        uc = MagicMock()
        uc.predict.return_value = ("benign", 0.95)
        pipeline = DetectionPipeline(url_classifier=uc)

        event = _make_event(data={"url": "https://google.com"})
        assert pipeline.process_event(event) == []

    def test_no_url_in_event_skips_classifier(self) -> None:
        uc = MagicMock()
        pipeline = DetectionPipeline(url_classifier=uc)

        event = _make_event(data={"dst_ip": "10.0.0.1"})
        pipeline.process_event(event)
        uc.predict.assert_not_called()


# ------------------------------------------------------------------ #
# Parallel engines — Graph analyzer
# ------------------------------------------------------------------ #

class TestGraphAnalyzer:
    """Tests for graph analyzer in parallel engines."""

    def test_chain_match_produces_critical_alert(self) -> None:
        ga = MagicMock()
        ga.analyze.return_value = [_FakeChain()]
        pipeline = DetectionPipeline(graph_analyzer=ga)

        alerts = pipeline.process_event(_make_event())
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.CRITICAL
        assert "chain_ransomware" == alerts[0].alert_type

    def test_no_chain_match_no_alert(self) -> None:
        ga = MagicMock()
        ga.analyze.return_value = []
        pipeline = DetectionPipeline(graph_analyzer=ga)

        assert pipeline.process_event(_make_event()) == []


# ------------------------------------------------------------------ #
# Parallel engines — LSTM analyzer
# ------------------------------------------------------------------ #

class TestLSTMAnalyzer:
    """Tests for LSTM temporal pattern detection."""

    def test_beaconing_detected(self) -> None:
        lstm = MagicMock()
        lstm.detect_beaconing.return_value = (True, {
            "description": "C2 beaconing detected",
            "confidence": 0.88,
        })
        pipeline = DetectionPipeline(lstm_analyzer=lstm)

        alerts = pipeline.process_event(_make_event())
        assert len(alerts) == 1
        assert alerts[0].alert_type == "temporal_pattern"

    def test_no_pattern_no_alert(self) -> None:
        lstm = MagicMock()
        lstm.detect_beaconing.return_value = (False, {})
        pipeline = DetectionPipeline(lstm_analyzer=lstm)

        assert pipeline.process_event(_make_event()) == []


# ------------------------------------------------------------------ #
# Alert factory
# ------------------------------------------------------------------ #

class TestAlertFactory:
    """Tests for the _make_alert helper."""

    def test_alert_has_correct_fields(self) -> None:
        event = _make_event()
        alert = DetectionPipeline._make_alert(
            event=event,
            alert_type="test_type",
            title="Test Title",
            severity=Severity.HIGH,
            confidence=0.85,
            engine="test_engine",
            mitre_ids=["T1059"],
        )
        assert isinstance(alert, Alert)
        assert alert.event_id == event.event_id
        assert alert.sensor == event.sensor
        assert alert.alert_type == "test_type"
        assert alert.severity == Severity.HIGH
        assert alert.confidence == 0.85
        assert alert.status == AlertStatus.NEW
        assert "T1059" in alert.mitre_ids
        assert alert.alert_id.startswith("alt-")
        assert "test_engine" in alert.description

    def test_alert_with_no_mitre_ids(self) -> None:
        event = _make_event()
        alert = DetectionPipeline._make_alert(
            event=event,
            alert_type="test",
            title="T",
            severity=Severity.LOW,
            confidence=0.5,
            engine="e",
        )
        assert alert.mitre_ids == []


# ------------------------------------------------------------------ #
# Parallel engines — Memory forensics
# ------------------------------------------------------------------ #

class TestMemoryForensics:
    """Tests for memory forensics engine in parallel engines."""

    def test_pipeline_runs_memory_forensics_on_image_load(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.return_value = [
            Alert(
                event_id="evt-test",
                sensor=SensorType.ETW,
                alert_type="memory_reflective_dll",
                severity=Severity.CRITICAL,
                title="Reflective DLL",
                description="Test",
                confidence=0.95,
                data={},
                mitre_ids=["T1620"],
            )
        ]
        pipeline = DetectionPipeline(memory_forensics=mock_engine)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.process_image_load",
            data={"pid": 1234, "image_path": "\\evil.dll"},
        )
        alerts = pipeline.process_event(event)
        assert len(alerts) >= 1
        assert any(
            a.alert_type == "memory_reflective_dll" for a in alerts
        )

    def test_memory_forensics_not_called_for_unrelated_event(
        self,
    ) -> None:
        mock_engine = MagicMock()
        pipeline = DetectionPipeline(memory_forensics=mock_engine)
        event = _make_event(
            event_type="connection",
            data={"dst_ip": "10.0.0.1"},
        )
        pipeline.process_event(event)
        mock_engine.analyze_event.assert_not_called()

    def test_memory_forensics_called_for_process_new(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.return_value = []
        pipeline = DetectionPipeline(memory_forensics=mock_engine)
        event = _make_event(
            sensor=SensorType.PROCESS,
            event_type="process_new",
            data={"pid": 5678, "name": "suspicious.exe"},
        )
        pipeline.process_event(event)
        mock_engine.analyze_event.assert_called_once_with(event)

    def test_memory_forensics_exception_handled(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.side_effect = RuntimeError("boom")
        pipeline = DetectionPipeline(memory_forensics=mock_engine)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.process_image_load",
            data={"pid": 1234, "image_path": "\\evil.dll"},
        )
        alerts = pipeline.process_event(event)
        # Exception should be handled gracefully, not crash
        assert isinstance(alerts, list)

    def test_memory_forensics_none_skipped(self) -> None:
        pipeline = DetectionPipeline(memory_forensics=None)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.process_image_load",
            data={"pid": 1234, "image_path": "\\evil.dll"},
        )
        alerts = pipeline.process_event(event)
        assert alerts == []


# ------------------------------------------------------------------ #
# Parallel engines — Encrypted traffic
# ------------------------------------------------------------------ #

class TestEncryptedTraffic:
    """Tests for encrypted traffic engine in parallel engines."""

    def test_pipeline_runs_encrypted_traffic_on_tls(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.return_value = [
            Alert(
                event_id="evt-test",
                sensor=SensorType.ETW,
                alert_type="encrypted_traffic_malicious_ja3",
                severity=Severity.HIGH,
                title="Malicious JA3",
                description="Test",
                confidence=0.9,
                data={},
                mitre_ids=["T1573"],
            )
        ]
        pipeline = DetectionPipeline(encrypted_traffic=mock_engine)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={
                "server_name": "evil.com",
                "ja3_hash": "abc123",
            },
        )
        alerts = pipeline.process_event(event)
        assert any(
            a.alert_type == "encrypted_traffic_malicious_ja3"
            for a in alerts
        )

    def test_encrypted_traffic_on_http(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.return_value = []
        pipeline = DetectionPipeline(encrypted_traffic=mock_engine)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.http_request",
            data={"url": "https://test.com", "pid": 1234},
        )
        pipeline.process_event(event)
        mock_engine.analyze_event.assert_called_once()

    def test_encrypted_traffic_on_connection(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.return_value = []
        pipeline = DetectionPipeline(encrypted_traffic=mock_engine)
        event = _make_event(
            sensor=SensorType.NETWORK,
            event_type="connection",
            data={"dst_ip": "10.0.0.1", "dst_port": 443},
        )
        pipeline.process_event(event)
        mock_engine.analyze_event.assert_called_once_with(event)

    def test_encrypted_traffic_not_called_for_unrelated(self) -> None:
        mock_engine = MagicMock()
        pipeline = DetectionPipeline(encrypted_traffic=mock_engine)
        event = _make_event(
            event_type="file_change",
            data={"path": "/tmp/test.txt", "change_type": "created"},
        )
        pipeline.process_event(event)
        mock_engine.analyze_event.assert_not_called()

    def test_encrypted_traffic_exception_handled(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.side_effect = RuntimeError("boom")
        pipeline = DetectionPipeline(encrypted_traffic=mock_engine)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={"server_name": "evil.com", "ja3_hash": "abc"},
        )
        alerts = pipeline.process_event(event)
        # Exception should be handled gracefully, not crash
        assert isinstance(alerts, list)

    def test_encrypted_traffic_none_skipped(self) -> None:
        pipeline = DetectionPipeline(encrypted_traffic=None)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={"server_name": "evil.com", "ja3_hash": "abc"},
        )
        alerts = pipeline.process_event(event)
        assert alerts == []


# ------------------------------------------------------------------ #
# Parallel engines — Fileless detector
# ------------------------------------------------------------------ #

class TestFilelessDetector:
    """Tests for fileless detector engine in parallel engines."""

    def test_pipeline_runs_fileless_on_powershell(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.return_value = [
            Alert(
                event_id="evt-test",
                sensor=SensorType.ETW,
                alert_type="fileless_powershell_obfuscation",
                severity=Severity.HIGH,
                title="Obfuscated PowerShell",
                description="Test",
                confidence=0.8,
                data={},
                mitre_ids=["T1027"],
            )
        ]
        pipeline = DetectionPipeline(fileless_detector=mock_engine)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.powershell_scriptblock",
            data={"script_text": "test", "pid": 1234},
        )
        alerts = pipeline.process_event(event)
        assert any(
            a.alert_type == "fileless_powershell_obfuscation"
            for a in alerts
        )

    def test_fileless_on_process_new(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.return_value = []
        pipeline = DetectionPipeline(fileless_detector=mock_engine)
        event = _make_event(
            sensor=SensorType.PROCESS,
            event_type="process_new",
            data={"name": "cmd.exe", "parent_name": "winword.exe"},
        )
        pipeline.process_event(event)
        mock_engine.analyze_event.assert_called_once()

    def test_fileless_on_dotnet_assembly_load(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.return_value = [
            Alert(
                event_id="evt-test",
                sensor=SensorType.ETW,
                alert_type="fileless_dotnet_injection",
                severity=Severity.HIGH,
                title="In-memory .NET assembly",
                description="Test",
                confidence=0.7,
                data={},
                mitre_ids=["T1055"],
            )
        ]
        pipeline = DetectionPipeline(fileless_detector=mock_engine)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.dotnet_assembly_load",
            data={"assembly_name": "evil", "is_dynamic": True},
        )
        alerts = pipeline.process_event(event)
        assert any(
            a.alert_type == "fileless_dotnet_injection"
            for a in alerts
        )

    def test_fileless_on_wmi_activity(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.return_value = []
        pipeline = DetectionPipeline(fileless_detector=mock_engine)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.wmi_activity",
            data={"namespace": "root\\subscription"},
        )
        pipeline.process_event(event)
        mock_engine.analyze_event.assert_called_once()

    def test_fileless_on_amsi_scan(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.return_value = []
        pipeline = DetectionPipeline(fileless_detector=mock_engine)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.amsi_scan",
            data={"content_name": "test", "app_name": "pwsh"},
        )
        pipeline.process_event(event)
        mock_engine.analyze_event.assert_called_once()

    def test_fileless_not_called_for_unrelated_event(self) -> None:
        mock_engine = MagicMock()
        pipeline = DetectionPipeline(fileless_detector=mock_engine)
        event = _make_event(
            event_type="connection",
            data={"dst_ip": "10.0.0.1"},
        )
        pipeline.process_event(event)
        mock_engine.analyze_event.assert_not_called()

    def test_fileless_exception_handled(self) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze_event.side_effect = RuntimeError("boom")
        pipeline = DetectionPipeline(fileless_detector=mock_engine)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.powershell_scriptblock",
            data={"script_text": "test", "pid": 1234},
        )
        alerts = pipeline.process_event(event)
        assert isinstance(alerts, list)

    def test_fileless_none_skipped(self) -> None:
        pipeline = DetectionPipeline(fileless_detector=None)
        event = _make_event(
            sensor=SensorType.ETW,
            event_type="etw.powershell_scriptblock",
            data={"script_text": "test", "pid": 1234},
        )
        alerts = pipeline.process_event(event)
        assert alerts == []
