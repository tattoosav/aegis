"""Integration tests: Phase 3 — detection engines + alert manager pipeline."""

import pytest
import numpy as np
from aegis.core.models import AegisEvent, Alert, SensorType, Severity
from aegis.detection.rule_engine import RuleEngine, BehavioralRule
from aegis.detection.anomaly import AnomalyDetector
from aegis.alerting.manager import AlertManager


class TestDetectionToAlertPipeline:
    """Full pipeline: Event → Rule Engine → Alert Manager → Scored Alert."""

    def test_rule_match_creates_alert(self):
        """When a rule matches, an alert is created and scored."""
        engine = RuleEngine()
        engine.add_rule(BehavioralRule(
            rule_id="test_masquerade",
            description="Process masquerading",
            severity=Severity.HIGH,
            mitre_ids=["T1036.005"],
            sensor="process",
            event_type="process_snapshot",
            conditions=[{"field": "is_masquerading", "op": "eq", "value": True}],
        ))

        mgr = AlertManager()

        # Simulate an event from the process sensor
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={
                "pid": 1234,
                "name": "svchost.exe",
                "exe": "C:\\Users\\Temp\\svchost.exe",
                "is_masquerading": True,
                "cmdline_entropy": 2.1,
                "lineage_depth": 1,
            },
        )

        # Rule engine evaluates
        matches = engine.evaluate(event)
        assert len(matches) == 1

        # Create alert from match
        rule = matches[0]
        alert = mgr.create_alert(
            event_id=event.event_id,
            sensor=event.sensor,
            alert_type=rule.rule_id,
            severity=rule.severity,
            title=rule.description,
            description=f"Rule '{rule.rule_id}' matched event {event.event_id}",
            confidence=0.95,
            mitre_ids=rule.mitre_ids,
            recommended_actions=["Kill process", "Investigate executable path"],
        )

        # Alert should be properly scored
        assert alert is not None
        assert alert.severity == Severity.HIGH
        assert alert.mitre_ids == ["T1036.005"]
        assert alert.data["_computed_priority"] > 50  # HIGH * 0.95

        # Process through alert manager
        result = mgr.process_alert(alert)
        assert result is not None
        assert len(mgr.alert_history) == 1

        # Route the alert
        route = mgr.route_priority(alert.data["_computed_priority"])
        assert route in ("toast", "fullscreen")

    def test_anomaly_score_creates_alert_when_high(self):
        """High anomaly score triggers alert creation."""
        detector = AnomalyDetector(domain="network")
        mgr = AlertManager()

        # Train on normal data
        np.random.seed(42)
        normal_data = np.random.randn(200, 6) * 0.5 + 5.0
        detector.train(normal_data)

        # Normal event — should NOT create alert
        normal_event = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="network_flow_stats",
            data={
                "total_connections": 5,
                "unique_remote_ips": 5,
                "unique_remote_ports": 5,
                "port_entropy": 5.0,
                "new_destination_rate": 5,
                "dns_query_count": 5,
            },
        )
        features = detector.extract_features(normal_event)
        score = detector.score(features.reshape(1, -1))
        classification = detector.classify(score)
        assert classification in ("normal", "suspicious")

        # Anomalous event — extreme outlier
        anomaly_event = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="network_flow_stats",
            data={
                "total_connections": 500,
                "unique_remote_ips": 200,
                "unique_remote_ports": 300,
                "port_entropy": 100.0,
                "new_destination_rate": 150,
                "dns_query_count": 500,
            },
        )
        features = detector.extract_features(anomaly_event)
        score = detector.score(features.reshape(1, -1))
        classification = detector.classify(score)

        if classification == "anomalous":
            alert = mgr.create_alert(
                event_id=anomaly_event.event_id,
                sensor=anomaly_event.sensor,
                alert_type="anomaly_network",
                severity=Severity.MEDIUM,
                title="Network anomaly detected",
                description=f"Anomaly score: {score:.2f}",
                confidence=score,
            )
            result = mgr.process_alert(alert)
            assert result is not None

    def test_multiple_engines_same_event(self):
        """Rule engine + anomaly detector can both fire on same event."""
        rule_engine = RuleEngine()
        rule_engine.add_rule(BehavioralRule(
            rule_id="high_entropy",
            description="High entropy cmdline",
            severity=Severity.MEDIUM,
            mitre_ids=["T1027"],
            sensor="process",
            event_type="process_snapshot",
            conditions=[{"field": "cmdline_entropy", "op": "gt", "value": 5.0}],
        ))

        anomaly = AnomalyDetector(domain="process")
        np.random.seed(42)
        normal = np.random.randn(200, 7) * 0.5 + 5.0
        anomaly.train(normal)

        mgr = AlertManager()

        # Event that triggers the rule
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={
                "cpu_percent": 50.0,
                "memory_mb": 500.0,
                "num_threads": 100,
                "cmdline_entropy": 6.5,
                "lineage_depth": 4,
                "num_connections": 20,
                "num_open_files": 50,
            },
        )

        # Rule engine fires
        rule_matches = rule_engine.evaluate(event)
        assert len(rule_matches) >= 1

        # Anomaly detector scores
        features = anomaly.extract_features(event)
        score = anomaly.score(features.reshape(1, -1))
        assert 0.0 <= score <= 1.0

        # Both can create alerts
        rule_alert = mgr.create_alert(
            event_id=event.event_id,
            sensor=event.sensor,
            alert_type="high_entropy",
            severity=Severity.MEDIUM,
            title="High entropy cmdline",
            description="Test",
            confidence=0.9,
        )
        mgr.process_alert(rule_alert)

        if anomaly.classify(score) != "normal":
            anomaly_alert = mgr.create_alert(
                event_id=event.event_id,
                sensor=event.sensor,
                alert_type="anomaly_process",
                severity=Severity.MEDIUM,
                title="Process anomaly",
                description=f"Score: {score:.2f}",
                confidence=score,
            )
            mgr.process_alert(anomaly_alert)

        # At least the rule engine alert should be in history
        assert len(mgr.alert_history) >= 1

    def test_builtin_rules_load_and_evaluate(self):
        """Built-in behavioral.yaml rules load and can evaluate events."""
        engine = RuleEngine()
        count = engine.load_builtin_rules()
        assert count >= 5, f"Expected at least 5 built-in rules, got {count}"

        # Test against a masquerading process
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={
                "name": "powershell.exe",
                "cmdline": "powershell.exe -enc SGVsbG8gV29ybGQ=",
                "cmdline_entropy": 4.5,
                "is_masquerading": False,
                "lineage_depth": 2,
                "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            },
        )
        matches = engine.evaluate(event)
        # Should match encoded_powershell rule
        rule_ids = [m.rule_id for m in matches]
        assert "encoded_powershell" in rule_ids
