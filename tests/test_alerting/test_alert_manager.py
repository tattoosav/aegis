"""Tests for the Alert Manager — scoring, dedup, routing."""

from aegis.alerting.manager import AlertManager
from aegis.core.models import Alert, SensorType, Severity


class TestAlertScoring:
    def test_score_critical_single_engine(self):
        mgr = AlertManager()
        score = mgr.compute_priority(
            base_severity=Severity.CRITICAL,
            engine_confidence=0.95,
            context_multiplier=1.0,
            threat_intel_multiplier=1.0,
            user_familiarity_dampener=1.0,
        )
        # Critical(1.0) * 0.95 * 1.0 * 1.0 / 1.0 * 100 = 95
        assert 90 <= score <= 100

    def test_score_low_dismissed(self):
        mgr = AlertManager()
        score = mgr.compute_priority(
            base_severity=Severity.LOW,
            engine_confidence=0.5,
            context_multiplier=1.0,
            threat_intel_multiplier=1.0,
            user_familiarity_dampener=2.0,
        )
        # Low(0.2) * 0.5 * 1.0 * 1.0 / 2.0 * 100 = 5
        assert score < 10

    def test_score_multi_engine_boost(self):
        mgr = AlertManager()
        single = mgr.compute_priority(
            base_severity=Severity.MEDIUM,
            engine_confidence=0.8,
            context_multiplier=1.0,
            threat_intel_multiplier=1.0,
            user_familiarity_dampener=1.0,
        )
        multi = mgr.compute_priority(
            base_severity=Severity.MEDIUM,
            engine_confidence=0.8,
            context_multiplier=1.5,
            threat_intel_multiplier=1.0,
            user_familiarity_dampener=1.0,
        )
        assert multi > single

    def test_score_threat_intel_boost(self):
        mgr = AlertManager()
        no_intel = mgr.compute_priority(
            base_severity=Severity.HIGH,
            engine_confidence=0.9,
            context_multiplier=1.0,
            threat_intel_multiplier=1.0,
            user_familiarity_dampener=1.0,
        )
        with_intel = mgr.compute_priority(
            base_severity=Severity.HIGH,
            engine_confidence=0.9,
            context_multiplier=1.0,
            threat_intel_multiplier=2.0,
            user_familiarity_dampener=1.0,
        )
        assert with_intel > no_intel

    def test_score_clamped_to_100(self):
        mgr = AlertManager()
        score = mgr.compute_priority(
            base_severity=Severity.CRITICAL,
            engine_confidence=1.0,
            context_multiplier=2.0,
            threat_intel_multiplier=2.0,
            user_familiarity_dampener=1.0,
        )
        assert score == 100


class TestAlertDedup:
    def test_dedup_identical_alerts(self):
        mgr = AlertManager()
        alert1 = Alert(
            event_id="e1",
            sensor=SensorType.PROCESS,
            alert_type="masquerade",
            severity=Severity.HIGH,
            title="Process masquerading",
            description="svchost.exe from wrong path",
            confidence=0.9,
            data={},
        )
        alert2 = Alert(
            event_id="e2",
            sensor=SensorType.PROCESS,
            alert_type="masquerade",
            severity=Severity.HIGH,
            title="Process masquerading",
            description="svchost.exe from wrong path",
            confidence=0.9,
            data={},
        )
        # Add first alert — should pass through
        result1 = mgr.process_alert(alert1)
        assert result1 is not None

        # Add duplicate within 60s — should be deduplicated
        result2 = mgr.process_alert(alert2)
        assert result2 is None  # Suppressed as duplicate

    def test_different_alert_types_not_deduped(self):
        mgr = AlertManager()
        alert1 = Alert(
            event_id="e1",
            sensor=SensorType.PROCESS,
            alert_type="masquerade",
            severity=Severity.HIGH,
            title="Alert 1",
            description="Test",
            confidence=0.9,
            data={},
        )
        alert2 = Alert(
            event_id="e2",
            sensor=SensorType.NETWORK,
            alert_type="port_scan",
            severity=Severity.HIGH,
            title="Alert 2",
            description="Test",
            confidence=0.9,
            data={},
        )
        result1 = mgr.process_alert(alert1)
        result2 = mgr.process_alert(alert2)
        assert result1 is not None
        assert result2 is not None

    def test_dedup_increments_count(self):
        mgr = AlertManager()
        alert1 = Alert(
            event_id="e1",
            sensor=SensorType.PROCESS,
            alert_type="high_entropy",
            severity=Severity.MEDIUM,
            title="High entropy",
            description="Test",
            confidence=0.7,
            data={},
        )
        mgr.process_alert(alert1)
        # Second identical within window
        alert2 = Alert(
            event_id="e2",
            sensor=SensorType.PROCESS,
            alert_type="high_entropy",
            severity=Severity.MEDIUM,
            title="High entropy",
            description="Test",
            confidence=0.7,
            data={},
        )
        mgr.process_alert(alert2)
        # The original should have incremented count
        assert mgr.dedup_count("process:high_entropy") >= 2


class TestAlertRouting:
    def test_route_critical(self):
        mgr = AlertManager()
        route = mgr.route_priority(95)
        assert route == "fullscreen"

    def test_route_high(self):
        mgr = AlertManager()
        route = mgr.route_priority(65)
        assert route == "toast"

    def test_route_medium(self):
        mgr = AlertManager()
        route = mgr.route_priority(40)
        assert route == "tray"

    def test_route_low(self):
        mgr = AlertManager()
        route = mgr.route_priority(15)
        assert route == "log"


class TestAlertManagerCreateAlert:
    def test_create_alert_from_rule_match(self):
        mgr = AlertManager()
        alert = mgr.create_alert(
            event_id="evt-123",
            sensor=SensorType.PROCESS,
            alert_type="masquerade",
            severity=Severity.HIGH,
            title="Process masquerading detected",
            description="svchost.exe running from C:\\Users\\Temp",
            confidence=0.95,
            mitre_ids=["T1036.005"],
            recommended_actions=["Kill process", "Investigate path"],
        )
        assert alert.alert_id.startswith("alt-")
        assert alert.severity == Severity.HIGH
        assert alert.confidence == 0.95
        assert alert.mitre_ids == ["T1036.005"]
        assert alert.priority_score > 0

    def test_alert_history_tracking(self):
        mgr = AlertManager()
        alert = Alert(
            event_id="e1",
            sensor=SensorType.NETWORK,
            alert_type="scan",
            severity=Severity.HIGH,
            title="Port scan",
            description="Test",
            confidence=0.9,
            data={},
        )
        mgr.process_alert(alert)
        assert len(mgr.alert_history) == 1
        assert mgr.alert_history[0].alert_id == alert.alert_id
