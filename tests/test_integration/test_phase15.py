"""Phase 15 integration tests — end-to-end detection flows.

Tests that the new detection engines (YARA, Sigma, Registry, DNS)
integrate correctly with the DetectionPipeline and produce proper alerts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from aegis.core.models import (
    AegisEvent,
    Alert,
    SensorType,
    Severity,
)
from aegis.detection.dns_analyzer import DNSAnalyzer
from aegis.detection.pipeline import DetectionPipeline
from aegis.detection.rule_engine import BehavioralRule, RuleEngine
from aegis.detection.sigma_converter import SigmaConverter
from aegis.detection.yara_scanner import YaraMatch, YaraScanner
from aegis.sensors.registry import RegistrySensor, RegistryValue, _hash_value


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _make_event(**overrides: Any) -> AegisEvent:
    defaults: dict[str, Any] = {
        "sensor": SensorType.FILE,
        "event_type": "file_change",
        "data": {"path": "C:\\test.exe", "change_type": "created"},
        "severity": Severity.INFO,
        "timestamp": time.time(),
    }
    defaults.update(overrides)
    return AegisEvent(**defaults)


# ------------------------------------------------------------------ #
# YARA → Pipeline integration
# ------------------------------------------------------------------ #

class TestYaraPipelineIntegration:
    """FIM event → YARA scan → alert."""

    def test_yara_match_produces_alert(self) -> None:
        """A YARA match on a file_change event produces an alert."""
        scanner = MagicMock(spec=YaraScanner)
        scanner.scan_file.return_value = [
            YaraMatch(
                rule_name="Ransomware_Note_Generic",
                tags=["ransomware"],
                meta={"severity": "critical", "mitre": "T1486"},
                strings_matched=["$a1"],
                file_path="C:\\test.exe",
            ),
        ]

        pipeline = DetectionPipeline(yara_scanner=scanner)
        event = _make_event()
        alerts = pipeline.process_event(event)

        assert len(alerts) >= 1
        yara_alert = next(
            a for a in alerts if a.alert_type.startswith("yara_")
        )
        assert yara_alert.severity == Severity.CRITICAL
        assert "T1486" in yara_alert.mitre_ids
        assert "Ransomware_Note_Generic" in yara_alert.title

    def test_yara_no_match_no_alert(self) -> None:
        """YARA scanner with no matches produces no YARA alerts."""
        scanner = MagicMock(spec=YaraScanner)
        scanner.scan_file.return_value = []

        pipeline = DetectionPipeline(yara_scanner=scanner)
        event = _make_event()
        alerts = pipeline.process_event(event)

        yara_alerts = [a for a in alerts if "yara" in a.alert_type]
        assert yara_alerts == []

    def test_yara_ignores_non_file_events(self) -> None:
        """YARA scanner is not called for non-file-change events."""
        scanner = MagicMock(spec=YaraScanner)
        pipeline = DetectionPipeline(yara_scanner=scanner)
        event = _make_event(
            sensor=SensorType.NETWORK,
            event_type="connection_snapshot",
            data={"dst_ip": "1.2.3.4"},
        )
        pipeline.process_event(event)
        scanner.scan_file.assert_not_called()

    def test_yara_ignores_deleted_files(self) -> None:
        """YARA scanner is not called for file deletion events."""
        scanner = MagicMock(spec=YaraScanner)
        pipeline = DetectionPipeline(yara_scanner=scanner)
        event = _make_event(data={"path": "C:\\test.exe", "change_type": "deleted"})
        pipeline.process_event(event)
        scanner.scan_file.assert_not_called()


# ------------------------------------------------------------------ #
# Sigma → Rule Engine integration
# ------------------------------------------------------------------ #

class TestSigmaRuleEngineIntegration:
    """Sigma rule → RuleEngine → event match."""

    def test_sigma_rule_matches_event(self) -> None:
        """A Sigma rule converted to BehavioralRule matches an event."""
        sigma_yaml = """\
title: Test Encoded PowerShell
id: test-sigma-001
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - "-EncodedCommand"
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
"""
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(sigma_yaml)
        assert result.success

        engine = RuleEngine()
        engine.add_rule(result.rule)

        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={
                "cmdline": "powershell.exe -EncodedCommand ABC123",
                "exe": "C:\\Windows\\System32\\powershell.exe",
            },
        )
        matches = engine.evaluate(event)
        assert len(matches) == 1
        assert matches[0].rule_id == "sigma_test-sigma-001"
        assert matches[0].severity == Severity.HIGH

    def test_sigma_rule_no_match(self) -> None:
        """A Sigma rule does not match an unrelated event."""
        sigma_yaml = "title: Test Rule\n" \
            "id: test-sigma-002\n" \
            "level: medium\n" \
            "logsource:\n" \
            "    product: windows\n" \
            "    category: process_creation\n" \
            "detection:\n" \
            "    selection:\n" \
            "        Image|endswith: '\\\\malware.exe'\n" \
            "    condition: selection\n"
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(sigma_yaml)
        assert result.success

        engine = RuleEngine()
        engine.add_rule(result.rule)

        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"exe": "C:\\Windows\\System32\\notepad.exe"},
        )
        matches = engine.evaluate(event)
        assert len(matches) == 0


# ------------------------------------------------------------------ #
# DNS Analyzer → Pipeline integration
# ------------------------------------------------------------------ #

class TestDnsPipelineIntegration:
    """DNS query event → DNS analyzer → alert."""

    def test_tunneling_query_produces_alert(self) -> None:
        """A high-entropy long-subdomain DNS query produces a tunneling alert."""
        dns_analyzer = DNSAnalyzer(
            tunneling_entropy_threshold=3.0,
            tunneling_length_threshold=30,
        )
        pipeline = DetectionPipeline(dns_analyzer=dns_analyzer)

        subdomain = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
        event = _make_event(
            sensor=SensorType.NETWORK,
            event_type="dns_query",
            data={"query_name": f"{subdomain}.evil-tunnel.com"},
        )
        alerts = pipeline.process_event(event)

        dns_alerts = [a for a in alerts if a.alert_type.startswith("dns_")]
        assert len(dns_alerts) >= 1
        assert dns_alerts[0].alert_type == "dns_tunneling"
        assert "T1071.004" in dns_alerts[0].mitre_ids

    def test_benign_dns_no_alert(self) -> None:
        """A normal DNS query produces no DNS alerts."""
        dns_analyzer = DNSAnalyzer()
        pipeline = DetectionPipeline(dns_analyzer=dns_analyzer)

        event = _make_event(
            sensor=SensorType.NETWORK,
            event_type="dns_query",
            data={"query_name": "www.google.com"},
        )
        alerts = pipeline.process_event(event)

        dns_alerts = [a for a in alerts if a.alert_type.startswith("dns_")]
        assert dns_alerts == []

    def test_dns_analyzer_not_called_for_non_dns_events(self) -> None:
        """DNS analyzer is not triggered for non-dns_query events."""
        dns_analyzer = MagicMock(spec=DNSAnalyzer)
        pipeline = DetectionPipeline(dns_analyzer=dns_analyzer)

        event = _make_event(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"name": "test.exe"},
        )
        pipeline.process_event(event)
        dns_analyzer.analyze_query.assert_not_called()


# ------------------------------------------------------------------ #
# Registry Sensor → Rule Engine integration
# ------------------------------------------------------------------ #

class TestRegistryRuleIntegration:
    """Registry change event → behavioral rule → alert."""

    def test_registry_change_matches_behavioral_rule(self) -> None:
        """A registry_change event matches a registry behavioral rule."""
        rule = BehavioralRule(
            rule_id="registry_run_key_created",
            description="New entry added to Run key",
            severity=Severity.HIGH,
            mitre_ids=["T1547.001"],
            sensor="registry",
            event_type="registry_change",
            conditions=[
                {"field": "change_type", "op": "eq", "value": "created"},
                {"field": "category", "op": "eq", "value": "persistence"},
            ],
        )

        engine = RuleEngine()
        engine.add_rule(rule)

        event = AegisEvent(
            sensor=SensorType.REGISTRY,
            event_type="registry_change",
            data={
                "hive": "HKCU",
                "key_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "value_name": "malware",
                "value_data": "C:\\malware.exe",
                "change_type": "created",
                "category": "persistence",
                "mitre_id": "T1547.001",
            },
        )
        matches = engine.evaluate(event)
        assert len(matches) == 1
        assert matches[0].rule_id == "registry_run_key_created"

    def test_registry_snapshot_does_not_match_change_rule(self) -> None:
        """A registry_snapshot event does not match change rules."""
        rule = BehavioralRule(
            rule_id="registry_run_key_created",
            description="New entry added to Run key",
            severity=Severity.HIGH,
            mitre_ids=["T1547.001"],
            sensor="registry",
            event_type="registry_change",
            conditions=[
                {"field": "change_type", "op": "eq", "value": "created"},
            ],
        )

        engine = RuleEngine()
        engine.add_rule(rule)

        event = AegisEvent(
            sensor=SensorType.REGISTRY,
            event_type="registry_snapshot",
            data={"cycle": 1, "total_values": 50},
        )
        matches = engine.evaluate(event)
        assert len(matches) == 0


# ------------------------------------------------------------------ #
# New rule engine operators (startswith / endswith)
# ------------------------------------------------------------------ #

class TestNewRuleEngineOperators:
    """Tests for startswith and endswith operators added in Phase 15."""

    def test_startswith_single_value(self) -> None:
        rule = BehavioralRule(
            rule_id="test_startswith",
            description="test",
            severity=Severity.MEDIUM,
            mitre_ids=[],
            sensor="process",
            event_type="process_snapshot",
            conditions=[
                {"field": "exe", "op": "startswith", "value": "C:\\Windows"},
            ],
        )
        engine = RuleEngine()
        engine.add_rule(rule)

        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"exe": "C:\\Windows\\System32\\cmd.exe"},
        )
        assert len(engine.evaluate(event)) == 1

    def test_endswith_list(self) -> None:
        rule = BehavioralRule(
            rule_id="test_endswith_list",
            description="test",
            severity=Severity.HIGH,
            mitre_ids=[],
            sensor="process",
            event_type="process_snapshot",
            conditions=[
                {
                    "field": "exe",
                    "op": "endswith",
                    "value": ["\\cmd.exe", "\\powershell.exe"],
                },
            ],
        )
        engine = RuleEngine()
        engine.add_rule(rule)

        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"exe": "C:\\Windows\\System32\\powershell.exe"},
        )
        assert len(engine.evaluate(event)) == 1

    def test_endswith_no_match(self) -> None:
        rule = BehavioralRule(
            rule_id="test_endswith_no",
            description="test",
            severity=Severity.LOW,
            mitre_ids=[],
            sensor="process",
            event_type="process_snapshot",
            conditions=[
                {"field": "exe", "op": "endswith", "value": "\\malware.exe"},
            ],
        )
        engine = RuleEngine()
        engine.add_rule(rule)

        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"exe": "C:\\Windows\\notepad.exe"},
        )
        assert len(engine.evaluate(event)) == 0
