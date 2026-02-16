"""Tests for the Rule Engine detection module."""

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.detection.rule_engine import BehavioralRule, RuleEngine


class TestBehavioralRule:
    def test_rule_from_dict(self):
        rule_dict = {
            "id": "test_rule",
            "description": "Test rule",
            "severity": "high",
            "mitre": ["T1059"],
            "sensor": "process",
            "event_type": "process_snapshot",
            "conditions": [
                {"field": "name", "op": "eq", "value": "cmd.exe"},
            ],
        }
        rule = BehavioralRule.from_dict(rule_dict)
        assert rule.rule_id == "test_rule"
        assert rule.severity == Severity.HIGH
        assert rule.mitre_ids == ["T1059"]
        assert len(rule.conditions) == 1

    def test_rule_matches_eq(self):
        rule = BehavioralRule(
            rule_id="test_eq",
            description="Test eq operator",
            severity=Severity.HIGH,
            mitre_ids=["T1059"],
            sensor="process",
            event_type="process_snapshot",
            conditions=[{"field": "name", "op": "eq", "value": "cmd.exe"}],
        )
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"name": "cmd.exe", "pid": 1234},
        )
        assert rule.matches(event) is True

    def test_rule_no_match_wrong_value(self):
        rule = BehavioralRule(
            rule_id="test_eq",
            description="Test",
            severity=Severity.HIGH,
            mitre_ids=[],
            sensor="process",
            event_type="process_snapshot",
            conditions=[{"field": "name", "op": "eq", "value": "cmd.exe"}],
        )
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"name": "notepad.exe", "pid": 1234},
        )
        assert rule.matches(event) is False

    def test_rule_no_match_wrong_event_type(self):
        rule = BehavioralRule(
            rule_id="test_type",
            description="Test",
            severity=Severity.HIGH,
            mitre_ids=[],
            sensor="process",
            event_type="process_snapshot",
            conditions=[{"field": "name", "op": "eq", "value": "cmd.exe"}],
        )
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_new",
            data={"name": "cmd.exe"},
        )
        assert rule.matches(event) is False

    def test_rule_matches_in(self):
        rule = BehavioralRule(
            rule_id="test_in",
            description="Test in operator",
            severity=Severity.HIGH,
            mitre_ids=[],
            sensor="process",
            event_type="process_snapshot",
            conditions=[
                {"field": "name", "op": "in", "value": ["cmd.exe", "powershell.exe"]},
            ],
        )
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"name": "powershell.exe"},
        )
        assert rule.matches(event) is True

    def test_rule_matches_gt(self):
        rule = BehavioralRule(
            rule_id="test_gt",
            description="Test gt operator",
            severity=Severity.MEDIUM,
            mitre_ids=[],
            sensor="process",
            event_type="process_snapshot",
            conditions=[
                {"field": "cmdline_entropy", "op": "gt", "value": 5.0},
            ],
        )
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"cmdline_entropy": 6.2},
        )
        assert rule.matches(event) is True

        event_low = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"cmdline_entropy": 3.1},
        )
        assert rule.matches(event_low) is False

    def test_rule_matches_contains_any(self):
        rule = BehavioralRule(
            rule_id="test_contains",
            description="Test contains_any operator",
            severity=Severity.HIGH,
            mitre_ids=[],
            sensor="process",
            event_type="process_snapshot",
            conditions=[
                {"field": "cmdline", "op": "contains_any", "value": ["-enc ", "-e "]},
            ],
        )
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"cmdline": "powershell.exe -enc SGVsbG8="},
        )
        assert rule.matches(event) is True

    def test_rule_multiple_conditions_all_must_match(self):
        rule = BehavioralRule(
            rule_id="test_multi",
            description="Test AND logic",
            severity=Severity.HIGH,
            mitre_ids=[],
            sensor="network",
            event_type="network_flow_stats",
            conditions=[
                {"field": "port_entropy", "op": "gt", "value": 4.0},
                {"field": "unique_remote_ports", "op": "gt", "value": 50},
            ],
        )
        # Both match
        event_match = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="network_flow_stats",
            data={"port_entropy": 5.2, "unique_remote_ports": 100},
        )
        assert rule.matches(event_match) is True

        # Only one matches
        event_partial = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="network_flow_stats",
            data={"port_entropy": 5.2, "unique_remote_ports": 10},
        )
        assert rule.matches(event_partial) is False


class TestRuleEngine:
    def test_load_rules_from_yaml(self, tmp_path):
        yaml_content = """
rules:
  - id: test_yaml_rule
    description: "Test rule from YAML"
    severity: medium
    mitre: [T1027]
    sensor: process
    event_type: process_snapshot
    conditions:
      - field: cmdline_entropy
        op: gt
        value: 5.0
"""
        rule_file = tmp_path / "test_rules.yaml"
        rule_file.write_text(yaml_content)
        engine = RuleEngine()
        engine.load_rules_file(str(rule_file))
        assert len(engine.rules) == 1
        assert engine.rules[0].rule_id == "test_yaml_rule"

    def test_evaluate_returns_matching_rules(self):
        engine = RuleEngine()
        engine.add_rule(BehavioralRule(
            rule_id="masquerade",
            description="Masquerade detection",
            severity=Severity.HIGH,
            mitre_ids=["T1036.005"],
            sensor="process",
            event_type="process_snapshot",
            conditions=[{"field": "is_masquerading", "op": "eq", "value": True}],
        ))
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"is_masquerading": True, "name": "svchost.exe"},
        )
        matches = engine.evaluate(event)
        assert len(matches) == 1
        assert matches[0].rule_id == "masquerade"

    def test_evaluate_no_matches(self):
        engine = RuleEngine()
        engine.add_rule(BehavioralRule(
            rule_id="masquerade",
            description="Test",
            severity=Severity.HIGH,
            mitre_ids=[],
            sensor="process",
            event_type="process_snapshot",
            conditions=[{"field": "is_masquerading", "op": "eq", "value": True}],
        ))
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"is_masquerading": False, "name": "notepad.exe"},
        )
        matches = engine.evaluate(event)
        assert len(matches) == 0

    def test_evaluate_multiple_rules_can_match(self):
        engine = RuleEngine()
        engine.add_rule(BehavioralRule(
            rule_id="rule1",
            description="Rule 1",
            severity=Severity.HIGH,
            mitre_ids=[],
            sensor="process",
            event_type="process_snapshot",
            conditions=[{"field": "is_masquerading", "op": "eq", "value": True}],
        ))
        engine.add_rule(BehavioralRule(
            rule_id="rule2",
            description="Rule 2",
            severity=Severity.MEDIUM,
            mitre_ids=[],
            sensor="process",
            event_type="process_snapshot",
            conditions=[{"field": "cmdline_entropy", "op": "gt", "value": 5.0}],
        ))
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={"is_masquerading": True, "cmdline_entropy": 6.5},
        )
        matches = engine.evaluate(event)
        assert len(matches) == 2

    def test_rule_count(self):
        engine = RuleEngine()
        assert engine.rule_count == 0
        engine.add_rule(BehavioralRule(
            rule_id="r1", description="", severity=Severity.LOW,
            mitre_ids=[], sensor="process", event_type="process_snapshot",
            conditions=[],
        ))
        assert engine.rule_count == 1

    def test_load_builtin_rules(self):
        """Loading the shipped behavioral.yaml should work."""
        engine = RuleEngine()
        engine.load_builtin_rules()
        assert engine.rule_count >= 5  # We ship at least 10 rules
