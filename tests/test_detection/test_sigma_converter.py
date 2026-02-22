"""Tests for the Sigma rule converter module."""

from __future__ import annotations

import textwrap

import pytest

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.detection.rule_engine import BehavioralRule, RuleEngine
from aegis.detection.sigma_converter import (
    LOGSOURCE_MAP,
    SIGMA_FIELD_MAP,
    SigmaConversionResult,
    SigmaConverter,
)


# ------------------------------------------------------------------ #
#  Embedded Sigma YAML templates used across tests
# ------------------------------------------------------------------ #

VALID_SIGMA_PROCESS = textwrap.dedent("""\
    title: Suspicious cmd.exe Usage
    id: abc12345-1234-1234-1234-abcdefabcdef
    status: test
    level: high
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            Image: 'C:\\Windows\\System32\\cmd.exe'
            CommandLine|contains: '/c whoami'
        condition: selection
    tags:
        - attack.execution
        - attack.t1059.001
""")

VALID_SIGMA_REGISTRY = textwrap.dedent("""\
    title: Suspicious Registry Modification
    id: reg-1111-2222-3333-444455556666
    status: test
    level: medium
    logsource:
        product: windows
        category: registry_event
    detection:
        selection:
            TargetObject|contains: 'CurrentVersion\\Run'
            Details|endswith: '.exe'
        condition: selection
    tags:
        - attack.persistence
        - attack.t1547.001
""")

VALID_SIGMA_DNS = textwrap.dedent("""\
    title: Suspicious DNS Query
    id: dns-aaaa-bbbb-cccc-ddddeeeeffff
    status: test
    level: low
    logsource:
        product: windows
        category: dns_query
    detection:
        selection:
            QueryName|endswith:
                - '.tk'
                - '.ml'
                - '.cf'
        condition: selection
    tags:
        - attack.command_and_control
        - attack.t1071.004
""")

VALID_SIGMA_NETWORK = textwrap.dedent("""\
    title: Outbound Connection to Rare Port
    id: net-1111-2222-3333-444455556666
    status: test
    level: medium
    logsource:
        product: windows
        category: network_connection
    detection:
        selection:
            DestinationPort:
                - 4444
                - 5555
                - 6666
        condition: selection
""")

VALID_SIGMA_MULTIPLE_SELECTIONS = textwrap.dedent("""\
    title: Multiple Selection Rule
    id: multi-sel-1234-5678
    status: test
    level: high
    logsource:
        product: windows
        category: process_creation
    detection:
        selection_process:
            Image|endswith: '\\powershell.exe'
        selection_cmdline:
            CommandLine|contains: '-enc'
        condition: selection_process and selection_cmdline
""")

VALID_SIGMA_REGEX = textwrap.dedent("""\
    title: Regex-Based Detection
    id: regex-1111-2222-3333
    status: test
    level: critical
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            CommandLine|re: 'base64.*-exec'
        condition: selection
""")

VALID_SIGMA_STARTSWITH = textwrap.dedent("""\
    title: Process Starts with Temp
    id: starts-1111-2222-3333
    status: test
    level: medium
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            Image|startswith: 'C:\\Users\\Public'
        condition: selection
""")

VALID_SIGMA_INFORMATIONAL = textwrap.dedent("""\
    title: Informational Level Rule
    id: info-1111-2222-3333
    status: test
    level: informational
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            Image: 'notepad.exe'
        condition: selection
""")

VALID_SIGMA_CRITICAL = textwrap.dedent("""\
    title: Critical Level Rule
    id: crit-1111-2222-3333
    status: test
    level: critical
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            Image: 'mimikatz.exe'
        condition: selection
    tags:
        - attack.credential_access
        - attack.t1003
""")

VALID_SIGMA_MULTIPLE_MITRE = textwrap.dedent("""\
    title: Multi MITRE Rule
    id: mitre-1111-2222-3333
    status: test
    level: high
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            Image: 'test.exe'
        condition: selection
    tags:
        - attack.execution
        - attack.t1059.001
        - attack.defense_evasion
        - attack.t1027
        - attack.t1059
""")


# ================================================================== #
#  SigmaConversionResult tests
# ================================================================== #


class TestSigmaConversionResult:
    """Tests for the SigmaConversionResult dataclass."""

    def test_default_rule_is_none(self):
        result = SigmaConversionResult(rule=None)
        assert result.rule is None

    def test_default_source_file(self):
        result = SigmaConversionResult(rule=None)
        assert result.source_file == ""

    def test_default_sigma_id(self):
        result = SigmaConversionResult(rule=None)
        assert result.sigma_id == ""

    def test_default_sigma_title(self):
        result = SigmaConversionResult(rule=None)
        assert result.sigma_title == ""

    def test_default_success(self):
        result = SigmaConversionResult(rule=None)
        assert result.success is False

    def test_default_error(self):
        result = SigmaConversionResult(rule=None)
        assert result.error == ""

    def test_explicit_values(self):
        result = SigmaConversionResult(
            rule="fake_rule",
            source_file="test.yml",
            sigma_id="abc-123",
            sigma_title="Test Rule",
            success=True,
            error="",
        )
        assert result.rule == "fake_rule"
        assert result.source_file == "test.yml"
        assert result.sigma_id == "abc-123"
        assert result.sigma_title == "Test Rule"
        assert result.success is True


# ================================================================== #
#  SigmaConverter init tests
# ================================================================== #


class TestSigmaConverterInit:
    """Tests for SigmaConverter constructor."""

    def test_init_defaults(self):
        converter = SigmaConverter()
        assert converter._field_map is SIGMA_FIELD_MAP
        assert converter._logsource_map is LOGSOURCE_MAP

    def test_init_custom_field_map(self):
        custom = {"Image": "process_path"}
        converter = SigmaConverter(field_map=custom)
        assert converter._field_map is custom
        assert converter._logsource_map is LOGSOURCE_MAP

    def test_init_custom_logsource_map(self):
        custom = {("linux", "process_creation"): ("process", "proc_event")}
        converter = SigmaConverter(logsource_map=custom)
        assert converter._field_map is SIGMA_FIELD_MAP
        assert converter._logsource_map is custom

    def test_init_both_custom(self):
        fm = {"Image": "binary"}
        lm = {("linux", "syslog"): ("syslog", "log_event")}
        converter = SigmaConverter(field_map=fm, logsource_map=lm)
        assert converter._field_map is fm
        assert converter._logsource_map is lm


# ================================================================== #
#  convert_rule_yaml tests
# ================================================================== #


class TestConvertRuleYaml:
    """Tests for SigmaConverter.convert_rule_yaml."""

    def test_valid_process_creation_rule(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_PROCESS)
        assert result.success is True
        assert result.sigma_id == "abc12345-1234-1234-1234-abcdefabcdef"
        assert result.sigma_title == "Suspicious cmd.exe Usage"
        assert result.rule is not None

    def test_process_creation_maps_to_process_sensor(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_PROCESS)
        assert result.rule.sensor == "process"
        assert result.rule.event_type == "process_snapshot"

    def test_registry_event_maps_to_registry_sensor(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_REGISTRY)
        assert result.rule.sensor == "registry"
        assert result.rule.event_type == "registry_change"

    def test_dns_query_maps_to_network_sensor(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_DNS)
        assert result.rule.sensor == "network"
        assert result.rule.event_type == "dns_query"

    def test_network_connection_maps_correctly(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_NETWORK)
        assert result.rule.sensor == "network"
        assert result.rule.event_type == "connection_snapshot"

    def test_rule_id_prefixed_with_sigma(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_PROCESS)
        assert result.rule.rule_id.startswith("sigma_")

    def test_rule_description_is_sigma_title(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_PROCESS)
        assert result.rule.description == "Suspicious cmd.exe Usage"

    def test_conditions_are_list(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_PROCESS)
        assert isinstance(result.rule.conditions, list)
        assert len(result.rule.conditions) >= 1

    def test_multiple_selections_produces_conditions(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_MULTIPLE_SELECTIONS)
        assert result.success is True
        # Both selections should produce conditions
        assert len(result.rule.conditions) >= 2

    def test_unknown_logsource_produces_empty_sensor(self):
        yaml_content = textwrap.dedent("""\
            title: Unknown Logsource
            id: unknown-1234
            logsource:
                product: linux
                category: syslog
            detection:
                selection:
                    Message: 'test'
                condition: selection
        """)
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(yaml_content)
        assert result.success is True
        assert result.rule.sensor == ""
        assert result.rule.event_type == ""


# ================================================================== #
#  Field mapping tests
# ================================================================== #


class TestFieldMapping:
    """Tests for Sigma-to-Aegis field name mapping."""

    def test_image_maps_to_exe(self):
        assert SIGMA_FIELD_MAP["Image"] == "exe"

    def test_commandline_maps_to_cmdline(self):
        assert SIGMA_FIELD_MAP["CommandLine"] == "cmdline"

    def test_parentimage_maps_to_parent_exe(self):
        assert SIGMA_FIELD_MAP["ParentImage"] == "parent_exe"

    def test_parentcommandline_maps_to_parent_cmdline(self):
        assert SIGMA_FIELD_MAP["ParentCommandLine"] == "parent_cmdline"

    def test_user_maps_to_username(self):
        assert SIGMA_FIELD_MAP["User"] == "username"

    def test_targetfilename_maps_to_path(self):
        assert SIGMA_FIELD_MAP["TargetFilename"] == "path"

    def test_destinationip_maps_to_remote_addr(self):
        assert SIGMA_FIELD_MAP["DestinationIp"] == "remote_addr"

    def test_destinationport_maps_to_remote_port(self):
        assert SIGMA_FIELD_MAP["DestinationPort"] == "remote_port"

    def test_targetobject_maps_to_key_path(self):
        assert SIGMA_FIELD_MAP["TargetObject"] == "key_path"

    def test_details_maps_to_value_data(self):
        assert SIGMA_FIELD_MAP["Details"] == "value_data"

    def test_queryname_maps_to_query_name(self):
        assert SIGMA_FIELD_MAP["QueryName"] == "query_name"

    def test_unmapped_field_lowercased_in_condition(self):
        """An unmapped field should be lowercased by the converter."""
        yaml_content = textwrap.dedent("""\
            title: Unmapped Field
            id: unmapped-1234
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CustomField: 'test_value'
                condition: selection
        """)
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(yaml_content)
        assert result.success is True
        fields = [c["field"] for c in result.rule.conditions]
        assert "customfield" in fields


# ================================================================== #
#  Modifier handling tests
# ================================================================== #


class TestModifierHandling:
    """Tests for Sigma modifier-to-operator conversion."""

    def test_contains_modifier_single_value(self):
        converter = SigmaConverter()
        op = converter._modifiers_to_op(["contains"], "test")
        assert op == "contains"

    def test_endswith_modifier(self):
        converter = SigmaConverter()
        op = converter._modifiers_to_op(["endswith"], "test")
        assert op == "endswith"

    def test_startswith_modifier(self):
        converter = SigmaConverter()
        op = converter._modifiers_to_op(["startswith"], "test")
        assert op == "startswith"

    def test_re_modifier(self):
        converter = SigmaConverter()
        op = converter._modifiers_to_op(["re"], "test")
        assert op == "regex"

    def test_no_modifier_single_value_eq(self):
        converter = SigmaConverter()
        op = converter._modifiers_to_op([], "test_value")
        assert op == "eq"

    def test_no_modifier_list_value_in(self):
        converter = SigmaConverter()
        op = converter._modifiers_to_op([], ["val1", "val2"])
        assert op == "in"

    def test_contains_with_list_value_contains_any(self):
        converter = SigmaConverter()
        op = converter._modifiers_to_op(["contains"], ["val1", "val2"])
        assert op == "contains_any"

    def test_re_takes_priority(self):
        """When 're' is present, it should return 'regex' regardless of other modifiers."""
        converter = SigmaConverter()
        op = converter._modifiers_to_op(["contains", "re"], "pattern")
        assert op == "regex"

    def test_regex_condition_in_yaml(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_REGEX)
        assert result.success is True
        ops = [c["op"] for c in result.rule.conditions]
        assert "regex" in ops

    def test_startswith_condition_in_yaml(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_STARTSWITH)
        assert result.success is True
        ops = [c["op"] for c in result.rule.conditions]
        assert "startswith" in ops


# ================================================================== #
#  Value normalisation tests
# ================================================================== #


class TestNormalizeValue:
    """Tests for _normalize_value."""

    def test_string_value_unchanged(self):
        converter = SigmaConverter()
        assert converter._normalize_value("test", []) == "test"

    def test_int_value_unchanged(self):
        converter = SigmaConverter()
        assert converter._normalize_value(4444, []) == 4444

    def test_list_values_stringified(self):
        converter = SigmaConverter()
        result = converter._normalize_value([1, 2, "three"], [])
        assert result == ["1", "2", "three"]

    def test_bool_value_unchanged(self):
        converter = SigmaConverter()
        assert converter._normalize_value(True, []) is True


# ================================================================== #
#  Severity mapping tests
# ================================================================== #


class TestSeverityMapping:
    """Tests for Sigma level -> Aegis severity mapping."""

    def test_informational_maps_to_info(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_INFORMATIONAL)
        assert result.rule.severity == Severity.INFO

    def test_low_maps_to_low(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_DNS)  # level: low
        assert result.rule.severity == Severity.LOW

    def test_medium_maps_to_medium(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_REGISTRY)  # level: medium
        assert result.rule.severity == Severity.MEDIUM

    def test_high_maps_to_high(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_PROCESS)  # level: high
        assert result.rule.severity == Severity.HIGH

    def test_critical_maps_to_critical(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_CRITICAL)
        assert result.rule.severity == Severity.CRITICAL

    def test_missing_level_defaults_to_medium(self):
        yaml_content = textwrap.dedent("""\
            title: No Level
            id: nolevel-1234
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image: 'test.exe'
                condition: selection
        """)
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(yaml_content)
        assert result.rule.severity == Severity.MEDIUM


# ================================================================== #
#  MITRE tag extraction tests
# ================================================================== #


class TestMitreExtraction:
    """Tests for MITRE ATT&CK technique ID extraction from tags."""

    def test_subtechnique_extraction(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_PROCESS)
        # attack.t1059.001 should be extracted
        assert "T1059.001" in result.rule.mitre_ids

    def test_technique_without_subtechnique(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_CRITICAL)
        # attack.t1003
        assert "T1003" in result.rule.mitre_ids

    def test_multiple_mitre_ids(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_MULTIPLE_MITRE)
        assert "T1059.001" in result.rule.mitre_ids
        assert "T1027" in result.rule.mitre_ids
        assert "T1059" in result.rule.mitre_ids

    def test_non_technique_tags_ignored(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_PROCESS)
        # "attack.execution" should not produce an ID
        for mid in result.rule.mitre_ids:
            assert mid.startswith("T")

    def test_no_tags_produces_empty_mitre_ids(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_NETWORK)  # no tags key
        assert result.rule.mitre_ids == []


# ================================================================== #
#  Error handling tests
# ================================================================== #


class TestErrorHandling:
    """Tests for error cases in convert_rule_yaml."""

    def test_invalid_yaml_returns_error(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(":::invalid yaml {{{}}")
        assert result.success is False
        assert result.rule is None
        assert result.error != ""

    def test_missing_detection_block_returns_error(self):
        yaml_content = textwrap.dedent("""\
            title: No Detection
            id: nodet-1234
            logsource:
                product: windows
                category: process_creation
        """)
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(yaml_content)
        assert result.success is False
        assert result.rule is None
        assert "No detection block" in result.error

    def test_empty_detection_block_returns_error(self):
        yaml_content = textwrap.dedent("""\
            title: Empty Detection
            id: emptydet-1234
            logsource:
                product: windows
                category: process_creation
            detection: {}
        """)
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(yaml_content)
        assert result.success is False
        assert "detection" in result.error.lower()

    def test_non_dict_yaml_returns_error(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml("- just a list item")
        assert result.success is False
        assert "Invalid" in result.error

    def test_empty_yaml_returns_error(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml("")
        assert result.success is False

    def test_detection_only_condition_key_returns_error(self):
        yaml_content = textwrap.dedent("""\
            title: Only Condition
            id: condonly-1234
            logsource:
                product: windows
                category: process_creation
            detection:
                condition: selection
        """)
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(yaml_content)
        assert result.success is False
        assert "conditions" in result.error.lower() or "detection" in result.error.lower()


# ================================================================== #
#  File and directory conversion tests
# ================================================================== #


class TestFileConversion:
    """Tests for convert_file and convert_directory."""

    def test_convert_file_not_found(self, tmp_path):
        converter = SigmaConverter()
        results = converter.convert_file(tmp_path / "nonexistent.yml")
        assert len(results) == 1
        assert results[0].success is False
        assert "not found" in results[0].error.lower() or "File not found" in results[0].error

    def test_convert_file_success(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(VALID_SIGMA_PROCESS, encoding="utf-8")
        converter = SigmaConverter()
        results = converter.convert_file(rule_file)
        assert len(results) == 1
        assert results[0].success is True
        assert results[0].source_file == str(rule_file)

    def test_convert_file_sets_source_file(self, tmp_path):
        rule_file = tmp_path / "my_rule.yml"
        rule_file.write_text(VALID_SIGMA_PROCESS, encoding="utf-8")
        converter = SigmaConverter()
        results = converter.convert_file(rule_file)
        assert str(rule_file) in results[0].source_file

    def test_convert_directory_empty(self, tmp_path):
        converter = SigmaConverter()
        results = converter.convert_directory(tmp_path)
        assert results == []

    def test_convert_directory_with_yml_files(self, tmp_path):
        (tmp_path / "rule1.yml").write_text(VALID_SIGMA_PROCESS, encoding="utf-8")
        (tmp_path / "rule2.yaml").write_text(VALID_SIGMA_REGISTRY, encoding="utf-8")
        converter = SigmaConverter()
        results = converter.convert_directory(tmp_path)
        assert len(results) == 2
        successes = [r for r in results if r.success]
        assert len(successes) == 2

    def test_convert_directory_recursive(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "deep_rule.yml").write_text(VALID_SIGMA_DNS, encoding="utf-8")
        converter = SigmaConverter()
        results = converter.convert_directory(tmp_path)
        assert len(results) == 1
        assert results[0].success is True

    def test_convert_directory_nonexistent(self, tmp_path):
        converter = SigmaConverter()
        results = converter.convert_directory(tmp_path / "no_such_dir")
        assert results == []

    def test_convert_directory_ignores_non_yaml(self, tmp_path):
        (tmp_path / "readme.txt").write_text("not a sigma rule", encoding="utf-8")
        (tmp_path / "rule.yml").write_text(VALID_SIGMA_PROCESS, encoding="utf-8")
        converter = SigmaConverter()
        results = converter.convert_directory(tmp_path)
        assert len(results) == 1


# ================================================================== #
#  Selection/condition conversion internals
# ================================================================== #


class TestDetectionToConditions:
    """Tests for _detection_to_conditions and _selection_to_conditions."""

    def test_selection_dict_produces_conditions(self):
        converter = SigmaConverter()
        detection = {
            "selection": {"Image": "cmd.exe"},
            "condition": "selection",
        }
        conditions = converter._detection_to_conditions(detection)
        assert len(conditions) == 1
        assert conditions[0]["field"] == "exe"
        assert conditions[0]["op"] == "eq"
        assert conditions[0]["value"] == "cmd.exe"

    def test_selection_list_produces_conditions(self):
        converter = SigmaConverter()
        detection = {
            "selection": [
                {"Image": "cmd.exe"},
                {"Image": "powershell.exe"},
            ],
            "condition": "selection",
        }
        conditions = converter._detection_to_conditions(detection)
        assert len(conditions) == 2

    def test_contains_modifier_in_selection(self):
        converter = SigmaConverter()
        conditions = converter._selection_to_conditions(
            {"CommandLine|contains": "whoami"},
        )
        assert len(conditions) == 1
        assert conditions[0]["field"] == "cmdline"
        assert conditions[0]["op"] == "contains"
        assert conditions[0]["value"] == "whoami"

    def test_endswith_modifier_in_selection(self):
        converter = SigmaConverter()
        conditions = converter._selection_to_conditions(
            {"Image|endswith": "\\cmd.exe"},
        )
        assert len(conditions) == 1
        assert conditions[0]["op"] == "endswith"

    def test_contains_with_list_in_selection(self):
        converter = SigmaConverter()
        conditions = converter._selection_to_conditions(
            {"CommandLine|contains": ["-enc", "-e "]},
        )
        assert len(conditions) == 1
        assert conditions[0]["op"] == "contains_any"
        assert conditions[0]["value"] == ["-enc", "-e "]


# ================================================================== #
#  Integration: converted rule works with RuleEngine.evaluate()
# ================================================================== #


class TestRuleEngineIntegration:
    """Integration tests — Sigma-converted rules work with RuleEngine."""

    def test_converted_rule_matches_event(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_PROCESS)
        assert result.success is True

        engine = RuleEngine()
        engine.add_rule(result.rule)

        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={
                "exe": r"C:\Windows\System32\cmd.exe",
                "cmdline": "cmd.exe /c whoami",
            },
        )
        matches = engine.evaluate(event)
        assert len(matches) == 1
        assert matches[0].rule_id.startswith("sigma_")

    def test_converted_rule_does_not_match_wrong_data(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_PROCESS)

        engine = RuleEngine()
        engine.add_rule(result.rule)

        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_snapshot",
            data={
                "exe": r"C:\Windows\System32\notepad.exe",
                "cmdline": "notepad.exe readme.txt",
            },
        )
        matches = engine.evaluate(event)
        assert len(matches) == 0

    def test_converted_rule_does_not_match_wrong_event_type(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_PROCESS)

        engine = RuleEngine()
        engine.add_rule(result.rule)

        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_new",
            data={
                "exe": r"C:\Windows\System32\cmd.exe",
                "cmdline": "cmd.exe /c whoami",
            },
        )
        matches = engine.evaluate(event)
        assert len(matches) == 0

    def test_converted_dns_rule_matches(self):
        converter = SigmaConverter()
        result = converter.convert_rule_yaml(VALID_SIGMA_DNS)
        assert result.success is True

        engine = RuleEngine()
        engine.add_rule(result.rule)

        event = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="dns_query",
            data={"query_name": "evil-domain.tk"},
        )
        matches = engine.evaluate(event)
        assert len(matches) == 1

    def test_multiple_sigma_rules_loaded(self):
        converter = SigmaConverter()
        engine = RuleEngine()

        for yaml_str in (VALID_SIGMA_PROCESS, VALID_SIGMA_DNS, VALID_SIGMA_REGISTRY):
            result = converter.convert_rule_yaml(yaml_str)
            assert result.success is True
            engine.add_rule(result.rule)

        assert engine.rule_count == 3
