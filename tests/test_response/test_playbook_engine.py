"""Tests for PlaybookEngine — incident response playbook loading and execution."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from aegis.core.models import Alert, Severity, SensorType
from aegis.response.playbook_engine import (
    Playbook,
    PlaybookEngine,
    PlaybookExecution,
    PlaybookStep,
    PlaybookTrigger,
)

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _make_alert(
    alert_type: str = "test_alert",
    severity: Severity = Severity.MEDIUM,
    sensor: SensorType = SensorType.PROCESS,
    data: dict[str, Any] | None = None,
) -> Alert:
    """Create a minimal Alert for testing."""
    return Alert(
        event_id="evt-test123",
        sensor=sensor,
        alert_type=alert_type,
        severity=severity,
        title="Test Alert",
        description="A test alert for playbook engine tests.",
        confidence=0.9,
        data=data or {},
    )


def _make_playbook_dict(
    *,
    playbook_id: str = "pb_test",
    name: str = "Test Playbook",
    description: str = "A test playbook.",
    trigger: dict[str, Any] | None = None,
    steps: list[dict[str, Any]] | None = None,
    enabled: bool = True,
) -> dict[str, Any]:
    """Build a playbook dict suitable for Playbook.from_dict."""
    d: dict[str, Any] = {
        "id": playbook_id,
        "name": name,
        "description": description,
        "enabled": enabled,
    }
    if trigger is not None:
        d["trigger"] = trigger
    if steps is not None:
        d["steps"] = steps
    return d


def _make_playbook(**kwargs: Any) -> Playbook:
    """Convenience: build a Playbook dataclass from dict helpers."""
    return Playbook.from_dict(_make_playbook_dict(**kwargs))


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #

@pytest.fixture()
def engine() -> PlaybookEngine:
    """Return a fresh PlaybookEngine with no playbooks loaded."""
    return PlaybookEngine(playbooks_dir=None)


@pytest.fixture()
def sample_playbook() -> Playbook:
    """A single playbook with two steps."""
    return _make_playbook(
        playbook_id="ransomware_response",
        name="Ransomware Response",
        trigger={"alert_type": "yara_ransomware", "min_severity": "high"},
        steps=[
            {
                "action": "quarantine_file",
                "target_from": "alert.data.path",
                "requires_approval": True,
            },
            {
                "action": "block_ip",
                "target": "10.0.0.1",
                "requires_approval": True,
                "condition": "alert.data.remote_addr != null",
            },
        ],
    )


@pytest.fixture()
def high_alert() -> Alert:
    """A high-severity alert with data fields."""
    return _make_alert(
        alert_type="yara_ransomware",
        severity=Severity.HIGH,
        sensor=SensorType.FILE,
        data={
            "path": "C:\\temp\\malware.exe",
            "remote_addr": "10.0.0.1",
        },
    )


# ------------------------------------------------------------------ #
# TestPlaybookFromDict
# ------------------------------------------------------------------ #

class TestPlaybookFromDict:
    """Playbook.from_dict parsing."""

    def test_basic_fields(self) -> None:
        """Playbook id, name, and description are parsed."""
        pb = _make_playbook(
            playbook_id="pb1", name="My Playbook",
            description="desc",
        )
        assert pb.playbook_id == "pb1"
        assert pb.name == "My Playbook"
        assert pb.description == "desc"

    def test_trigger_parsed(self) -> None:
        """Trigger fields are forwarded to PlaybookTrigger."""
        pb = _make_playbook(trigger={
            "alert_type": "malware_detected",
            "min_severity": "critical",
            "sensor": "file",
        })
        assert pb.trigger.alert_type == "malware_detected"
        assert pb.trigger.min_severity == "critical"
        assert pb.trigger.sensor == "file"

    def test_step_parsing(self) -> None:
        """Steps list is converted to PlaybookStep objects."""
        pb = _make_playbook(steps=[
            {"action": "kill_process", "target": "1234"},
        ])
        assert len(pb.steps) == 1
        assert pb.steps[0].action == "kill_process"
        assert pb.steps[0].target == "1234"

    def test_defaults_when_missing(self) -> None:
        """Missing optional fields receive sensible defaults."""
        d: dict[str, Any] = {"id": "minimal", "name": "Minimal"}
        pb = Playbook.from_dict(d)
        assert pb.description == ""
        assert pb.enabled is True
        assert pb.trigger.min_severity == "medium"
        assert pb.steps == []

    def test_missing_id_generates_one(self) -> None:
        """A playbook dict without 'id' gets an auto-generated id."""
        d: dict[str, Any] = {"name": "No ID"}
        pb = Playbook.from_dict(d)
        assert pb.playbook_id.startswith("pb-")

    def test_empty_steps_list(self) -> None:
        """An explicit empty steps list is fine."""
        pb = _make_playbook(steps=[])
        assert pb.steps == []

    def test_multiple_steps_indexed(self) -> None:
        """Step IDs incorporate their index."""
        pb = _make_playbook(
            playbook_id="multi",
            steps=[
                {"action": "a1"},
                {"action": "a2"},
                {"action": "a3"},
            ],
        )
        assert len(pb.steps) == 3
        assert pb.steps[0].step_id == "multi_0"
        assert pb.steps[1].step_id == "multi_1"
        assert pb.steps[2].step_id == "multi_2"

    def test_enabled_flag_false(self) -> None:
        """enabled=False is preserved."""
        pb = _make_playbook(enabled=False)
        assert pb.enabled is False


# ------------------------------------------------------------------ #
# TestPlaybookTrigger
# ------------------------------------------------------------------ #

class TestPlaybookTrigger:
    """PlaybookTrigger dataclass defaults and fields."""

    def test_defaults(self) -> None:
        """Default trigger has empty strings and min_severity medium."""
        t = PlaybookTrigger()
        assert t.alert_type == ""
        assert t.alert_type_prefix == ""
        assert t.min_severity == "medium"
        assert t.sensor == ""

    def test_all_fields_set(self) -> None:
        """All fields can be set explicitly."""
        t = PlaybookTrigger(
            alert_type="malware",
            alert_type_prefix="yara_",
            min_severity="critical",
            sensor="network",
        )
        assert t.alert_type == "malware"
        assert t.alert_type_prefix == "yara_"
        assert t.min_severity == "critical"
        assert t.sensor == "network"

    def test_partial_alert_type_only(self) -> None:
        """Setting only alert_type leaves others default."""
        t = PlaybookTrigger(alert_type="suspicious_login")
        assert t.alert_type == "suspicious_login"
        assert t.alert_type_prefix == ""
        assert t.min_severity == "medium"

    def test_partial_prefix_only(self) -> None:
        """Setting only alert_type_prefix leaves others default."""
        t = PlaybookTrigger(alert_type_prefix="sigma_")
        assert t.alert_type_prefix == "sigma_"
        assert t.alert_type == ""

    def test_partial_sensor_only(self) -> None:
        """Setting only sensor leaves others default."""
        t = PlaybookTrigger(sensor="file")
        assert t.sensor == "file"
        assert t.min_severity == "medium"


# ------------------------------------------------------------------ #
# TestPlaybookEngine
# ------------------------------------------------------------------ #

class TestPlaybookEngine:
    """PlaybookEngine init, add, count, list, and load operations."""

    def test_init_empty(self, engine: PlaybookEngine) -> None:
        """Fresh engine has zero playbooks and no executions."""
        assert engine.playbook_count == 0
        assert engine.playbooks == []
        assert engine.active_executions == []

    def test_add_playbook_increments_count(
        self, engine: PlaybookEngine,
    ) -> None:
        """add_playbook increases playbook_count."""
        pb = _make_playbook(playbook_id="one")
        engine.add_playbook(pb)
        assert engine.playbook_count == 1

    def test_add_multiple_playbooks(
        self, engine: PlaybookEngine,
    ) -> None:
        """Multiple playbooks can be added."""
        engine.add_playbook(_make_playbook(playbook_id="a"))
        engine.add_playbook(_make_playbook(playbook_id="b"))
        engine.add_playbook(_make_playbook(playbook_id="c"))
        assert engine.playbook_count == 3

    def test_playbooks_property_returns_copy(
        self, engine: PlaybookEngine,
    ) -> None:
        """playbooks property returns a new list (not the internal ref)."""
        pb = _make_playbook(playbook_id="x")
        engine.add_playbook(pb)
        result = engine.playbooks
        result.clear()
        assert engine.playbook_count == 1  # Internal list unaffected

    def test_playbooks_property_contents(
        self, engine: PlaybookEngine,
    ) -> None:
        """playbooks property contains the added playbook objects."""
        pb = _make_playbook(playbook_id="myid", name="My PB")
        engine.add_playbook(pb)
        pbs = engine.playbooks
        assert len(pbs) == 1
        assert pbs[0].playbook_id == "myid"
        assert pbs[0].name == "My PB"

    def test_load_playbooks_from_directory(
        self, engine: PlaybookEngine, tmp_path: Path,
    ) -> None:
        """load_playbooks reads YAML files from a directory."""
        yaml_content = (
            "id: loaded_pb\n"
            "name: Loaded Playbook\n"
            "trigger:\n"
            "  alert_type: test\n"
            "  min_severity: low\n"
            "steps:\n"
            "  - action: block_ip\n"
            "    target: 1.2.3.4\n"
        )
        (tmp_path / "test_playbook.yaml").write_text(
            yaml_content, encoding="utf-8",
        )
        count = engine.load_playbooks(tmp_path)
        assert count == 1
        assert engine.playbook_count == 1
        assert engine.playbooks[0].playbook_id == "loaded_pb"

    def test_load_playbooks_yml_extension(
        self, engine: PlaybookEngine, tmp_path: Path,
    ) -> None:
        """load_playbooks also reads *.yml files."""
        yaml_content = (
            "id: yml_pb\n"
            "name: YML Playbook\n"
            "steps: []\n"
        )
        (tmp_path / "playbook.yml").write_text(
            yaml_content, encoding="utf-8",
        )
        count = engine.load_playbooks(tmp_path)
        assert count == 1
        assert engine.playbooks[0].playbook_id == "yml_pb"

    def test_load_multiple_files(
        self, engine: PlaybookEngine, tmp_path: Path,
    ) -> None:
        """load_playbooks reads all YAML files in the directory."""
        for i in range(3):
            (tmp_path / f"pb{i}.yaml").write_text(
                f"id: pb{i}\nname: Playbook {i}\n",
                encoding="utf-8",
            )
        count = engine.load_playbooks(tmp_path)
        assert count == 3
        assert engine.playbook_count == 3

    def test_load_playbooks_missing_directory(
        self, engine: PlaybookEngine, tmp_path: Path,
    ) -> None:
        """load_playbooks returns 0 for a nonexistent directory."""
        missing = tmp_path / "no_such_dir"
        count = engine.load_playbooks(missing)
        assert count == 0

    def test_load_playbooks_invalid_yaml(
        self, engine: PlaybookEngine, tmp_path: Path,
    ) -> None:
        """Invalid YAML files are skipped without crashing."""
        (tmp_path / "bad.yaml").write_text(
            "{{{{not valid yaml: [[[",
            encoding="utf-8",
        )
        (tmp_path / "good.yaml").write_text(
            "id: good\nname: Good\n",
            encoding="utf-8",
        )
        count = engine.load_playbooks(tmp_path)
        # The good file should load; the bad one is skipped
        assert count >= 1
        ids = [pb.playbook_id for pb in engine.playbooks]
        assert "good" in ids

    def test_load_playbooks_empty_yaml(
        self, engine: PlaybookEngine, tmp_path: Path,
    ) -> None:
        """An empty YAML file (None result) is skipped."""
        (tmp_path / "empty.yaml").write_text("", encoding="utf-8")
        count = engine.load_playbooks(tmp_path)
        assert count == 0

    def test_load_uses_default_dir_when_none(
        self, tmp_path: Path,
    ) -> None:
        """Engine constructor stores playbooks_dir, used by load."""
        eng = PlaybookEngine(playbooks_dir=tmp_path)
        (tmp_path / "def.yaml").write_text(
            "id: def\nname: Default Dir PB\n",
            encoding="utf-8",
        )
        count = eng.load_playbooks()
        assert count == 1


# ------------------------------------------------------------------ #
# TestEvaluateTrigger
# ------------------------------------------------------------------ #

class TestEvaluateTrigger:
    """Trigger evaluation against alerts."""

    def test_exact_alert_type_match(
        self, engine: PlaybookEngine,
    ) -> None:
        """Playbook matches when alert_type is identical."""
        engine.add_playbook(_make_playbook(
            trigger={"alert_type": "malware_detected"},
        ))
        alert = _make_alert(alert_type="malware_detected")
        matches = engine.evaluate_trigger(alert)
        assert len(matches) == 1

    def test_exact_alert_type_no_match(
        self, engine: PlaybookEngine,
    ) -> None:
        """Playbook does not match when alert_type differs."""
        engine.add_playbook(_make_playbook(
            trigger={"alert_type": "malware_detected"},
        ))
        alert = _make_alert(alert_type="network_anomaly")
        matches = engine.evaluate_trigger(alert)
        assert len(matches) == 0

    def test_prefix_match(self, engine: PlaybookEngine) -> None:
        """Playbook matches when alert_type starts with prefix."""
        engine.add_playbook(_make_playbook(
            trigger={"alert_type_prefix": "yara_"},
        ))
        alert = _make_alert(alert_type="yara_Ransomware_Note")
        matches = engine.evaluate_trigger(alert)
        assert len(matches) == 1

    def test_prefix_no_match(self, engine: PlaybookEngine) -> None:
        """Prefix trigger rejects alert_type without the prefix."""
        engine.add_playbook(_make_playbook(
            trigger={"alert_type_prefix": "sigma_"},
        ))
        alert = _make_alert(alert_type="yara_Ransomware_Note")
        matches = engine.evaluate_trigger(alert)
        assert len(matches) == 0

    @pytest.mark.parametrize(
        ("min_sev", "alert_sev", "should_match"),
        [
            ("info", Severity.INFO, True),
            ("info", Severity.CRITICAL, True),
            ("low", Severity.INFO, False),
            ("medium", Severity.LOW, False),
            ("medium", Severity.MEDIUM, True),
            ("medium", Severity.HIGH, True),
            ("high", Severity.MEDIUM, False),
            ("high", Severity.HIGH, True),
            ("high", Severity.CRITICAL, True),
            ("critical", Severity.HIGH, False),
            ("critical", Severity.CRITICAL, True),
        ],
    )
    def test_min_severity_filtering(
        self,
        engine: PlaybookEngine,
        min_sev: str,
        alert_sev: Severity,
        should_match: bool,
    ) -> None:
        """min_severity correctly filters by severity level."""
        engine.add_playbook(_make_playbook(
            playbook_id=f"sev_{min_sev}",
            trigger={"min_severity": min_sev},
        ))
        alert = _make_alert(severity=alert_sev)
        matches = engine.evaluate_trigger(alert)
        assert (len(matches) > 0) is should_match

    def test_sensor_filter_match(
        self, engine: PlaybookEngine,
    ) -> None:
        """Sensor filter matches correct sensor type."""
        engine.add_playbook(_make_playbook(
            trigger={"sensor": "network"},
        ))
        alert = _make_alert(sensor=SensorType.NETWORK)
        matches = engine.evaluate_trigger(alert)
        assert len(matches) == 1

    def test_sensor_filter_no_match(
        self, engine: PlaybookEngine,
    ) -> None:
        """Sensor filter rejects wrong sensor type."""
        engine.add_playbook(_make_playbook(
            trigger={"sensor": "network"},
        ))
        alert = _make_alert(sensor=SensorType.FILE)
        matches = engine.evaluate_trigger(alert)
        assert len(matches) == 0

    def test_multiple_playbook_matches(
        self, engine: PlaybookEngine,
    ) -> None:
        """Multiple playbooks can match the same alert."""
        engine.add_playbook(_make_playbook(
            playbook_id="a",
            trigger={"alert_type_prefix": "yara_"},
        ))
        engine.add_playbook(_make_playbook(
            playbook_id="b",
            trigger={"min_severity": "low"},
        ))
        alert = _make_alert(
            alert_type="yara_Ransomware",
            severity=Severity.HIGH,
        )
        matches = engine.evaluate_trigger(alert)
        assert len(matches) == 2

    def test_no_match_returns_empty(
        self, engine: PlaybookEngine,
    ) -> None:
        """No matches returns an empty list."""
        engine.add_playbook(_make_playbook(
            trigger={
                "alert_type": "specific_type",
                "min_severity": "critical",
            },
        ))
        alert = _make_alert(
            alert_type="other_type",
            severity=Severity.LOW,
        )
        matches = engine.evaluate_trigger(alert)
        assert matches == []

    def test_disabled_playbook_skipped(
        self, engine: PlaybookEngine,
    ) -> None:
        """Disabled playbooks are not matched."""
        engine.add_playbook(_make_playbook(
            playbook_id="disabled",
            enabled=False,
            trigger={"min_severity": "info"},
        ))
        alert = _make_alert(severity=Severity.CRITICAL)
        matches = engine.evaluate_trigger(alert)
        assert len(matches) == 0

    def test_combined_trigger_conditions(
        self, engine: PlaybookEngine,
    ) -> None:
        """All trigger conditions must be satisfied together."""
        engine.add_playbook(_make_playbook(
            trigger={
                "alert_type": "yara_ransomware",
                "min_severity": "high",
                "sensor": "file",
            },
        ))
        # All conditions met
        alert_good = _make_alert(
            alert_type="yara_ransomware",
            severity=Severity.HIGH,
            sensor=SensorType.FILE,
        )
        assert len(engine.evaluate_trigger(alert_good)) == 1

        # Wrong sensor
        alert_bad_sensor = _make_alert(
            alert_type="yara_ransomware",
            severity=Severity.HIGH,
            sensor=SensorType.NETWORK,
        )
        assert len(engine.evaluate_trigger(alert_bad_sensor)) == 0

        # Right sensor, wrong severity
        alert_bad_sev = _make_alert(
            alert_type="yara_ransomware",
            severity=Severity.LOW,
            sensor=SensorType.FILE,
        )
        assert len(engine.evaluate_trigger(alert_bad_sev)) == 0


# ------------------------------------------------------------------ #
# TestExecution
# ------------------------------------------------------------------ #

class TestExecution:
    """Playbook execution lifecycle."""

    def test_start_execution_creates_execution(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """start_execution returns a PlaybookExecution."""
        exe = engine.start_execution(sample_playbook, high_alert)
        assert isinstance(exe, PlaybookExecution)
        assert exe.status == "running"
        assert exe.execution_id.startswith("exec-")

    def test_start_execution_resolves_static_target(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """Static target values are preserved in execution steps."""
        exe = engine.start_execution(sample_playbook, high_alert)
        # Second step has target="10.0.0.1"
        assert exe.steps[1].target == "10.0.0.1"

    def test_start_execution_resolves_target_from(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """target_from resolves dotted path from alert data."""
        exe = engine.start_execution(sample_playbook, high_alert)
        # First step: target_from="alert.data.path"
        assert exe.steps[0].target == "C:\\temp\\malware.exe"

    def test_execution_steps_are_independent_copies(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """Each execution gets independent step copies."""
        exe1 = engine.start_execution(sample_playbook, high_alert)
        exe2 = engine.start_execution(sample_playbook, high_alert)
        exe1.steps[0].status = "approved"
        assert exe2.steps[0].status == "pending"

    def test_get_pending_steps_returns_next(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """get_pending_steps returns the next pending step only."""
        exe = engine.start_execution(sample_playbook, high_alert)
        pending = engine.get_pending_steps(exe.execution_id)
        assert len(pending) == 1
        assert pending[0].action == "quarantine_file"

    def test_approve_step(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """approve_step changes status from pending to approved."""
        exe = engine.start_execution(sample_playbook, high_alert)
        pending = engine.get_pending_steps(exe.execution_id)
        step = engine.approve_step(pending[0].step_id)
        assert step is not None
        assert step.status == "approved"

    def test_skip_step(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """skip_step marks step as skipped with user message."""
        exe = engine.start_execution(sample_playbook, high_alert)
        pending = engine.get_pending_steps(exe.execution_id)
        step = engine.skip_step(pending[0].step_id)
        assert step is not None
        assert step.status == "skipped"
        assert "Skipped by user" in step.result_message

    def test_mark_step_executed_success(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """mark_step_executed with success=True sets status executed."""
        exe = engine.start_execution(sample_playbook, high_alert)
        pending = engine.get_pending_steps(exe.execution_id)
        step_id = pending[0].step_id
        engine.approve_step(step_id)
        engine.mark_step_executed(step_id, success=True, message="OK")
        assert exe.steps[0].status == "executed"
        assert exe.steps[0].result_message == "OK"

    def test_mark_step_executed_failure(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """mark_step_executed with success=False sets status failed."""
        exe = engine.start_execution(sample_playbook, high_alert)
        pending = engine.get_pending_steps(exe.execution_id)
        step_id = pending[0].step_id
        engine.approve_step(step_id)
        engine.mark_step_executed(
            step_id, success=False, message="Access denied",
        )
        assert exe.steps[0].status == "failed"
        assert exe.steps[0].result_message == "Access denied"

    def test_auto_complete_when_all_done(
        self,
        engine: PlaybookEngine,
        high_alert: Alert,
    ) -> None:
        """Execution auto-completes when every step is done."""
        pb = _make_playbook(
            playbook_id="auto_complete",
            steps=[{"action": "block_ip", "target": "1.2.3.4"}],
        )
        exe = engine.start_execution(pb, high_alert)
        pending = engine.get_pending_steps(exe.execution_id)
        step_id = pending[0].step_id
        engine.approve_step(step_id)
        engine.mark_step_executed(step_id, success=True)
        assert exe.status == "completed"

    def test_abort_execution(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """abort_execution sets status aborted and skips pending."""
        exe = engine.start_execution(sample_playbook, high_alert)
        result = engine.abort_execution(exe.execution_id)
        assert result is True
        assert exe.status == "aborted"
        for step in exe.steps:
            assert step.status in ("skipped",)

    def test_abort_nonexistent_execution(
        self, engine: PlaybookEngine,
    ) -> None:
        """Aborting a nonexistent execution returns False."""
        result = engine.abort_execution("exec-nonexistent")
        assert result is False

    def test_abort_already_completed(
        self,
        engine: PlaybookEngine,
        high_alert: Alert,
    ) -> None:
        """Cannot abort an already-completed execution."""
        pb = _make_playbook(
            playbook_id="one_step",
            steps=[{"action": "block_ip", "target": "1.2.3.4"}],
        )
        exe = engine.start_execution(pb, high_alert)
        pending = engine.get_pending_steps(exe.execution_id)
        engine.approve_step(pending[0].step_id)
        engine.mark_step_executed(pending[0].step_id, success=True)
        assert exe.status == "completed"
        result = engine.abort_execution(exe.execution_id)
        assert result is False

    def test_get_execution(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """get_execution returns the correct execution by ID."""
        exe = engine.start_execution(sample_playbook, high_alert)
        found = engine.get_execution(exe.execution_id)
        assert found is exe

    def test_get_execution_not_found(
        self, engine: PlaybookEngine,
    ) -> None:
        """get_execution returns None for unknown ID."""
        assert engine.get_execution("exec-nope") is None

    def test_active_executions_excludes_completed(
        self,
        engine: PlaybookEngine,
        high_alert: Alert,
    ) -> None:
        """active_executions only returns running executions."""
        pb = _make_playbook(
            playbook_id="single",
            steps=[{"action": "a", "target": "t"}],
        )
        exe = engine.start_execution(pb, high_alert)
        assert len(engine.active_executions) == 1

        pending = engine.get_pending_steps(exe.execution_id)
        engine.approve_step(pending[0].step_id)
        engine.mark_step_executed(pending[0].step_id, success=True)
        assert len(engine.active_executions) == 0

    def test_approve_nonexistent_step(
        self, engine: PlaybookEngine,
    ) -> None:
        """Approving a step that does not exist returns None."""
        result = engine.approve_step("no-such-step-id")
        assert result is None

    def test_skip_nonexistent_step(
        self, engine: PlaybookEngine,
    ) -> None:
        """Skipping a step that does not exist returns None."""
        result = engine.skip_step("no-such-step-id")
        assert result is None

    def test_get_pending_steps_empty_for_aborted(
        self,
        engine: PlaybookEngine,
        sample_playbook: Playbook,
        high_alert: Alert,
    ) -> None:
        """get_pending_steps returns empty for aborted execution."""
        exe = engine.start_execution(sample_playbook, high_alert)
        engine.abort_execution(exe.execution_id)
        pending = engine.get_pending_steps(exe.execution_id)
        assert pending == []

    def test_condition_skips_step_in_get_pending(
        self, engine: PlaybookEngine,
    ) -> None:
        """Step whose condition fails is auto-skipped by get_pending."""
        pb = _make_playbook(
            playbook_id="cond_skip",
            steps=[
                {
                    "action": "block_ip",
                    "target": "1.2.3.4",
                    "condition": "alert.data.remote_addr != null",
                },
            ],
        )
        # Alert WITHOUT remote_addr
        alert = _make_alert(data={})
        exe = engine.start_execution(pb, alert)
        pending = engine.get_pending_steps(exe.execution_id)
        assert pending == []
        assert exe.steps[0].status == "skipped"
        assert "Condition not met" in exe.steps[0].result_message


# ------------------------------------------------------------------ #
# TestConditionEvaluation
# ------------------------------------------------------------------ #

class TestConditionEvaluation:
    """PlaybookEngine._evaluate_condition static method."""

    def test_field_not_null_present(self) -> None:
        """'!= null' returns True when field exists and is non-empty."""
        alert = _make_alert(data={"remote_addr": "10.0.0.1"})
        result = PlaybookEngine._evaluate_condition(
            "alert.data.remote_addr != null", alert,
        )
        assert result is True

    def test_field_not_null_missing(self) -> None:
        """'!= null' returns False when field is missing."""
        alert = _make_alert(data={})
        result = PlaybookEngine._evaluate_condition(
            "alert.data.remote_addr != null", alert,
        )
        assert result is False

    def test_field_not_null_empty_string(self) -> None:
        """'!= null' returns False when field is an empty string."""
        alert = _make_alert(data={"remote_addr": ""})
        result = PlaybookEngine._evaluate_condition(
            "alert.data.remote_addr != null", alert,
        )
        assert result is False

    def test_severity_equals_match(self) -> None:
        """'alert.severity == X' returns True on match."""
        alert = _make_alert(severity=Severity.CRITICAL)
        result = PlaybookEngine._evaluate_condition(
            "alert.severity == critical", alert,
        )
        assert result is True

    def test_severity_equals_no_match(self) -> None:
        """'alert.severity == X' returns False on mismatch."""
        alert = _make_alert(severity=Severity.LOW)
        result = PlaybookEngine._evaluate_condition(
            "alert.severity == critical", alert,
        )
        assert result is False

    def test_unknown_condition_defaults_true(self) -> None:
        """Unknown condition expressions default to True."""
        alert = _make_alert()
        result = PlaybookEngine._evaluate_condition(
            "some.weird.condition > 42", alert,
        )
        assert result is True

    def test_nested_field_not_null(self) -> None:
        """'!= null' traverses nested dict fields."""
        alert = _make_alert(
            data={"network": {"dest_ip": "192.168.1.1"}},
        )
        result = PlaybookEngine._evaluate_condition(
            "alert.data.network.dest_ip != null", alert,
        )
        assert result is True

    def test_nested_field_not_null_missing_parent(self) -> None:
        """'!= null' returns False when parent dict is missing."""
        alert = _make_alert(data={})
        result = PlaybookEngine._evaluate_condition(
            "alert.data.network.dest_ip != null", alert,
        )
        assert result is False


# ------------------------------------------------------------------ #
# TestTargetResolution
# ------------------------------------------------------------------ #

class TestTargetResolution:
    """PlaybookEngine._resolve_target static method."""

    def test_static_target(self) -> None:
        """When step.target is set, it is returned directly."""
        step = PlaybookStep(
            step_id="s1",
            action="block_ip",
            target="10.0.0.1",
        )
        alert = _make_alert()
        result = PlaybookEngine._resolve_target(step, alert)
        assert result == "10.0.0.1"

    def test_target_from_dotted_path(self) -> None:
        """target_from resolves a simple dotted path."""
        step = PlaybookStep(
            step_id="s2",
            action="quarantine_file",
            target_from="alert.data.path",
        )
        alert = _make_alert(data={"path": "/tmp/evil.bin"})
        result = PlaybookEngine._resolve_target(step, alert)
        assert result == "/tmp/evil.bin"

    def test_target_from_nested_dict(self) -> None:
        """target_from traverses nested dict values."""
        step = PlaybookStep(
            step_id="s3",
            action="block_ip",
            target_from="alert.data.connection.remote_ip",
        )
        alert = _make_alert(
            data={"connection": {"remote_ip": "203.0.113.5"}},
        )
        result = PlaybookEngine._resolve_target(step, alert)
        assert result == "203.0.113.5"

    def test_target_from_missing_field(self) -> None:
        """target_from returns '' when the path does not exist."""
        step = PlaybookStep(
            step_id="s4",
            action="quarantine_file",
            target_from="alert.data.nonexistent",
        )
        alert = _make_alert(data={})
        result = PlaybookEngine._resolve_target(step, alert)
        assert result == ""

    def test_no_target_no_target_from(self) -> None:
        """Returns '' when neither target nor target_from is set."""
        step = PlaybookStep(step_id="s5", action="disconnect_network")
        alert = _make_alert()
        result = PlaybookEngine._resolve_target(step, alert)
        assert result == ""
