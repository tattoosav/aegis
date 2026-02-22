"""Incident Response Playbook Engine.

Loads YAML-defined response playbooks and executes them when alerts
match trigger conditions.  All actions go through the existing
ActionExecutor with mandatory user approval — no action fires
automatically.

Playbook format::

    id: ransomware_response
    name: Ransomware Incident Response
    trigger:
      alert_type: yara_Ransomware_Note_Generic
      min_severity: high
    steps:
      - action: quarantine_file
        target_from: alert.data.path
        requires_approval: true
      - action: block_ip
        target: "1.2.3.4"
        requires_approval: true
        condition: alert.data.remote_addr != null
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aegis.core.models import Alert

logger = logging.getLogger(__name__)

# Default playbook directory
_DEFAULT_PLAYBOOKS_DIR = (
    Path(__file__).parent.parent.parent.parent / "rules" / "playbooks"
)

# Severity ordering for min_severity comparison
_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class PlaybookStep:
    """A single step in a response playbook."""

    step_id: str
    action: str
    target: str = ""
    target_from: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = True
    condition: str = ""
    status: str = "pending"  # pending, approved, executed, skipped, failed
    result_message: str = ""


@dataclass
class PlaybookTrigger:
    """Conditions that activate a playbook."""

    alert_type: str = ""
    alert_type_prefix: str = ""
    min_severity: str = "medium"
    sensor: str = ""


@dataclass
class Playbook:
    """A complete incident response playbook."""

    playbook_id: str
    name: str
    description: str = ""
    trigger: PlaybookTrigger = field(default_factory=PlaybookTrigger)
    steps: list[PlaybookStep] = field(default_factory=list)
    enabled: bool = True

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Playbook:
        """Create a Playbook from a parsed YAML dict."""
        trigger_data = d.get("trigger", {})
        trigger = PlaybookTrigger(
            alert_type=trigger_data.get("alert_type", ""),
            alert_type_prefix=trigger_data.get("alert_type_prefix", ""),
            min_severity=trigger_data.get("min_severity", "medium"),
            sensor=trigger_data.get("sensor", ""),
        )

        steps: list[PlaybookStep] = []
        for i, step_data in enumerate(d.get("steps", [])):
            steps.append(PlaybookStep(
                step_id=f"{d.get('id', 'pb')}_{i}",
                action=step_data.get("action", ""),
                target=str(step_data.get("target", "")),
                target_from=step_data.get("target_from", ""),
                params=step_data.get("params", {}),
                requires_approval=step_data.get("requires_approval", True),
                condition=step_data.get("condition", ""),
            ))

        return cls(
            playbook_id=d.get("id", f"pb-{uuid.uuid4().hex[:8]}"),
            name=d.get("name", "Unnamed Playbook"),
            description=d.get("description", ""),
            trigger=trigger,
            steps=steps,
            enabled=d.get("enabled", True),
        )


@dataclass
class PlaybookExecution:
    """Tracks the state of a running playbook execution."""

    execution_id: str
    playbook: Playbook
    alert: Alert
    steps: list[PlaybookStep]
    current_step: int = 0
    status: str = "running"  # running, completed, aborted


class PlaybookEngine:
    """Load and execute incident response playbooks.

    Playbooks are matched against alerts by trigger conditions.
    Steps are executed sequentially, each requiring user approval
    via the ActionExecutor's preview/approve workflow.
    """

    def __init__(
        self,
        playbooks_dir: str | Path | None = None,
    ) -> None:
        self._playbooks_dir = Path(playbooks_dir) if playbooks_dir else _DEFAULT_PLAYBOOKS_DIR
        self._playbooks: list[Playbook] = []
        self._executions: dict[str, PlaybookExecution] = {}

    @property
    def playbook_count(self) -> int:
        """Number of loaded playbooks."""
        return len(self._playbooks)

    @property
    def playbooks(self) -> list[Playbook]:
        """Get loaded playbooks."""
        return list(self._playbooks)

    @property
    def active_executions(self) -> list[PlaybookExecution]:
        """Get currently running playbook executions."""
        return [
            e for e in self._executions.values()
            if e.status == "running"
        ]

    def load_playbooks(self, directory: str | Path | None = None) -> int:
        """Load playbook YAML files from a directory.

        Returns count of playbooks loaded.
        """
        path = Path(directory) if directory else self._playbooks_dir
        if not path.is_dir():
            logger.warning("Playbooks directory not found: %s", path)
            return 0

        count = 0
        for ext in ("*.yaml", "*.yml"):
            for fpath in path.glob(ext):
                try:
                    text = fpath.read_text(encoding="utf-8")
                    data = yaml.safe_load(text)
                    if data:
                        playbook = Playbook.from_dict(data)
                        self._playbooks.append(playbook)
                        count += 1
                        logger.debug("Loaded playbook: %s", playbook.name)
                except Exception:
                    logger.warning(
                        "Failed to load playbook %s", fpath,
                        exc_info=True,
                    )

        logger.info("Loaded %d playbooks from %s", count, path)
        return count

    def add_playbook(self, playbook: Playbook) -> None:
        """Add a single playbook programmatically."""
        self._playbooks.append(playbook)

    def evaluate_trigger(self, alert: Alert) -> list[Playbook]:
        """Find all playbooks whose trigger matches the given alert.

        Returns list of matching playbooks (may be empty).
        """
        matches: list[Playbook] = []
        alert_severity_level = _SEVERITY_ORDER.get(alert.severity.value, 2)

        for pb in self._playbooks:
            if not pb.enabled:
                continue

            trigger = pb.trigger

            # Check alert_type exact match
            if trigger.alert_type:
                if alert.alert_type != trigger.alert_type:
                    continue

            # Check alert_type prefix match
            if trigger.alert_type_prefix:
                if not alert.alert_type.startswith(trigger.alert_type_prefix):
                    continue

            # Check min_severity
            min_level = _SEVERITY_ORDER.get(trigger.min_severity, 2)
            if alert_severity_level < min_level:
                continue

            # Check sensor filter
            if trigger.sensor:
                if alert.sensor.value != trigger.sensor:
                    continue

            matches.append(pb)

        return matches

    def start_execution(
        self, playbook: Playbook, alert: Alert,
    ) -> PlaybookExecution:
        """Begin executing a playbook for the given alert.

        Creates step instances with resolved targets and returns
        the execution tracker.
        """
        execution_id = f"exec-{uuid.uuid4().hex[:12]}"

        # Deep-copy steps so each execution is independent
        steps: list[PlaybookStep] = []
        for step in playbook.steps:
            resolved_target = self._resolve_target(step, alert)
            steps.append(PlaybookStep(
                step_id=f"{execution_id}_{step.step_id}",
                action=step.action,
                target=resolved_target,
                target_from=step.target_from,
                params=dict(step.params),
                requires_approval=step.requires_approval,
                condition=step.condition,
            ))

        execution = PlaybookExecution(
            execution_id=execution_id,
            playbook=playbook,
            alert=alert,
            steps=steps,
        )
        self._executions[execution_id] = execution
        logger.info(
            "Started playbook execution %s (%s) for alert %s",
            execution_id,
            playbook.name,
            alert.alert_id,
        )
        return execution

    def get_pending_steps(
        self, execution_id: str,
    ) -> list[PlaybookStep]:
        """Get steps awaiting user approval for an execution."""
        execution = self._executions.get(execution_id)
        if not execution or execution.status != "running":
            return []

        pending: list[PlaybookStep] = []
        for step in execution.steps:
            if step.status == "pending":
                # Check condition
                if step.condition and not self._evaluate_condition(
                    step.condition, execution.alert,
                ):
                    step.status = "skipped"
                    step.result_message = "Condition not met"
                    continue
                pending.append(step)
                break  # Only return next pending step (sequential)

        return pending

    def approve_step(self, step_id: str) -> PlaybookStep | None:
        """Mark a step as approved (ready for execution)."""
        for execution in self._executions.values():
            for step in execution.steps:
                if step.step_id == step_id and step.status == "pending":
                    step.status = "approved"
                    return step
        return None

    def skip_step(self, step_id: str) -> PlaybookStep | None:
        """Skip a step (user chose not to execute it)."""
        for execution in self._executions.values():
            for step in execution.steps:
                if step.step_id == step_id and step.status == "pending":
                    step.status = "skipped"
                    step.result_message = "Skipped by user"
                    return step
        return None

    def mark_step_executed(
        self, step_id: str, success: bool, message: str = "",
    ) -> None:
        """Mark a step as executed with result."""
        for execution in self._executions.values():
            for step in execution.steps:
                if step.step_id == step_id:
                    step.status = "executed" if success else "failed"
                    step.result_message = message

                    # Check if all steps are done
                    all_done = all(
                        s.status in ("executed", "skipped", "failed")
                        for s in execution.steps
                    )
                    if all_done:
                        execution.status = "completed"
                        logger.info(
                            "Playbook execution %s completed",
                            execution.execution_id,
                        )
                    return

    def abort_execution(self, execution_id: str) -> bool:
        """Abort a running playbook execution."""
        execution = self._executions.get(execution_id)
        if not execution or execution.status != "running":
            return False
        execution.status = "aborted"
        for step in execution.steps:
            if step.status == "pending":
                step.status = "skipped"
                step.result_message = "Execution aborted"
        logger.info("Playbook execution %s aborted", execution_id)
        return True

    def get_execution(self, execution_id: str) -> PlaybookExecution | None:
        """Get execution by ID."""
        return self._executions.get(execution_id)

    @staticmethod
    def _resolve_target(step: PlaybookStep, alert: Alert) -> str:
        """Resolve the target value for a step from the alert data."""
        if step.target:
            return step.target

        if step.target_from:
            # Navigate dotted path: "alert.data.path"
            parts = step.target_from.split(".")
            current: Any = alert
            for part in parts:
                if part == "alert":
                    continue
                if isinstance(current, dict):
                    current = current.get(part, "")
                elif hasattr(current, part):
                    current = getattr(current, part, "")
                else:
                    return ""
            return str(current) if current else ""

        return ""

    @staticmethod
    def _evaluate_condition(condition: str, alert: Alert) -> bool:
        """Evaluate a simple condition string against alert data.

        Supports:
        - ``alert.data.field != null`` — field exists and is not empty
        - ``alert.severity == critical`` — severity matches
        """
        condition = condition.strip()

        # Handle "alert.data.field != null"
        if "!= null" in condition:
            field_path = condition.replace("!= null", "").strip()
            parts = field_path.split(".")
            current: Any = alert
            for part in parts:
                if part == "alert":
                    continue
                if isinstance(current, dict):
                    current = current.get(part)
                elif hasattr(current, part):
                    current = getattr(current, part, None)
                else:
                    return False
            return current is not None and current != ""

        # Handle "alert.severity == value"
        if "alert.severity ==" in condition:
            expected = condition.split("==")[1].strip()
            return alert.severity.value == expected

        # Unknown condition — default to True (permissive)
        logger.debug("Unknown playbook condition: %s", condition)
        return True
