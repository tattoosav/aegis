"""Rule Engine — signature and behavioral rule matching.

Evaluates incoming events against a set of behavioral rules defined in YAML.
Rules use field-level conditions with operators (eq, in, gt, lt, contains_any).
All conditions in a rule must match for the rule to fire (AND logic).

Future: YARA file scanning and Sigma rule conversion will be added as
separate modules that feed into this engine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from aegis.core.models import AegisEvent, Severity

logger = logging.getLogger(__name__)

# Path to the built-in rules directory
_BUILTIN_RULES_DIR = Path(__file__).parent.parent.parent.parent / "rules"


def _check_condition(condition: dict[str, Any], data: dict[str, Any]) -> bool:
    """Evaluate a single condition against event data."""
    field_name = condition["field"]
    op = condition["op"]
    expected = condition["value"]

    actual = data.get(field_name)
    if actual is None:
        return False

    if op == "eq":
        return actual == expected
    elif op == "neq":
        return actual != expected
    elif op == "in":
        return actual in expected
    elif op == "not_in":
        return actual not in expected
    elif op == "gt":
        return float(actual) > float(expected)
    elif op == "lt":
        return float(actual) < float(expected)
    elif op == "gte":
        return float(actual) >= float(expected)
    elif op == "lte":
        return float(actual) <= float(expected)
    elif op == "contains":
        return str(expected) in str(actual)
    elif op == "contains_any":
        actual_str = str(actual).lower()
        return any(str(v).lower() in actual_str for v in expected)
    elif op == "startswith":
        if isinstance(expected, list):
            return any(str(actual).lower().startswith(str(v).lower()) for v in expected)
        return str(actual).lower().startswith(str(expected).lower())
    elif op == "endswith":
        if isinstance(expected, list):
            return any(str(actual).lower().endswith(str(v).lower()) for v in expected)
        return str(actual).lower().endswith(str(expected).lower())
    elif op == "regex":
        import re
        return bool(re.search(str(expected), str(actual)))
    else:
        logger.warning(f"Unknown operator '{op}' in rule condition")
        return False


@dataclass
class BehavioralRule:
    """A single behavioral detection rule."""

    rule_id: str
    description: str
    severity: Severity
    mitre_ids: list[str]
    sensor: str
    event_type: str
    conditions: list[dict[str, Any]]

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BehavioralRule:
        """Create a rule from a YAML dictionary."""
        severity_str = d.get("severity", "info")
        return cls(
            rule_id=d["id"],
            description=d.get("description", ""),
            severity=Severity.from_string(severity_str),
            mitre_ids=d.get("mitre", []),
            sensor=d.get("sensor", ""),
            event_type=d.get("event_type", ""),
            conditions=d.get("conditions", []),
        )

    def matches(self, event: AegisEvent) -> bool:
        """Check if this rule matches the given event.

        Returns True only if:
        - The event type matches the rule's expected event_type
        - ALL conditions evaluate to True against the event data
        """
        # Check event type filter
        if self.event_type and event.event_type != self.event_type:
            return False

        # Check sensor type filter
        if self.sensor and event.sensor.value != self.sensor:
            return False

        # All conditions must match (AND logic)
        if not self.conditions:
            return True

        return all(_check_condition(c, event.data) for c in self.conditions)


class RuleEngine:
    """Behavioral rule matching engine.

    Loads rules from YAML files and evaluates events against them.
    Returns list of matching rules for each event — fast, microsecond-level.
    """

    def __init__(self) -> None:
        self._rules: list[BehavioralRule] = []

    @property
    def rules(self) -> list[BehavioralRule]:
        """Get the loaded rules."""
        return list(self._rules)

    @property
    def rule_count(self) -> int:
        """Number of loaded rules."""
        return len(self._rules)

    def add_rule(self, rule: BehavioralRule) -> None:
        """Add a single rule to the engine."""
        self._rules.append(rule)

    def load_rules_file(self, path: str | Path) -> int:
        """Load rules from a YAML file. Returns count of rules loaded."""
        path = Path(path)
        if not path.exists():
            logger.warning(f"Rules file not found: {path}")
            return 0

        with open(path) as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            logger.warning(f"No 'rules' key found in {path}")
            return 0

        count = 0
        for rule_dict in data["rules"]:
            try:
                rule = BehavioralRule.from_dict(rule_dict)
                self._rules.append(rule)
                count += 1
            except (KeyError, ValueError) as e:
                logger.error(f"Error loading rule from {path}: {e}")

        logger.info(f"Loaded {count} rules from {path}")
        return count

    def load_builtin_rules(self) -> int:
        """Load the built-in behavioral rules shipped with Aegis."""
        builtin_path = _BUILTIN_RULES_DIR / "behavioral.yaml"
        if builtin_path.exists():
            return self.load_rules_file(builtin_path)
        logger.warning(f"Built-in rules not found at {builtin_path}")
        return 0

    def load_sigma_rules(self, directory: str | Path) -> int:
        """Load Sigma rules by converting them to BehavioralRules.

        Returns count of successfully converted rules.
        """
        try:
            from aegis.detection.sigma_converter import SigmaConverter
        except ImportError:
            logger.warning("Sigma converter not available")
            return 0

        converter = SigmaConverter()
        results = converter.convert_directory(directory)
        count = 0
        for result in results:
            if result.success and result.rule is not None:
                self._rules.append(result.rule)
                count += 1
            elif result.error:
                logger.debug(
                    "Sigma rule conversion failed (%s): %s",
                    result.source_file,
                    result.error,
                )
        logger.info("Loaded %d Sigma rules from %s", count, directory)
        return count

    def evaluate(self, event: AegisEvent) -> list[BehavioralRule]:
        """Evaluate an event against all rules. Returns matching rules."""
        return [rule for rule in self._rules if rule.matches(event)]
