"""Sigma rule converter — translates Sigma YAML rules to Aegis detection format.

Parses Sigma rule YAML and converts Sigma detection logic (selection/condition
blocks with field modifiers) into Aegis BehavioralRule condition lists that the
existing RuleEngine can evaluate.

When pySigma is not available, the converter parses Sigma YAML directly using
PyYAML (which is already a dependency) to extract detection conditions.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aegis.core.models import Severity

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Field name mapping: Sigma field names → Aegis event.data field names
# --------------------------------------------------------------------------- #

SIGMA_FIELD_MAP: dict[str, str] = {
    "Image": "exe",
    "OriginalFileName": "name",
    "CommandLine": "cmdline",
    "ParentImage": "parent_exe",
    "ParentCommandLine": "parent_cmdline",
    "User": "username",
    "EventID": "event_id",
    "SourceName": "source",
    "TargetFilename": "path",
    "DestinationIp": "remote_addr",
    "DestinationPort": "remote_port",
    "SourceIp": "local_addr",
    "SourcePort": "local_port",
    "TargetObject": "key_path",
    "Details": "value_data",
    "QueryName": "query_name",
}

# Sigma logsource → Aegis (sensor_value, event_type) mapping
LOGSOURCE_MAP: dict[tuple[str, str], tuple[str, str]] = {
    ("windows", "process_creation"): ("process", "process_snapshot"),
    ("windows", "network_connection"): ("network", "connection_snapshot"),
    ("windows", "file_event"): ("file", "file_change"),
    ("windows", "registry_event"): ("registry", "registry_change"),
    ("windows", "ps_script"): ("eventlog", "security_event"),
    ("windows", "security"): ("eventlog", "security_event"),
    ("windows", "system"): ("eventlog", "security_event"),
    ("windows", "dns_query"): ("network", "dns_query"),
}

# Sigma severity → Aegis severity
_SEVERITY_MAP: dict[str, Severity] = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass
class SigmaConversionResult:
    """Outcome of converting a single Sigma rule."""

    rule: Any | None  # BehavioralRule or None
    source_file: str = ""
    sigma_id: str = ""
    sigma_title: str = ""
    success: bool = False
    error: str = ""


class SigmaConverter:
    """Converts Sigma YAML rules to Aegis BehavioralRule objects.

    Uses direct YAML parsing (no external pySigma dependency required).
    """

    def __init__(
        self,
        field_map: dict[str, str] | None = None,
        logsource_map: dict[tuple[str, str], tuple[str, str]] | None = None,
    ) -> None:
        self._field_map = field_map or SIGMA_FIELD_MAP
        self._logsource_map = logsource_map or LOGSOURCE_MAP

    def convert_file(self, path: str | Path) -> list[SigmaConversionResult]:
        """Convert a single Sigma YAML file (may contain one rule)."""
        path = Path(path)
        if not path.is_file():
            return [SigmaConversionResult(
                rule=None, source_file=str(path),
                error=f"File not found: {path}",
            )]

        try:
            text = path.read_text(encoding="utf-8")
            result = self.convert_rule_yaml(text)
            result.source_file = str(path)
            return [result]
        except Exception as exc:
            return [SigmaConversionResult(
                rule=None, source_file=str(path), error=str(exc),
            )]

    def convert_directory(self, path: str | Path) -> list[SigmaConversionResult]:
        """Convert all .yml/.yaml Sigma files in a directory recursively."""
        path = Path(path)
        results: list[SigmaConversionResult] = []
        if not path.is_dir():
            return results
        for ext in ("**/*.yml", "**/*.yaml"):
            for fpath in path.glob(ext):
                results.extend(self.convert_file(fpath))
        return results

    def convert_rule_yaml(self, yaml_content: str) -> SigmaConversionResult:
        """Convert a single Sigma rule from YAML string."""
        try:
            data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as exc:
            return SigmaConversionResult(rule=None, error=f"YAML parse error: {exc}")

        if not isinstance(data, dict):
            return SigmaConversionResult(rule=None, error="Invalid Sigma rule structure")

        sigma_id = data.get("id", "")
        sigma_title = data.get("title", "")

        # Extract logsource for sensor / event_type mapping
        logsource = data.get("logsource", {})
        product = logsource.get("product", "")
        category = logsource.get("category", "")
        sensor_val, event_type = self._logsource_map.get(
            (product, category), ("", ""),
        )

        # Extract detection block
        detection = data.get("detection", {})
        if not detection:
            return SigmaConversionResult(
                rule=None, sigma_id=sigma_id, sigma_title=sigma_title,
                error="No detection block found",
            )

        conditions = self._detection_to_conditions(detection)
        if not conditions:
            return SigmaConversionResult(
                rule=None, sigma_id=sigma_id, sigma_title=sigma_title,
                error="Could not convert detection conditions",
            )

        # Map severity
        level = data.get("level", "medium")
        severity = _SEVERITY_MAP.get(level, Severity.MEDIUM)

        # Extract MITRE tags
        mitre_ids: list[str] = []
        for tag in data.get("tags", []):
            tag_str = str(tag)
            match = re.search(r"t(\d{4}(?:\.\d{3})?)", tag_str, re.IGNORECASE)
            if match:
                mitre_ids.append(f"T{match.group(1)}")

        # Build BehavioralRule — import here to avoid circular dependency
        from aegis.detection.rule_engine import BehavioralRule

        rule_id = f"sigma_{sigma_id}" if sigma_id else f"sigma_{sigma_title[:30]}"
        rule = BehavioralRule(
            rule_id=rule_id,
            description=sigma_title or data.get("description", "Sigma rule"),
            severity=severity,
            mitre_ids=mitre_ids,
            sensor=sensor_val,
            event_type=event_type,
            conditions=conditions,
        )

        return SigmaConversionResult(
            rule=rule,
            sigma_id=sigma_id,
            sigma_title=sigma_title,
            success=True,
        )

    def _detection_to_conditions(
        self, detection: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Convert Sigma detection block to Aegis condition list.

        Handles the ``selection`` key and common Sigma modifiers:
        - field|contains → op: "contains"
        - field|endswith → op: "endswith"
        - field|startswith → op: "startswith"
        - field|re → op: "regex"
        - field with list value → op: "in"
        - field with single value → op: "eq"
        """
        conditions: list[dict[str, Any]] = []

        # Find the primary selection (ignore 'condition' key which is the logic expr)
        selection_keys = [
            k for k in detection if k not in ("condition", "timeframe")
        ]
        if not selection_keys:
            return []

        for sel_key in selection_keys:
            selection = detection[sel_key]
            if isinstance(selection, dict):
                conditions.extend(self._selection_to_conditions(selection))
            elif isinstance(selection, list):
                # List of dicts (OR logic) — take all as conditions
                for item in selection:
                    if isinstance(item, dict):
                        conditions.extend(self._selection_to_conditions(item))

        return conditions

    def _selection_to_conditions(
        self, selection: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Convert a single Sigma selection dict to conditions."""
        conditions: list[dict[str, Any]] = []

        for raw_field, value in selection.items():
            # Parse modifiers from field name: "CommandLine|contains"
            parts = raw_field.split("|")
            field_name = parts[0]
            modifiers = parts[1:] if len(parts) > 1 else []

            # Map Sigma field name to Aegis field name
            aegis_field = self._field_map.get(field_name, field_name.lower())

            # Determine operator based on modifiers
            op = self._modifiers_to_op(modifiers, value)
            cond_value = self._normalize_value(value, modifiers)

            conditions.append({
                "field": aegis_field,
                "op": op,
                "value": cond_value,
            })

        return conditions

    def _modifiers_to_op(
        self, modifiers: list[str], value: Any,
    ) -> str:
        """Determine the Aegis condition operator from Sigma modifiers."""
        if "re" in modifiers:
            return "regex"
        if "contains" in modifiers:
            if isinstance(value, list):
                return "contains_any"
            return "contains"
        if "startswith" in modifiers:
            return "startswith"
        if "endswith" in modifiers:
            return "endswith"
        # No modifier — infer from value type
        if isinstance(value, list):
            return "in"
        return "eq"

    def _normalize_value(self, value: Any, modifiers: list[str]) -> Any:
        """Normalize the condition value for Aegis."""
        if isinstance(value, list):
            return [str(v) for v in value]
        return value
