"""LOLBins behavioral analysis — parent-child and command-line detection.

Detects Living-off-the-Land Binaries (LOLBins) abuse by analysing
process creation events for two categories of suspicious behaviour:

1. **Parent-child relationships** — e.g. Office apps spawning scripting
   engines, which is a hallmark of macro-based malware delivery.
2. **Command-line patterns** — regex matching against known abuse
   patterns for certutil, mshta, regsvr32, rundll32, bitsadmin,
   wmic, cmstp, and msiexec.

Rules are loaded from a YAML file (``rules/lolbins/lolbins.yaml``) with
a built-in fallback dictionary when the file is not available.

MITRE coverage: T1105, T1140, T1197, T1204.002, T1218.*,
T1047, T1059.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from aegis.core.models import AegisEvent

logger = logging.getLogger(__name__)

# Default YAML rules path relative to the project root.
_DEFAULT_RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "lolbins" / "lolbins.yaml"


@dataclass
class LOLBinFinding:
    """A single LOLBins detection finding.

    Attributes
    ----------
    binary : str
        The suspicious binary that was matched.
    severity : str
        Severity level (``low``, ``medium``, ``high``, ``critical``).
    mitre_id : str
        MITRE ATT&CK technique identifier.
    description : str
        Human-readable description of the finding.
    matched_rule : str
        Name of the YAML rule that triggered this finding.
    """

    binary: str
    severity: str
    mitre_id: str
    description: str
    matched_rule: str


# ------------------------------------------------------------------ #
#  Built-in fallback rules (used when YAML file is unavailable)
# ------------------------------------------------------------------ #

_FALLBACK_RULES: dict[str, Any] = {
    "parent_child_rules": [
        {
            "name": "office_spawns_scripting",
            "parents": [
                "winword.exe", "excel.exe", "powerpnt.exe",
                "outlook.exe", "msaccess.exe",
            ],
            "children": [
                "powershell.exe", "cmd.exe", "wscript.exe",
                "cscript.exe", "mshta.exe",
            ],
            "severity": "high",
            "mitre_id": "T1204.002",
            "description": "Office application spawned scripting engine",
        },
        {
            "name": "office_spawns_rundll32",
            "parents": [
                "winword.exe", "excel.exe", "powerpnt.exe",
            ],
            "children": ["rundll32.exe", "regsvr32.exe"],
            "severity": "high",
            "mitre_id": "T1218",
            "description": "Office application spawned system binary",
        },
    ],
    "command_line_rules": [
        {
            "binary": "certutil.exe",
            "patterns": [
                {
                    "pattern": "urlcache.*-f\\s+https?://",
                    "severity": "high",
                    "mitre_id": "T1105",
                    "description": "Certutil used for file download",
                },
                {
                    "pattern": "-decode",
                    "severity": "medium",
                    "mitre_id": "T1140",
                    "description": "Certutil used for base64 decode",
                },
            ],
        },
        {
            "binary": "mshta.exe",
            "patterns": [
                {
                    "pattern": "https?://",
                    "severity": "high",
                    "mitre_id": "T1218.005",
                    "description": "MSHTA executing remote HTA",
                },
                {
                    "pattern": "vbscript:|javascript:",
                    "severity": "high",
                    "mitre_id": "T1218.005",
                    "description": "MSHTA executing inline script",
                },
            ],
        },
        {
            "binary": "regsvr32.exe",
            "patterns": [
                {
                    "pattern": "/i:https?://|scrobj\\.dll",
                    "severity": "high",
                    "mitre_id": "T1218.010",
                    "description": "Regsvr32 Squiblydoo attack",
                },
            ],
        },
        {
            "binary": "rundll32.exe",
            "patterns": [
                {
                    "pattern": "javascript:|vbscript:",
                    "severity": "high",
                    "mitre_id": "T1218.011",
                    "description": "Rundll32 executing script",
                },
            ],
        },
        {
            "binary": "bitsadmin.exe",
            "patterns": [
                {
                    "pattern": "/transfer.*https?://",
                    "severity": "medium",
                    "mitre_id": "T1197",
                    "description": "BITSAdmin used for file download",
                },
            ],
        },
        {
            "binary": "wmic.exe",
            "patterns": [
                {
                    "pattern": "process\\s+call\\s+create",
                    "severity": "medium",
                    "mitre_id": "T1047",
                    "description": "WMIC remote process creation",
                },
            ],
        },
        {
            "binary": "cmstp.exe",
            "patterns": [
                {
                    "pattern": "/s\\s+.*\\.inf",
                    "severity": "high",
                    "mitre_id": "T1218.003",
                    "description": "CMSTP bypass via INF file",
                },
            ],
        },
        {
            "binary": "msiexec.exe",
            "patterns": [
                {
                    "pattern": "https?://",
                    "severity": "medium",
                    "mitre_id": "T1218.007",
                    "description": "Msiexec executing remote MSI",
                },
            ],
        },
    ],
}


class LOLBinsAnalyzer:
    """Detect Living-off-the-Land Binary abuse.

    Loads detection rules from a YAML file and provides two public
    check methods:

    * :meth:`check_parent_child` — flags suspicious process lineage.
    * :meth:`check_command_line` — flags suspicious CLI patterns.
    * :meth:`analyze_process_event` — runs both checks on an
      :class:`~aegis.core.models.AegisEvent`.
    """

    def __init__(self, rules_path: str | None = None) -> None:
        """Load LOLBins detection rules.

        Parameters
        ----------
        rules_path : str | None
            Path to a YAML rules file.  Falls back to the default
            ``rules/lolbins/lolbins.yaml`` relative to the project
            root, or to a built-in dictionary if the file cannot be
            read.
        """
        raw = self._load_rules(rules_path)
        self._parent_child_rules: list[dict[str, Any]] = raw.get(
            "parent_child_rules", [],
        )
        self._command_line_rules: dict[str, list[dict[str, Any]]] = (
            self._index_command_line_rules(
                raw.get("command_line_rules", []),
            )
        )

    # ------------------------------------------------------------------ #
    #  Rule loading
    # ------------------------------------------------------------------ #

    @staticmethod
    def _load_rules(rules_path: str | None) -> dict[str, Any]:
        """Load rules from YAML file or fall back to built-in dict."""
        path = Path(rules_path) if rules_path else _DEFAULT_RULES_PATH
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if isinstance(data, dict):
                logger.info("Loaded LOLBins rules from %s", path)
                return data
        except (OSError, yaml.YAMLError) as exc:
            logger.warning(
                "Could not load LOLBins rules from %s: %s — "
                "using built-in fallback",
                path,
                exc,
            )
        return _FALLBACK_RULES

    @staticmethod
    def _index_command_line_rules(
        rules: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Index command-line rules by binary name (lowercased).

        Compiles the regex patterns and stores them alongside the
        original rule metadata.
        """
        indexed: dict[str, list[dict[str, Any]]] = {}
        for rule in rules:
            binary = rule["binary"].lower()
            compiled: list[dict[str, Any]] = []
            for pat in rule.get("patterns", []):
                compiled.append({
                    "regex": re.compile(pat["pattern"], re.IGNORECASE),
                    "severity": pat["severity"],
                    "mitre_id": pat["mitre_id"],
                    "description": pat["description"],
                })
            indexed[binary] = compiled
        return indexed

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def check_parent_child(
        self,
        parent: str,
        child: str,
        cmd: str,
    ) -> LOLBinFinding | None:
        """Check for a suspicious parent-child process relationship.

        Parameters
        ----------
        parent : str
            Parent process executable name (e.g. ``winword.exe``).
        child : str
            Child process executable name (e.g. ``powershell.exe``).
        cmd : str
            Full command-line string of the child process (reserved
            for future use).

        Returns
        -------
        LOLBinFinding | None
            A finding if the relationship matches a rule, else None.
        """
        parent_lower = parent.lower()
        child_lower = child.lower()

        for rule in self._parent_child_rules:
            parents = [p.lower() for p in rule["parents"]]
            children = [c.lower() for c in rule["children"]]
            if parent_lower in parents and child_lower in children:
                return LOLBinFinding(
                    binary=child_lower,
                    severity=rule["severity"],
                    mitre_id=rule["mitre_id"],
                    description=rule["description"],
                    matched_rule=rule["name"],
                )
        return None

    def check_command_line(
        self,
        binary: str,
        command_line: str,
    ) -> LOLBinFinding | None:
        """Check a command line for suspicious LOLBin usage patterns.

        Parameters
        ----------
        binary : str
            Executable name (e.g. ``certutil.exe``).
        command_line : str
            Full command-line string.

        Returns
        -------
        LOLBinFinding | None
            A finding if the command line matches a rule, else None.
        """
        binary_lower = binary.lower()
        patterns = self._command_line_rules.get(binary_lower)
        if patterns is None:
            return None

        for pat in patterns:
            if pat["regex"].search(command_line):
                return LOLBinFinding(
                    binary=binary_lower,
                    severity=pat["severity"],
                    mitre_id=pat["mitre_id"],
                    description=pat["description"],
                    matched_rule=f"{binary_lower}_{pat['mitre_id']}",
                )
        return None

    def analyze_process_event(
        self,
        event: AegisEvent,
    ) -> list[LOLBinFinding]:
        """Run all LOLBin checks against an AegisEvent.

        Extracts ``parent_name``, ``process_name``, and
        ``command_line`` from ``event.data`` and returns any findings.

        Parameters
        ----------
        event : AegisEvent
            A process-creation event.

        Returns
        -------
        list[LOLBinFinding]
            All findings (may be empty).
        """
        findings: list[LOLBinFinding] = []
        data = event.data

        parent = data.get("parent_name", "")
        child = data.get("process_name", "")
        cmd = data.get("command_line", "")

        if parent and child:
            pc_finding = self.check_parent_child(parent, child, cmd)
            if pc_finding is not None:
                findings.append(pc_finding)

        if child and cmd:
            cl_finding = self.check_command_line(child, cmd)
            if cl_finding is not None:
                findings.append(cl_finding)

        return findings
