"""MITRE ATT&CK technique mapper.

Provides local lookup of ATT&CK technique metadata from a bundled
JSON data file.  No external API calls -- all data is loaded at startup.

Falls back to a minimal built-in dict if the data file is missing.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default data file location (relative to project root)
_DEFAULT_DATA_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "mitre"
    / "enterprise-techniques.json"
)


@dataclass(frozen=True)
class MITRETechnique:
    """MITRE ATT&CK technique metadata."""

    technique_id: str
    name: str
    tactic: str
    description: str
    platforms: tuple[str, ...] = ("Windows",)


# -----------------------------------------------------------------------
# Minimal fallback data for the 14 techniques used by graph_analyzer.py
# -----------------------------------------------------------------------
_FALLBACK_TECHNIQUES: dict[str, MITRETechnique] = {
    "T1189": MITRETechnique(
        "T1189", "Drive-by Compromise", "initial-access",
        "Browser exploitation during website visit.",
    ),
    "T1204.002": MITRETechnique(
        "T1204.002", "User Execution: Malicious File", "execution",
        "User opens a malicious file to execute code.",
    ),
    "T1555": MITRETechnique(
        "T1555", "Credentials from Password Stores", "credential-access",
        "Searching password stores for credentials.",
    ),
    "T1003": MITRETechnique(
        "T1003", "OS Credential Dumping", "credential-access",
        "Dumping credentials from the operating system.",
    ),
    "T1486": MITRETechnique(
        "T1486", "Data Encrypted for Impact", "impact",
        "Encrypting data to disrupt availability (ransomware).",
    ),
    "T1547.001": MITRETechnique(
        "T1547.001", "Registry Run Keys / Startup Folder", "persistence",
        "Adding programs to Run keys or Startup folder.",
    ),
    "T1053": MITRETechnique(
        "T1053", "Scheduled Task/Job", "persistence",
        "Creating scheduled tasks for recurring execution.",
    ),
    "T1059.001": MITRETechnique(
        "T1059.001", "PowerShell", "execution",
        "Abusing PowerShell for command execution.",
    ),
    "T1027": MITRETechnique(
        "T1027", "Obfuscated Files or Information", "defense-evasion",
        "Obfuscating payloads to hinder detection.",
    ),
    "T1021": MITRETechnique(
        "T1021", "Remote Services", "lateral-movement",
        "Using remote services for lateral movement.",
    ),
    "T1110": MITRETechnique(
        "T1110", "Brute Force", "credential-access",
        "Brute-force guessing of account credentials.",
    ),
    "T1041": MITRETechnique(
        "T1041", "Exfiltration Over C2 Channel", "exfiltration",
        "Exfiltrating data over the C2 channel.",
    ),
    "T1567": MITRETechnique(
        "T1567", "Exfiltration Over Web Service", "exfiltration",
        "Using web services for data exfiltration.",
    ),
    "T1055.001": MITRETechnique(
        "T1055.001", "DLL Injection", "defense-evasion",
        "Injecting a DLL into another process.",
    ),
    # Phase 15: Registry, DNS, and additional techniques
    "T1547.004": MITRETechnique(
        "T1547.004", "Winlogon Helper DLL", "persistence",
        "Modifying Winlogon registry entries for persistence.",
    ),
    "T1546.001": MITRETechnique(
        "T1546.001", "Change Default File Association", "persistence",
        "Changing file associations for persistence.",
    ),
    "T1546.012": MITRETechnique(
        "T1546.012", "Image File Execution Options Injection", "persistence",
        "Setting IFEO debugger key to hijack process execution.",
    ),
    "T1543.003": MITRETechnique(
        "T1543.003", "Windows Service", "persistence",
        "Creating or modifying Windows services for persistence.",
    ),
    "T1071.004": MITRETechnique(
        "T1071.004", "Application Layer Protocol: DNS", "command-and-control",
        "Using DNS for command and control communication.",
    ),
    "T1048.003": MITRETechnique(
        "T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", "exfiltration",
        "Exfiltrating data over DNS or other non-C2 protocols.",
    ),
    "T1568.002": MITRETechnique(
        "T1568.002", "Domain Generation Algorithms", "command-and-control",
        "Using algorithmically generated domains for C2.",
    ),
    "T1547.005": MITRETechnique(
        "T1547.005", "Security Support Provider", "persistence",
        "Abusing SSP DLLs for persistence and credential access.",
    ),
    "T1505.003": MITRETechnique(
        "T1505.003", "Web Shell", "persistence",
        "Installing web shells on servers for persistence.",
    ),
    "T1140": MITRETechnique(
        "T1140", "Deobfuscate/Decode Files or Information", "defense-evasion",
        "Using utilities to deobfuscate or decode data.",
    ),
}


class MITREMapper:
    """Lookup service for MITRE ATT&CK technique metadata.

    Args:
        data_path: Path to enterprise-techniques.json.  If *None* or
            the file does not exist, uses built-in fallback data.
    """

    def __init__(self, data_path: Path | None = None) -> None:
        self._techniques: dict[str, MITRETechnique] = {}
        self._load(data_path or _DEFAULT_DATA_PATH)

    # -- public API -----------------------------------------------------

    @property
    def technique_count(self) -> int:
        """Number of loaded techniques."""
        return len(self._techniques)

    def get(self, technique_id: str) -> MITRETechnique | None:
        """Look up a single technique by ID."""
        return self._techniques.get(technique_id)

    def get_many(
        self, technique_ids: list[str],
    ) -> list[MITRETechnique]:
        """Look up multiple techniques.  Skips unknown IDs."""
        return [
            t for tid in technique_ids
            if (t := self._techniques.get(tid)) is not None
        ]

    def describe(self, technique_ids: list[str]) -> list[str]:
        """Convert technique IDs to human-readable descriptions.

        Format: ``"T1486: Data Encrypted for Impact (impact)"``
        Returns ``"T1234: Unknown technique"`` for unknown IDs.
        """
        lines: list[str] = []
        for tid in technique_ids:
            tech = self._techniques.get(tid)
            if tech:
                lines.append(
                    f"{tech.technique_id}: {tech.name}"
                    f" ({tech.tactic})"
                )
            else:
                lines.append(f"{tid}: Unknown technique")
        return lines

    # -- private --------------------------------------------------------

    def _load(self, data_path: Path) -> None:
        """Load from JSON file, falling back to built-in data."""
        if data_path.is_file():
            try:
                raw: dict[str, Any] = json.loads(
                    data_path.read_text(encoding="utf-8"),
                )
                for entry in raw.get("techniques", []):
                    tid = entry["technique_id"]
                    self._techniques[tid] = MITRETechnique(
                        technique_id=tid,
                        name=entry["name"],
                        tactic=entry["tactic"],
                        description=entry.get("description", ""),
                        platforms=tuple(
                            entry.get("platforms", ["Windows"]),
                        ),
                    )
                logger.info(
                    "Loaded %d MITRE techniques from %s",
                    len(self._techniques),
                    data_path,
                )
                return
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.warning(
                    "Failed to parse %s: %s — using fallback",
                    data_path,
                    exc,
                )

        # Fallback: use the built-in minimal dict
        self._techniques = dict(_FALLBACK_TECHNIQUES)
        logger.info(
            "Using fallback MITRE data (%d techniques)",
            len(self._techniques),
        )
