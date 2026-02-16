"""Narrative Generator -- converts attack chain matches into human-readable
security narratives.

Each of the 8 canonical attack chains has a dedicated template that explains
what happened, assesses severity, references MITRE ATT&CK technique IDs,
and provides recommended remediation actions.
"""

from __future__ import annotations

import logging

from aegis.detection.graph_analyzer import ChainMatch

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Recommended actions per chain type
# ---------------------------------------------------------------------------

_RECOMMENDED_ACTIONS: dict[str, list[str]] = {
    "drive_by_download": [
        "Isolate the affected endpoint from the network immediately.",
        "Quarantine or delete the downloaded executable file.",
        "Scan the system with an updated antivirus engine.",
        "Review browser history and block the malicious URL at the proxy.",
    ],
    "credential_theft": [
        "Terminate the suspicious process immediately.",
        "Rotate all credentials stored in the affected browser profiles.",
        "Block the external IP addresses contacted during exfiltration.",
        "Enable multi-factor authentication on all exposed accounts.",
    ],
    "ransomware": [
        "Disconnect the affected machine from the network immediately.",
        "Do NOT pay the ransom -- restore from verified offline backups.",
        "Preserve forensic evidence before reimaging the system.",
        "Notify the incident response team and legal/compliance.",
    ],
    "persistence_installation": [
        "Remove the persistence entry (registry Run key or Startup item).",
        "Quarantine the suspicious executable.",
        "Audit all scheduled tasks and services for unauthorized entries.",
    ],
    "fileless_attack": [
        "Kill the PowerShell process and parent process tree.",
        "Block the contacted command-and-control IP at the firewall.",
        "Enable PowerShell script-block logging and constrained mode.",
        "Inspect memory for injected payloads using a live-forensics tool.",
    ],
    "lateral_movement": [
        "Lock the compromised account and force a password reset.",
        "Isolate the source and destination hosts from the network.",
        "Audit newly created services and scheduled tasks on the target.",
        "Review network segmentation to limit lateral traversal.",
    ],
    "data_exfiltration": [
        "Block the external destination IP/domain at the firewall.",
        "Terminate the exfiltrating process immediately.",
        "Determine what data was accessed and assess breach scope.",
        "Notify the data-protection officer if PII may be involved.",
    ],
    "dll_injection": [
        "Terminate the injecting process and the target process.",
        "Scan the injecting executable with multiple AV engines.",
        "Check for persistence mechanisms left by the injector.",
    ],
}

# ---------------------------------------------------------------------------
# Narrative templates (one per chain type)
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, str] = {
    "drive_by_download": (
        "ATTACK DETECTED: Drive-By Download\n"
        "Severity: {severity} | Confidence: {confidence_pct}%\n\n"
        "A web browser downloaded and executed a suspicious file. "
        "{description}\n\n"
        "MITRE ATT&CK: {mitre_ids}\n"
        "Matched entities: {node_count}\n\n"
        "Recommended actions:\n{recommended_actions}"
    ),
    "credential_theft": (
        "ATTACK DETECTED: Credential Theft\n"
        "Severity: {severity} | Confidence: {confidence_pct}%\n\n"
        "A non-browser process accessed credential stores and opened "
        "external network connections, indicating credential harvesting "
        "and exfiltration. {description}\n\n"
        "MITRE ATT&CK: {mitre_ids}\n"
        "Matched entities: {node_count}\n\n"
        "Recommended actions:\n{recommended_actions}"
    ),
    "ransomware": (
        "ATTACK DETECTED: Ransomware Activity\n"
        "Severity: {severity} | Confidence: {confidence_pct}%\n\n"
        "A process performed rapid mass file modifications consistent "
        "with encryption-based ransomware. {description}\n\n"
        "MITRE ATT&CK: {mitre_ids}\n"
        "Matched entities: {node_count}\n\n"
        "Recommended actions:\n{recommended_actions}"
    ),
    "persistence_installation": (
        "ATTACK DETECTED: Persistence Installation\n"
        "Severity: {severity} | Confidence: {confidence_pct}%\n\n"
        "A suspicious process wrote to a persistence location such as "
        "a registry Run key or Startup folder, ensuring it survives "
        "reboot. {description}\n\n"
        "MITRE ATT&CK: {mitre_ids}\n"
        "Matched entities: {node_count}\n\n"
        "Recommended actions:\n{recommended_actions}"
    ),
    "fileless_attack": (
        "ATTACK DETECTED: Fileless Attack\n"
        "Severity: {severity} | Confidence: {confidence_pct}%\n\n"
        "A process launched PowerShell with an encoded command that "
        "made network connections without writing to disk -- a classic "
        "fileless attack pattern. {description}\n\n"
        "MITRE ATT&CK: {mitre_ids}\n"
        "Matched entities: {node_count}\n\n"
        "Recommended actions:\n{recommended_actions}"
    ),
    "lateral_movement": (
        "ATTACK DETECTED: Lateral Movement\n"
        "Severity: {severity} | Confidence: {confidence_pct}%\n\n"
        "Multiple failed authentication attempts were followed by a "
        "successful logon and new service creation, indicating an "
        "attacker moving laterally through the network. {description}\n\n"
        "MITRE ATT&CK: {mitre_ids}\n"
        "Matched entities: {node_count}\n\n"
        "Recommended actions:\n{recommended_actions}"
    ),
    "data_exfiltration": (
        "ATTACK DETECTED: Data Exfiltration\n"
        "Severity: {severity} | Confidence: {confidence_pct}%\n\n"
        "A process read a large number of files and transmitted data "
        "to an external destination. {description}\n\n"
        "MITRE ATT&CK: {mitre_ids}\n"
        "Matched entities: {node_count}\n\n"
        "Recommended actions:\n{recommended_actions}"
    ),
    "dll_injection": (
        "ATTACK DETECTED: DLL Injection\n"
        "Severity: {severity} | Confidence: {confidence_pct}%\n\n"
        "A process performed the VirtualAllocEx / WriteProcessMemory / "
        "CreateRemoteThread API sequence or triggered a Sysmon "
        "CreateRemoteThread event, indicating code injection into "
        "another process. {description}\n\n"
        "MITRE ATT&CK: {mitre_ids}\n"
        "Matched entities: {node_count}\n\n"
        "Recommended actions:\n{recommended_actions}"
    ),
}

_UNKNOWN_TEMPLATE = (
    "ATTACK DETECTED: {chain_name}\n"
    "Severity: {severity} | Confidence: {confidence_pct}%\n\n"
    "{description}\n\n"
    "MITRE ATT&CK: {mitre_ids}\n"
    "Matched entities: {node_count}\n\n"
    "Recommended actions:\n{recommended_actions}"
)


# ---------------------------------------------------------------------------
# NarrativeGenerator
# ---------------------------------------------------------------------------

class NarrativeGenerator:
    """Convert :class:`ChainMatch` instances into human-readable narratives.

    Each narrative includes what happened, severity, MITRE references,
    and actionable remediation steps.
    """

    def generate(self, chain_match: ChainMatch) -> str:
        """Generate a plain-English narrative for *chain_match*.

        Returns a multi-line string suitable for display in the
        dashboard alert detail panel or log output.
        """
        template = _TEMPLATES.get(chain_match.chain_name, _UNKNOWN_TEMPLATE)
        actions = self._get_recommended_actions(chain_match.chain_name)
        actions_text = "\n".join(f"  - {a}" for a in actions)
        mitre_text = ", ".join(chain_match.mitre_ids) or "N/A"
        confidence_pct = round(chain_match.confidence * 100, 1)

        narrative = template.format(
            chain_name=chain_match.chain_name,
            severity=chain_match.severity,
            confidence_pct=confidence_pct,
            mitre_ids=mitre_text,
            node_count=len(chain_match.matched_nodes),
            description=chain_match.description,
            recommended_actions=actions_text,
        )
        return narrative

    @staticmethod
    def _get_recommended_actions(chain_name: str) -> list[str]:
        """Return 3-4 recommended remediation actions for *chain_name*.

        Falls back to generic actions for unknown chain types.
        """
        return _RECOMMENDED_ACTIONS.get(chain_name, [
            "Investigate the alert and gather forensic evidence.",
            "Isolate the affected system if the threat is confirmed.",
            "Escalate to the incident response team.",
        ])
