"""Threat Explainer -- generates plain-English alert explanations.

Provides user-facing descriptions of what was detected, why it matters,
the risk level, and suggested next steps.  Templates are keyed by
``(sensor, severity)`` pairs and by common ``alert_type`` strings.
"""

from __future__ import annotations

import logging
from typing import Any

from aegis.core.models import Alert
from aegis.detection.graph_analyzer import ChainMatch
from aegis.detection.narratives import NarrativeGenerator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Templates keyed by (sensor_value, severity_value)
# ---------------------------------------------------------------------------

_SENSOR_SEVERITY_TEMPLATES: dict[tuple[str, str], str] = {
    # -- network sensor -----------------------------------------------------
    ("network", "critical"): (
        "CRITICAL NETWORK THREAT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: A critical network event indicates an active, "
        "high-confidence threat such as command-and-control traffic or "
        "active data exfiltration.\n"
        "Risk level: CRITICAL (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("network", "high"): (
        "HIGH-SEVERITY NETWORK ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: Suspicious network activity was observed that "
        "may indicate reconnaissance, lateral movement, or data staging.\n"
        "Risk level: HIGH (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("network", "medium"): (
        "NETWORK ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: Unusual network behaviour was observed. While "
        "not immediately critical, it warrants investigation.\n"
        "Risk level: MEDIUM (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("network", "low"): (
        "Network notice: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: Minor network anomaly detected. Likely benign "
        "but logged for correlation.\n"
        "Risk level: LOW (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("network", "info"): (
        "Network info: {title}\n\n"
        "What was detected: {description}\n"
        "Risk level: INFO\n\n"
        "No immediate action required."
    ),
    # -- process sensor -----------------------------------------------------
    ("process", "critical"): (
        "CRITICAL PROCESS THREAT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: A process exhibited behaviour strongly "
        "associated with malware execution or code injection.\n"
        "Risk level: CRITICAL (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("process", "high"): (
        "HIGH-SEVERITY PROCESS ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: A process performed suspicious operations "
        "that could indicate privilege escalation or defence evasion.\n"
        "Risk level: HIGH (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("process", "medium"): (
        "PROCESS ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: A process behaved unusually. Review the "
        "process tree and command-line arguments.\n"
        "Risk level: MEDIUM (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("process", "low"): (
        "Process notice: {title}\n\n"
        "What was detected: {description}\n"
        "Risk level: LOW (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("process", "info"): (
        "Process info: {title}\n\n"
        "What was detected: {description}\n"
        "Risk level: INFO\n\n"
        "No immediate action required."
    ),
    # -- file_integrity sensor ----------------------------------------------
    ("file_integrity", "critical"): (
        "CRITICAL FILE INTEGRITY THREAT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: Critical system or application files were "
        "tampered with, potentially indicating rootkit installation.\n"
        "Risk level: CRITICAL (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("file_integrity", "high"): (
        "HIGH-SEVERITY FILE ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: Important files were modified unexpectedly. "
        "Verify the change is authorized.\n"
        "Risk level: HIGH (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("file_integrity", "medium"): (
        "FILE INTEGRITY ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: A monitored file was changed outside the "
        "expected maintenance window.\n"
        "Risk level: MEDIUM (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    # -- eventlog sensor ----------------------------------------------------
    ("eventlog", "critical"): (
        "CRITICAL EVENT LOG ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: A critical Windows event was recorded that "
        "strongly correlates with active compromise or policy violation.\n"
        "Risk level: CRITICAL (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("eventlog", "high"): (
        "HIGH-SEVERITY EVENT LOG ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: A high-severity Windows event was logged. "
        "This may indicate brute-force attempts or privilege abuse.\n"
        "Risk level: HIGH (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("eventlog", "medium"): (
        "EVENT LOG ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: An unusual Windows event was logged that "
        "warrants review.\n"
        "Risk level: MEDIUM (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    # -- hardware sensor ----------------------------------------------------
    ("hardware", "high"): (
        "HIGH-SEVERITY HARDWARE ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: A hardware change was detected that could "
        "indicate a rogue USB device or physical tampering.\n"
        "Risk level: HIGH (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("hardware", "medium"): (
        "HARDWARE ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: A hardware change was detected. Verify the "
        "device is authorized.\n"
        "Risk level: MEDIUM (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    # -- clipboard sensor ---------------------------------------------------
    ("clipboard", "high"): (
        "HIGH-SEVERITY CLIPBOARD ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: Sensitive data may have been exfiltrated "
        "via the clipboard (e.g., password or key material).\n"
        "Risk level: HIGH (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    ("clipboard", "medium"): (
        "CLIPBOARD ALERT: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: Unusual clipboard activity was detected.\n"
        "Risk level: MEDIUM (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
}

# ---------------------------------------------------------------------------
# Templates keyed by alert_type
# ---------------------------------------------------------------------------

_ALERT_TYPE_TEMPLATES: dict[str, str] = {
    "dns_tunneling": (
        "DNS Tunneling Detected: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: DNS tunneling encodes data inside DNS queries "
        "to bypass firewalls and exfiltrate information covertly.\n"
        "Risk level: {severity} (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    "port_scan": (
        "Port Scan Detected: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: Port scanning is a common reconnaissance "
        "technique used to map open services before exploitation.\n"
        "Risk level: {severity} (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    "brute_force": (
        "Brute-Force Attack Detected: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: Repeated failed authentications suggest an "
        "attacker is attempting to guess credentials.\n"
        "Risk level: {severity} (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    "privilege_escalation": (
        "Privilege Escalation Detected: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: A process elevated its privileges in an "
        "unexpected way, which may indicate exploitation.\n"
        "Risk level: {severity} (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
    "suspicious_download": (
        "Suspicious Download Detected: {title}\n\n"
        "What was detected: {description}\n"
        "Why it matters: A file was downloaded from a suspicious or "
        "untrusted source and may contain malware.\n"
        "Risk level: {severity} (confidence {confidence_pct}%)\n\n"
        "Suggested next steps:\n{actions}"
    ),
}

# ---------------------------------------------------------------------------
# Fallback template
# ---------------------------------------------------------------------------

_FALLBACK_TEMPLATE = (
    "Security Alert: {title}\n\n"
    "What was detected: {description}\n"
    "Sensor: {sensor} | Severity: {severity} | "
    "Confidence: {confidence_pct}%\n\n"
    "Suggested next steps:\n{actions}"
)


# ---------------------------------------------------------------------------
# ThreatExplainer
# ---------------------------------------------------------------------------

class ThreatExplainer:
    """Generate plain-English explanations for security alerts.

    Uses a two-tier template lookup:
      1. ``alert_type`` -- specific patterns like ``dns_tunneling``.
      2. ``(sensor, severity)`` -- general sensor/severity combinations.
      3. Fallback generic template.

    Also delegates attack-chain explanations to
    :class:`~aegis.detection.narratives.NarrativeGenerator`.
    """

    def __init__(self) -> None:
        self._narrator = NarrativeGenerator()

    def explain_alert(self, alert: Alert) -> str:
        """Return a human-readable explanation for *alert*.

        Template resolution order:
          1. Match on ``alert.alert_type`` in the alert-type table.
          2. Match on ``(alert.sensor.value, alert.severity.value)`` in
             the sensor/severity table.
          3. Generic fallback template.
        """
        confidence_pct = round(alert.confidence * 100, 1)
        actions = self._format_actions(alert.recommended_actions)
        sensor_val = alert.sensor.value
        severity_val = alert.severity.value

        fmt_kwargs: dict[str, Any] = {
            "title": alert.title,
            "description": alert.description,
            "sensor": sensor_val,
            "severity": severity_val.upper(),
            "confidence_pct": confidence_pct,
            "actions": actions,
        }

        # Tier 1: alert_type match
        if alert.alert_type in _ALERT_TYPE_TEMPLATES:
            template = _ALERT_TYPE_TEMPLATES[alert.alert_type]
            return template.format(**fmt_kwargs)

        # Tier 2: (sensor, severity) match
        key = (sensor_val, severity_val)
        if key in _SENSOR_SEVERITY_TEMPLATES:
            template = _SENSOR_SEVERITY_TEMPLATES[key]
            return template.format(**fmt_kwargs)

        # Tier 3: fallback
        return _FALLBACK_TEMPLATE.format(**fmt_kwargs)

    def explain_chain(self, chain_match: ChainMatch) -> str:
        """Return a human-readable narrative for an attack chain.

        Delegates to :class:`NarrativeGenerator`.
        """
        return self._narrator.generate(chain_match)

    @staticmethod
    def _format_actions(actions: list[str]) -> str:
        """Format a list of recommended actions as indented bullet points."""
        if not actions:
            return "  - Review the alert details and investigate further."
        return "\n".join(f"  - {a}" for a in actions)
