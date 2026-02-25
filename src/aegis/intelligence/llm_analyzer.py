"""LLM-powered analysis for alert triage, NL-to-SQL, and incident summaries.

Provides Claude API integration with offline template fallback, privacy
controls (path/username anonymization), and daily rate-limit budgeting.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from aegis.core.models import Alert, Severity

# Optional anthropic SDK — all methods fall back to templates when absent.
try:
    import anthropic  # type: ignore[import-untyped]

    _HAS_ANTHROPIC = True
except ImportError:
    _HAS_ANTHROPIC = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration & result data classes
# ---------------------------------------------------------------------------

_USER_PATH_RE = re.compile(
    r"(C:\\Users\\)([^\\]+)(\\)",
    re.IGNORECASE,
)


@dataclass
class LLMConfig:
    """Configuration for the LLM analyzer."""

    api_key: str | None = None
    daily_budget: int = 100
    anonymize_paths: bool = True
    anonymize_usernames: bool = True
    provider: str = "claude"  # "claude" | "ollama"


@dataclass
class TriageResult:
    """Result of an alert triage analysis."""

    severity_assessment: str
    narrative: str
    investigation_steps: list[str]
    fp_likelihood: float
    source: str  # "api" | "template"


# ---------------------------------------------------------------------------
# Template fallback helpers
# ---------------------------------------------------------------------------

_SEVERITY_DESCRIPTIONS: dict[Severity, str] = {
    Severity.CRITICAL: "Critical — immediate investigation required",
    Severity.HIGH: "High — investigate promptly",
    Severity.MEDIUM: "Medium — review when possible",
    Severity.LOW: "Low — informational, monitor",
    Severity.INFO: "Informational — no action needed",
}

_DEFAULT_INVESTIGATION_STEPS: dict[Severity, list[str]] = {
    Severity.CRITICAL: [
        "Isolate affected host immediately",
        "Capture volatile forensic data",
        "Check for lateral movement indicators",
        "Escalate to incident response team",
    ],
    Severity.HIGH: [
        "Review related events for context",
        "Check process tree for anomalies",
        "Verify network connections",
        "Determine if behaviour is expected",
    ],
    Severity.MEDIUM: [
        "Review alert details and context",
        "Check if this pattern recurs",
        "Validate against known-good baselines",
    ],
    Severity.LOW: [
        "Log for trend analysis",
        "Review if frequency increases",
    ],
    Severity.INFO: [
        "No immediate action required",
    ],
}

_FP_BASELINES: dict[Severity, float] = {
    Severity.CRITICAL: 0.1,
    Severity.HIGH: 0.2,
    Severity.MEDIUM: 0.35,
    Severity.LOW: 0.5,
    Severity.INFO: 0.7,
}

_NL_SQL_TEMPLATES: dict[str, str] = {
    "recent alerts": (
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20"
    ),
    "critical alerts": (
        "SELECT * FROM alerts WHERE severity = 'critical' "
        "ORDER BY timestamp DESC LIMIT 20"
    ),
    "high severity": (
        "SELECT * FROM alerts WHERE severity = 'high' "
        "ORDER BY timestamp DESC LIMIT 20"
    ),
    "network alerts": (
        "SELECT * FROM alerts WHERE sensor = 'network' "
        "ORDER BY timestamp DESC LIMIT 20"
    ),
}

_DEFAULT_NL_SQL = "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20"


def _template_triage(alert: Alert) -> TriageResult:
    """Produce a triage result using hardcoded templates."""
    sev = alert.severity
    mitre_str = ", ".join(alert.mitre_ids) if alert.mitre_ids else "none"
    narrative = (
        f"{alert.title}: {alert.description} "
        f"(confidence {alert.confidence:.0%}, MITRE: {mitre_str})"
    )
    return TriageResult(
        severity_assessment=_SEVERITY_DESCRIPTIONS.get(
            sev, "Unknown severity"
        ),
        narrative=narrative,
        investigation_steps=list(
            _DEFAULT_INVESTIGATION_STEPS.get(sev, ["Review alert details"])
        ),
        fp_likelihood=_FP_BASELINES.get(sev, 0.5),
        source="template",
    )


def _template_nl_to_sql(question: str) -> str:
    """Simple keyword-matching NL-to-SQL for offline use."""
    q_lower = question.lower()
    for keyword, sql in _NL_SQL_TEMPLATES.items():
        if keyword in q_lower:
            return sql
    return _DEFAULT_NL_SQL


def _template_summarize(incident: dict[str, Any]) -> str:
    """Produce a plain-text incident summary from template."""
    title = incident.get("title", "Unknown incident")
    alerts: list[Alert] = incident.get("alerts", [])
    severity = incident.get("severity", Severity.MEDIUM)
    sev_label = (
        severity.value if isinstance(severity, Severity) else str(severity)
    )
    lines = [
        f"Incident Summary: {title}",
        f"Severity: {sev_label}",
        f"Related alerts: {len(alerts)}",
    ]
    for i, a in enumerate(alerts, 1):
        lines.append(f"  {i}. [{a.severity.value}] {a.title}")
    lines.append(
        "Recommendation: review related alerts and determine scope."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LLMAnalyzer
# ---------------------------------------------------------------------------


class LLMAnalyzer:
    """LLM-powered analysis with Claude API and offline fallback.

    Parameters
    ----------
    api_key:
        Anthropic API key. When *None* (or SDK not installed), every
        method falls back to deterministic template-based output.
    config:
        Optional :class:`LLMConfig` for budget, privacy, and provider.
    """

    def __init__(
        self,
        api_key: str | None = None,
        config: LLMConfig | None = None,
    ) -> None:
        self._config = config or LLMConfig(api_key=api_key)
        if api_key is not None:
            self._config.api_key = api_key

        self._client: Any | None = None
        if self._config.api_key and _HAS_ANTHROPIC:
            try:
                self._client = anthropic.Anthropic(
                    api_key=self._config.api_key,
                )
            except Exception:
                logger.warning(
                    "Failed to initialise Anthropic client; "
                    "falling back to templates."
                )

        self._call_count: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def triage(
        self,
        alert: Alert,
        context: dict[str, Any] | None = None,
    ) -> TriageResult:
        """Triage an alert using the LLM, with template fallback.

        Falls back to template when:
        - No API key configured
        - Anthropic SDK not installed
        - Daily budget exceeded
        - API call fails
        """
        if not self._can_call_api():
            return _template_triage(alert)

        prompt = self._build_triage_prompt(alert, context)
        try:
            response_text = self._call_api(prompt)
            return self._parse_triage_response(response_text, alert)
        except Exception:
            logger.warning(
                "LLM triage API call failed; using template fallback.",
                exc_info=True,
            )
            return _template_triage(alert)

    def nl_to_sql(
        self,
        question: str,
        schema_hint: str = "",
    ) -> str | None:
        """Convert a natural-language question to a SELECT-only SQL query.

        Returns *None* if the generated SQL fails validation.
        """
        if not self._can_call_api():
            sql = _template_nl_to_sql(question)
            return self._validate_sql(sql)

        prompt = self._build_nl_to_sql_prompt(question, schema_hint)
        try:
            raw_sql = self._call_api(prompt).strip()
            return self._validate_sql(raw_sql)
        except Exception:
            logger.warning(
                "LLM nl_to_sql API call failed; using template fallback.",
                exc_info=True,
            )
            return self._validate_sql(_template_nl_to_sql(question))

    def summarize_incident(
        self,
        incident: dict[str, Any],
    ) -> str:
        """Generate a human-readable incident summary."""
        if not self._can_call_api():
            return _template_summarize(incident)

        prompt = self._build_summary_prompt(incident)
        try:
            return self._call_api(prompt)
        except Exception:
            logger.warning(
                "LLM summarize API call failed; using template fallback.",
                exc_info=True,
            )
            return _template_summarize(incident)

    # ------------------------------------------------------------------
    # Privacy / anonymization
    # ------------------------------------------------------------------

    def _anonymize(self, text: str) -> str:
        """Replace Windows user paths and usernames with placeholders.

        Respects :pyattr:`LLMConfig.anonymize_paths` and
        :pyattr:`LLMConfig.anonymize_usernames`.
        """
        if not (
            self._config.anonymize_paths
            or self._config.anonymize_usernames
        ):
            return text

        result = text
        if self._config.anonymize_paths or self._config.anonymize_usernames:
            # Replace C:\Users\<name>\... with C:\Users\<USER>\...
            result = _USER_PATH_RE.sub(r"\1<USER>\3", result)

        return result

    # ------------------------------------------------------------------
    # SQL validation
    # ------------------------------------------------------------------

    def _validate_sql(self, sql: str | None) -> str | None:
        """Ensure *sql* is a SELECT-only statement.

        Returns the sanitised SQL or *None* if validation fails.
        """
        if sql is None:
            return None
        stripped = sql.strip().rstrip(";").strip()
        if not stripped:
            return None
        # Must start with SELECT (case-insensitive)
        if not stripped.upper().startswith("SELECT"):
            return None
        # Reject dangerous keywords anywhere in the statement
        dangerous = {
            "DROP",
            "DELETE",
            "INSERT",
            "UPDATE",
            "ALTER",
            "CREATE",
            "TRUNCATE",
            "EXEC",
            "EXECUTE",
            "GRANT",
            "REVOKE",
        }
        tokens = set(stripped.upper().split())
        if tokens & dangerous:
            return None
        return stripped

    # ------------------------------------------------------------------
    # Budget / rate-limit helpers
    # ------------------------------------------------------------------

    def _budget_exceeded(self) -> bool:
        """Return *True* when the daily call budget is exhausted."""
        return self._call_count >= self._config.daily_budget

    def _can_call_api(self) -> bool:
        """Check whether an API call is permissible right now."""
        if self._client is None:
            return False
        if self._budget_exceeded():
            return False
        return True

    # ------------------------------------------------------------------
    # API interaction (private)
    # ------------------------------------------------------------------

    def _call_api(self, prompt: str) -> str:
        """Send *prompt* to the configured LLM and return the text reply."""
        assert self._client is not None
        self._call_count += 1
        message = self._client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Prompt builders (private)
    # ------------------------------------------------------------------

    def _build_triage_prompt(
        self,
        alert: Alert,
        context: dict[str, Any] | None = None,
    ) -> str:
        desc = self._anonymize(alert.description)
        title = self._anonymize(alert.title)
        data_str = self._anonymize(str(alert.data))
        mitre = ", ".join(alert.mitre_ids) if alert.mitre_ids else "none"

        parts = [
            "You are a senior SOC analyst. Triage this security alert.",
            f"Title: {title}",
            f"Description: {desc}",
            f"Severity: {alert.severity.value}",
            f"Confidence: {alert.confidence}",
            f"Sensor: {alert.sensor.value}",
            f"MITRE ATT&CK: {mitre}",
            f"Data: {data_str}",
        ]
        if context:
            parts.append(f"Additional context: {self._anonymize(str(context))}")
        parts.append(
            "\nRespond in this exact format:\n"
            "SEVERITY_ASSESSMENT: <one line>\n"
            "NARRATIVE: <paragraph>\n"
            "INVESTIGATION_STEPS:\n- step 1\n- step 2\n...\n"
            "FP_LIKELIHOOD: <float 0-1>"
        )
        return "\n".join(parts)

    def _build_nl_to_sql_prompt(
        self,
        question: str,
        schema_hint: str,
    ) -> str:
        return (
            "Convert this natural-language question to a single "
            "SELECT-only SQL query. Return ONLY the SQL, nothing else.\n"
            f"Schema: {schema_hint}\n"
            f"Question: {question}"
        )

    def _build_summary_prompt(
        self,
        incident: dict[str, Any],
    ) -> str:
        title = incident.get("title", "Unknown")
        alerts: list[Alert] = incident.get("alerts", [])
        sev = incident.get("severity", "unknown")
        sev_val = sev.value if isinstance(sev, Severity) else str(sev)
        alert_lines = []
        for a in alerts:
            alert_lines.append(
                f"- [{a.severity.value}] {self._anonymize(a.title)}: "
                f"{self._anonymize(a.description)}"
            )
        return (
            "Summarise this security incident in 2-4 sentences "
            "for a non-technical user.\n"
            f"Title: {self._anonymize(title)}\n"
            f"Severity: {sev_val}\n"
            f"Alerts:\n" + "\n".join(alert_lines)
        )

    def _parse_triage_response(
        self,
        text: str,
        alert: Alert,
    ) -> TriageResult:
        """Parse structured LLM response into a TriageResult."""
        sev_match = re.search(
            r"SEVERITY_ASSESSMENT:\s*(.+)", text, re.IGNORECASE
        )
        narr_match = re.search(
            r"NARRATIVE:\s*(.+?)(?=INVESTIGATION_STEPS:|FP_LIKELIHOOD:|$)",
            text,
            re.IGNORECASE | re.DOTALL,
        )
        steps_match = re.search(
            r"INVESTIGATION_STEPS:\s*(.+?)(?=FP_LIKELIHOOD:|$)",
            text,
            re.IGNORECASE | re.DOTALL,
        )
        fp_match = re.search(
            r"FP_LIKELIHOOD:\s*([\d.]+)", text, re.IGNORECASE
        )

        severity_assessment = (
            sev_match.group(1).strip() if sev_match else "Unable to assess"
        )
        narrative = (
            narr_match.group(1).strip() if narr_match else text.strip()
        )
        steps: list[str] = []
        if steps_match:
            for line in steps_match.group(1).strip().splitlines():
                line = line.strip().lstrip("-").strip()
                if line:
                    steps.append(line)
        if not steps:
            steps = list(
                _DEFAULT_INVESTIGATION_STEPS.get(
                    alert.severity, ["Review alert details"]
                )
            )

        fp = 0.5
        if fp_match:
            try:
                fp = max(0.0, min(1.0, float(fp_match.group(1))))
            except ValueError:
                pass

        return TriageResult(
            severity_assessment=severity_assessment,
            narrative=narrative,
            investigation_steps=steps,
            fp_likelihood=fp,
            source="api",
        )
