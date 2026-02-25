"""Tests for LLM-powered analysis."""
from __future__ import annotations

from aegis.core.models import Alert, SensorType, Severity
from aegis.intelligence.llm_analyzer import (
    LLMAnalyzer,
    LLMConfig,
    TriageResult,
)


class TestLLMConfig:
    def test_default_rate_limit(self) -> None:
        cfg = LLMConfig()
        assert cfg.daily_budget == 100

    def test_privacy_defaults(self) -> None:
        cfg = LLMConfig()
        assert cfg.anonymize_paths is True

    def test_default_provider(self) -> None:
        cfg = LLMConfig()
        assert cfg.provider == "claude"

    def test_default_anonymize_usernames(self) -> None:
        cfg = LLMConfig()
        assert cfg.anonymize_usernames is True

    def test_custom_config(self) -> None:
        cfg = LLMConfig(
            api_key="sk-test",
            daily_budget=50,
            anonymize_paths=False,
            provider="ollama",
        )
        assert cfg.api_key == "sk-test"
        assert cfg.daily_budget == 50
        assert cfg.anonymize_paths is False
        assert cfg.provider == "ollama"


def _make_alert(**overrides: object) -> Alert:
    """Helper to create Alert instances with sensible defaults."""
    defaults: dict = {
        "event_id": "test-evt-001",
        "sensor": SensorType.NETWORK,
        "alert_type": "suspicious_connection",
        "severity": Severity.HIGH,
        "title": "Test Alert",
        "description": "Test alert description",
        "confidence": 0.9,
        "data": {},
        "mitre_ids": ["T1071"],
    }
    defaults.update(overrides)
    return Alert(**defaults)


class TestLLMAnalyzer:
    def test_triage_offline_fallback(self) -> None:
        """With no API key, triage should use template fallback."""
        analyzer = LLMAnalyzer(api_key=None)
        alert = _make_alert()
        result = analyzer.triage(alert)
        assert isinstance(result, TriageResult)
        assert result.source == "template"
        assert result.severity_assessment != ""
        assert result.narrative != ""
        assert isinstance(result.investigation_steps, list)
        assert len(result.investigation_steps) > 0
        assert 0.0 <= result.fp_likelihood <= 1.0

    def test_rate_limiting(self) -> None:
        """When daily budget is exhausted, should fall back to template."""
        analyzer = LLMAnalyzer(api_key="test-key")
        analyzer._call_count = 100
        alert = _make_alert(
            severity=Severity.LOW,
            confidence=0.5,
            mitre_ids=[],
        )
        result = analyzer.triage(alert)
        assert result.source == "template"

    def test_anonymize_paths(self) -> None:
        """Windows paths with usernames should be anonymized."""
        analyzer = LLMAnalyzer(api_key=None)
        text = r"File at C:\Users\john\Documents\secret.doc"
        anon = analyzer._anonymize(text)
        assert "john" not in anon
        assert "secret.doc" in anon

    def test_anonymize_paths_preserves_non_user_paths(self) -> None:
        """System paths without user info should be preserved."""
        analyzer = LLMAnalyzer(api_key=None)
        text = r"Running C:\Windows\System32\cmd.exe"
        anon = analyzer._anonymize(text)
        assert "System32" in anon

    def test_anonymize_usernames_in_text(self) -> None:
        """Usernames in common patterns should be anonymized."""
        analyzer = LLMAnalyzer(api_key=None)
        text = r"C:\Users\alice\Desktop\file.txt and C:\Users\bob\file.txt"
        anon = analyzer._anonymize(text)
        assert "alice" not in anon
        assert "bob" not in anon

    def test_anonymize_disabled(self) -> None:
        """When anonymization is disabled, paths should be preserved."""
        config = LLMConfig(anonymize_paths=False, anonymize_usernames=False)
        analyzer = LLMAnalyzer(api_key=None, config=config)
        text = r"File at C:\Users\john\Documents\secret.doc"
        anon = analyzer._anonymize(text)
        assert "john" in anon

    def test_nl_to_sql_offline(self) -> None:
        """Without API, should return template-based SQL fallback."""
        analyzer = LLMAnalyzer(api_key=None)
        sql = analyzer.nl_to_sql(
            "show me recent alerts",
            schema_hint="alerts(alert_id, timestamp, severity)",
        )
        assert sql is not None
        assert sql.upper().startswith("SELECT")

    def test_nl_to_sql_rejects_non_select(self) -> None:
        """SQL validation should reject non-SELECT statements."""
        analyzer = LLMAnalyzer(api_key=None)
        assert analyzer._validate_sql("DROP TABLE alerts") is None
        assert analyzer._validate_sql("DELETE FROM alerts") is None
        assert analyzer._validate_sql("INSERT INTO alerts VALUES (1)") is None
        assert analyzer._validate_sql("UPDATE alerts SET x=1") is None

    def test_nl_to_sql_allows_select(self) -> None:
        """SQL validation should allow SELECT statements."""
        analyzer = LLMAnalyzer(api_key=None)
        sql = "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10"
        assert analyzer._validate_sql(sql) == sql

    def test_summarize_incident_offline(self) -> None:
        """Without API, should return template-based summary."""
        analyzer = LLMAnalyzer(api_key=None)
        incident = {
            "title": "Suspicious outbound connection",
            "alerts": [_make_alert()],
            "severity": Severity.HIGH,
        }
        summary = analyzer.summarize_incident(incident)
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_triage_result_fields(self) -> None:
        """TriageResult should have all required fields."""
        result = TriageResult(
            severity_assessment="High severity",
            narrative="Suspicious activity detected",
            investigation_steps=["Check logs", "Isolate host"],
            fp_likelihood=0.2,
            source="template",
        )
        assert result.severity_assessment == "High severity"
        assert result.narrative == "Suspicious activity detected"
        assert result.investigation_steps == ["Check logs", "Isolate host"]
        assert result.fp_likelihood == 0.2
        assert result.source == "template"

    def test_call_count_starts_at_zero(self) -> None:
        """Fresh analyzer should have zero call count."""
        analyzer = LLMAnalyzer(api_key="test-key")
        assert analyzer._call_count == 0

    def test_budget_not_exceeded_at_limit_minus_one(self) -> None:
        """At budget - 1, API should still be attempted (if key present)."""
        analyzer = LLMAnalyzer(api_key="test-key")
        analyzer._call_count = 99
        assert not analyzer._budget_exceeded()

    def test_budget_exceeded_at_limit(self) -> None:
        """At budget limit, should report exceeded."""
        analyzer = LLMAnalyzer(api_key="test-key")
        analyzer._call_count = 100
        assert analyzer._budget_exceeded()
