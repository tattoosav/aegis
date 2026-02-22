"""Tests for ReportGenerator — forensic incident report generation."""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from aegis.response.report_generator import (
    IncidentReport,
    ReportGenerator,
)

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _make_alert_entry(
    *,
    timestamp: float = 1000.0,
    severity: str = "high",
    source: str = "detection",
    alert_type: str = "network_c2",
    title: str = "C2 beacon detected",
    confidence: float = 0.9,
    mitre_ids: list[str] | None = None,
    target: str = "1.2.3.4",
) -> dict[str, Any]:
    """Build a timeline entry that represents an alert."""
    return {
        "timestamp": timestamp,
        "severity": severity,
        "source": source,
        "type": "alert",
        "details": {
            "log_type": "alert",
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "mitre_ids": mitre_ids or ["T1059"],
            "alert_type": alert_type,
            "target": target,
        },
    }


def _make_action_entry(
    *,
    timestamp: float = 1001.0,
    action_type: str = "block_ip",
    target: str = "1.2.3.4",
    success: bool = True,
    message: str = "blocked",
) -> dict[str, Any]:
    """Build a timeline entry that represents an action result."""
    return {
        "timestamp": timestamp,
        "severity": "info",
        "source": "response",
        "type": "action",
        "details": {
            "log_type": "action_result",
            "action_type": action_type,
            "target": target,
            "success": success,
            "message": message,
        },
    }


def _make_info_entry(
    *, timestamp: float = 999.0,
) -> dict[str, Any]:
    """Build a generic informational timeline entry."""
    return {
        "timestamp": timestamp,
        "severity": "info",
        "source": "sensor",
        "type": "heartbeat",
        "details": {"log_type": "info", "message": "heartbeat"},
    }


def _mock_forensic_logger(
    timeline: list[dict[str, Any]] | None = None,
) -> MagicMock:
    """Return a MagicMock ForensicLogger with export_timeline."""
    mock = MagicMock()
    mock.export_timeline.return_value = timeline or []
    return mock


def _mock_mitre_mapper(
    descriptions: list[str] | None = None,
) -> MagicMock:
    """Return a MagicMock MITREMapper with describe()."""
    mock = MagicMock()
    mock.describe.return_value = descriptions or []
    return mock


# ------------------------------------------------------------------ #
# TestIncidentReport
# ------------------------------------------------------------------ #


class TestIncidentReport:
    """Tests for the IncidentReport dataclass."""

    def test_defaults_for_list_fields(self) -> None:
        """Empty lists should be the default for collection fields."""
        report = IncidentReport(title="Test")
        assert report.timeline == []
        assert report.alerts == []
        assert report.actions == []
        assert report.mitre_techniques == []
        assert report.iocs == []

    def test_defaults_for_scalar_fields(self) -> None:
        """Numeric and string defaults should be zero / empty."""
        report = IncidentReport(title="Test")
        assert report.time_range_start == 0.0
        assert report.time_range_end == 0.0
        assert report.summary == ""
        assert report.total_events == 0
        assert report.total_alerts == 0
        assert report.total_actions == 0

    def test_generated_at_auto_set(self) -> None:
        """generated_at should be close to current time by default."""
        before = time.time()
        report = IncidentReport(title="Test")
        after = time.time()
        assert before <= report.generated_at <= after

    def test_custom_values(self) -> None:
        """All fields should accept custom values."""
        report = IncidentReport(
            title="Custom",
            generated_at=12345.0,
            time_range_start=100.0,
            time_range_end=200.0,
            timeline=[{"a": 1}],
            alerts=[{"b": 2}],
            actions=[{"c": 3}],
            mitre_techniques=["T1059"],
            iocs=[{"type": "ip", "value": "1.2.3.4"}],
            summary="test summary",
            total_events=10,
            total_alerts=5,
            total_actions=3,
        )
        assert report.title == "Custom"
        assert report.generated_at == 12345.0
        assert report.total_events == 10
        assert len(report.iocs) == 1

    def test_separate_default_lists(self) -> None:
        """Each instance should have independent list instances."""
        r1 = IncidentReport(title="A")
        r2 = IncidentReport(title="B")
        r1.timeline.append({"x": 1})
        assert r2.timeline == []


# ------------------------------------------------------------------ #
# TestGenerateReport
# ------------------------------------------------------------------ #


class TestGenerateReport:
    """Tests for ReportGenerator.generate_report()."""

    def test_empty_timeline(self) -> None:
        """An empty timeline should produce an empty report."""
        fl = _mock_forensic_logger([])
        gen = ReportGenerator(forensic_logger=fl)
        report = gen.generate_report(since=0.0)
        assert report.total_events == 0
        assert report.total_alerts == 0
        assert report.total_actions == 0
        assert report.alerts == []
        assert report.actions == []

    def test_with_alerts(self) -> None:
        """Alerts should be separated from the timeline."""
        entries = [_make_alert_entry(), _make_alert_entry(timestamp=1002)]
        fl = _mock_forensic_logger(entries)
        gen = ReportGenerator(forensic_logger=fl)
        report = gen.generate_report(since=0.0)
        assert report.total_alerts == 2
        assert len(report.alerts) == 2

    def test_with_actions(self) -> None:
        """Action results should be separated from the timeline."""
        entries = [_make_action_entry()]
        fl = _mock_forensic_logger(entries)
        gen = ReportGenerator(forensic_logger=fl)
        report = gen.generate_report(since=0.0)
        assert report.total_actions == 1
        assert len(report.actions) == 1

    def test_mixed_timeline(self) -> None:
        """Mixed entries should be correctly categorised."""
        entries = [
            _make_alert_entry(timestamp=100),
            _make_action_entry(timestamp=101),
            _make_info_entry(timestamp=102),
        ]
        fl = _mock_forensic_logger(entries)
        gen = ReportGenerator(forensic_logger=fl)
        report = gen.generate_report(since=0.0)
        assert report.total_events == 3
        assert report.total_alerts == 1
        assert report.total_actions == 1

    def test_ioc_extraction_ip(self) -> None:
        """IP IOCs should be extracted from network-type alerts."""
        entries = [
            _make_alert_entry(
                alert_type="network_c2", target="10.0.0.1",
            ),
        ]
        fl = _mock_forensic_logger(entries)
        gen = ReportGenerator(forensic_logger=fl)
        report = gen.generate_report(since=0.0)
        assert any(
            ioc["type"] == "ip" and ioc["value"] == "10.0.0.1"
            for ioc in report.iocs
        )

    def test_ioc_extraction_dns(self) -> None:
        """Domain IOCs should be extracted from dns-type alerts."""
        entries = [
            _make_alert_entry(
                alert_type="dns_query",
                title="Suspicious DNS query: evil.com",
            ),
        ]
        fl = _mock_forensic_logger(entries)
        gen = ReportGenerator(forensic_logger=fl)
        report = gen.generate_report(since=0.0)
        assert any(
            ioc["type"] == "domain" and ioc["value"] == "evil.com"
            for ioc in report.iocs
        )

    def test_mitre_technique_collection(self) -> None:
        """MITRE technique IDs should be collected from alerts."""
        entries = [
            _make_alert_entry(mitre_ids=["T1059", "T1071"]),
            _make_alert_entry(mitre_ids=["T1059"]),
        ]
        fl = _mock_forensic_logger(entries)
        mapper = _mock_mitre_mapper(["T1059 desc", "T1071 desc"])
        gen = ReportGenerator(forensic_logger=fl, mitre_mapper=mapper)
        report = gen.generate_report(since=0.0)
        mapper.describe.assert_called_once_with(["T1059", "T1071"])
        assert len(report.mitre_techniques) == 2

    def test_summary_generation(self) -> None:
        """Summary should mention alert and action counts."""
        entries = [
            _make_alert_entry(),
            _make_action_entry(),
        ]
        fl = _mock_forensic_logger(entries)
        gen = ReportGenerator(forensic_logger=fl)
        report = gen.generate_report(since=0.0)
        assert "1 alert(s) generated" in report.summary
        assert "1 response action(s) taken" in report.summary

    def test_default_since_last_24h(self) -> None:
        """When since is None, export_timeline should get ~24h ago."""
        fl = _mock_forensic_logger([])
        gen = ReportGenerator(forensic_logger=fl)
        before = time.time() - 86400
        gen.generate_report()
        call_kwargs = fl.export_timeline.call_args
        actual_since = call_kwargs.kwargs.get(
            "since", call_kwargs[1].get("since"),
        )
        after = time.time() - 86400
        assert before <= actual_since <= after + 1

    def test_custom_since(self) -> None:
        """A custom since value should be forwarded to the logger."""
        fl = _mock_forensic_logger([])
        gen = ReportGenerator(forensic_logger=fl)
        gen.generate_report(since=42.0)
        fl.export_timeline.assert_called_once_with(
            since=42.0, limit=500,
        )

    def test_no_forensic_logger(self) -> None:
        """Without a forensic logger the report should be empty."""
        gen = ReportGenerator(forensic_logger=None)
        report = gen.generate_report(since=0.0)
        assert report.total_events == 0
        assert report.timeline == []

    def test_no_mitre_mapper(self) -> None:
        """Without a MITRE mapper, techniques list should be empty."""
        entries = [_make_alert_entry(mitre_ids=["T1059"])]
        fl = _mock_forensic_logger(entries)
        gen = ReportGenerator(forensic_logger=fl, mitre_mapper=None)
        report = gen.generate_report(since=0.0)
        assert report.mitre_techniques == []


# ------------------------------------------------------------------ #
# TestRenderHtml
# ------------------------------------------------------------------ #


class TestRenderHtml:
    """Tests for ReportGenerator.render_html()."""

    @pytest.fixture()
    def full_report(self) -> IncidentReport:
        """A report with data in every section."""
        return IncidentReport(
            title="Test Incident",
            generated_at=1700000000.0,
            time_range_start=1699990000.0,
            time_range_end=1700000000.0,
            timeline=[
                {
                    "timestamp": 1699995000.0,
                    "severity": "high",
                    "source": "detection",
                    "type": "alert",
                },
            ],
            alerts=[
                {
                    "title": "C2 beacon",
                    "severity": "high",
                    "confidence": 0.85,
                    "mitre_ids": ["T1059"],
                },
            ],
            actions=[
                {
                    "action_type": "block_ip",
                    "target": "1.2.3.4",
                    "success": True,
                    "message": "blocked",
                },
            ],
            mitre_techniques=["T1059 — Command-Line Interface"],
            iocs=[{"type": "ip", "value": "1.2.3.4"}],
            summary="1 alert(s) generated.",
            total_events=1,
            total_alerts=1,
            total_actions=1,
        )

    def test_returns_string(self, full_report: IncidentReport) -> None:
        """render_html should return a string."""
        gen = ReportGenerator()
        result = gen.render_html(full_report)
        assert isinstance(result, str)

    def test_valid_html_structure(
        self, full_report: IncidentReport,
    ) -> None:
        """Output should contain DOCTYPE and closing html tag."""
        gen = ReportGenerator()
        result = gen.render_html(full_report)
        assert result.startswith("<!DOCTYPE html>")
        assert result.strip().endswith("</html>")

    def test_contains_title(
        self, full_report: IncidentReport,
    ) -> None:
        """The report title should appear in the HTML."""
        gen = ReportGenerator()
        result = gen.render_html(full_report)
        assert "Test Incident" in result

    def test_contains_generated_date(
        self, full_report: IncidentReport,
    ) -> None:
        """The generated-at timestamp should appear formatted."""
        gen = ReportGenerator()
        result = gen.render_html(full_report)
        expected = time.strftime(
            "%Y-%m-%d %H:%M:%S UTC",
            time.gmtime(1700000000.0),
        )
        assert expected in result

    def test_contains_timeline_rows(
        self, full_report: IncidentReport,
    ) -> None:
        """Timeline entries should produce table rows."""
        gen = ReportGenerator()
        result = gen.render_html(full_report)
        assert "<tr" in result
        assert "detection" in result

    def test_contains_alert_cards(
        self, full_report: IncidentReport,
    ) -> None:
        """Alert data should appear in alert-card divs."""
        gen = ReportGenerator()
        result = gen.render_html(full_report)
        assert "alert-card" in result
        assert "C2 beacon" in result

    def test_contains_action_rows(
        self, full_report: IncidentReport,
    ) -> None:
        """Action data should appear in table rows."""
        gen = ReportGenerator()
        result = gen.render_html(full_report)
        assert "block_ip" in result
        assert "1.2.3.4" in result

    def test_contains_mitre_items(
        self, full_report: IncidentReport,
    ) -> None:
        """MITRE techniques should appear as list items."""
        gen = ReportGenerator()
        result = gen.render_html(full_report)
        assert "<li>" in result
        assert "T1059" in result

    def test_contains_ioc_rows(
        self, full_report: IncidentReport,
    ) -> None:
        """IOC entries should appear in the IOC table."""
        gen = ReportGenerator()
        result = gen.render_html(full_report)
        assert "1.2.3.4" in result
        assert "<code>" in result

    def test_escapes_html_entities(self) -> None:
        """User data with HTML characters should be escaped."""
        report = IncidentReport(
            title="<script>alert('xss')</script>",
            generated_at=1700000000.0,
            summary="Test & verify <b>escaping</b>",
        )
        gen = ReportGenerator()
        result = gen.render_html(report)
        assert "<script>" not in result
        assert "&lt;script&gt;" in result
        assert "&amp;" in result

    def test_empty_report_renders(self) -> None:
        """An empty report should render without raising."""
        report = IncidentReport(title="Empty Report")
        gen = ReportGenerator()
        result = gen.render_html(report)
        assert "Empty Report" in result
        assert "<!DOCTYPE html>" in result


# ------------------------------------------------------------------ #
# TestRenderJson
# ------------------------------------------------------------------ #


class TestRenderJson:
    """Tests for ReportGenerator.render_json()."""

    @pytest.fixture()
    def sample_report(self) -> IncidentReport:
        """A report with representative data for JSON tests."""
        return IncidentReport(
            title="JSON Test",
            generated_at=1700000000.0,
            time_range_start=1699990000.0,
            time_range_end=1700000000.0,
            timeline=[{"timestamp": 100, "type": "alert"}],
            alerts=[{"title": "alert-1"}],
            actions=[{"action_type": "block_ip"}],
            mitre_techniques=["T1059"],
            iocs=[{"type": "ip", "value": "1.2.3.4"}],
            summary="1 alert(s) generated.",
            total_events=1,
            total_alerts=1,
            total_actions=0,
        )

    def test_returns_valid_json(
        self, sample_report: IncidentReport,
    ) -> None:
        """Output should be parseable JSON."""
        result = ReportGenerator.render_json(sample_report)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_contains_all_top_level_keys(
        self, sample_report: IncidentReport,
    ) -> None:
        """JSON output should include every required key."""
        parsed = json.loads(
            ReportGenerator.render_json(sample_report),
        )
        expected_keys = {
            "title", "generated_at", "time_range", "summary",
            "statistics", "timeline", "alerts", "actions",
            "mitre_techniques", "iocs",
        }
        assert expected_keys.issubset(parsed.keys())

    def test_statistics_correct(
        self, sample_report: IncidentReport,
    ) -> None:
        """Statistics section should match report totals."""
        parsed = json.loads(
            ReportGenerator.render_json(sample_report),
        )
        stats = parsed["statistics"]
        assert stats["total_events"] == 1
        assert stats["total_alerts"] == 1
        assert stats["total_actions"] == 0

    def test_timeline_included(
        self, sample_report: IncidentReport,
    ) -> None:
        """Timeline entries should appear in JSON output."""
        parsed = json.loads(
            ReportGenerator.render_json(sample_report),
        )
        assert len(parsed["timeline"]) == 1
        assert parsed["timeline"][0]["type"] == "alert"

    def test_alerts_included(
        self, sample_report: IncidentReport,
    ) -> None:
        """Alert data should appear in JSON output."""
        parsed = json.loads(
            ReportGenerator.render_json(sample_report),
        )
        assert len(parsed["alerts"]) == 1
        assert parsed["alerts"][0]["title"] == "alert-1"

    def test_iocs_included(
        self, sample_report: IncidentReport,
    ) -> None:
        """IOC entries should appear in JSON output."""
        parsed = json.loads(
            ReportGenerator.render_json(sample_report),
        )
        assert len(parsed["iocs"]) == 1
        assert parsed["iocs"][0]["value"] == "1.2.3.4"

    def test_empty_report_json(self) -> None:
        """An empty report should produce valid JSON."""
        report = IncidentReport(title="Empty")
        result = ReportGenerator.render_json(report)
        parsed = json.loads(result)
        assert parsed["title"] == "Empty"
        assert parsed["timeline"] == []

    def test_roundtrip_title(
        self, sample_report: IncidentReport,
    ) -> None:
        """Parsing the JSON back should preserve the title."""
        parsed = json.loads(
            ReportGenerator.render_json(sample_report),
        )
        assert parsed["title"] == sample_report.title
        assert parsed["generated_at"] == sample_report.generated_at


# ------------------------------------------------------------------ #
# TestExportStixBundle
# ------------------------------------------------------------------ #


class TestExportStixBundle:
    """Tests for ReportGenerator.export_stix_bundle()."""

    def test_bundle_structure(self) -> None:
        """Bundle should have type, id, and objects keys."""
        report = IncidentReport(title="STIX", iocs=[])
        bundle = ReportGenerator.export_stix_bundle(report)
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--aegis-report-")
        assert isinstance(bundle["objects"], list)

    def test_ip_indicator(self) -> None:
        """An IP IOC should produce an ipv4-addr STIX pattern."""
        report = IncidentReport(
            title="IP",
            iocs=[{"type": "ip", "value": "10.0.0.1"}],
        )
        bundle = ReportGenerator.export_stix_bundle(report)
        assert len(bundle["objects"]) == 1
        obj = bundle["objects"][0]
        assert obj["type"] == "indicator"
        assert "[ipv4-addr:value = '10.0.0.1']" in obj["pattern"]

    def test_domain_indicator(self) -> None:
        """A domain IOC should produce a domain-name STIX pattern."""
        report = IncidentReport(
            title="Domain",
            iocs=[{"type": "domain", "value": "evil.com"}],
        )
        bundle = ReportGenerator.export_stix_bundle(report)
        obj = bundle["objects"][0]
        assert "[domain-name:value = 'evil.com']" in obj["pattern"]

    def test_url_indicator(self) -> None:
        """A URL IOC should produce a url STIX pattern."""
        report = IncidentReport(
            title="URL",
            iocs=[{"type": "url", "value": "http://evil.com/c2"}],
        )
        bundle = ReportGenerator.export_stix_bundle(report)
        obj = bundle["objects"][0]
        assert "[url:value = 'http://evil.com/c2']" in obj["pattern"]

    def test_hash_indicator(self) -> None:
        """A hash IOC should produce a file hash STIX pattern."""
        sha = "abc123def456"
        report = IncidentReport(
            title="Hash",
            iocs=[{"type": "hash", "value": sha}],
        )
        bundle = ReportGenerator.export_stix_bundle(report)
        obj = bundle["objects"][0]
        assert f"[file:hashes.'SHA-256' = '{sha}']" in obj["pattern"]

    def test_empty_iocs(self) -> None:
        """No IOCs should produce an empty objects list."""
        report = IncidentReport(title="Empty", iocs=[])
        bundle = ReportGenerator.export_stix_bundle(report)
        assert bundle["objects"] == []

    def test_unknown_type_skipped(self) -> None:
        """IOCs with unrecognised types should be silently skipped."""
        report = IncidentReport(
            title="Unknown",
            iocs=[{"type": "foobar", "value": "whatever"}],
        )
        bundle = ReportGenerator.export_stix_bundle(report)
        assert bundle["objects"] == []


# ------------------------------------------------------------------ #
# TestBuildSummary
# ------------------------------------------------------------------ #


class TestBuildSummary:
    """Tests for ReportGenerator._build_summary()."""

    def test_alerts_only(self) -> None:
        """Summary with only alerts should mention alert count."""
        result = ReportGenerator._build_summary(3, 0, [])
        assert result == "3 alert(s) generated."

    def test_actions_only(self) -> None:
        """Summary with only actions should mention action count."""
        result = ReportGenerator._build_summary(0, 2, [])
        assert result == "2 response action(s) taken."

    def test_mitre_only(self) -> None:
        """Summary with only MITRE techs should mention them."""
        result = ReportGenerator._build_summary(0, 0, ["T1059"])
        assert "1 MITRE" in result
        assert result.endswith(".")

    def test_combined(self) -> None:
        """Summary with all components should join with '. '."""
        result = ReportGenerator._build_summary(
            3, 2, ["T1059", "T1071"],
        )
        assert "3 alert(s) generated" in result
        assert "2 response action(s) taken" in result
        assert "2 MITRE" in result
        parts = result.rstrip(".").split(". ")
        assert len(parts) == 3

    def test_empty(self) -> None:
        """No events should produce the 'no events' message."""
        result = ReportGenerator._build_summary(0, 0, [])
        assert result == (
            "No security events recorded in this period."
        )
