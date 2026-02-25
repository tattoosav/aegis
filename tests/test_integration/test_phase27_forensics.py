"""Phase 27 integration tests — Threat Hunting & Forensics end-to-end.

Tests the full forensics pipeline: timeline reconstruction from mock
incidents, report generation in HTML/CSV, and NL query validation.
All tests are fast (no Qt, no external dependencies).
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any

import pytest

from aegis.forensics.timeline_engine import TimelineEngine
from aegis.response.report_generator import (
    DailySummary,
    IncidentReport,
    ReportGenerator,
)
from aegis.ui.pages.threat_hunt import (
    PRE_BUILT_QUERIES,
    QueryBookmarks,
    QueryHistory,
    validate_query,
)

# ── helpers ──────────────────────────────────────────────────────────


def _make_raw_events() -> list[dict[str, Any]]:
    """Create a realistic chain of raw events simulating an attack.

    Chain: explorer.exe (pid=100) -> cmd.exe (pid=200)
           -> powershell.exe (pid=300) -> outbound connection
           -> DNS query -> file drop.
    """
    base_ts = 1_700_000_000.0
    return [
        {
            "timestamp": base_ts,
            "sensor": "process",
            "event_type": "process_new",
            "severity": "info",
            "data": {
                "pid": 100,
                "name": "explorer.exe",
                "cmdline": "explorer.exe",
                "user": "SYSTEM",
            },
        },
        {
            "timestamp": base_ts + 1,
            "sensor": "process",
            "event_type": "process_new",
            "severity": "medium",
            "data": {
                "pid": 200,
                "name": "cmd.exe",
                "parent_pid": 100,
                "cmdline": "cmd.exe /c whoami",
                "user": "admin",
            },
        },
        {
            "timestamp": base_ts + 2,
            "sensor": "process",
            "event_type": "process_new",
            "severity": "high",
            "data": {
                "pid": 300,
                "name": "powershell.exe",
                "parent_pid": 200,
                "cmdline": (
                    "powershell.exe -ep bypass -e ZW5jb2Rl"
                ),
                "user": "admin",
            },
        },
        {
            "timestamp": base_ts + 3,
            "sensor": "network",
            "event_type": "connection",
            "severity": "high",
            "data": {
                "remote_ip": "10.0.0.99",
                "remote_port": 443,
                "protocol": "tcp",
                "direction": "outbound",
            },
        },
        {
            "timestamp": base_ts + 4,
            "sensor": "network",
            "event_type": "dns_query",
            "severity": "medium",
            "data": {
                "domain": "evil.example.com",
            },
        },
        {
            "timestamp": base_ts + 5,
            "sensor": "file",
            "event_type": "file_create",
            "severity": "high",
            "data": {
                "path": "C:\\Temp\\payload.exe",
            },
        },
    ]


def _make_incident_report_data() -> dict[str, Any]:
    """Build mock data dict for Jinja2 incident report rendering."""
    return {
        "id": "INC-2026-0001",
        "title": "Suspicious PowerShell Activity",
        "severity": "high",
        "timestamp": 1_700_000_010.0,
        "summary": "PowerShell launched with bypass flag.",
        "timeline": [
            {
                "timestamp": 1_700_000_000.0,
                "severity": "info",
                "event": "explorer.exe started",
            },
            {
                "timestamp": 1_700_000_001.0,
                "severity": "high",
                "event": "powershell.exe with -ep bypass",
            },
        ],
        "alerts": [
            {
                "title": "Encoded PowerShell",
                "alert_type": "process_anomaly",
                "severity": "high",
                "description": "Base64-encoded command detected.",
            },
        ],
        "iocs": [
            {"type": "ip", "value": "10.0.0.99"},
            {"type": "domain", "value": "evil.example.com"},
        ],
        "mitre_techniques": [
            {"id": "T1059.001", "name": "PowerShell"},
            {"id": "T1071", "name": "Application Layer Protocol"},
        ],
        "response_actions": [
            {
                "action": "block_ip",
                "target": "10.0.0.99",
                "success": True,
            },
        ],
        "remediation_steps": [
            "Isolate affected host",
            "Reset compromised credentials",
        ],
    }


def _make_daily_summary() -> DailySummary:
    """Build a DailySummary with realistic data."""
    return DailySummary(
        alert_counts={
            "critical": 2,
            "high": 5,
            "medium": 12,
            "low": 30,
        },
        top_rules=[
            {"rule": "encoded_powershell", "count": 8},
            {"rule": "outbound_c2", "count": 5},
        ],
        new_iocs=[
            {"type": "ip", "value": "192.168.1.42"},
            {"type": "domain", "value": "bad.example.com"},
        ],
        sensor_status={
            "process": "running",
            "network": "running",
            "file": "degraded",
        },
    )


def _make_incident_report_obj() -> IncidentReport:
    """Build an IncidentReport dataclass for CSV / HTML export."""
    return IncidentReport(
        title="Test Incident Report",
        generated_at=1_700_000_020.0,
        time_range_start=1_700_000_000.0,
        time_range_end=1_700_000_010.0,
        timeline=[
            {
                "timestamp": 1_700_000_000.0,
                "severity": "info",
                "source": "process",
                "type": "process_new",
            },
            {
                "timestamp": 1_700_000_001.0,
                "severity": "high",
                "source": "process",
                "type": "process_new",
            },
            {
                "timestamp": 1_700_000_003.0,
                "severity": "high",
                "source": "network",
                "type": "connection",
            },
        ],
        alerts=[
            {
                "title": "Encoded PowerShell",
                "severity": "high",
                "confidence": 0.95,
                "mitre_ids": ["T1059.001"],
                "log_type": "alert",
            },
        ],
        actions=[
            {
                "action_type": "block_ip",
                "target": "10.0.0.99",
                "success": True,
                "message": "Blocked",
                "log_type": "action_result",
            },
        ],
        mitre_techniques=["T1059.001 - PowerShell"],
        iocs=[
            {"type": "ip", "value": "10.0.0.99"},
            {"type": "domain", "value": "evil.example.com"},
        ],
        summary="1 alert(s) generated. 1 response action(s) taken.",
        total_events=3,
        total_alerts=1,
        total_actions=1,
    )


# ── 1. Timeline reconstruction ──────────────────────────────────────


class TestTimelineReconstruction:
    """Build a timeline from mock events, verify causality + sorting."""

    def test_build_returns_sorted_timeline(self) -> None:
        engine = TimelineEngine()
        timeline = engine.build(_make_raw_events())

        assert len(timeline) == 6
        # Chronological order
        timestamps = [e.timestamp for e in timeline]
        assert timestamps == sorted(timestamps)

    def test_causality_linking(self) -> None:
        engine = TimelineEngine()
        timeline = engine.build(_make_raw_events())

        # Build pid -> event_id index for assertions
        pid_map: dict[int, str] = {}
        for evt in timeline:
            if evt.process_context and "pid" in evt.process_context:
                pid_map[evt.process_context["pid"]] = evt.event_id

        # cmd.exe (pid=200) should be linked to explorer (pid=100)
        cmd_evt = next(
            e for e in timeline
            if e.process_context
            and e.process_context.get("name") == "cmd.exe"
        )
        assert cmd_evt.parent_event_id == pid_map[100]

        # powershell (pid=300) should be linked to cmd (pid=200)
        ps_evt = next(
            e for e in timeline
            if e.process_context
            and e.process_context.get("name") == "powershell.exe"
        )
        assert ps_evt.parent_event_id == pid_map[200]

    def test_mitre_technique_inference(self) -> None:
        engine = TimelineEngine()
        timeline = engine.build(_make_raw_events())

        mitre_ids = {
            e.mitre_technique
            for e in timeline
            if e.mitre_technique
        }
        # powershell -> T1059.001, cmd -> T1059.003,
        # connection -> T1071, dns_query -> T1071.004,
        # file_create -> T1105
        assert "T1059.001" in mitre_ids
        assert "T1059.003" in mitre_ids
        assert "T1071" in mitre_ids
        assert "T1071.004" in mitre_ids
        assert "T1105" in mitre_ids

    def test_summary_strings(self) -> None:
        engine = TimelineEngine()
        timeline = engine.build(_make_raw_events())

        ps_evt = next(
            e for e in timeline
            if e.process_context
            and e.process_context.get("name") == "powershell.exe"
        )
        assert "powershell.exe" in ps_evt.summary
        assert "pid=300" in ps_evt.summary

        conn_evt = next(
            e for e in timeline
            if e.event_type == "connection"
        )
        assert "10.0.0.99" in conn_evt.summary

    def test_empty_events(self) -> None:
        engine = TimelineEngine()
        assert engine.build([]) == []

    def test_process_and_network_contexts(self) -> None:
        engine = TimelineEngine()
        timeline = engine.build(_make_raw_events())

        process_evts = [
            e for e in timeline if e.process_context
        ]
        assert len(process_evts) == 3  # explorer, cmd, powershell

        network_evts = [
            e for e in timeline if e.network_context
        ]
        assert len(network_evts) == 2  # connection + dns


# ── 2. Timeline export (HTML + JSON) ────────────────────────────────


class TestTimelineExport:
    """Export timeline to HTML and JSON, verify content."""

    def test_export_html(self) -> None:
        engine = TimelineEngine()
        timeline = engine.build(_make_raw_events())
        html_out = engine.export_html(timeline)

        assert "<!DOCTYPE html>" in html_out
        assert "Aegis Attack Timeline" in html_out
        assert "powershell.exe" in html_out
        assert "10.0.0.99" in html_out
        assert "<table>" in html_out
        assert "T1059.001" in html_out

    def test_export_json(self) -> None:
        engine = TimelineEngine()
        timeline = engine.build(_make_raw_events())
        json_out = engine.export_json(timeline)

        data = json.loads(json_out)
        assert isinstance(data, list)
        assert len(data) == 6
        # Every record should have event_id
        for record in data:
            assert "event_id" in record
            assert "timestamp" in record
            assert "source_sensor" in record

    def test_json_round_trip_fields(self) -> None:
        engine = TimelineEngine()
        timeline = engine.build(_make_raw_events())
        data = json.loads(engine.export_json(timeline))

        # Check a process event has process_context
        ps_record = next(
            r for r in data
            if r.get("process_context", {}).get("name")
            == "powershell.exe"
        )
        assert ps_record["mitre_technique"] == "T1059.001"
        assert ps_record["process_context"]["pid"] == 300

    def test_export_html_severity_colors(self) -> None:
        engine = TimelineEngine()
        timeline = engine.build(_make_raw_events())
        html_out = engine.export_html(timeline)

        # High severity events should have the orange color
        assert "#fd7e14" in html_out  # high color
        assert "#ffc107" in html_out  # medium color


# ── 3. Incident report rendering (Jinja2 HTML) ──────────────────────


class TestIncidentReportRendering:
    """Render Jinja2 incident report, verify key sections."""

    def test_render_incident_html(self) -> None:
        gen = ReportGenerator()
        data = _make_incident_report_data()
        html_out = gen.render_incident_report(data)

        assert "<!DOCTYPE html>" in html_out
        assert "Suspicious PowerShell Activity" in html_out
        assert "INC-2026-0001" in html_out
        assert "Summary" in html_out
        assert "PowerShell launched with bypass flag" in html_out

    def test_incident_report_has_timeline_section(self) -> None:
        gen = ReportGenerator()
        html_out = gen.render_incident_report(
            _make_incident_report_data(),
        )
        assert "Event Timeline" in html_out
        assert "explorer.exe started" in html_out

    def test_incident_report_has_alerts_section(self) -> None:
        gen = ReportGenerator()
        html_out = gen.render_incident_report(
            _make_incident_report_data(),
        )
        assert "Alerts" in html_out
        assert "Encoded PowerShell" in html_out
        assert "process_anomaly" in html_out

    def test_incident_report_has_iocs(self) -> None:
        gen = ReportGenerator()
        html_out = gen.render_incident_report(
            _make_incident_report_data(),
        )
        assert "Indicators of Compromise" in html_out
        assert "10.0.0.99" in html_out
        assert "evil.example.com" in html_out

    def test_incident_report_has_mitre(self) -> None:
        gen = ReportGenerator()
        html_out = gen.render_incident_report(
            _make_incident_report_data(),
        )
        assert "MITRE" in html_out
        assert "T1059.001" in html_out
        assert "PowerShell" in html_out

    def test_incident_report_has_response_actions(self) -> None:
        gen = ReportGenerator()
        html_out = gen.render_incident_report(
            _make_incident_report_data(),
        )
        assert "Response Actions" in html_out
        assert "block_ip" in html_out

    def test_incident_report_has_remediation(self) -> None:
        gen = ReportGenerator()
        html_out = gen.render_incident_report(
            _make_incident_report_data(),
        )
        assert "Remediation" in html_out
        assert "Isolate affected host" in html_out


# ── 4. Daily summary rendering ──────────────────────────────────────


class TestDailySummaryRendering:
    """Render daily summary HTML, verify alert counts."""

    def test_render_daily_summary_html(self) -> None:
        gen = ReportGenerator()
        summary = _make_daily_summary()
        html_out = gen.render_daily_summary(summary)

        assert "<!DOCTYPE html>" in html_out
        assert "Daily Summary" in html_out

    def test_daily_summary_alert_counts(self) -> None:
        gen = ReportGenerator()
        html_out = gen.render_daily_summary(_make_daily_summary())

        # Individual severity counts should appear
        assert ">2<" in html_out   # critical
        assert ">5<" in html_out   # high
        assert ">12<" in html_out  # medium
        assert ">30<" in html_out  # low
        # Total = 2+5+12+30 = 49
        assert ">49<" in html_out

    def test_daily_summary_top_rules(self) -> None:
        gen = ReportGenerator()
        html_out = gen.render_daily_summary(_make_daily_summary())

        assert "encoded_powershell" in html_out
        assert "outbound_c2" in html_out

    def test_daily_summary_sensor_status(self) -> None:
        gen = ReportGenerator()
        html_out = gen.render_daily_summary(_make_daily_summary())

        assert "running" in html_out
        assert "degraded" in html_out

    def test_daily_summary_new_iocs(self) -> None:
        gen = ReportGenerator()
        html_out = gen.render_daily_summary(_make_daily_summary())

        assert "192.168.1.42" in html_out
        assert "bad.example.com" in html_out


# ── 5. CSV export ────────────────────────────────────────────────────


class TestCSVExport:
    """Export incident report to CSV, verify headers and data."""

    def test_csv_has_correct_headers(self) -> None:
        report = _make_incident_report_obj()
        csv_str = ReportGenerator.export_csv(report)
        reader = csv.reader(io.StringIO(csv_str))
        headers = next(reader)

        assert headers == ["timestamp", "severity", "source", "type"]

    def test_csv_row_count(self) -> None:
        report = _make_incident_report_obj()
        csv_str = ReportGenerator.export_csv(report)
        reader = csv.reader(io.StringIO(csv_str))
        rows = list(reader)

        # 1 header + 3 data rows
        assert len(rows) == 4

    def test_csv_data_content(self) -> None:
        report = _make_incident_report_obj()
        csv_str = ReportGenerator.export_csv(report)
        reader = csv.reader(io.StringIO(csv_str))
        _ = next(reader)  # skip header
        rows = list(reader)

        # First row: info severity, process source
        assert rows[0][1] == "info"
        assert rows[0][2] == "process"
        assert rows[0][3] == "process_new"

        # Last row: high severity, network source
        assert rows[2][1] == "high"
        assert rows[2][2] == "network"
        assert rows[2][3] == "connection"

    def test_csv_empty_timeline(self) -> None:
        report = IncidentReport(title="Empty")
        csv_str = ReportGenerator.export_csv(report)
        reader = csv.reader(io.StringIO(csv_str))
        rows = list(reader)

        # Only the header row
        assert len(rows) == 1
        assert rows[0] == [
            "timestamp", "severity", "source", "type",
        ]


# ── 6. Query validation ─────────────────────────────────────────────


class TestQueryValidation:
    """Validate SQL: SELECT allowed, dangerous keywords blocked."""

    @pytest.mark.parametrize("sql", [
        "SELECT * FROM events",
        "SELECT id, name FROM alerts WHERE severity = 'high'",
        "  SELECT count(*) FROM events GROUP BY sensor",
        "select * from events",  # case-insensitive
    ])
    def test_valid_select_queries(self, sql: str) -> None:
        assert validate_query(sql) is True

    @pytest.mark.parametrize("sql,keyword", [
        ("DELETE FROM events", "DELETE"),
        ("DROP TABLE alerts", "DROP"),
        ("INSERT INTO events VALUES (1)", "INSERT"),
        ("UPDATE events SET severity='low'", "UPDATE"),
        ("ALTER TABLE events ADD col INT", "ALTER"),
        ("CREATE TABLE hack (id INT)", "CREATE"),
        ("TRUNCATE TABLE events", "TRUNCATE"),
        ("EXEC xp_cmdshell 'whoami'", "EXEC"),
        ("GRANT ALL ON events TO hacker", "GRANT"),
        ("REVOKE ALL ON events FROM user", "REVOKE"),
    ])
    def test_blocked_keywords(
        self, sql: str, keyword: str,
    ) -> None:
        assert validate_query(sql) is False

    def test_empty_string(self) -> None:
        assert validate_query("") is False

    def test_whitespace_only(self) -> None:
        assert validate_query("   ") is False

    def test_non_select_non_blocked(self) -> None:
        # Random text that is neither SELECT nor blocked
        assert validate_query("SHOW TABLES") is False


# ── 7. Pre-built queries pass validation ─────────────────────────────


class TestPreBuiltQueries:
    """Every pre-built query must pass validate_query."""

    @pytest.mark.parametrize(
        "name,sql",
        list(PRE_BUILT_QUERIES.items()),
    )
    def test_prebuilt_query_valid(
        self, name: str, sql: str,
    ) -> None:
        assert validate_query(sql) is True, (
            f"Pre-built query {name!r} failed validation"
        )

    def test_prebuilt_queries_not_empty(self) -> None:
        assert len(PRE_BUILT_QUERIES) > 0


# ── 8. Bookmarks and history ────────────────────────────────────────


class TestBookmarksAndHistory:
    """Save/retrieve bookmarks; verify history deduplication."""

    def test_bookmark_save_and_retrieve(self) -> None:
        bm = QueryBookmarks()
        bm.save("my_query", "SELECT * FROM events")

        assert bm.get("my_query") == "SELECT * FROM events"
        assert "my_query" in bm.list_names()

    def test_bookmark_remove(self) -> None:
        bm = QueryBookmarks()
        bm.save("temp", "SELECT 1")
        bm.remove("temp")

        assert bm.get("temp") is None
        assert "temp" not in bm.list_names()

    def test_bookmark_remove_nonexistent(self) -> None:
        bm = QueryBookmarks()
        # Should be a no-op, not raise
        bm.remove("nonexistent")

    def test_bookmark_overwrite(self) -> None:
        bm = QueryBookmarks()
        bm.save("q1", "SELECT 1")
        bm.save("q1", "SELECT 2")
        assert bm.get("q1") == "SELECT 2"

    def test_history_deduplication(self) -> None:
        hist = QueryHistory()
        hist.add("SELECT 1")
        hist.add("SELECT 2")
        hist.add("SELECT 1")  # duplicate -> move to front

        entries = hist.entries()
        assert entries[0] == "SELECT 1"
        assert entries[1] == "SELECT 2"
        assert len(entries) == 2

    def test_history_max_size(self) -> None:
        hist = QueryHistory(max_size=3)
        for i in range(5):
            hist.add(f"SELECT {i}")

        entries = hist.entries()
        assert len(entries) == 3
        # Most recent first
        assert entries[0] == "SELECT 4"

    def test_history_clear(self) -> None:
        hist = QueryHistory()
        hist.add("SELECT 1")
        hist.clear()
        assert hist.entries() == []

    def test_history_order_most_recent_first(self) -> None:
        hist = QueryHistory()
        hist.add("alpha")
        hist.add("beta")
        hist.add("gamma")

        entries = hist.entries()
        assert entries == ["gamma", "beta", "alpha"]


# ── 9. End-to-end: timeline -> report -> CSV ────────────────────────


class TestEndToEnd:
    """Build timeline -> generate incident report -> export CSV."""

    def test_full_pipeline(self) -> None:
        # Step 1: Build timeline from raw events
        engine = TimelineEngine()
        timeline = engine.build(_make_raw_events())
        assert len(timeline) > 0

        # Step 2: Convert timeline events to report-compatible dicts
        report_timeline = []
        for evt in timeline:
            report_timeline.append({
                "timestamp": evt.timestamp,
                "severity": evt.severity,
                "source": evt.source_sensor,
                "type": evt.event_type,
            })

        # Step 3: Build an IncidentReport from the timeline
        report = IncidentReport(
            title="End-to-End Test Incident",
            time_range_start=timeline[0].timestamp,
            time_range_end=timeline[-1].timestamp,
            timeline=report_timeline,
            alerts=[
                {
                    "title": "PowerShell Detected",
                    "severity": "high",
                    "confidence": 0.9,
                    "mitre_ids": ["T1059.001"],
                    "log_type": "alert",
                },
            ],
            actions=[],
            mitre_techniques=["T1059.001"],
            iocs=[
                {"type": "ip", "value": "10.0.0.99"},
            ],
            summary="Pipeline integration test.",
            total_events=len(report_timeline),
            total_alerts=1,
            total_actions=0,
        )

        # Step 4: Render the legacy HTML report
        gen = ReportGenerator()
        html_out = gen.render_html(report)
        assert "End-to-End Test Incident" in html_out
        assert "PowerShell Detected" in html_out
        assert "T1059.001" in html_out

        # Step 5: Export to CSV
        csv_str = ReportGenerator.export_csv(report)
        reader = csv.reader(io.StringIO(csv_str))
        header = next(reader)
        assert header == [
            "timestamp", "severity", "source", "type",
        ]
        rows = list(reader)
        assert len(rows) == len(report_timeline)

        # Step 6: Export to JSON
        json_str = ReportGenerator.render_json(report)
        json_data = json.loads(json_str)
        assert json_data["title"] == "End-to-End Test Incident"
        assert json_data["statistics"]["total_events"] == len(
            report_timeline,
        )

    def test_timeline_html_then_report_html(self) -> None:
        """Timeline HTML and incident report HTML are both valid."""
        engine = TimelineEngine()
        timeline = engine.build(_make_raw_events())

        # Timeline HTML export
        tl_html = engine.export_html(timeline)
        assert "Aegis Attack Timeline" in tl_html
        assert "<table>" in tl_html

        # Jinja2 incident report
        gen = ReportGenerator()
        report_html = gen.render_incident_report(
            _make_incident_report_data(),
        )
        assert "Incident Report" in report_html

        # Both are valid HTML docs
        assert tl_html.startswith("<!DOCTYPE html>")
        assert report_html.startswith("<!DOCTYPE html>")

    def test_stix_export_from_report(self) -> None:
        """STIX bundle export produces valid structure."""
        report = _make_incident_report_obj()
        bundle = ReportGenerator.export_stix_bundle(report)

        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 2  # ip + domain
        types = {
            obj["type"] for obj in bundle["objects"]
        }
        assert types == {"indicator"}
