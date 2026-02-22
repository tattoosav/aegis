"""Forensic Report Generator — HTML and JSON incident reports.

Generates self-contained HTML incident reports from the forensic
audit trail.  Uses the ForensicLogger timeline, MITRE mapper, and
alert data to produce compliance-ready documentation.
"""

from __future__ import annotations

import html
import json
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.intelligence.mitre_mapper import MITREMapper
    from aegis.response.forensic_logger import ForensicLogger

logger = logging.getLogger(__name__)


@dataclass
class IncidentReport:
    """A complete incident report ready for rendering."""

    title: str
    generated_at: float = field(default_factory=time.time)
    time_range_start: float = 0.0
    time_range_end: float = 0.0
    timeline: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    iocs: list[dict[str, str]] = field(default_factory=list)
    summary: str = ""
    total_events: int = 0
    total_alerts: int = 0
    total_actions: int = 0


class ReportGenerator:
    """Generate incident reports from the forensic audit trail.

    Parameters
    ----------
    forensic_logger:
        ForensicLogger instance for querying the audit trail.
    mitre_mapper:
        Optional MITREMapper for technique descriptions.
    """

    def __init__(
        self,
        forensic_logger: ForensicLogger | None = None,
        mitre_mapper: MITREMapper | None = None,
    ) -> None:
        self._forensic_logger = forensic_logger
        self._mitre_mapper = mitre_mapper

    def generate_report(
        self,
        title: str = "Aegis Incident Report",
        since: float | None = None,
        limit: int = 500,
    ) -> IncidentReport:
        """Build an incident report from the audit trail.

        Parameters
        ----------
        title:
            Report title.
        since:
            Only include events after this timestamp.
            Defaults to last 24 hours.
        limit:
            Maximum number of timeline entries.
        """
        if since is None:
            since = time.time() - 86400  # Last 24 hours

        # Get timeline from forensic logger
        timeline: list[dict[str, Any]] = []
        if self._forensic_logger:
            timeline = self._forensic_logger.export_timeline(
                since=since, limit=limit,
            )

        # Separate alerts and actions
        alerts: list[dict[str, Any]] = []
        actions: list[dict[str, Any]] = []
        mitre_set: set[str] = set()
        ioc_set: set[tuple[str, str]] = set()

        for entry in timeline:
            details = entry.get("details", {})
            log_type = details.get("log_type", entry.get("type", ""))

            if log_type == "alert":
                alerts.append(details)
                for tid in details.get("mitre_ids", []):
                    mitre_set.add(tid)
            elif log_type == "action_result":
                actions.append(details)

        # Extract IOCs from alert data
        for alert_entry in alerts:
            alert_type = alert_entry.get("alert_type", "")
            if "ip" in alert_type or "network" in alert_type:
                target = alert_entry.get("target", "")
                if target:
                    ioc_set.add(("ip", target))
            if "dns" in alert_type or "url" in alert_type:
                title_text = alert_entry.get("title", "")
                if ":" in title_text:
                    domain = title_text.split(":")[-1].strip()[:100]
                    if domain:
                        ioc_set.add(("domain", domain))

        # Get MITRE descriptions
        mitre_descriptions: list[str] = []
        if self._mitre_mapper and mitre_set:
            mitre_descriptions = self._mitre_mapper.describe(
                sorted(mitre_set),
            )

        # Compute time range
        timestamps = [e.get("timestamp", 0) for e in timeline if e.get("timestamp")]
        time_start = min(timestamps) if timestamps else since
        time_end = max(timestamps) if timestamps else time.time()

        # Build summary
        summary = self._build_summary(
            len(alerts), len(actions), mitre_descriptions,
        )

        return IncidentReport(
            title=title,
            time_range_start=time_start,
            time_range_end=time_end,
            timeline=timeline,
            alerts=alerts,
            actions=actions,
            mitre_techniques=mitre_descriptions,
            iocs=[
                {"type": t, "value": v} for t, v in sorted(ioc_set)
            ],
            summary=summary,
            total_events=len(timeline),
            total_alerts=len(alerts),
            total_actions=len(actions),
        )

    def render_html(self, report: IncidentReport) -> str:
        """Render an IncidentReport to self-contained HTML."""
        title_esc = html.escape(report.title)
        generated = time.strftime(
            "%Y-%m-%d %H:%M:%S UTC", time.gmtime(report.generated_at),
        )
        range_start = time.strftime(
            "%Y-%m-%d %H:%M", time.gmtime(report.time_range_start),
        )
        range_end = time.strftime(
            "%Y-%m-%d %H:%M", time.gmtime(report.time_range_end),
        )

        # Build timeline rows
        timeline_rows = ""
        for entry in report.timeline:
            ts = time.strftime(
                "%H:%M:%S", time.gmtime(entry.get("timestamp", 0)),
            )
            severity = html.escape(str(entry.get("severity", "info")))
            source = html.escape(str(entry.get("source", "")))
            etype = html.escape(str(entry.get("type", "")))
            sev_class = f"sev-{severity}"
            timeline_rows += (
                f"<tr class=\"{sev_class}\">"
                f"<td>{ts}</td>"
                f"<td><span class=\"badge {sev_class}\">{severity}</span></td>"
                f"<td>{source}</td>"
                f"<td>{etype}</td>"
                f"</tr>\n"
            )

        # Build alert cards
        alert_cards = ""
        for alert in report.alerts:
            a_title = html.escape(str(alert.get("title", "")))
            a_sev = html.escape(str(alert.get("severity", "medium")))
            a_conf = alert.get("confidence", 0)
            a_mitre = ", ".join(alert.get("mitre_ids", []))
            alert_cards += (
                f"<div class=\"alert-card sev-{a_sev}\">"
                f"<strong>{a_title}</strong><br>"
                f"Severity: {a_sev} | Confidence: {a_conf:.0%}<br>"
                f"MITRE: {html.escape(a_mitre) or 'N/A'}"
                f"</div>\n"
            )

        # Build action rows
        action_rows = ""
        for action in report.actions:
            a_type = html.escape(str(action.get("action_type", "")))
            a_target = html.escape(str(action.get("target", "")))
            a_success = "Yes" if action.get("success") else "No"
            a_msg = html.escape(str(action.get("message", "")))
            action_rows += (
                f"<tr>"
                f"<td>{a_type}</td>"
                f"<td>{a_target}</td>"
                f"<td>{a_success}</td>"
                f"<td>{a_msg}</td>"
                f"</tr>\n"
            )

        # Build MITRE list
        mitre_items = ""
        for tech in report.mitre_techniques:
            mitre_items += f"<li>{html.escape(tech)}</li>\n"

        # Build IOC rows
        ioc_rows = ""
        for ioc in report.iocs:
            ioc_rows += (
                f"<tr>"
                f"<td>{html.escape(ioc['type'])}</td>"
                f"<td><code>{html.escape(ioc['value'])}</code></td>"
                f"</tr>\n"
            )

        summary_esc = html.escape(report.summary)

        return _HTML_TEMPLATE.format(
            title=title_esc,
            generated=generated,
            range_start=range_start,
            range_end=range_end,
            total_events=report.total_events,
            total_alerts=report.total_alerts,
            total_actions=report.total_actions,
            summary=summary_esc,
            timeline_rows=timeline_rows,
            alert_cards=alert_cards,
            action_rows=action_rows,
            mitre_items=mitre_items,
            ioc_rows=ioc_rows,
        )

    @staticmethod
    def render_json(report: IncidentReport) -> str:
        """Export report as structured JSON."""
        return json.dumps(
            {
                "title": report.title,
                "generated_at": report.generated_at,
                "time_range": {
                    "start": report.time_range_start,
                    "end": report.time_range_end,
                },
                "summary": report.summary,
                "statistics": {
                    "total_events": report.total_events,
                    "total_alerts": report.total_alerts,
                    "total_actions": report.total_actions,
                },
                "timeline": report.timeline,
                "alerts": report.alerts,
                "actions": report.actions,
                "mitre_techniques": report.mitre_techniques,
                "iocs": report.iocs,
            },
            indent=2,
        )

    @staticmethod
    def export_stix_bundle(report: IncidentReport) -> dict[str, Any]:
        """Export IOCs from the report as a STIX 2.1 bundle dict."""
        objects: list[dict[str, Any]] = []
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        for ioc in report.iocs:
            ioc_type = ioc["type"]
            value = ioc["value"]

            if ioc_type == "ip":
                pattern = f"[ipv4-addr:value = '{value}']"
            elif ioc_type == "domain":
                pattern = f"[domain-name:value = '{value}']"
            elif ioc_type == "url":
                pattern = f"[url:value = '{value}']"
            elif ioc_type == "hash":
                pattern = f"[file:hashes.'SHA-256' = '{value}']"
            else:
                continue

            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--aegis-{len(objects)}",
                "created": now,
                "modified": now,
                "name": f"Aegis IOC: {value[:50]}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "labels": ["malicious-activity"],
            })

        return {
            "type": "bundle",
            "id": f"bundle--aegis-report-{int(time.time())}",
            "objects": objects,
        }

    @staticmethod
    def _build_summary(
        alert_count: int, action_count: int, mitre_techs: list[str],
    ) -> str:
        """Build a human-readable summary string."""
        parts: list[str] = []
        if alert_count:
            parts.append(f"{alert_count} alert(s) generated")
        if action_count:
            parts.append(f"{action_count} response action(s) taken")
        if mitre_techs:
            parts.append(
                f"{len(mitre_techs)} MITRE ATT&CK technique(s) observed"
            )
        if not parts:
            return "No security events recorded in this period."
        return ". ".join(parts) + "."


# --------------------------------------------------------------------------- #
# HTML template (self-contained, inline CSS)
# --------------------------------------------------------------------------- #

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }}
h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 8px; }}
h2 {{ color: #79c0ff; margin-top: 24px; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; }}
th {{ background: #161b22; color: #79c0ff; }}
.badge {{ padding: 2px 8px; border-radius: 4px; font-size: 12px;
          font-weight: bold; text-transform: uppercase; }}
.sev-critical {{ background: #f85149; color: #fff; }}
.sev-high {{ background: #d29922; color: #000; }}
.sev-medium {{ background: #3fb950; color: #000; }}
.sev-low {{ background: #58a6ff; color: #000; }}
.sev-info {{ background: #484f58; color: #c9d1d9; }}
.alert-card {{ border: 1px solid #30363d; border-left: 4px solid #d29922;
              padding: 12px; margin: 8px 0; border-radius: 4px;
              background: #161b22; }}
.alert-card.sev-critical {{ border-left-color: #f85149; }}
.alert-card.sev-high {{ border-left-color: #d29922; }}
.alert-card.sev-medium {{ border-left-color: #3fb950; }}
.meta {{ color: #8b949e; font-size: 14px; }}
code {{ background: #161b22; padding: 2px 6px; border-radius: 3px; }}
.stats {{ display: flex; gap: 16px; margin: 12px 0; }}
.stat {{ background: #161b22; padding: 16px; border-radius: 8px;
         border: 1px solid #30363d; text-align: center; min-width: 120px; }}
.stat-value {{ font-size: 28px; font-weight: bold; color: #58a6ff; }}
.stat-label {{ font-size: 12px; color: #8b949e; margin-top: 4px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="meta">Generated: {generated} | Period: {range_start} — {range_end}</p>

<div class="stats">
  <div class="stat">
    <div class="stat-value">{total_events}</div>
    <div class="stat-label">Events</div>
  </div>
  <div class="stat">
    <div class="stat-value">{total_alerts}</div>
    <div class="stat-label">Alerts</div>
  </div>
  <div class="stat">
    <div class="stat-value">{total_actions}</div>
    <div class="stat-label">Actions</div>
  </div>
</div>

<p>{summary}</p>

<h2>Event Timeline</h2>
<table>
<tr><th>Time</th><th>Severity</th><th>Source</th><th>Type</th></tr>
{timeline_rows}
</table>

<h2>Alerts</h2>
{alert_cards}

<h2>Response Actions</h2>
<table>
<tr><th>Action</th><th>Target</th><th>Success</th><th>Message</th></tr>
{action_rows}
</table>

<h2>MITRE ATT&amp;CK Techniques</h2>
<ul>
{mitre_items}
</ul>

<h2>Indicators of Compromise</h2>
<table>
<tr><th>Type</th><th>Value</th></tr>
{ioc_rows}
</table>

<footer class="meta" style="margin-top: 32px; border-top: 1px solid #30363d;
  padding-top: 12px;">
  Aegis AI Security Defense System — Automated Incident Report
</footer>
</body>
</html>"""
