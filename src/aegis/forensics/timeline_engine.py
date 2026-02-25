"""Attack timeline reconstruction engine.

Takes raw event dicts (the format stored in the database) and converts
them to TimelineEvent objects with causality linking.  PID/parent_PID
relationships are used to determine which process spawned which.
"""

from __future__ import annotations

import html
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------
# Known process-name -> MITRE technique heuristics
# -----------------------------------------------------------------------
_PROCESS_MITRE_MAP: dict[str, str] = {
    "powershell.exe": "T1059.001",
    "powershell": "T1059.001",
    "cmd.exe": "T1059.003",
    "cmd": "T1059.003",
    "wscript.exe": "T1059.005",
    "cscript.exe": "T1059.005",
    "mshta.exe": "T1218.005",
    "regsvr32.exe": "T1218.010",
    "rundll32.exe": "T1218.011",
    "schtasks.exe": "T1053.005",
    "at.exe": "T1053.002",
}

_EVENT_TYPE_MITRE_MAP: dict[str, str] = {
    "connection": "T1071",
    "dns_query": "T1071.004",
    "file_create": "T1105",
    "file_modify": "T1565.001",
    "registry_modify": "T1112",
}


@dataclass
class TimelineEvent:
    """A single event in an attack timeline.

    Attributes:
        timestamp:       Epoch seconds when the event occurred.
        source_sensor:   Sensor that produced this event (e.g. "process").
        event_type:      Event category (e.g. "process_new", "connection").
        severity:        Severity label (info / low / medium / high / critical).
        mitre_technique: MITRE ATT&CK technique ID, or None if unknown.
        summary:         Human-readable one-line description.
        process_context: Optional dict with pid, name, parent_pid, etc.
        network_context: Optional dict with remote_ip, port, protocol, etc.
        parent_event_id: ID of the causal parent event, or None.
        event_id:        Unique identifier for this timeline event.
    """

    timestamp: float
    source_sensor: str
    event_type: str
    severity: str
    mitre_technique: str | None = None
    summary: str = ""
    process_context: dict[str, Any] | None = None
    network_context: dict[str, Any] | None = None
    parent_event_id: str | None = None
    event_id: str = field(
        default_factory=lambda: f"tl-{uuid.uuid4().hex[:12]}",
    )


class TimelineEngine:
    """Builds a causally-linked attack timeline from raw events.

    Usage::

        engine = TimelineEngine()
        timeline = engine.build(raw_events)
        html_report = engine.export_html(timeline)
    """

    def build(self, events: list[dict[str, Any]]) -> list[TimelineEvent]:
        """Convert raw event dicts into a sorted, causally-linked timeline.

        Args:
            events: List of dicts, each with at minimum ``timestamp``,
                ``sensor``, ``event_type``, ``severity``, and ``data``.

        Returns:
            Sorted list of :class:`TimelineEvent` objects with parent
            links populated where PID/parent_PID relationships exist.
        """
        if not events:
            return []

        timeline_events = [self._convert(evt) for evt in events]

        # Sort by timestamp (stable sort preserves insertion order for ties)
        timeline_events.sort(key=lambda e: e.timestamp)

        # Build causality links via PID -> event_id mapping
        self._link_causality(timeline_events)

        return timeline_events

    def export_json(self, timeline: list[TimelineEvent]) -> str:
        """Serialize a timeline to a JSON string.

        Args:
            timeline: List of timeline events.

        Returns:
            Pretty-printed JSON string.
        """
        records: list[dict[str, Any]] = []
        for evt in timeline:
            records.append({
                "event_id": evt.event_id,
                "timestamp": evt.timestamp,
                "source_sensor": evt.source_sensor,
                "event_type": evt.event_type,
                "severity": evt.severity,
                "mitre_technique": evt.mitre_technique,
                "summary": evt.summary,
                "process_context": evt.process_context,
                "network_context": evt.network_context,
                "parent_event_id": evt.parent_event_id,
            })
        return json.dumps(records, indent=2)

    def export_html(self, timeline: list[TimelineEvent]) -> str:
        """Render the timeline as an HTML table.

        Args:
            timeline: List of timeline events.

        Returns:
            Self-contained HTML string with an inline-styled table.
        """
        severity_colors: dict[str, str] = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#6c757d",
        }

        rows: list[str] = []
        for evt in timeline:
            color = severity_colors.get(evt.severity, "#6c757d")
            mitre = html.escape(evt.mitre_technique or "—")
            summary = html.escape(evt.summary)
            parent = html.escape(evt.parent_event_id or "—")
            rows.append(
                f"<tr>"
                f"<td>{evt.timestamp:.3f}</td>"
                f"<td>{html.escape(evt.source_sensor)}</td>"
                f"<td>{html.escape(evt.event_type)}</td>"
                f'<td style="color:{color};font-weight:bold">'
                f"{html.escape(evt.severity)}</td>"
                f"<td><code>{mitre}</code></td>"
                f"<td>{summary}</td>"
                f"<td><code>{parent}</code></td>"
                f"</tr>",
            )

        table_rows = "\n".join(rows)
        return (
            "<!DOCTYPE html>\n"
            "<html><head><meta charset='utf-8'>"
            "<title>Aegis Attack Timeline</title>"
            "<style>"
            "body{font-family:sans-serif;margin:2em}"
            "table{border-collapse:collapse;width:100%}"
            "th,td{border:1px solid #ddd;padding:6px 10px;text-align:left}"
            "th{background:#343a40;color:#fff}"
            "tr:nth-child(even){background:#f8f9fa}"
            "</style></head><body>"
            "<h1>Aegis Attack Timeline</h1>"
            "<table>"
            "<thead><tr>"
            "<th>Timestamp</th><th>Sensor</th><th>Type</th>"
            "<th>Severity</th><th>MITRE</th>"
            "<th>Summary</th><th>Parent</th>"
            "</tr></thead>"
            f"<tbody>{table_rows}</tbody>"
            "</table></body></html>"
        )

    # -- private helpers ---------------------------------------------------

    def _convert(self, raw: dict[str, Any]) -> TimelineEvent:
        """Convert a single raw event dict to a TimelineEvent."""
        data: dict[str, Any] = raw.get("data", {})
        sensor: str = raw.get("sensor", "unknown")
        event_type: str = raw.get("event_type", "unknown")
        severity: str = raw.get("severity", "info")

        # Build context dicts
        process_ctx = self._extract_process_context(data) if sensor == "process" else None
        network_ctx = self._extract_network_context(data) if sensor == "network" else None

        # Infer MITRE technique
        mitre = self._infer_mitre(event_type, data)

        # Build summary
        summary = self._build_summary(sensor, event_type, data)

        return TimelineEvent(
            timestamp=float(raw.get("timestamp", 0)),
            source_sensor=sensor,
            event_type=event_type,
            severity=severity,
            mitre_technique=mitre,
            summary=summary,
            process_context=process_ctx,
            network_context=network_ctx,
        )

    @staticmethod
    def _extract_process_context(
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Pull process-relevant fields out of event data."""
        ctx: dict[str, Any] = {}
        for key in ("pid", "name", "parent_pid", "cmdline", "user"):
            if key in data:
                ctx[key] = data[key]
        return ctx

    @staticmethod
    def _extract_network_context(
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Pull network-relevant fields out of event data."""
        ctx: dict[str, Any] = {}
        for key in (
            "remote_ip", "remote_port", "local_port",
            "protocol", "direction", "domain",
        ):
            if key in data:
                ctx[key] = data[key]
        return ctx

    @staticmethod
    def _infer_mitre(
        event_type: str,
        data: dict[str, Any],
    ) -> str | None:
        """Best-effort MITRE ATT&CK technique inference."""
        # Check process name first
        name = data.get("name", "").lower()
        if name in _PROCESS_MITRE_MAP:
            return _PROCESS_MITRE_MAP[name]

        # Check event type mapping
        if event_type in _EVENT_TYPE_MITRE_MAP:
            return _EVENT_TYPE_MITRE_MAP[event_type]

        return None

    @staticmethod
    def _build_summary(
        sensor: str,
        event_type: str,
        data: dict[str, Any],
    ) -> str:
        """Create a human-readable summary line."""
        if sensor == "process" and event_type == "process_new":
            name = data.get("name", "unknown")
            pid = data.get("pid", "?")
            parent_pid = data.get("parent_pid")
            if parent_pid is not None:
                return (
                    f"{name} (pid={pid}) spawned by parent_pid={parent_pid}"
                )
            return f"{name} (pid={pid}) started"

        if sensor == "network" and event_type == "connection":
            ip = data.get("remote_ip", "?")
            port = data.get("remote_port", "?")
            return f"Connection to {ip}:{port}"

        if sensor == "network" and event_type == "dns_query":
            domain = data.get("domain", "?")
            return f"DNS query for {domain}"

        if sensor == "file":
            path = data.get("path", "?")
            return f"File {event_type}: {path}"

        # Generic fallback
        return f"{sensor}/{event_type}"

    @staticmethod
    def _link_causality(timeline: list[TimelineEvent]) -> None:
        """Set parent_event_id based on PID/parent_PID relationships.

        For every process event that has a ``parent_pid``, find the
        timeline event whose ``pid`` matches and set the parent link.
        """
        # Build PID -> event_id index from process events
        pid_to_event_id: dict[int, str] = {}
        for evt in timeline:
            if evt.process_context and "pid" in evt.process_context:
                pid_to_event_id[evt.process_context["pid"]] = evt.event_id

        # Link children to parents
        for evt in timeline:
            if evt.process_context and "parent_pid" in evt.process_context:
                parent_pid = evt.process_context["parent_pid"]
                parent_event_id = pid_to_event_id.get(parent_pid)
                if parent_event_id is not None:
                    evt.parent_event_id = parent_event_id
