"""Tests for attack timeline reconstruction."""
from __future__ import annotations

from aegis.forensics.timeline_engine import (
    TimelineEngine,
    TimelineEvent,
)


class TestTimelineEvent:
    def test_creation(self) -> None:
        evt = TimelineEvent(
            timestamp=1000.0,
            source_sensor="process",
            event_type="process_new",
            severity="high",
            mitre_technique="T1059",
            summary="powershell.exe spawned by winword.exe",
            process_context={"pid": 1234, "name": "powershell.exe"},
            parent_event_id=None,
        )
        assert evt.mitre_technique == "T1059"


class TestTimelineEngine:
    def test_build_timeline_from_events(self) -> None:
        engine = TimelineEngine()
        events = [
            {"timestamp": 1000, "sensor": "process",
             "event_type": "process_new", "severity": "medium",
             "data": {"name": "cmd.exe", "pid": 1}},
            {"timestamp": 1001, "sensor": "network",
             "event_type": "connection", "severity": "high",
             "data": {"remote_ip": "10.0.0.1"}},
        ]
        timeline = engine.build(events)
        assert len(timeline) == 2
        assert timeline[0].timestamp <= timeline[1].timestamp

    def test_causality_linking(self) -> None:
        engine = TimelineEngine()
        events = [
            {"timestamp": 1000, "sensor": "process",
             "event_type": "process_new", "severity": "medium",
             "data": {"name": "powershell.exe", "pid": 100,
                      "parent_pid": 50}},
            {"timestamp": 999, "sensor": "process",
             "event_type": "process_new", "severity": "low",
             "data": {"name": "winword.exe", "pid": 50}},
        ]
        timeline = engine.build(events)
        # powershell should link to winword as parent
        ps_event = [e for e in timeline if "powershell" in e.summary][0]
        assert ps_event.parent_event_id is not None

    def test_empty_events(self) -> None:
        engine = TimelineEngine()
        timeline = engine.build([])
        assert timeline == []
