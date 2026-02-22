"""Tests for the Alert Correlation Engine.

Validates alert-to-incident correlation by entity, MITRE chain,
and time proximity.  Also tests incident lifecycle, campaign
detection, severity escalation, and stale-incident pruning.
"""

from __future__ import annotations

import time
from uuid import uuid4

from aegis.alerting.correlation_engine import (
    Campaign,
    CorrelationEngine,
    Incident,
    IncidentStatus,
)
from aegis.core.models import Alert, SensorType, Severity


# ------------------------------------------------------------------ #
#  Helper
# ------------------------------------------------------------------ #

def _make_alert(**overrides: object) -> Alert:
    """Create an Alert with sensible defaults, overridable by kwargs."""
    defaults: dict[str, object] = {
        "event_id": f"evt-{uuid4().hex[:12]}",
        "sensor": SensorType.PROCESS,
        "alert_type": "test_alert",
        "severity": Severity.MEDIUM,
        "title": "Test Alert",
        "description": "Test",
        "confidence": 0.8,
        "data": {},
        "timestamp": time.time(),
    }
    defaults.update(overrides)
    return Alert(**defaults)  # type: ignore[arg-type]


# ------------------------------------------------------------------ #
#  TestCorrelationEngineInit
# ------------------------------------------------------------------ #

class TestCorrelationEngineInit:
    """Verify initial state of a newly-created CorrelationEngine."""

    def test_default_params(self) -> None:
        """Default time_window is 300 and min_alerts is 2."""
        engine = CorrelationEngine()
        assert engine._time_window == 300.0
        assert engine._min_alerts == 2

    def test_custom_params(self) -> None:
        """Custom time_window and min_alerts are stored correctly."""
        engine = CorrelationEngine(
            time_window=600.0, min_alerts_for_incident=5,
        )
        assert engine._time_window == 600.0
        assert engine._min_alerts == 5

    def test_no_incidents_initially(self) -> None:
        """A fresh engine has zero incidents."""
        engine = CorrelationEngine()
        assert engine.incident_count == 0
        assert engine.get_all_incidents() == []
        assert engine.get_active_incidents() == []


# ------------------------------------------------------------------ #
#  TestEntityCorrelation
# ------------------------------------------------------------------ #

class TestEntityCorrelation:
    """Alerts that share an entity within the time window are grouped."""

    def test_same_pid_grouped(self) -> None:
        """Two alerts sharing the same PID correlate."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(data={"pid": 1234}, timestamp=now)
        a2 = _make_alert(data={"pid": 1234}, timestamp=now + 1)

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None
        assert inc2 is not None
        assert inc1.incident_id == inc2.incident_id
        assert inc1.alert_count == 2
        assert "pid:1234" in inc1.entities

    def test_same_ip_grouped(self) -> None:
        """Two alerts sharing the same destination IP correlate."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            data={"dst_ip": "10.0.0.5"}, timestamp=now,
        )
        a2 = _make_alert(
            data={"dst_ip": "10.0.0.5"}, timestamp=now + 1,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        assert inc1.incident_id == inc2.incident_id
        assert "ip:10.0.0.5" in inc1.entities

    def test_same_file_path_grouped(self) -> None:
        """Two alerts sharing the same file path correlate."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            data={"path": "C:\\malware.exe"}, timestamp=now,
        )
        a2 = _make_alert(
            data={"file_path": "C:\\malware.exe"}, timestamp=now + 1,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        assert inc1.incident_id == inc2.incident_id
        assert "file:C:\\malware.exe" in inc1.entities

    def test_same_domain_grouped(self) -> None:
        """Two alerts sharing the same domain correlate."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            data={"domain": "evil.com"}, timestamp=now,
        )
        a2 = _make_alert(
            data={"query_name": "evil.com"}, timestamp=now + 1,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        assert inc1.incident_id == inc2.incident_id
        assert "domain:evil.com" in inc1.entities

    def test_different_entities_create_separate_incidents(self) -> None:
        """Alerts with completely different entities are not grouped."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            data={"pid": 100},
            sensor=SensorType.FILE,
            timestamp=now,
        )
        a2 = _make_alert(
            data={"pid": 999},
            sensor=SensorType.NETWORK,
            timestamp=now + 1,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        assert inc1.incident_id != inc2.incident_id
        assert engine.incident_count == 2

    def test_entity_extracted_from_various_ip_keys(self) -> None:
        """IP entities are extracted from src_ip, remote_addr, etc."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            data={"src_ip": "192.168.1.1"}, timestamp=now,
        )
        a2 = _make_alert(
            data={"remote_addr": "192.168.1.1"},
            timestamp=now + 1,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        assert inc1.incident_id == inc2.incident_id
        assert "ip:192.168.1.1" in inc1.entities

    def test_entity_correlation_respects_time_window(self) -> None:
        """Entity match is ignored if the incident is outside window."""
        engine = CorrelationEngine(time_window=300.0)
        now = time.time()
        a1 = _make_alert(
            data={"pid": 42}, timestamp=now - 400,
        )
        a2 = _make_alert(
            data={"pid": 42},
            sensor=SensorType.NETWORK,
            timestamp=now,
        )

        engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        # Second alert cannot entity-match because the incident is
        # stale (last_seen 400s ago > 300s window).  It may still
        # match by time proximity if same sensor, but we used
        # different sensors so it should create a new incident.
        assert inc2 is not None
        assert engine.incident_count == 2

    def test_no_entities_means_no_entity_correlation(self) -> None:
        """Alerts with empty data dicts do not entity-correlate."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            data={}, sensor=SensorType.FILE, timestamp=now,
        )
        a2 = _make_alert(
            data={}, sensor=SensorType.NETWORK, timestamp=now + 1,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        # Different sensors, no entities -- separate incidents
        assert inc1.incident_id != inc2.incident_id


# ------------------------------------------------------------------ #
#  TestMitreChainCorrelation
# ------------------------------------------------------------------ #

class TestMitreChainCorrelation:
    """MITRE kill-chain progression groups alerts."""

    def test_new_tactic_added_to_existing_incident(self) -> None:
        """Alert with a new tactic joins an existing incident."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            mitre_ids=["T1059"],      # execution
            sensor=SensorType.FILE,
            data={},
            timestamp=now,
        )
        a2 = _make_alert(
            mitre_ids=["T1547"],      # persistence (new tactic)
            sensor=SensorType.NETWORK,
            data={},
            timestamp=now + 1,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        assert inc1.incident_id == inc2.incident_id
        assert "T1059" in inc1.mitre_chain
        assert "T1547" in inc1.mitre_chain

    def test_same_tactic_not_chain_correlated(self) -> None:
        """Alert with an already-seen tactic does not MITRE-chain match.

        It may still correlate via time proximity if same sensor.
        """
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            mitre_ids=["T1059"],      # execution
            sensor=SensorType.FILE,
            data={},
            timestamp=now,
        )
        a2 = _make_alert(
            mitre_ids=["T1059.001"],  # also execution -- same tactic
            sensor=SensorType.NETWORK,
            data={},
            timestamp=now + 1,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        # Same tactic, different sensor, no entity overlap:
        # no MITRE chain correlation, no time proximity
        assert inc1.incident_id != inc2.incident_id

    def test_chain_tracks_technique_ids(self) -> None:
        """Incident mitre_chain accumulates technique IDs."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            mitre_ids=["T1190"],      # initial-access
            sensor=SensorType.FILE,
            data={},
            timestamp=now,
        )
        a2 = _make_alert(
            mitre_ids=["T1059"],      # execution
            sensor=SensorType.NETWORK,
            data={},
            timestamp=now + 1,
        )
        a3 = _make_alert(
            mitre_ids=["T1048"],      # exfiltration
            sensor=SensorType.EVENTLOG,
            data={},
            timestamp=now + 2,
        )

        inc = engine.ingest_alert(a1)
        engine.ingest_alert(a2)
        engine.ingest_alert(a3)

        assert inc is not None
        assert inc.alert_count == 3
        assert "T1190" in inc.mitre_chain
        assert "T1059" in inc.mitre_chain
        assert "T1048" in inc.mitre_chain

    def test_alerts_without_mitre_ids_skip_chain(self) -> None:
        """Alerts without mitre_ids bypass MITRE chain correlation."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            mitre_ids=["T1059"],
            sensor=SensorType.FILE,
            data={},
            timestamp=now,
        )
        a2 = _make_alert(
            mitre_ids=[],
            sensor=SensorType.NETWORK,
            data={},
            timestamp=now + 1,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        # No MITRE match, no entity, different sensor -> separate
        assert inc1.incident_id != inc2.incident_id

    def test_multiple_techniques_in_single_alert(self) -> None:
        """An alert carrying multiple technique IDs all get recorded."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            mitre_ids=["T1190", "T1059", "T1048"],
            data={},
            timestamp=now,
        )

        inc = engine.ingest_alert(a1)

        assert inc is not None
        assert "T1190" in inc.mitre_chain
        assert "T1059" in inc.mitre_chain
        assert "T1048" in inc.mitre_chain

    def test_mitre_chain_new_tactic_across_three_alerts(self) -> None:
        """Three alerts each adding a new tactic all join one inc."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            mitre_ids=["T1190"],       # initial-access
            sensor=SensorType.FILE,
            data={},
            timestamp=now,
        )
        a2 = _make_alert(
            mitre_ids=["T1547"],       # persistence
            sensor=SensorType.NETWORK,
            data={},
            timestamp=now + 1,
        )
        a3 = _make_alert(
            mitre_ids=["T1486"],       # impact
            sensor=SensorType.EVENTLOG,
            data={},
            timestamp=now + 2,
        )

        inc = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)
        inc3 = engine.ingest_alert(a3)

        assert inc is not None
        assert inc2 is not None and inc3 is not None
        assert inc.incident_id == inc2.incident_id == inc3.incident_id
        assert inc.alert_count == 3


# ------------------------------------------------------------------ #
#  TestTimeProximityCorrelation
# ------------------------------------------------------------------ #

class TestTimeProximityCorrelation:
    """Same-sensor alerts within time window group together."""

    def test_same_sensor_within_window_grouped(self) -> None:
        """Two PROCESS alerts within 300s share an incident."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            sensor=SensorType.PROCESS, data={}, timestamp=now,
        )
        a2 = _make_alert(
            sensor=SensorType.PROCESS, data={}, timestamp=now + 10,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        assert inc1.incident_id == inc2.incident_id
        assert inc1.alert_count == 2

    def test_different_sensors_not_grouped(self) -> None:
        """PROCESS and NETWORK alerts are not time-proximity grouped."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            sensor=SensorType.PROCESS, data={}, timestamp=now,
        )
        a2 = _make_alert(
            sensor=SensorType.NETWORK, data={}, timestamp=now + 1,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        assert inc1.incident_id != inc2.incident_id

    def test_outside_time_window_not_grouped(self) -> None:
        """Same-sensor alerts >window apart are separate."""
        engine = CorrelationEngine(time_window=300.0)
        now = time.time()
        a1 = _make_alert(
            sensor=SensorType.PROCESS,
            data={},
            timestamp=now - 400,
        )
        a2 = _make_alert(
            sensor=SensorType.PROCESS,
            data={},
            timestamp=now,
        )

        engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc2 is not None
        assert engine.incident_count == 2

    def test_timestamp_based_calculation(self) -> None:
        """Time proximity uses alert timestamps, not wall clock."""
        engine = CorrelationEngine(time_window=100.0)
        now = time.time()
        a1 = _make_alert(
            sensor=SensorType.FILE, data={}, timestamp=now,
        )
        a2 = _make_alert(
            sensor=SensorType.FILE, data={}, timestamp=now + 50,
        )
        a3 = _make_alert(
            sensor=SensorType.FILE, data={}, timestamp=now + 200,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)
        inc3 = engine.ingest_alert(a3)

        assert inc1 is not None and inc2 is not None
        assert inc1.incident_id == inc2.incident_id
        # a3 is 150s after a2 (last alert in inc1) -- exceeds 100s
        assert inc3 is not None
        assert inc3.incident_id != inc1.incident_id

    def test_time_proximity_only_checks_last_alert(self) -> None:
        """Proximity compares against the last alert in the incident."""
        engine = CorrelationEngine(time_window=60.0)
        now = time.time()
        a1 = _make_alert(
            sensor=SensorType.PROCESS, data={},
            timestamp=now,
        )
        a2 = _make_alert(
            sensor=SensorType.PROCESS, data={},
            timestamp=now + 30,
        )
        a3 = _make_alert(
            sensor=SensorType.PROCESS, data={},
            timestamp=now + 80,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)
        inc3 = engine.ingest_alert(a3)

        # a3 is 80s from a1 but only 50s from a2 (the last alert)
        assert inc1 is not None
        assert inc2 is not None and inc3 is not None
        assert (
            inc1.incident_id
            == inc2.incident_id
            == inc3.incident_id
        )


# ------------------------------------------------------------------ #
#  TestIncidentLifecycle
# ------------------------------------------------------------------ #

class TestIncidentLifecycle:
    """Incident creation, update, retrieval, and closure."""

    def test_ingest_creates_incident(self) -> None:
        """Ingesting one alert creates a new incident."""
        engine = CorrelationEngine()
        alert = _make_alert()
        inc = engine.ingest_alert(alert)

        assert inc is not None
        assert inc.alert_count == 1
        assert engine.incident_count == 1

    def test_second_alert_adds_to_incident(self) -> None:
        """A correlated alert is added to the existing incident."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(data={"pid": 77}, timestamp=now)
        a2 = _make_alert(data={"pid": 77}, timestamp=now + 1)

        inc = engine.ingest_alert(a1)
        engine.ingest_alert(a2)

        assert inc is not None
        assert inc.alert_count == 2

    def test_severity_escalates(self) -> None:
        """Incident severity escalates to the max of its alerts."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            severity=Severity.LOW,
            data={"pid": 10},
            timestamp=now,
        )
        a2 = _make_alert(
            severity=Severity.HIGH,
            data={"pid": 10},
            timestamp=now + 1,
        )

        inc = engine.ingest_alert(a1)
        engine.ingest_alert(a2)

        assert inc is not None
        assert inc.severity == Severity.HIGH

    def test_title_updates_for_multi_alert(self) -> None:
        """Title changes once an incident has >= 2 alerts."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            title="First Alert",
            data={"pid": 88},
            timestamp=now,
        )
        inc = engine.ingest_alert(a1)
        assert inc is not None
        assert inc.title == "Incident: First Alert"

        a2 = _make_alert(
            title="Second Alert",
            data={"pid": 88},
            timestamp=now + 1,
        )
        engine.ingest_alert(a2)
        assert inc.title == "Incident: 2 related alerts"

    def test_get_incident_by_id(self) -> None:
        """get_incident returns the correct incident by ID."""
        engine = CorrelationEngine()
        alert = _make_alert()
        inc = engine.ingest_alert(alert)

        assert inc is not None
        fetched = engine.get_incident(inc.incident_id)
        assert fetched is inc

    def test_get_active_incidents_filters_open(self) -> None:
        """get_active_incidents only returns OPEN incidents."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            data={"pid": 1}, sensor=SensorType.FILE,
            timestamp=now,
        )
        a2 = _make_alert(
            data={"pid": 2}, sensor=SensorType.NETWORK,
            timestamp=now + 1,
        )

        inc1 = engine.ingest_alert(a1)
        inc2 = engine.ingest_alert(a2)

        assert inc1 is not None and inc2 is not None
        engine.close_incident(inc1.incident_id)

        active = engine.get_active_incidents()
        ids = [i.incident_id for i in active]
        assert inc1.incident_id not in ids
        assert inc2.incident_id in ids

    def test_close_incident(self) -> None:
        """Closing an open incident sets status to CLOSED."""
        engine = CorrelationEngine()
        inc = engine.ingest_alert(_make_alert())
        assert inc is not None

        result = engine.close_incident(inc.incident_id)
        assert result is True
        assert inc.status == IncidentStatus.CLOSED

    def test_close_already_closed_returns_false(self) -> None:
        """Closing an already-closed incident returns False."""
        engine = CorrelationEngine()
        inc = engine.ingest_alert(_make_alert())
        assert inc is not None

        engine.close_incident(inc.incident_id)
        result = engine.close_incident(inc.incident_id)
        assert result is False


# ------------------------------------------------------------------ #
#  TestCampaignDetection
# ------------------------------------------------------------------ #

class TestCampaignDetection:
    """Campaign detection links closed incidents by shared IOCs."""

    def _ingest_and_close(
        self,
        engine: CorrelationEngine,
        data: dict[str, object],
        sensor: SensorType = SensorType.FILE,
        timestamp: float | None = None,
    ) -> Incident:
        """Helper: ingest a single alert and close its incident."""
        ts = timestamp if timestamp is not None else time.time()
        alert = _make_alert(
            data=data, sensor=sensor, timestamp=ts,
        )
        inc = engine.ingest_alert(alert)
        assert inc is not None
        engine.close_incident(inc.incident_id)
        return inc

    def test_shared_entities_form_campaign(self) -> None:
        """Two closed incidents sharing an entity form a campaign."""
        engine = CorrelationEngine()
        now = time.time()
        # Two incidents that share the same IP entity
        inc1 = self._ingest_and_close(
            engine,
            data={"dst_ip": "10.0.0.99"},
            sensor=SensorType.FILE,
            timestamp=now,
        )
        inc2 = self._ingest_and_close(
            engine,
            data={"dst_ip": "10.0.0.99"},
            sensor=SensorType.NETWORK,
            timestamp=now + 1,
        )

        campaigns = engine.detect_campaigns()
        assert len(campaigns) == 1
        camp_ids = [
            i.incident_id for i in campaigns[0].incidents
        ]
        assert inc1.incident_id in camp_ids
        assert inc2.incident_id in camp_ids

    def test_no_campaigns_with_single_incident(self) -> None:
        """A single closed incident cannot form a campaign."""
        engine = CorrelationEngine()
        self._ingest_and_close(
            engine, data={"pid": 1}, sensor=SensorType.FILE,
        )

        campaigns = engine.detect_campaigns()
        assert campaigns == []

    def test_campaigns_have_shared_iocs(self) -> None:
        """Campaign shared_iocs contains the overlapping entities."""
        engine = CorrelationEngine()
        now = time.time()
        self._ingest_and_close(
            engine,
            data={"domain": "c2.evil.com"},
            sensor=SensorType.FILE,
            timestamp=now,
        )
        self._ingest_and_close(
            engine,
            data={"domain": "c2.evil.com"},
            sensor=SensorType.NETWORK,
            timestamp=now + 1,
        )

        campaigns = engine.detect_campaigns()
        assert len(campaigns) == 1
        assert "domain:c2.evil.com" in campaigns[0].shared_iocs

    def test_no_overlap_means_no_campaign(self) -> None:
        """Closed incidents without shared entities form no campaign."""
        engine = CorrelationEngine()
        now = time.time()
        self._ingest_and_close(
            engine,
            data={"pid": 111},
            sensor=SensorType.FILE,
            timestamp=now,
        )
        self._ingest_and_close(
            engine,
            data={"pid": 222},
            sensor=SensorType.NETWORK,
            timestamp=now + 1,
        )

        campaigns = engine.detect_campaigns()
        assert campaigns == []

    def test_campaign_timestamps(self) -> None:
        """Campaign first/last_seen span the incidents' timestamps."""
        engine = CorrelationEngine()
        t1, t2 = 1000000.0, 1000500.0
        self._ingest_and_close(
            engine,
            data={"dst_ip": "1.2.3.4"},
            sensor=SensorType.FILE,
            timestamp=t1,
        )
        self._ingest_and_close(
            engine,
            data={"dst_ip": "1.2.3.4"},
            sensor=SensorType.NETWORK,
            timestamp=t2,
        )

        campaigns = engine.detect_campaigns()
        assert len(campaigns) == 1
        camp = campaigns[0]
        assert camp.first_seen == t1
        assert camp.last_seen == t2

    def test_detect_campaigns_returns_list(self) -> None:
        """detect_campaigns always returns a list."""
        engine = CorrelationEngine()
        result = engine.detect_campaigns()
        assert isinstance(result, list)


# ------------------------------------------------------------------ #
#  TestIncidentSeverityEscalation
# ------------------------------------------------------------------ #

class TestIncidentSeverityEscalation:
    """Severity of an incident reflects the max of its alerts."""

    def test_low_then_high_escalates(self) -> None:
        """LOW followed by HIGH escalates incident to HIGH."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            severity=Severity.LOW,
            data={"pid": 50},
            timestamp=now,
        )
        a2 = _make_alert(
            severity=Severity.HIGH,
            data={"pid": 50},
            timestamp=now + 1,
        )

        inc = engine.ingest_alert(a1)
        engine.ingest_alert(a2)

        assert inc is not None
        assert inc.severity == Severity.HIGH

    def test_high_then_low_stays_high(self) -> None:
        """HIGH followed by LOW keeps incident at HIGH."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            severity=Severity.HIGH,
            data={"pid": 60},
            timestamp=now,
        )
        a2 = _make_alert(
            severity=Severity.LOW,
            data={"pid": 60},
            timestamp=now + 1,
        )

        inc = engine.ingest_alert(a1)
        engine.ingest_alert(a2)

        assert inc is not None
        assert inc.severity == Severity.HIGH

    def test_critical_overrides_all(self) -> None:
        """CRITICAL alert always becomes the incident severity."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            severity=Severity.HIGH,
            data={"pid": 70},
            timestamp=now,
        )
        a2 = _make_alert(
            severity=Severity.CRITICAL,
            data={"pid": 70},
            timestamp=now + 1,
        )

        inc = engine.ingest_alert(a1)
        engine.ingest_alert(a2)

        assert inc is not None
        assert inc.severity == Severity.CRITICAL

    def test_severity_reflects_max_alert(self) -> None:
        """Mixed severities resolve to the maximum weight."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            severity=Severity.INFO,
            data={"pid": 80},
            timestamp=now,
        )
        a2 = _make_alert(
            severity=Severity.MEDIUM,
            data={"pid": 80},
            timestamp=now + 1,
        )
        a3 = _make_alert(
            severity=Severity.LOW,
            data={"pid": 80},
            timestamp=now + 2,
        )

        inc = engine.ingest_alert(a1)
        engine.ingest_alert(a2)
        engine.ingest_alert(a3)

        assert inc is not None
        assert inc.severity == Severity.MEDIUM


# ------------------------------------------------------------------ #
#  TestPruning
# ------------------------------------------------------------------ #

class TestPruning:
    """Stale incident pruning closes old open incidents."""

    def test_stale_open_incidents_closed(self) -> None:
        """Incidents older than max_age are closed by prune."""
        engine = CorrelationEngine()
        old = time.time() - 3600
        a = _make_alert(data={"pid": 1}, timestamp=old)
        inc = engine.ingest_alert(a)

        assert inc is not None
        assert inc.status == IncidentStatus.OPEN

        pruned = engine.prune_stale_incidents(max_age=1800)
        assert pruned == 1
        assert inc.status == IncidentStatus.CLOSED

    def test_recent_incidents_kept(self) -> None:
        """Incidents within max_age remain open."""
        engine = CorrelationEngine()
        now = time.time()
        a = _make_alert(data={"pid": 2}, timestamp=now)
        inc = engine.ingest_alert(a)

        pruned = engine.prune_stale_incidents(max_age=1800)
        assert pruned == 0
        assert inc is not None
        assert inc.status == IncidentStatus.OPEN

    def test_already_closed_not_affected(self) -> None:
        """Already-closed incidents are not counted as pruned."""
        engine = CorrelationEngine()
        old = time.time() - 3600
        a = _make_alert(data={"pid": 3}, timestamp=old)
        inc = engine.ingest_alert(a)

        assert inc is not None
        engine.close_incident(inc.incident_id)

        pruned = engine.prune_stale_incidents(max_age=1800)
        assert pruned == 0

    def test_max_age_parameter(self) -> None:
        """Different max_age values prune different incidents."""
        engine = CorrelationEngine()
        now = time.time()
        a1 = _make_alert(
            data={"pid": 10},
            sensor=SensorType.FILE,
            timestamp=now - 500,
        )
        a2 = _make_alert(
            data={"pid": 20},
            sensor=SensorType.NETWORK,
            timestamp=now - 100,
        )

        engine.ingest_alert(a1)
        engine.ingest_alert(a2)

        # max_age=200 should prune only a1's incident (500s old)
        pruned = engine.prune_stale_incidents(max_age=200)
        assert pruned == 1

    def test_returns_count_pruned(self) -> None:
        """prune_stale_incidents returns the number closed."""
        engine = CorrelationEngine()
        old = time.time() - 7200
        for i in range(5):
            a = _make_alert(
                data={"pid": 900 + i},
                sensor=SensorType(
                    ["process", "network", "file",
                     "eventlog", "registry"][i]
                ),
                timestamp=old + i,
            )
            engine.ingest_alert(a)

        pruned = engine.prune_stale_incidents(max_age=3600)
        assert pruned == 5
        assert len(engine.get_active_incidents()) == 0
