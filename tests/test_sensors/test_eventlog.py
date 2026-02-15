"""Tests for the EventLog Analyzer sensor."""

import base64
import time

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.eventlog import (
    ALL_MONITORED_IDS,
    ATTACK_CHAIN_PATTERNS,
    BRUTE_FORCE_THRESHOLD,
    EVENT_SEVERITY,
    EVTID_EXPLICIT_CREDENTIAL,
    EVTID_FAILED_LOGIN,
    EVTID_GROUP_MEMBER_ADDED,
    EVTID_NEW_PROCESS,
    EVTID_NEW_SERVICE,
    EVTID_POWERSHELL_SCRIPTBLOCK,
    EVTID_SPECIAL_PRIVILEGES,
    EVTID_USER_CREATED,
    MITRE_MAPPING,
    POWERSHELL_EVENT_IDS,
    SECURITY_EVENT_IDS,
    SYSTEM_EVENT_IDS,
    EventLogSensor,
    _RawEvent,
    _StubEventGenerator,
    detect_encoded_powershell,
    find_attack_chains,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_raw(
    event_id: int,
    *,
    timestamp: float | None = None,
    message: str = "",
    source: str = "test",
    log_name: str = "Security",
    computer: str = "TEST-PC",
) -> _RawEvent:
    """Create a _RawEvent with sensible defaults for testing."""
    return _RawEvent(
        event_id=event_id,
        source=source,
        log_name=log_name,
        timestamp=timestamp if timestamp is not None else time.time(),
        computer=computer,
        message=message,
    )


def _encode_utf16le(text: str) -> str:
    """Base64-encode *text* as UTF-16LE (how PowerShell -enc works)."""
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


# ===========================================================================
# Encoded PowerShell Detection
# ===========================================================================
class TestEncodedPowerShellDetection:
    """Tests for detect_encoded_powershell()."""

    def test_detects_enc_flag(self) -> None:
        encoded = _encode_utf16le("Write-Host hello")
        msg = f"powershell.exe -enc {encoded}"
        result = detect_encoded_powershell(msg)
        assert result is not None
        assert "Write-Host hello" in result

    def test_detects_encodedcommand_flag(self) -> None:
        encoded = _encode_utf16le("Get-Process")
        msg = f"powershell.exe -encodedcommand {encoded}"
        result = detect_encoded_powershell(msg)
        assert result is not None
        assert "Get-Process" in result

    def test_returns_none_for_normal_command(self) -> None:
        msg = "powershell.exe Get-Process"
        result = detect_encoded_powershell(msg)
        assert result is None

    def test_decodes_utf16le(self) -> None:
        original = "Invoke-Expression $env:TEMP"
        encoded = _encode_utf16le(original)
        msg = f"powershell -e {encoded}"
        result = detect_encoded_powershell(msg)
        assert result is not None
        assert original in result

    def test_returns_none_for_empty_string(self) -> None:
        assert detect_encoded_powershell("") is None

    def test_returns_none_for_short_base64(self) -> None:
        # The regex requires at least 20 base64 chars; a very short payload
        # should not match.
        msg = "powershell -enc AQID"
        assert detect_encoded_powershell(msg) is None

    def test_case_insensitive_flag(self) -> None:
        encoded = _encode_utf16le("Get-ChildItem")
        msg = f"powershell.exe -EncodedCommand {encoded}"
        result = detect_encoded_powershell(msg)
        assert result is not None
        assert "Get-ChildItem" in result


# ===========================================================================
# Attack Chain Detection
# ===========================================================================
class TestAttackChainDetection:
    """Tests for find_attack_chains()."""

    def test_empty_events_returns_empty(self) -> None:
        assert find_attack_chains([]) == []

    def test_credential_attack_chain(self) -> None:
        now = time.time()
        events = [
            _make_raw(EVTID_FAILED_LOGIN, timestamp=now),
            _make_raw(EVTID_FAILED_LOGIN, timestamp=now + 1),
            _make_raw(EVTID_SPECIAL_PRIVILEGES, timestamp=now + 2),
        ]
        chains = find_attack_chains(events)
        names = [c["chain_name"] for c in chains]
        assert "credential_attack" in names
        chain = next(c for c in chains if c["chain_name"] == "credential_attack")
        assert chain["severity"] == Severity.CRITICAL.value
        assert chain["event_ids_matched"] == [
            EVTID_FAILED_LOGIN,
            EVTID_FAILED_LOGIN,
            EVTID_SPECIAL_PRIVILEGES,
        ]

    def test_persistence_install_chain(self) -> None:
        now = time.time()
        events = [
            _make_raw(EVTID_NEW_PROCESS, timestamp=now),
            _make_raw(EVTID_NEW_SERVICE, timestamp=now + 5),
        ]
        chains = find_attack_chains(events)
        names = [c["chain_name"] for c in chains]
        assert "persistence_install" in names

    def test_lateral_movement_chain(self) -> None:
        now = time.time()
        events = [
            _make_raw(EVTID_USER_CREATED, timestamp=now),
            _make_raw(EVTID_GROUP_MEMBER_ADDED, timestamp=now + 3),
        ]
        chains = find_attack_chains(events)
        names = [c["chain_name"] for c in chains]
        assert "lateral_movement_prep" in names

    def test_chain_outside_window_not_detected(self) -> None:
        now = time.time()
        events = [
            _make_raw(EVTID_FAILED_LOGIN, timestamp=now),
            _make_raw(EVTID_FAILED_LOGIN, timestamp=now + 1),
            # Third event is >300 s after the first — outside the default window
            _make_raw(EVTID_SPECIAL_PRIVILEGES, timestamp=now + 400),
        ]
        chains = find_attack_chains(events)
        cred_chains = [c for c in chains if c["chain_name"] == "credential_attack"]
        assert len(cred_chains) == 0

    def test_chain_has_mitre_ids(self) -> None:
        now = time.time()
        events = [
            _make_raw(EVTID_NEW_PROCESS, timestamp=now),
            _make_raw(EVTID_NEW_SERVICE, timestamp=now + 2),
        ]
        chains = find_attack_chains(events)
        chain = next(c for c in chains if c["chain_name"] == "persistence_install")
        assert isinstance(chain["mitre_ids"], list)
        assert len(chain["mitre_ids"]) > 0

    def test_custom_window_seconds(self) -> None:
        now = time.time()
        events = [
            _make_raw(EVTID_USER_CREATED, timestamp=now),
            _make_raw(EVTID_GROUP_MEMBER_ADDED, timestamp=now + 50),
        ]
        # Within default 300 s — detected
        assert len(find_attack_chains(events, window_seconds=300.0)) > 0
        # Narrower window — NOT detected
        assert all(
            c["chain_name"] != "lateral_movement_prep"
            for c in find_attack_chains(events, window_seconds=10.0)
        )


# ===========================================================================
# Event ID Constants
# ===========================================================================
class TestEventIdConstants:
    """Tests for module-level constant sets and mappings."""

    def test_all_monitored_ids_is_union(self) -> None:
        expected = SECURITY_EVENT_IDS | SYSTEM_EVENT_IDS | POWERSHELL_EVENT_IDS
        assert ALL_MONITORED_IDS == expected

    def test_mitre_mapping_covers_key_events(self) -> None:
        key_ids = {
            EVTID_FAILED_LOGIN,
            EVTID_NEW_SERVICE,
            EVTID_POWERSHELL_SCRIPTBLOCK,
            EVTID_SPECIAL_PRIVILEGES,
            EVTID_USER_CREATED,
            EVTID_NEW_PROCESS,
        }
        for eid in key_ids:
            assert eid in MITRE_MAPPING, f"MITRE_MAPPING missing event {eid}"
            technique_id, technique_name = MITRE_MAPPING[eid]
            assert technique_id.startswith("T")
            assert len(technique_name) > 0

    def test_severity_defined_for_all_monitored_ids(self) -> None:
        for eid in ALL_MONITORED_IDS:
            assert eid in EVENT_SEVERITY, (
                f"EVENT_SEVERITY missing event ID {eid}"
            )
            assert isinstance(EVENT_SEVERITY[eid], Severity)

    def test_brute_force_threshold_is_positive(self) -> None:
        assert BRUTE_FORCE_THRESHOLD > 0

    def test_security_event_ids_are_ints(self) -> None:
        for eid in SECURITY_EVENT_IDS:
            assert isinstance(eid, int)

    def test_system_event_ids_are_ints(self) -> None:
        for eid in SYSTEM_EVENT_IDS:
            assert isinstance(eid, int)

    def test_attack_chain_patterns_well_formed(self) -> None:
        for name, (pattern, desc, severity) in ATTACK_CHAIN_PATTERNS.items():
            assert isinstance(name, str) and len(name) > 0
            assert isinstance(pattern, list) and len(pattern) >= 2
            assert isinstance(desc, str) and len(desc) > 0
            assert isinstance(severity, Severity)


# ===========================================================================
# Stub Event Generator
# ===========================================================================
class TestStubEventGenerator:
    """Tests for _StubEventGenerator."""

    def test_generates_events(self) -> None:
        gen = _StubEventGenerator()
        events = gen.generate()
        assert isinstance(events, list)
        assert len(events) > 0
        for evt in events:
            assert isinstance(evt, _RawEvent)

    def test_generates_failed_logins_periodically(self) -> None:
        gen = _StubEventGenerator()
        gen.generate()  # call 1
        gen.generate()  # call 2
        events3 = gen.generate()  # call 3 — should inject failed logins
        failed = [e for e in events3 if e.event_id == EVTID_FAILED_LOGIN]
        assert len(failed) > 0, "3rd call should contain failed login events"

    def test_generates_encoded_powershell_periodically(self) -> None:
        gen = _StubEventGenerator()
        for _ in range(4):
            gen.generate()
        events5 = gen.generate()  # call 5 — should inject encoded PS
        ps_events = [
            e for e in events5
            if e.event_id == EVTID_POWERSHELL_SCRIPTBLOCK
        ]
        assert len(ps_events) > 0, "5th call should contain PS scriptblock event"
        # The message should contain an encoded command
        for ps in ps_events:
            assert "-enc" in ps.message.lower() or "-encodedcommand" in ps.message.lower()

    def test_generates_new_service_periodically(self) -> None:
        gen = _StubEventGenerator()
        for _ in range(6):
            gen.generate()
        events7 = gen.generate()  # call 7 — should inject new service
        svc_events = [e for e in events7 if e.event_id == EVTID_NEW_SERVICE]
        assert len(svc_events) > 0, "7th call should contain a new-service event"

    def test_call_count_increments(self) -> None:
        gen = _StubEventGenerator()
        assert gen._call_count == 0
        gen.generate()
        assert gen._call_count == 1
        gen.generate()
        assert gen._call_count == 2

    def test_events_have_valid_timestamps(self) -> None:
        gen = _StubEventGenerator()
        before = time.time()
        events = gen.generate()
        after = time.time()
        for evt in events:
            # Timestamp should be at most ~15 s before "now"
            assert evt.timestamp >= before - 15
            assert evt.timestamp <= after + 1


# ===========================================================================
# EventLogSensor Init
# ===========================================================================
class TestEventLogSensorInit:
    """Tests for EventLogSensor construction and properties."""

    def test_sensor_type(self) -> None:
        sensor = EventLogSensor(interval=999)
        assert sensor.sensor_type == SensorType.EVENTLOG

    def test_sensor_name(self) -> None:
        sensor = EventLogSensor(interval=999)
        assert sensor.sensor_name == "eventlog_analyzer"

    def test_default_interval_15(self) -> None:
        sensor = EventLogSensor()
        assert sensor._interval == 15.0

    def test_custom_interval(self) -> None:
        sensor = EventLogSensor(interval=42.0)
        assert sensor._interval == 42.0

    def test_server_defaults_to_none(self) -> None:
        sensor = EventLogSensor()
        assert sensor._server is None

    def test_server_can_be_set(self) -> None:
        sensor = EventLogSensor(server="REMOTE-DC")
        assert sensor._server == "REMOTE-DC"


# ===========================================================================
# EventLogSensor Collect
# ===========================================================================
class TestEventLogSensorCollect:
    """Tests for EventLogSensor.setup() and .collect()."""

    def test_setup_initializes_stub_mode(self) -> None:
        sensor = EventLogSensor(interval=999)
        sensor.setup()
        try:
            # Without pywin32, stub should be set
            assert sensor._stub is not None
            assert isinstance(sensor._stub, _StubEventGenerator)
        finally:
            sensor.teardown()

    def test_teardown_clears_stub(self) -> None:
        sensor = EventLogSensor(interval=999)
        sensor.setup()
        sensor.teardown()
        assert sensor._stub is None

    def test_collect_returns_events(self) -> None:
        sensor = EventLogSensor(interval=999)
        sensor.setup()
        try:
            events = sensor.collect()
            assert isinstance(events, list)
            assert len(events) > 0
            for event in events:
                assert isinstance(event, AegisEvent)
                assert event.sensor == SensorType.EVENTLOG

            # Should have at least: security events + snapshot
            snapshot_events = [
                e for e in events if e.event_type == "eventlog_snapshot"
            ]
            security_events = [
                e for e in events if e.event_type == "security_event"
            ]
            assert len(snapshot_events) == 1
            assert len(security_events) >= 1
        finally:
            sensor.teardown()

    def test_collect_snapshot_has_feature_fields(self) -> None:
        sensor = EventLogSensor(interval=999)
        sensor.setup()
        try:
            events = sensor.collect()
            snapshot = next(
                e for e in events if e.event_type == "eventlog_snapshot"
            )
            data = snapshot.data
            assert "failed_login_rate" in data
            assert "privilege_escalation_events" in data
            assert "new_service_count" in data
            assert "encoded_powershell_count" in data
            assert "total_events_collected" in data
            assert "brute_force_detected" in data
        finally:
            sensor.teardown()

    def test_collect_security_events_have_mitre_mapping(self) -> None:
        sensor = EventLogSensor(interval=999)
        sensor.setup()
        try:
            events = sensor.collect()
            security_events = [
                e for e in events if e.event_type == "security_event"
            ]
            # Every security event whose ID has a MITRE mapping should include it
            for evt in security_events:
                eid = evt.data.get("event_id")
                if eid in MITRE_MAPPING:
                    assert "mitre_technique_id" in evt.data
                    assert "mitre_technique_name" in evt.data
        finally:
            sensor.teardown()

    def test_collect_multiple_cycles_accumulates_chain_events(self) -> None:
        sensor = EventLogSensor(interval=999)
        sensor.setup()
        try:
            sensor.collect()
            sensor.collect()
            # Internal deque should have accumulated events across cycles
            assert len(sensor._recent_events) > 0
        finally:
            sensor.teardown()


# ===========================================================================
# Feature Extraction
# ===========================================================================
class TestFeatureExtraction:
    """Tests for _extract_features via the sensor's collect path."""

    def test_features_count_failed_logins(self) -> None:
        sensor = EventLogSensor(interval=999)
        sensor.setup()
        try:
            # Force the stub to 3rd call to inject failed logins
            sensor._stub._call_count = 2  # type: ignore[union-attr]
            events = sensor.collect()
            snapshot = next(
                e for e in events if e.event_type == "eventlog_snapshot"
            )
            # 3rd call injects between 3 and 8 failed logins
            assert snapshot.data["failed_login_rate"] >= 3
        finally:
            sensor.teardown()

    def test_features_detect_brute_force(self) -> None:
        sensor = EventLogSensor(interval=999)
        # Access the private method directly for deterministic control
        raw_events = [
            _make_raw(EVTID_FAILED_LOGIN) for _ in range(BRUTE_FORCE_THRESHOLD)
        ]
        features = sensor._extract_features(raw_events)
        assert features["brute_force_detected"] is True
        assert features["failed_login_rate"] == BRUTE_FORCE_THRESHOLD

    def test_features_no_brute_force_below_threshold(self) -> None:
        sensor = EventLogSensor(interval=999)
        raw_events = [
            _make_raw(EVTID_FAILED_LOGIN)
            for _ in range(BRUTE_FORCE_THRESHOLD - 1)
        ]
        features = sensor._extract_features(raw_events)
        assert features["brute_force_detected"] is False

    def test_features_count_encoded_powershell(self) -> None:
        sensor = EventLogSensor(interval=999)
        encoded = _encode_utf16le("Get-Process | Out-File C:\\temp\\ps.txt")
        raw_events = [
            _make_raw(
                EVTID_POWERSHELL_SCRIPTBLOCK,
                message=f"powershell.exe -enc {encoded}",
            ),
        ]
        features = sensor._extract_features(raw_events)
        assert features["encoded_powershell_count"] == 1

    def test_features_count_privilege_events(self) -> None:
        sensor = EventLogSensor(interval=999)
        raw_events = [
            _make_raw(EVTID_SPECIAL_PRIVILEGES),
            _make_raw(EVTID_EXPLICIT_CREDENTIAL),
            _make_raw(EVTID_SPECIAL_PRIVILEGES),
        ]
        features = sensor._extract_features(raw_events)
        assert features["privilege_escalation_events"] == 3

    def test_features_count_new_services(self) -> None:
        sensor = EventLogSensor(interval=999)
        raw_events = [
            _make_raw(EVTID_NEW_SERVICE, log_name="System"),
            _make_raw(EVTID_NEW_SERVICE, log_name="System"),
        ]
        features = sensor._extract_features(raw_events)
        assert features["new_service_count"] == 2

    def test_features_total_events_collected(self) -> None:
        sensor = EventLogSensor(interval=999)
        raw_events = [_make_raw(EVTID_NEW_PROCESS) for _ in range(7)]
        features = sensor._extract_features(raw_events)
        assert features["total_events_collected"] == 7

    def test_snapshot_severity_brute_force(self) -> None:
        features = {
            "brute_force_detected": True,
            "encoded_powershell_count": 0,
            "new_service_count": 0,
            "privilege_escalation_events": 0,
            "failed_login_rate": 6,
        }
        assert EventLogSensor._snapshot_severity(features) == Severity.HIGH

    def test_snapshot_severity_encoded_ps(self) -> None:
        features = {
            "brute_force_detected": False,
            "encoded_powershell_count": 1,
            "new_service_count": 0,
            "privilege_escalation_events": 0,
            "failed_login_rate": 0,
        }
        assert EventLogSensor._snapshot_severity(features) == Severity.HIGH

    def test_snapshot_severity_new_service(self) -> None:
        features = {
            "brute_force_detected": False,
            "encoded_powershell_count": 0,
            "new_service_count": 1,
            "privilege_escalation_events": 0,
            "failed_login_rate": 0,
        }
        assert EventLogSensor._snapshot_severity(features) == Severity.MEDIUM

    def test_snapshot_severity_info_when_quiet(self) -> None:
        features = {
            "brute_force_detected": False,
            "encoded_powershell_count": 0,
            "new_service_count": 0,
            "privilege_escalation_events": 0,
            "failed_login_rate": 0,
        }
        assert EventLogSensor._snapshot_severity(features) == Severity.INFO


# ===========================================================================
# _RawEvent dataclass sanity checks
# ===========================================================================
class TestRawEvent:
    """Basic sanity checks for the _RawEvent dataclass."""

    def test_fields(self) -> None:
        evt = _RawEvent(
            event_id=4625,
            source="Security",
            log_name="Security",
            timestamp=1.0,
            computer="PC",
            message="hello",
        )
        assert evt.event_id == 4625
        assert evt.source == "Security"
        assert evt.log_name == "Security"
        assert evt.timestamp == 1.0
        assert evt.computer == "PC"
        assert evt.message == "hello"
        assert evt.data == {}

    def test_data_default_empty_dict(self) -> None:
        evt1 = _RawEvent(
            event_id=1, source="s", log_name="l",
            timestamp=0, computer="c", message="m",
        )
        evt2 = _RawEvent(
            event_id=1, source="s", log_name="l",
            timestamp=0, computer="c", message="m",
        )
        # Each instance should get its own dict
        assert evt1.data is not evt2.data

    def test_data_can_be_provided(self) -> None:
        evt = _RawEvent(
            event_id=1, source="s", log_name="l",
            timestamp=0, computer="c", message="m",
            data={"key": "value"},
        )
        assert evt.data == {"key": "value"}
