"""Windows Event Log Analyzer sensor — monitors Security, System, and PowerShell logs.

Reads Windows Event Log entries and extracts security-relevant events including
failed logins, privilege escalation, new services, and encoded PowerShell commands.
Maps event sequences to MITRE ATT&CK techniques for attack chain reconstruction.

When pywin32 is not available (non-Windows or missing dependency), the sensor
operates in stub/mock mode generating simulated events for testing.
"""

from __future__ import annotations

import base64
import logging
import random
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.base import BaseSensor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Graceful import of pywin32
# ---------------------------------------------------------------------------
try:
    import win32evtlog  # type: ignore[import-untyped]
    import win32evtlogutil  # type: ignore[import-untyped]

    _HAS_WIN32 = True
except ImportError:
    _HAS_WIN32 = False
    logger.info(
        "pywin32 not available — EventLogSensor will run in stub/mock mode"
    )

# ---------------------------------------------------------------------------
# Event ID definitions
# ---------------------------------------------------------------------------
# Security log
EVTID_FAILED_LOGIN = 4625
EVTID_EXPLICIT_CREDENTIAL = 4648
EVTID_SPECIAL_PRIVILEGES = 4672
EVTID_NEW_PROCESS = 4688
EVTID_USER_CREATED = 4720
EVTID_PASSWORD_RESET = 4724
EVTID_GROUP_MEMBER_ADDED = 4732

# System log
EVTID_NEW_SERVICE = 7045
EVTID_SHUTDOWN_RESTART = 1074

# PowerShell log
EVTID_POWERSHELL_SCRIPTBLOCK = 4104

SECURITY_EVENT_IDS: set[int] = {
    EVTID_FAILED_LOGIN,
    EVTID_EXPLICIT_CREDENTIAL,
    EVTID_SPECIAL_PRIVILEGES,
    EVTID_NEW_PROCESS,
    EVTID_USER_CREATED,
    EVTID_PASSWORD_RESET,
    EVTID_GROUP_MEMBER_ADDED,
}

SYSTEM_EVENT_IDS: set[int] = {
    EVTID_NEW_SERVICE,
    EVTID_SHUTDOWN_RESTART,
}

POWERSHELL_EVENT_IDS: set[int] = {
    EVTID_POWERSHELL_SCRIPTBLOCK,
}

ALL_MONITORED_IDS: set[int] = (
    SECURITY_EVENT_IDS | SYSTEM_EVENT_IDS | POWERSHELL_EVENT_IDS
)

EVENT_DESCRIPTIONS: dict[int, str] = {
    EVTID_FAILED_LOGIN: "Failed login attempt",
    EVTID_EXPLICIT_CREDENTIAL: "Explicit credential logon",
    EVTID_SPECIAL_PRIVILEGES: "Special privileges assigned",
    EVTID_NEW_PROCESS: "New process created",
    EVTID_USER_CREATED: "User account created",
    EVTID_PASSWORD_RESET: "Password reset attempt",
    EVTID_GROUP_MEMBER_ADDED: "Member added to security group",
    EVTID_NEW_SERVICE: "New service installed",
    EVTID_SHUTDOWN_RESTART: "System shutdown/restart",
    EVTID_POWERSHELL_SCRIPTBLOCK: "PowerShell script block logged",
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK mappings
# ---------------------------------------------------------------------------
MITRE_MAPPING: dict[int, tuple[str, str]] = {
    EVTID_FAILED_LOGIN: ("T1110", "Brute Force"),
    EVTID_NEW_SERVICE: ("T1543.003", "Windows Service"),
    EVTID_POWERSHELL_SCRIPTBLOCK: ("T1059.001", "PowerShell"),
    EVTID_SPECIAL_PRIVILEGES: ("T1134", "Access Token Manipulation"),
    EVTID_USER_CREATED: ("T1136", "Create Account"),
    EVTID_EXPLICIT_CREDENTIAL: ("T1078", "Valid Accounts"),
    EVTID_PASSWORD_RESET: ("T1098", "Account Manipulation"),
    EVTID_GROUP_MEMBER_ADDED: ("T1098", "Account Manipulation"),
    EVTID_NEW_PROCESS: ("T1059", "Command and Scripting Interpreter"),
}

# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------
EVENT_SEVERITY: dict[int, Severity] = {
    EVTID_FAILED_LOGIN: Severity.MEDIUM,
    EVTID_EXPLICIT_CREDENTIAL: Severity.MEDIUM,
    EVTID_SPECIAL_PRIVILEGES: Severity.MEDIUM,
    EVTID_NEW_PROCESS: Severity.LOW,
    EVTID_USER_CREATED: Severity.HIGH,
    EVTID_PASSWORD_RESET: Severity.HIGH,
    EVTID_GROUP_MEMBER_ADDED: Severity.HIGH,
    EVTID_NEW_SERVICE: Severity.HIGH,
    EVTID_SHUTDOWN_RESTART: Severity.LOW,
    EVTID_POWERSHELL_SCRIPTBLOCK: Severity.MEDIUM,
}

# Threshold for brute force detection
BRUTE_FORCE_THRESHOLD = 5

# Maximum events to retain for attack chain analysis
_CHAIN_WINDOW_SIZE = 200

# Base64-encoded command pattern in PowerShell
_ENCODED_CMD_PATTERN = re.compile(
    r"(?:-(?:e|enc|encodedcommand))\s+([A-Za-z0-9+/=]{20,})",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------
@dataclass
class _RawEvent:
    """Internal representation of a parsed event log record."""

    event_id: int
    source: str
    log_name: str
    timestamp: float
    computer: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Encoded PowerShell detection
# ---------------------------------------------------------------------------
def detect_encoded_powershell(message: str) -> str | None:
    """Detect and decode base64-encoded PowerShell commands.

    Returns the decoded command string if found, otherwise None.
    """
    match = _ENCODED_CMD_PATTERN.search(message)
    if not match:
        return None
    encoded = match.group(1)
    # Pad if necessary
    pad = len(encoded) % 4
    if pad:
        encoded += "=" * (4 - pad)
    try:
        decoded_bytes = base64.b64decode(encoded)
        # PowerShell encoded commands are typically UTF-16LE
        return decoded_bytes.decode("utf-16-le", errors="replace")
    except Exception:
        try:
            decoded_bytes = base64.b64decode(encoded)
            return decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Attack chain reconstruction
# ---------------------------------------------------------------------------
# Define known attack chain patterns as ordered sequences of event IDs
ATTACK_CHAIN_PATTERNS: dict[str, tuple[list[int], str, Severity]] = {
    "credential_attack": (
        [EVTID_FAILED_LOGIN, EVTID_FAILED_LOGIN, EVTID_SPECIAL_PRIVILEGES],
        "Possible credential compromise: repeated failed logins "
        "followed by privilege escalation",
        Severity.CRITICAL,
    ),
    "persistence_install": (
        [EVTID_NEW_PROCESS, EVTID_NEW_SERVICE],
        "Possible persistence: new process created a new service",
        Severity.HIGH,
    ),
    "account_takeover": (
        [EVTID_FAILED_LOGIN, EVTID_PASSWORD_RESET, EVTID_SPECIAL_PRIVILEGES],
        "Possible account takeover: failed login, password reset, "
        "then privilege assignment",
        Severity.CRITICAL,
    ),
    "lateral_movement_prep": (
        [EVTID_USER_CREATED, EVTID_GROUP_MEMBER_ADDED],
        "Possible lateral movement prep: new account added to "
        "security group",
        Severity.HIGH,
    ),
    "powershell_execution": (
        [EVTID_NEW_PROCESS, EVTID_POWERSHELL_SCRIPTBLOCK],
        "Possible fileless attack: process spawned PowerShell "
        "script block execution",
        Severity.HIGH,
    ),
}


def find_attack_chains(
    recent_events: list[_RawEvent],
    window_seconds: float = 300.0,
) -> list[dict[str, Any]]:
    """Search recent events for known attack chain patterns.

    Looks for ordered subsequences of event IDs within a time window.
    Returns a list of detected chain descriptors.
    """
    chains: list[dict[str, Any]] = []
    if not recent_events:
        return chains

    for chain_name, (pattern, description, severity) in (
        ATTACK_CHAIN_PATTERNS.items()
    ):
        # Sliding window search for the ordered pattern
        pattern_idx = 0
        first_ts: float | None = None

        for evt in recent_events:
            if evt.event_id == pattern[pattern_idx]:
                if pattern_idx == 0:
                    first_ts = evt.timestamp
                pattern_idx += 1
                if pattern_idx == len(pattern):
                    # Check time window
                    assert first_ts is not None
                    if evt.timestamp - first_ts <= window_seconds:
                        mitre_ids = []
                        for eid in pattern:
                            if eid in MITRE_MAPPING:
                                tid = MITRE_MAPPING[eid][0]
                                if tid not in mitre_ids:
                                    mitre_ids.append(tid)
                        chains.append({
                            "chain_name": chain_name,
                            "description": description,
                            "severity": severity.value,
                            "mitre_ids": mitre_ids,
                            "event_ids_matched": list(pattern),
                            "window_seconds": evt.timestamp - first_ts,
                        })
                    # Reset for this pattern
                    pattern_idx = 0
                    first_ts = None

    return chains


# ---------------------------------------------------------------------------
# Stub / mock event generator (for non-Windows / testing)
# ---------------------------------------------------------------------------
class _StubEventGenerator:
    """Generates simulated Windows Event Log entries for testing."""

    def __init__(self) -> None:
        self._call_count: int = 0

    def generate(self) -> list[_RawEvent]:
        """Generate a batch of simulated events.

        Produces a realistic mix of events; occasionally injects
        suspicious patterns for testing detection logic.
        """
        self._call_count += 1
        events: list[_RawEvent] = []
        now = time.time()

        # Always generate some baseline events
        baseline_ids = [
            EVTID_NEW_PROCESS,
            EVTID_SPECIAL_PRIVILEGES,
            EVTID_SHUTDOWN_RESTART,
        ]
        for eid in random.sample(baseline_ids, k=min(2, len(baseline_ids))):
            events.append(_RawEvent(
                event_id=eid,
                source="stub",
                log_name="Security" if eid in SECURITY_EVENT_IDS else "System",
                timestamp=now - random.uniform(0, 14),
                computer="STUB-PC",
                message=EVENT_DESCRIPTIONS.get(eid, "Simulated event"),
            ))

        # Every 3rd call, inject failed logins (brute force simulation)
        if self._call_count % 3 == 0:
            for i in range(random.randint(3, 8)):
                events.append(_RawEvent(
                    event_id=EVTID_FAILED_LOGIN,
                    source="stub",
                    log_name="Security",
                    timestamp=now - random.uniform(0, 14),
                    computer="STUB-PC",
                    message=f"Failed login attempt #{i + 1} for user admin",
                    data={"target_user": "admin", "source_ip": "192.168.1.100"},
                ))

        # Every 5th call, inject an encoded PowerShell command
        if self._call_count % 5 == 0:
            encoded = base64.b64encode(
                "Get-Process | Out-File C:\\temp\\ps.txt".encode("utf-16-le")
            ).decode("ascii")
            events.append(_RawEvent(
                event_id=EVTID_POWERSHELL_SCRIPTBLOCK,
                source="stub",
                log_name="Microsoft-Windows-PowerShell/Operational",
                timestamp=now - random.uniform(0, 5),
                computer="STUB-PC",
                message=f"powershell.exe -enc {encoded}",
            ))

        # Every 7th call, inject a new service
        if self._call_count % 7 == 0:
            events.append(_RawEvent(
                event_id=EVTID_NEW_SERVICE,
                source="stub",
                log_name="System",
                timestamp=now - random.uniform(0, 10),
                computer="STUB-PC",
                message="A service was installed: TestSvc",
                data={"service_name": "TestSvc", "service_path": "C:\\temp\\svc.exe"},
            ))

        # Every 11th call, inject account creation + group add (chain)
        if self._call_count % 11 == 0:
            ts = now - 5
            events.append(_RawEvent(
                event_id=EVTID_USER_CREATED,
                source="stub",
                log_name="Security",
                timestamp=ts,
                computer="STUB-PC",
                message="User account created: backdoor_user",
                data={"new_user": "backdoor_user"},
            ))
            events.append(_RawEvent(
                event_id=EVTID_GROUP_MEMBER_ADDED,
                source="stub",
                log_name="Security",
                timestamp=ts + 2,
                computer="STUB-PC",
                message="backdoor_user added to Administrators",
                data={
                    "member": "backdoor_user",
                    "group": "Administrators",
                },
            ))

        return events


# ---------------------------------------------------------------------------
# Real Windows Event Log reader
# ---------------------------------------------------------------------------
def _read_win32_events(
    log_name: str,
    server: str | None,
    since: float,
    monitored_ids: set[int],
) -> list[_RawEvent]:
    """Read events from a Windows Event Log since a given timestamp.

    Requires pywin32. Returns only events whose EventID is in monitored_ids.
    """
    if not _HAS_WIN32:
        return []

    events: list[_RawEvent] = []
    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    try:
        handle = win32evtlog.OpenEventLog(server, log_name)
    except Exception as exc:
        logger.warning("Cannot open event log %r: %s", log_name, exc)
        return events

    try:
        while True:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break

            for record in records:
                # record.TimeGenerated is a pywintypes.datetime
                record_time = record.TimeGenerated.timestamp()
                if record_time < since:
                    # We are reading backwards; once we pass our marker, stop
                    return events

                event_id = record.EventID & 0xFFFF  # Mask qualifier bits
                if event_id not in monitored_ids:
                    continue

                # Safely extract message
                try:
                    message = win32evtlogutil.SafeFormatMessage(
                        record, log_name
                    )
                except Exception:
                    message = str(record.StringInserts or "")

                events.append(_RawEvent(
                    event_id=event_id,
                    source=record.SourceName or "",
                    log_name=log_name,
                    timestamp=record_time,
                    computer=record.ComputerName or "",
                    message=message,
                ))
    except Exception as exc:
        logger.error("Error reading event log %r: %s", log_name, exc)
    finally:
        try:
            win32evtlog.CloseEventLog(handle)
        except Exception:
            pass

    return events


# ---------------------------------------------------------------------------
# EventLogSensor
# ---------------------------------------------------------------------------
class EventLogSensor(BaseSensor):
    """Windows Event Log Analyzer — monitors Security, System, and PowerShell logs.

    Emits:
    - eventlog_snapshot: periodic summary with feature statistics
    - security_event: individual interesting events (failed login, etc.)
    - attack_chain: correlated event sequences mapped to MITRE ATT&CK
    """

    sensor_type = SensorType.EVENTLOG
    sensor_name = "eventlog_analyzer"

    def __init__(
        self,
        interval: float = 15.0,
        server: str | None = None,
        **kwargs: Any,
    ):
        super().__init__(interval=interval, **kwargs)
        self._server = server
        self._last_read: float = 0.0
        self._recent_events: deque[_RawEvent] = deque(
            maxlen=_CHAIN_WINDOW_SIZE,
        )
        self._stub: _StubEventGenerator | None = None

    # -- lifecycle ----------------------------------------------------------

    def setup(self) -> None:
        """Initialize the sensor and record the starting timestamp."""
        self._last_read = time.time()
        self._recent_events.clear()
        if not _HAS_WIN32:
            logger.info(
                "EventLogSensor running in stub mode (pywin32 not available)"
            )
            self._stub = _StubEventGenerator()
        else:
            self._stub = None

    def teardown(self) -> None:
        """Cleanup resources."""
        self._recent_events.clear()
        self._stub = None

    # -- collection ---------------------------------------------------------

    def collect(self) -> list[AegisEvent]:
        """Read events since last cycle, extract features, and return events."""
        raw_events = self._read_events()
        self._last_read = time.time()

        # Store for attack chain analysis
        for evt in raw_events:
            self._recent_events.append(evt)

        aegis_events: list[AegisEvent] = []

        # Emit individual security events
        for raw in raw_events:
            aegis_events.append(self._raw_to_aegis_event(raw))

        # Extract features
        features = self._extract_features(raw_events)

        # Emit snapshot with feature stats
        aegis_events.append(AegisEvent(
            sensor=SensorType.EVENTLOG,
            event_type="eventlog_snapshot",
            severity=self._snapshot_severity(features),
            data=features,
        ))

        # Attack chain detection
        chains = find_attack_chains(list(self._recent_events))
        for chain in chains:
            aegis_events.append(AegisEvent(
                sensor=SensorType.EVENTLOG,
                event_type="attack_chain",
                severity=Severity(chain["severity"]),
                data=chain,
            ))

        return aegis_events

    # -- internal helpers ---------------------------------------------------

    def _read_events(self) -> list[_RawEvent]:
        """Read raw events from all monitored logs or generate stubs."""
        if self._stub is not None:
            return self._stub.generate()

        all_events: list[_RawEvent] = []

        # Security log
        all_events.extend(_read_win32_events(
            "Security", self._server, self._last_read, SECURITY_EVENT_IDS,
        ))

        # System log
        all_events.extend(_read_win32_events(
            "System", self._server, self._last_read, SYSTEM_EVENT_IDS,
        ))

        # PowerShell operational log
        all_events.extend(_read_win32_events(
            "Microsoft-Windows-PowerShell/Operational",
            self._server,
            self._last_read,
            POWERSHELL_EVENT_IDS,
        ))

        # Sort chronologically
        all_events.sort(key=lambda e: e.timestamp)
        return all_events

    def _raw_to_aegis_event(self, raw: _RawEvent) -> AegisEvent:
        """Convert an internal _RawEvent to an AegisEvent."""
        severity = EVENT_SEVERITY.get(raw.event_id, Severity.INFO)

        # Check for encoded PowerShell
        decoded_cmd: str | None = None
        if raw.event_id == EVTID_POWERSHELL_SCRIPTBLOCK:
            decoded_cmd = detect_encoded_powershell(raw.message)
            if decoded_cmd:
                severity = Severity.HIGH

        data: dict[str, Any] = {
            "event_id": raw.event_id,
            "description": EVENT_DESCRIPTIONS.get(
                raw.event_id, "Unknown event"
            ),
            "source": raw.source,
            "log_name": raw.log_name,
            "computer": raw.computer,
            "message": raw.message,
            **raw.data,
        }

        # Add MITRE mapping if available
        if raw.event_id in MITRE_MAPPING:
            technique_id, technique_name = MITRE_MAPPING[raw.event_id]
            data["mitre_technique_id"] = technique_id
            data["mitre_technique_name"] = technique_name

        if decoded_cmd is not None:
            data["decoded_powershell"] = decoded_cmd
            data["encoded_command_detected"] = True

        return AegisEvent(
            sensor=SensorType.EVENTLOG,
            event_type="security_event",
            severity=severity,
            data=data,
        )

    def _extract_features(
        self, raw_events: list[_RawEvent],
    ) -> dict[str, Any]:
        """Extract numeric features from a batch of raw events.

        Features:
        - failed_login_rate: number of failed logins in this cycle
        - privilege_escalation_events: count of privilege-related events
        - new_service_count: number of new services installed
        - encoded_powershell_count: number of encoded PS commands detected
        """
        failed_logins = 0
        privilege_events = 0
        new_services = 0
        encoded_ps = 0

        for evt in raw_events:
            if evt.event_id == EVTID_FAILED_LOGIN:
                failed_logins += 1
            if evt.event_id in (
                EVTID_SPECIAL_PRIVILEGES,
                EVTID_EXPLICIT_CREDENTIAL,
            ):
                privilege_events += 1
            if evt.event_id == EVTID_NEW_SERVICE:
                new_services += 1
            if evt.event_id == EVTID_POWERSHELL_SCRIPTBLOCK:
                if detect_encoded_powershell(evt.message):
                    encoded_ps += 1

        return {
            "failed_login_rate": failed_logins,
            "privilege_escalation_events": privilege_events,
            "new_service_count": new_services,
            "encoded_powershell_count": encoded_ps,
            "total_events_collected": len(raw_events),
            "brute_force_detected": (
                failed_logins >= BRUTE_FORCE_THRESHOLD
            ),
        }

    @staticmethod
    def _snapshot_severity(features: dict[str, Any]) -> Severity:
        """Determine severity for the snapshot event based on features."""
        if features.get("brute_force_detected"):
            return Severity.HIGH
        if features.get("encoded_powershell_count", 0) > 0:
            return Severity.HIGH
        if features.get("new_service_count", 0) > 0:
            return Severity.MEDIUM
        if features.get("privilege_escalation_events", 0) > 0:
            return Severity.MEDIUM
        if features.get("failed_login_rate", 0) > 0:
            return Severity.LOW
        return Severity.INFO
