"""Alert Correlation Engine for Aegis.

Groups related alerts into incidents based on shared entities
(process, file, IP), MITRE ATT&CK kill-chain progression, and
temporal proximity.  Detects multi-stage attack campaigns by
identifying IOC overlap across closed incidents.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum

from aegis.core.models import Alert, Severity

logger = logging.getLogger(__name__)


class IncidentStatus(Enum):
    """Status of an incident in the correlation engine."""

    OPEN = "open"
    CLOSED = "closed"
    MERGED = "merged"


@dataclass
class Incident:
    """A group of correlated alerts forming a security incident."""

    incident_id: str
    title: str = ""
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    alerts: list[Alert] = field(default_factory=list)
    mitre_chain: list[str] = field(default_factory=list)
    entities: set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def alert_count(self) -> int:
        """Return the number of alerts in this incident."""
        return len(self.alerts)

    @property
    def duration(self) -> float:
        """Return the duration in seconds between first and last alert."""
        if self.first_seen and self.last_seen:
            return self.last_seen - self.first_seen
        return 0.0


@dataclass
class Campaign:
    """A set of incidents linked by shared IOCs."""

    campaign_id: str
    incidents: list[Incident] = field(default_factory=list)
    shared_iocs: list[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0


# MITRE ATT&CK tactics in kill-chain order
_TACTIC_ORDER: dict[str, int] = {
    "reconnaissance": 0,
    "resource-development": 1,
    "initial-access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege-escalation": 5,
    "defense-evasion": 6,
    "credential-access": 7,
    "discovery": 8,
    "lateral-movement": 9,
    "collection": 10,
    "command-and-control": 11,
    "exfiltration": 12,
    "impact": 13,
}

# Map common technique IDs to their tactic (simplified)
_TECHNIQUE_TACTIC: dict[str, str] = {
    "T1190": "initial-access",
    "T1059": "execution",
    "T1059.001": "execution",
    "T1059.003": "execution",
    "T1547": "persistence",
    "T1547.001": "persistence",
    "T1547.004": "persistence",
    "T1547.005": "persistence",
    "T1543.003": "persistence",
    "T1546.001": "persistence",
    "T1546.012": "persistence",
    "T1071": "command-and-control",
    "T1071.004": "command-and-control",
    "T1486": "impact",
    "T1048": "exfiltration",
    "T1048.003": "exfiltration",
    "T1568.002": "command-and-control",
    "T1505.003": "persistence",
    "T1140": "defense-evasion",
    "T1055": "defense-evasion",
    "T1055.012": "defense-evasion",
}


class CorrelationEngine:
    """Correlate alerts into incidents and detect campaigns.

    Parameters
    ----------
    time_window:
        Maximum seconds between alerts to consider them related.
    min_alerts_for_incident:
        Minimum alerts needed to form an incident.
    """

    def __init__(
        self,
        time_window: float = 300.0,
        min_alerts_for_incident: int = 2,
    ) -> None:
        self._time_window = time_window
        self._min_alerts = min_alerts_for_incident
        self._incidents: dict[str, Incident] = {}
        self._campaigns: list[Campaign] = []

    @property
    def incident_count(self) -> int:
        """Return the total number of tracked incidents."""
        return len(self._incidents)

    def ingest_alert(self, alert: Alert) -> Incident | None:
        """Process a new alert and correlate it.

        Tries correlation in priority order:
        1. Entity correlation (shared PID, IP, file path)
        2. MITRE kill-chain progression
        3. Time proximity from same sensor

        Returns the incident if the alert was added to one,
        or None.
        """
        # Extract entities from alert data
        entities = self._extract_entities(alert)

        # Try entity-based correlation first
        incident = self._correlate_by_entity(alert, entities)
        if incident:
            return incident

        # Try MITRE chain correlation
        incident = self._correlate_by_mitre_chain(alert)
        if incident:
            return incident

        # Try time-proximity correlation
        incident = self._correlate_by_time_proximity(alert)
        if incident:
            return incident

        # No correlation found -- create a new single-alert incident
        # (it becomes a real incident once min_alerts threshold is met)
        incident = self._create_incident(alert, entities)
        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        """Return an incident by ID, or None if not found."""
        return self._incidents.get(incident_id)

    def get_active_incidents(self) -> list[Incident]:
        """Return all incidents with OPEN status."""
        return [
            i for i in self._incidents.values()
            if i.status == IncidentStatus.OPEN
        ]

    def get_all_incidents(self) -> list[Incident]:
        """Return all tracked incidents."""
        return list(self._incidents.values())

    def close_incident(self, incident_id: str) -> bool:
        """Close an open incident. Returns True if closed."""
        incident = self._incidents.get(incident_id)
        if incident and incident.status == IncidentStatus.OPEN:
            incident.status = IncidentStatus.CLOSED
            return True
        return False

    def detect_campaigns(self) -> list[Campaign]:
        """Scan closed incidents for shared IOCs to find campaigns."""
        closed = [
            i for i in self._incidents.values()
            if i.status == IncidentStatus.CLOSED
        ]
        if len(closed) < 2:
            return []

        campaigns: list[Campaign] = []
        used: set[str] = set()

        for i, inc_a in enumerate(closed):
            if inc_a.incident_id in used:
                continue
            group = [inc_a]
            shared: set[str] = set(inc_a.entities)

            for inc_b in closed[i + 1:]:
                if inc_b.incident_id in used:
                    continue
                overlap = inc_a.entities & inc_b.entities
                if overlap:
                    group.append(inc_b)
                    shared &= inc_b.entities
                    used.add(inc_b.incident_id)

            if len(group) >= 2:
                used.add(inc_a.incident_id)
                timestamps = [
                    inc.first_seen
                    for inc in group
                    if inc.first_seen
                ] + [
                    inc.last_seen
                    for inc in group
                    if inc.last_seen
                ]
                campaigns.append(Campaign(
                    campaign_id=f"camp-{uuid.uuid4().hex[:8]}",
                    incidents=group,
                    shared_iocs=sorted(shared),
                    first_seen=(
                        min(timestamps) if timestamps else 0.0
                    ),
                    last_seen=(
                        max(timestamps) if timestamps else 0.0
                    ),
                ))

        self._campaigns = campaigns
        return campaigns

    def prune_stale_incidents(self, max_age: float) -> int:
        """Close open incidents older than *max_age* seconds.

        Returns the number of incidents closed.
        """
        now = time.time()
        stale = [
            iid for iid, inc in self._incidents.items()
            if inc.status == IncidentStatus.OPEN
            and inc.last_seen > 0
            and (now - inc.last_seen) > max_age
        ]
        for iid in stale:
            self._incidents[iid].status = IncidentStatus.CLOSED
        return len(stale)

    # --- Private correlation methods ---

    def _extract_entities(self, alert: Alert) -> set[str]:
        """Extract correlatable entities from alert data."""
        entities: set[str] = set()
        data = alert.data

        for key in ("pid", "ppid"):
            val = data.get(key)
            if val:
                entities.add(f"pid:{val}")

        for key in (
            "dst_ip", "src_ip", "remote_addr", "ip", "target",
        ):
            val = data.get(key)
            if val and isinstance(val, str) and "." in val:
                entities.add(f"ip:{val}")

        for key in ("path", "file_path", "exe"):
            val = data.get(key)
            if val and isinstance(val, str):
                entities.add(f"file:{val}")

        for key in ("domain", "query_name", "hostname"):
            val = data.get(key)
            if val and isinstance(val, str):
                entities.add(f"domain:{val}")

        return entities

    def _correlate_by_entity(
        self, alert: Alert, entities: set[str],
    ) -> Incident | None:
        """Find an open incident sharing entities with this alert."""
        if not entities:
            return None

        for incident in self._incidents.values():
            if incident.status != IncidentStatus.OPEN:
                continue
            if (time.time() - incident.last_seen) > self._time_window:
                continue
            overlap = entities & incident.entities
            if overlap:
                self._add_alert_to_incident(
                    incident, alert, entities,
                )
                return incident

        return None

    def _correlate_by_mitre_chain(
        self, alert: Alert,
    ) -> Incident | None:
        """Find an incident where this alert advances the chain."""
        if not alert.mitre_ids:
            return None

        alert_tactics: set[str] = set()
        for tid in alert.mitre_ids:
            tactic = _TECHNIQUE_TACTIC.get(tid)
            if tactic:
                alert_tactics.add(tactic)

        if not alert_tactics:
            return None

        for incident in self._incidents.values():
            if incident.status != IncidentStatus.OPEN:
                continue
            if (time.time() - incident.last_seen) > self._time_window:
                continue

            # Check if this alert represents a new tactic
            existing_tactics: set[str] = set()
            for tid in incident.mitre_chain:
                tactic = _TECHNIQUE_TACTIC.get(tid)
                if tactic:
                    existing_tactics.add(tactic)

            new_tactics = alert_tactics - existing_tactics
            if new_tactics:
                entities = self._extract_entities(alert)
                self._add_alert_to_incident(
                    incident, alert, entities,
                )
                return incident

        return None

    def _correlate_by_time_proximity(
        self, alert: Alert,
    ) -> Incident | None:
        """Find an open incident from same sensor within window."""
        for incident in self._incidents.values():
            if incident.status != IncidentStatus.OPEN:
                continue
            if not incident.alerts:
                continue

            last_alert = incident.alerts[-1]
            time_diff = abs(alert.timestamp - last_alert.timestamp)
            if time_diff > self._time_window:
                continue

            # Same sensor type correlation
            if alert.sensor == last_alert.sensor:
                entities = self._extract_entities(alert)
                self._add_alert_to_incident(
                    incident, alert, entities,
                )
                return incident

        return None

    def _create_incident(
        self, alert: Alert, entities: set[str],
    ) -> Incident:
        """Create a new incident from a single alert."""
        incident_id = f"inc-{uuid.uuid4().hex[:8]}"
        incident = Incident(
            incident_id=incident_id,
            title=f"Incident: {alert.title}",
            severity=alert.severity,
            alerts=[alert],
            mitre_chain=list(alert.mitre_ids),
            entities=set(entities),
            first_seen=alert.timestamp,
            last_seen=alert.timestamp,
        )
        self._incidents[incident_id] = incident
        return incident

    def _add_alert_to_incident(
        self,
        incident: Incident,
        alert: Alert,
        entities: set[str],
    ) -> None:
        """Add an alert to an existing incident."""
        incident.alerts.append(alert)
        incident.entities.update(entities)
        incident.last_seen = max(
            incident.last_seen, alert.timestamp,
        )

        # Update MITRE chain
        for tid in alert.mitre_ids:
            if tid not in incident.mitre_chain:
                incident.mitre_chain.append(tid)

        # Escalate severity if needed
        if alert.severity.weight > incident.severity.weight:
            incident.severity = alert.severity

        # Update title for multi-alert incidents
        if len(incident.alerts) >= 2:
            incident.title = (
                f"Incident: {len(incident.alerts)} related alerts"
            )
