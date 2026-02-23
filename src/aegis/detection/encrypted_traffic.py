"""Encrypted Traffic Analysis Engine.

Orchestrates multiple detection techniques to identify malicious
encrypted traffic:

1. **JA3 blacklist lookup** -- matches TLS ClientHello fingerprints
   against known-malicious hashes from the SSLBL feed.
2. **Beacon detection** -- delegates to :class:`BeaconDetector` for
   statistical and FFT-based timing analysis of destination connections.
3. **Certificate anomaly analysis** -- delegates to :class:`CertAnalyzer`
   to score X.509 certificates for self-signed, short-lived, missing SAN,
   or weak-key anomalies.

MITRE ATT&CK coverage:
  - T1071.001 (Application Layer Protocol: Web Protocols)
  - T1573 (Encrypted Channel)
  - T1587.003 (Develop Capabilities: Digital Certificates)
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict

from aegis.core.models import AegisEvent, Alert, Severity
from aegis.detection.beacon_detector import BeaconDetector
from aegis.detection.cert_analyzer import CertAnalyzer

logger = logging.getLogger(__name__)

# Event types this engine processes
_TLS_HANDSHAKE = "etw.tls_handshake"
_HTTP_REQUEST = "etw.http_request"

# Beacon detector minimum connections before analysis
_BEACON_MIN_CONNECTIONS = 15

# Certificate anomaly score threshold for alerting
_CERT_ANOMALY_THRESHOLD = 0.5


class EncryptedTrafficEngine:
    """Analyze encrypted traffic events for malicious indicators.

    Combines JA3 fingerprint blacklisting, C2 beacon timing analysis,
    and X.509 certificate anomaly detection into a single analysis
    pipeline for TLS handshake and HTTP request events.
    """

    def __init__(self) -> None:
        self._beacon_detector = BeaconDetector(
            min_connections=_BEACON_MIN_CONNECTIONS,
        )
        self._cert_analyzer = CertAnalyzer()
        self._malicious_ja3: set[str] = set()
        self._dest_timestamps: defaultdict[str, list[float]] = (
            defaultdict(list)
        )

    def load_ja3_blacklist(self, ja3_hashes: set[str]) -> None:
        """Merge known-malicious JA3 hashes into the blacklist.

        Parameters
        ----------
        ja3_hashes : set[str]
            Set of JA3 hash strings to add (e.g. from SSLBL feed).
        """
        self._malicious_ja3.update(ja3_hashes)
        logger.info(
            "JA3 blacklist updated, total hashes: %d",
            len(self._malicious_ja3),
        )

    def analyze_event(self, event: AegisEvent) -> list[Alert]:
        """Analyze a single event for encrypted-traffic threats.

        Parameters
        ----------
        event : AegisEvent
            An event from the ETW sensor (TLS handshake or HTTP
            request).

        Returns
        -------
        list[Alert]
            Zero or more alerts produced by the analysis pipeline.
        """
        if event.event_type == _TLS_HANDSHAKE:
            return self._analyze_tls(event)
        if event.event_type == _HTTP_REQUEST:
            return self._analyze_http(event)
        return []

    # ------------------------------------------------------------------ #
    #  Internal analysis helpers
    # ------------------------------------------------------------------ #

    def _analyze_tls(self, event: AegisEvent) -> list[Alert]:
        """Run full analysis pipeline on a TLS handshake event."""
        alerts: list[Alert] = []
        alerts.extend(self._check_ja3(event))
        alerts.extend(self._check_beacon(event))
        alerts.extend(self._check_cert(event))
        return alerts

    def _analyze_http(self, event: AegisEvent) -> list[Alert]:
        """Track HTTP request timestamps for beacon detection."""
        return self._check_beacon(event)

    def _check_ja3(self, event: AegisEvent) -> list[Alert]:
        """Check JA3 hash against the malicious blacklist."""
        ja3_hash = event.data.get("ja3_hash")
        if not ja3_hash or ja3_hash not in self._malicious_ja3:
            return []

        server = event.data.get("server_name", "unknown")
        return [
            Alert(
                event_id=event.event_id,
                sensor=event.sensor,
                alert_type="encrypted_traffic_malicious_ja3",
                severity=Severity.HIGH,
                title=f"Malicious JA3 fingerprint: {server}",
                description=(
                    f"TLS handshake to {server} matched known-malicious "
                    f"JA3 hash {ja3_hash}. This fingerprint is associated "
                    f"with malware or attack tools in the SSLBL feed."
                ),
                confidence=0.9,
                data={
                    "ja3_hash": ja3_hash,
                    "server_name": server,
                    "pid": event.data.get("pid"),
                },
                mitre_ids=["T1071.001", "T1573"],
            ),
        ]

    def _check_beacon(self, event: AegisEvent) -> list[Alert]:
        """Track timestamps and run beacon detection if enough data."""
        dest = event.data.get("server_name") or event.data.get(
            "destination",
        )
        if not dest:
            return []

        self._dest_timestamps[dest].append(time.time())
        timestamps = self._dest_timestamps[dest]

        if len(timestamps) < _BEACON_MIN_CONNECTIONS:
            return []

        result = self._beacon_detector.analyze(timestamps)
        if not result.is_beacon:
            return []

        return [
            Alert(
                event_id=event.event_id,
                sensor=event.sensor,
                alert_type="encrypted_traffic_beacon",
                severity=Severity.HIGH,
                title=f"C2 beacon detected: {dest}",
                description=(
                    f"Connections to {dest} show regular beaconing "
                    f"pattern (interval ~{result.median_interval:.1f}s, "
                    f"score {result.score:.2f}). This may indicate "
                    f"command-and-control activity."
                ),
                confidence=min(result.score, 1.0),
                data={
                    "destination": dest,
                    "beacon_score": result.score,
                    "median_interval": result.median_interval,
                    "cv": result.cv,
                    "connection_count": len(timestamps),
                    "pid": event.data.get("pid"),
                },
                mitre_ids=["T1071.001", "T1573"],
            ),
        ]

    def _check_cert(self, event: AegisEvent) -> list[Alert]:
        """Analyze certificate if DER bytes are present."""
        cert_der = event.data.get("cert_der")
        if not cert_der:
            return []

        try:
            result = self._cert_analyzer.analyze_certificate(cert_der)
        except Exception:
            logger.warning(
                "Failed to parse certificate for event %s",
                event.event_id,
                exc_info=True,
            )
            return []

        if result.anomaly_score <= _CERT_ANOMALY_THRESHOLD:
            return []

        server = event.data.get("server_name", "unknown")
        return [
            Alert(
                event_id=event.event_id,
                sensor=event.sensor,
                alert_type="encrypted_traffic_cert_anomaly",
                severity=Severity.MEDIUM,
                title=f"Anomalous certificate: {server}",
                description=(
                    f"Certificate from {server} has anomaly score "
                    f"{result.anomaly_score:.2f}. Flags: "
                    f"self_signed={result.is_self_signed}, "
                    f"weak_key={result.weak_key}."
                ),
                confidence=result.anomaly_score,
                data={
                    "server_name": server,
                    "anomaly_score": result.anomaly_score,
                    "is_self_signed": result.is_self_signed,
                    "weak_key": result.weak_key,
                    "pid": event.data.get("pid"),
                },
                mitre_ids=["T1587.003", "T1553.004"],
            ),
        ]
