"""Tests for Encrypted Traffic Analysis Engine."""
from __future__ import annotations

from unittest.mock import MagicMock

from aegis.core.models import AegisEvent, SensorType
from aegis.detection.encrypted_traffic import EncryptedTrafficEngine


class TestEncryptedTrafficJA3:
    """Tests for JA3 fingerprint blacklist checking."""

    def test_known_malicious_ja3_produces_alert(self) -> None:
        engine = EncryptedTrafficEngine()
        engine._malicious_ja3 = {"abc123deadbeef"}  # inject test data

        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={
                "server_name": "evil.com",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "pid": 1234,
                "ja3_hash": "abc123deadbeef",
            },
        )
        alerts = engine.analyze_event(event)
        assert len(alerts) >= 1
        assert any("ja3" in a.alert_type.lower() for a in alerts)

    def test_clean_ja3_no_alert(self) -> None:
        engine = EncryptedTrafficEngine()
        engine._malicious_ja3 = {"abc123deadbeef"}

        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={
                "server_name": "google.com",
                "ja3_hash": "clean_hash_xyz",
                "pid": 1234,
            },
        )
        alerts = engine.analyze_event(event)
        ja3_alerts = [a for a in alerts if "ja3" in a.alert_type.lower()]
        assert len(ja3_alerts) == 0


class TestEncryptedTrafficBeacon:
    """Tests for beacon detection via timestamp analysis."""

    def test_beaconing_pattern_produces_alert(self) -> None:
        engine = EncryptedTrafficEngine()
        # Simulate many connections to same destination
        dest = "evil.com"
        base = 1000.0
        for i in range(25):
            engine._dest_timestamps[dest].append(base + i * 60.0)

        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={"server_name": dest, "pid": 1234},
        )
        alerts = engine.analyze_event(event)
        beacon_alerts = [
            a for a in alerts if "beacon" in a.alert_type.lower()
        ]
        assert len(beacon_alerts) >= 1

    def test_no_beacon_for_few_connections(self) -> None:
        engine = EncryptedTrafficEngine()
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={"server_name": "normal.com", "pid": 1234},
        )
        alerts = engine.analyze_event(event)
        beacon_alerts = [
            a for a in alerts if "beacon" in a.alert_type.lower()
        ]
        assert len(beacon_alerts) == 0


class TestEncryptedTrafficNormal:
    """Tests for normal traffic and irrelevant events."""

    def test_normal_tls_no_alerts(self) -> None:
        engine = EncryptedTrafficEngine()
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={
                "server_name": "google.com",
                "ja3_hash": "normal_hash",
                "pid": 1234,
            },
        )
        alerts = engine.analyze_event(event)
        assert len(alerts) == 0

    def test_irrelevant_event_no_alerts(self) -> None:
        engine = EncryptedTrafficEngine()
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_new",
            data={"name": "notepad.exe"},
        )
        alerts = engine.analyze_event(event)
        assert len(alerts) == 0


class TestEncryptedTrafficCert:
    """Tests for certificate anomaly analysis."""

    def test_anomalous_cert_produces_alert(self) -> None:
        engine = EncryptedTrafficEngine()
        # Mock CertAnalyzer to return high anomaly score
        mock_result = MagicMock()
        mock_result.anomaly_score = 0.8
        mock_result.is_self_signed = True
        mock_result.weak_key = True
        engine._cert_analyzer.analyze_certificate = MagicMock(
            return_value=mock_result,
        )

        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={
                "server_name": "suspicious.com",
                "pid": 1234,
                "cert_der": b"\x30\x82",  # dummy DER bytes
            },
        )
        alerts = engine.analyze_event(event)
        cert_alerts = [
            a for a in alerts if "cert" in a.alert_type.lower()
        ]
        assert len(cert_alerts) >= 1

    def test_normal_cert_no_alert(self) -> None:
        engine = EncryptedTrafficEngine()
        mock_result = MagicMock()
        mock_result.anomaly_score = 0.1
        engine._cert_analyzer.analyze_certificate = MagicMock(
            return_value=mock_result,
        )

        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={
                "server_name": "google.com",
                "pid": 1234,
                "cert_der": b"\x30\x82",
            },
        )
        alerts = engine.analyze_event(event)
        cert_alerts = [
            a for a in alerts if "cert" in a.alert_type.lower()
        ]
        assert len(cert_alerts) == 0


class TestEncryptedTrafficHTTP:
    """Tests for HTTP request beacon tracking."""

    def test_http_request_tracks_timestamps(self) -> None:
        engine = EncryptedTrafficEngine()
        dest = "api.evil.com"
        # Pre-load enough timestamps to trigger beacon detection
        base = 1000.0
        for i in range(25):
            engine._dest_timestamps[dest].append(base + i * 60.0)

        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.http_request",
            data={"server_name": dest, "pid": 1234},
        )
        alerts = engine.analyze_event(event)
        beacon_alerts = [
            a for a in alerts if "beacon" in a.alert_type.lower()
        ]
        assert len(beacon_alerts) >= 1


class TestLoadJA3Blacklist:
    """Tests for loading JA3 hash blacklist."""

    def test_load_ja3_blacklist(self) -> None:
        engine = EncryptedTrafficEngine()
        hashes = {"hash1", "hash2", "hash3"}
        engine.load_ja3_blacklist(hashes)
        assert engine._malicious_ja3 == hashes

    def test_load_ja3_blacklist_merges(self) -> None:
        engine = EncryptedTrafficEngine()
        engine._malicious_ja3 = {"existing_hash"}
        engine.load_ja3_blacklist({"new_hash"})
        assert "existing_hash" in engine._malicious_ja3
        assert "new_hash" in engine._malicious_ja3
