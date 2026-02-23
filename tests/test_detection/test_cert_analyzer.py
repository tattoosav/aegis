"""Tests for X.509 certificate anomaly detection."""
from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aegis.detection.cert_analyzer import CertAnalyzer


def _make_cert(
    subject_cn: str = "test.example.com",
    issuer_cn: str | None = None,
    days_valid: int = 365,
    key_size: int = 2048,
    add_san: bool = True,
) -> bytes:
    """Generate a DER-encoded test certificate."""
    key = rsa.generate_private_key(65537, key_size)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
    ])
    if issuer_cn is None:
        issuer = subject  # self-signed
    else:
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        ])

    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
    )
    if add_san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(subject_cn),
            ]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


class TestSelfSigned:
    """Self-signed certificate detection."""

    def test_self_signed_detected(self) -> None:
        cert_der = _make_cert(subject_cn="evil.com")
        analyzer = CertAnalyzer()
        result = analyzer.analyze_certificate(cert_der)
        assert result.is_self_signed is True

    def test_ca_signed_not_self_signed(self) -> None:
        cert_der = _make_cert(
            subject_cn="legit.com", issuer_cn="DigiCert CA",
        )
        analyzer = CertAnalyzer()
        result = analyzer.analyze_certificate(cert_der)
        assert result.is_self_signed is False


class TestShortLived:
    """Short-lived certificate detection."""

    def test_short_lived_cert(self) -> None:
        cert_der = _make_cert(days_valid=7)
        analyzer = CertAnalyzer()
        result = analyzer.analyze_certificate(cert_der)
        assert result.is_short_lived is True
        assert result.validity_days == 7

    def test_normal_validity(self) -> None:
        cert_der = _make_cert(days_valid=365)
        analyzer = CertAnalyzer()
        result = analyzer.analyze_certificate(cert_der)
        assert result.is_short_lived is False


class TestMissingSAN:
    """Missing Subject Alternative Name detection."""

    def test_no_san(self) -> None:
        cert_der = _make_cert(add_san=False)
        analyzer = CertAnalyzer()
        result = analyzer.analyze_certificate(cert_der)
        assert result.no_san is True

    def test_has_san(self) -> None:
        cert_der = _make_cert(add_san=True)
        analyzer = CertAnalyzer()
        result = analyzer.analyze_certificate(cert_der)
        assert result.no_san is False


class TestWeakKey:
    """Weak key detection."""

    def test_weak_rsa_1024(self) -> None:
        cert_der = _make_cert(key_size=1024)
        analyzer = CertAnalyzer()
        result = analyzer.analyze_certificate(cert_der)
        assert result.weak_key is True

    def test_strong_rsa_2048(self) -> None:
        cert_der = _make_cert(key_size=2048)
        analyzer = CertAnalyzer()
        result = analyzer.analyze_certificate(cert_der)
        assert result.weak_key is False


class TestAnomalyScore:
    """Anomaly score calculation."""

    def test_normal_cert_low_score(self) -> None:
        cert_der = _make_cert(
            subject_cn="legit.com", issuer_cn="DigiCert CA",
            days_valid=365, add_san=True, key_size=2048,
        )
        analyzer = CertAnalyzer()
        result = analyzer.analyze_certificate(cert_der)
        assert result.anomaly_score < 0.3

    def test_many_anomalies_high_score(self) -> None:
        cert_der = _make_cert(
            days_valid=3, add_san=False, key_size=1024,
        )
        analyzer = CertAnalyzer()
        result = analyzer.analyze_certificate(cert_der)
        assert result.anomaly_score > 0.5
