"""X.509 certificate anomaly detection.

Analyzes TLS certificates for indicators of malicious or suspicious
activity: self-signed certs, short validity periods, missing Subject
Alternative Names, and weak cryptographic keys.

MITRE coverage: T1587.003 (Develop Capabilities: Digital Certificates),
T1553.004 (Subvert Trust Controls: Install Root Certificate).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

logger = logging.getLogger(__name__)

# Anomaly weight constants for score calculation
_WEIGHT_SELF_SIGNED: float = 0.25
_WEIGHT_SHORT_LIVED: float = 0.20
_WEIGHT_NO_SAN: float = 0.20
_WEIGHT_WEAK_KEY: float = 0.35

# Thresholds
_SHORT_LIVED_DAYS: int = 30
_MIN_RSA_BITS: int = 2048
_MIN_EC_BITS: int = 256


@dataclass
class CertAnomalyResult:
    """Result of analyzing an X.509 certificate for anomalies."""

    is_self_signed: bool
    is_short_lived: bool
    validity_days: int
    no_san: bool
    weak_key: bool
    anomaly_score: float


class CertAnalyzer:
    """X.509 certificate anomaly detector.

    Parses DER-encoded certificates and checks for indicators commonly
    associated with malicious TLS usage: self-signed certificates,
    short validity windows, missing SAN extensions, and weak keys.
    """

    def analyze_certificate(self, cert_der: bytes) -> CertAnomalyResult:
        """Analyze a DER-encoded X.509 certificate for anomalies.

        Parameters
        ----------
        cert_der : bytes
            DER-encoded X.509 certificate bytes.

        Returns
        -------
        CertAnomalyResult
            Dataclass with individual anomaly flags and a weighted
            composite anomaly score (0.0 = normal, 1.0 = highly
            anomalous).
        """
        cert = x509.load_der_x509_certificate(cert_der)

        is_self_signed = self._check_self_signed(cert)
        validity_days = self._compute_validity_days(cert)
        is_short_lived = validity_days <= _SHORT_LIVED_DAYS
        no_san = self._check_missing_san(cert)
        weak_key = self._check_weak_key(cert)

        anomaly_score = self._compute_score(
            is_self_signed, is_short_lived, no_san, weak_key,
        )

        return CertAnomalyResult(
            is_self_signed=is_self_signed,
            is_short_lived=is_short_lived,
            validity_days=validity_days,
            no_san=no_san,
            weak_key=weak_key,
            anomaly_score=anomaly_score,
        )

    @staticmethod
    def _check_self_signed(cert: x509.Certificate) -> bool:
        """Return True if the certificate is self-signed."""
        return cert.issuer == cert.subject

    @staticmethod
    def _compute_validity_days(cert: x509.Certificate) -> int:
        """Return the validity period in days."""
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        return delta.days

    @staticmethod
    def _check_missing_san(cert: x509.Certificate) -> bool:
        """Return True if the certificate lacks a SAN extension."""
        try:
            cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName,
            )
            return False
        except x509.ExtensionNotFound:
            return True

    @staticmethod
    def _check_weak_key(cert: x509.Certificate) -> bool:
        """Return True if the certificate uses a weak public key."""
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            return pub_key.key_size < _MIN_RSA_BITS
        if isinstance(pub_key, ec.EllipticCurvePublicKey):
            return pub_key.key_size < _MIN_EC_BITS
        # Unknown key type — flag as potentially weak
        return True

    @staticmethod
    def _compute_score(
        is_self_signed: bool,
        is_short_lived: bool,
        no_san: bool,
        weak_key: bool,
    ) -> float:
        """Compute a weighted anomaly score from individual flags."""
        score = 0.0
        if is_self_signed:
            score += _WEIGHT_SELF_SIGNED
        if is_short_lived:
            score += _WEIGHT_SHORT_LIVED
        if no_san:
            score += _WEIGHT_NO_SAN
        if weak_key:
            score += _WEIGHT_WEAK_KEY
        return round(score, 4)
