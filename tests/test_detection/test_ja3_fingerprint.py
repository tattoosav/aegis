"""Tests for JA3 TLS fingerprint computation."""
from __future__ import annotations

import hashlib

from aegis.detection.ja3_fingerprint import (
    compute_ja3,
    compute_ja3_string,
)


class TestJA3String:
    def test_basic_ja3_string_format(self):
        """JA3 string = version,ciphers,extensions,curves,formats."""
        result = compute_ja3_string(
            tls_version=769,
            cipher_suites=[47, 53, 5, 10],
            extensions=[0, 23, 65281],
            elliptic_curves=[29, 23, 24],
            ec_point_formats=[0],
        )
        assert result == "769,47-53-5-10,0-23-65281,29-23-24,0"

    def test_empty_fields(self):
        result = compute_ja3_string(
            tls_version=771,
            cipher_suites=[4866, 4867],
            extensions=[],
            elliptic_curves=[],
            ec_point_formats=[],
        )
        assert result == "771,4866-4867,,,"


class TestJA3Hash:
    def test_known_hash(self):
        """Verify MD5 hash matches expected JA3."""
        ja3_string = "769,47-53-5-10,0-23-65281,29-23-24,0"
        expected_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        result = compute_ja3(
            tls_version=769,
            cipher_suites=[47, 53, 5, 10],
            extensions=[0, 23, 65281],
            elliptic_curves=[29, 23, 24],
            ec_point_formats=[0],
        )
        assert result == expected_hash

    def test_hash_is_32_char_hex(self):
        result = compute_ja3(
            tls_version=771,
            cipher_suites=[4866],
            extensions=[],
            elliptic_curves=[],
            ec_point_formats=[],
        )
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    def test_different_inputs_different_hashes(self):
        h1 = compute_ja3(771, [4866], [], [], [])
        h2 = compute_ja3(771, [4867], [], [], [])
        assert h1 != h2
