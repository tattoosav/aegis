"""JA3 TLS fingerprint computation.

Computes JA3 fingerprints from TLS ClientHello parameters as defined
in https://github.com/salesforce/ja3.
"""
from __future__ import annotations

import hashlib


def compute_ja3_string(
    tls_version: int,
    cipher_suites: list[int],
    extensions: list[int],
    elliptic_curves: list[int],
    ec_point_formats: list[int],
) -> str:
    """Build the raw JA3 string from TLS ClientHello fields.

    Format: version,ciphers,extensions,curves,point_formats
    Each field is a dash-separated list of integers.
    """
    ciphers = "-".join(str(c) for c in cipher_suites)
    exts = "-".join(str(e) for e in extensions)
    curves = "-".join(str(c) for c in elliptic_curves)
    formats = "-".join(str(f) for f in ec_point_formats)
    return f"{tls_version},{ciphers},{exts},{curves},{formats}"


def compute_ja3(
    tls_version: int,
    cipher_suites: list[int],
    extensions: list[int],
    elliptic_curves: list[int],
    ec_point_formats: list[int],
) -> str:
    """Compute the JA3 fingerprint hash (MD5 of the JA3 string)."""
    ja3_string = compute_ja3_string(
        tls_version, cipher_suites, extensions,
        elliptic_curves, ec_point_formats,
    )
    return hashlib.md5(ja3_string.encode()).hexdigest()
