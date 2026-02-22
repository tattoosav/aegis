"""STIX/TAXII threat intelligence feed integration.

Ingests Indicators of Compromise from STIX 2.1 JSON bundles and
TAXII 2.1 server collections.  Extends the existing ThreatFeed ABC
so feeds plug directly into the ThreatFeedManager.

When ``stix2`` or ``taxii2-client`` are not installed the feeds
operate in disabled mode.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from aegis.intelligence.threat_feeds import IOCIndicator, ThreatFeed

logger = logging.getLogger(__name__)

# Graceful imports
try:
    import importlib
    importlib.import_module("stix2")  # type: ignore[import-untyped]
    _HAS_STIX2 = True
except ImportError:
    _HAS_STIX2 = False

try:
    from taxii2client.v20 import Collection as TAXIICollection  # type: ignore
    _HAS_TAXII = True
except ImportError:
    _HAS_TAXII = False

# --------------------------------------------------------------------------- #
# STIX pattern → IOC extraction
# --------------------------------------------------------------------------- #

# Regex patterns for common STIX indicator patterns
_PATTERN_REGEXES: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "ip",
        "ipv4-addr",
        re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]"),
    ),
    (
        "ip",
        "ipv6-addr",
        re.compile(r"\[ipv6-addr:value\s*=\s*'([^']+)'\]"),
    ),
    (
        "domain",
        "domain-name",
        re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]"),
    ),
    (
        "url",
        "url",
        re.compile(r"\[url:value\s*=\s*'([^']+)'\]"),
    ),
    (
        "hash",
        "file-hash-sha256",
        re.compile(
            r"\[file:hashes\.'?SHA-256'?\s*=\s*'([^']+)'\]",
            re.IGNORECASE,
        ),
    ),
    (
        "hash",
        "file-hash-md5",
        re.compile(
            r"\[file:hashes\.'?MD5'?\s*=\s*'([^']+)'\]",
            re.IGNORECASE,
        ),
    ),
    (
        "hash",
        "file-hash-sha1",
        re.compile(
            r"\[file:hashes\.'?SHA-1'?\s*=\s*'([^']+)'\]",
            re.IGNORECASE,
        ),
    ),
]

# STIX TLP marking → Aegis severity mapping
_TLP_SEVERITY: dict[str, str] = {
    "white": "low",
    "clear": "low",
    "green": "medium",
    "amber": "high",
    "amber+strict": "high",
    "red": "critical",
}


def parse_stix_indicators(
    bundle_data: dict[str, Any],
    source: str = "stix",
) -> list[IOCIndicator]:
    """Extract IOC indicators from a STIX 2.1 bundle dict.

    Parses ``indicator`` objects and extracts values from their
    ``pattern`` field using regex matching.

    Parameters
    ----------
    bundle_data:
        Parsed JSON of a STIX 2.1 bundle (must have ``"objects"`` key).
    source:
        Source name to tag on each IOCIndicator.

    Returns
    -------
    List of IOCIndicator objects extracted from the bundle.
    """
    objects = bundle_data.get("objects", [])
    indicators: list[IOCIndicator] = []
    now = time.time()

    for obj in objects:
        if obj.get("type") != "indicator":
            continue

        pattern = obj.get("pattern", "")
        if not pattern:
            continue

        # Determine severity from labels or TLP markings
        severity = _extract_severity(obj)

        # Extract IOC values from the pattern
        for ioc_type, _stix_type, regex in _PATTERN_REGEXES:
            match = regex.search(pattern)
            if match:
                value = match.group(1)
                indicators.append(IOCIndicator(
                    ioc_type=ioc_type,
                    value=value,
                    source=source,
                    severity=severity,
                    first_seen=now,
                    last_updated=now,
                    metadata={
                        "stix_id": obj.get("id", ""),
                        "stix_name": obj.get("name", ""),
                        "stix_description": obj.get("description", "")[:200],
                        "stix_pattern": pattern,
                        "labels": obj.get("labels", []),
                    },
                ))
                break  # One IOC per indicator object

    return indicators


def _extract_severity(obj: dict[str, Any]) -> str:
    """Determine severity from STIX object labels or markings."""
    labels = [lbl.lower() for lbl in obj.get("labels", [])]

    # Check for explicit severity labels
    for label in labels:
        if "critical" in label:
            return "critical"
        if "high" in label:
            return "high"
        if "low" in label:
            return "low"

    # Check TLP markings
    for marking_ref in obj.get("object_marking_refs", []):
        marking_str = str(marking_ref).lower()
        for tlp, sev in _TLP_SEVERITY.items():
            if tlp in marking_str:
                return sev

    # Check for malicious-activity label
    if "malicious-activity" in labels:
        return "high"

    return "medium"


# --------------------------------------------------------------------------- #
# STIX Bundle Feed (local files or HTTP URLs)
# --------------------------------------------------------------------------- #


class STIXBundleFeed(ThreatFeed):
    """Load IOCs from STIX 2.1 JSON bundle files or HTTP endpoints.

    Can ingest:
    - Local ``.json`` files containing STIX bundles
    - Remote URLs returning STIX JSON (via ``http_client.get()``)

    Parameters
    ----------
    sources:
        List of file paths or URLs to STIX bundles.
    http_client:
        Optional HTTP client (must have ``.get(url, timeout=N)`` → response
        with ``.json()``).  Only needed for URL sources.
    feed_name:
        Name for this feed instance.
    """

    def __init__(
        self,
        sources: list[str] | None = None,
        http_client: Any = None,
        feed_name: str = "stix_bundle",
    ) -> None:
        self._sources = sources or []
        self._http = http_client
        self._feed_name = feed_name

    @property
    def name(self) -> str:
        return self._feed_name

    def fetch(self) -> list[IOCIndicator]:
        """Fetch and parse all configured STIX bundle sources."""
        all_indicators: list[IOCIndicator] = []

        for source in self._sources:
            try:
                bundle = self._load_source(source)
                if bundle:
                    indicators = parse_stix_indicators(
                        bundle, source=self._feed_name,
                    )
                    all_indicators.extend(indicators)
                    logger.info(
                        "STIX feed %s: %d indicators from %s",
                        self._feed_name,
                        len(indicators),
                        source[:80],
                    )
            except Exception:
                logger.warning(
                    "STIX feed %s: failed to load %s",
                    self._feed_name,
                    source[:80],
                    exc_info=True,
                )

        return all_indicators

    def _load_source(self, source: str) -> dict[str, Any] | None:
        """Load a STIX bundle from a file path or URL."""
        # Check if it's a file path
        path = Path(source)
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            return json.loads(text)

        # Try as URL
        if source.startswith(("http://", "https://")):
            if self._http is None:
                logger.warning("HTTP client required for URL source: %s", source)
                return None
            response = self._http.get(source, timeout=30)
            return response.json()

        logger.warning("Unknown STIX source type: %s", source)
        return None


# --------------------------------------------------------------------------- #
# TAXII 2.1 Feed
# --------------------------------------------------------------------------- #


class TAXIIFeed(ThreatFeed):
    """Poll a TAXII 2.1 server collection for STIX indicators.

    Requires the ``taxii2-client`` library.

    Parameters
    ----------
    server_url:
        TAXII server discovery URL.
    collection_id:
        ID of the collection to poll.
    username, password:
        Optional credentials for authenticated feeds.
    feed_name:
        Name for this feed instance.
    """

    def __init__(
        self,
        server_url: str = "",
        collection_id: str = "",
        username: str = "",
        password: str = "",
        feed_name: str = "taxii",
    ) -> None:
        self._server_url = server_url
        self._collection_id = collection_id
        self._username = username
        self._password = password
        self._feed_name = feed_name

    @property
    def name(self) -> str:
        return self._feed_name

    @property
    def is_available(self) -> bool:
        """Whether taxii2-client is installed."""
        return _HAS_TAXII

    def fetch(self) -> list[IOCIndicator]:
        """Poll the TAXII collection and extract IOCs."""
        if not _HAS_TAXII:
            logger.warning("taxii2-client not installed — TAXII feed disabled")
            return []

        if not self._server_url or not self._collection_id:
            logger.warning("TAXII server_url and collection_id required")
            return []

        try:
            collection = TAXIICollection(
                url=f"{self._server_url}/collections/{self._collection_id}",
                user=self._username or None,
                password=self._password or None,
            )
            response = collection.get_objects()
            bundle = json.loads(response.text) if hasattr(response, "text") else response
            return parse_stix_indicators(bundle, source=self._feed_name)
        except Exception:
            logger.warning(
                "TAXII feed %s: failed to poll %s",
                self._feed_name,
                self._server_url,
                exc_info=True,
            )
            return []
