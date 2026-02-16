"""Threat intelligence feed integration.

Fetches IOC (Indicators of Compromise) data from external threat
intelligence feeds and stores them in the local SQLite database.
Uses a Bloom filter for fast negative lookups before querying the DB.

Supported feeds:
  - PhishTank (free, no API key required)
  - AbuseIPDB (requires API key)
  - VirusTotal (requires API key)
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from aegis.core.database import AegisDatabase
from aegis.intelligence.bloom_filter import BloomFilterCache

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class IOCIndicator:
    """A single Indicator of Compromise."""

    ioc_type: str       # "ip", "domain", "url", "hash"
    value: str
    source: str         # feed name, e.g. "phishtank"
    severity: str = "medium"
    first_seen: float = 0.0
    last_updated: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Abstract base feed
# ---------------------------------------------------------------------------


class ThreatFeed(ABC):
    """Abstract base for threat intelligence feeds."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable feed name."""

    @abstractmethod
    def fetch(self) -> list[IOCIndicator]:
        """Fetch IOC indicators from the external source.

        Returns:
            List of IOCIndicator objects. Empty list on failure.
        """


# ---------------------------------------------------------------------------
# Concrete feed implementations
# ---------------------------------------------------------------------------


class PhishTankFeed(ThreatFeed):
    """PhishTank free phishing URL feed.

    Fetches verified phishing URLs from the PhishTank API.
    No API key required for the public JSON endpoint.
    """

    ENDPOINT = "http://data.phishtank.com/data/online-valid.json"

    def __init__(self, http_client: Any = None) -> None:
        self._http = http_client

    @property
    def name(self) -> str:
        return "phishtank"

    def fetch(self) -> list[IOCIndicator]:
        try:
            response = self._http.get(self.ENDPOINT, timeout=30)
            data = response.json()
        except Exception:
            logger.warning("PhishTank fetch failed", exc_info=True)
            return []

        now = time.time()
        indicators: list[IOCIndicator] = []
        for entry in data:
            url = entry.get("url", "")
            if not url:
                continue
            indicators.append(IOCIndicator(
                ioc_type="url",
                value=url,
                source=self.name,
                severity="high",
                first_seen=now,
                last_updated=now,
                metadata={
                    "phish_id": entry.get("phish_id"),
                    "target": entry.get("target", ""),
                },
            ))
        return indicators


class AbuseIPDBFeed(ThreatFeed):
    """AbuseIPDB blacklisted IP feed.

    Requires an API key. Fetches IPs with high abuse confidence score.
    """

    ENDPOINT = "https://api.abuseipdb.com/api/v2/blacklist"

    def __init__(
        self,
        api_key: str = "",
        http_client: Any = None,
        min_confidence: int = 90,
    ) -> None:
        self._api_key = api_key
        self._http = http_client
        self._min_confidence = min_confidence

    @property
    def name(self) -> str:
        return "abuseipdb"

    def fetch(self) -> list[IOCIndicator]:
        if not self._api_key:
            logger.warning("AbuseIPDB API key not configured")
            return []
        try:
            response = self._http.get(
                self.ENDPOINT,
                headers={
                    "Key": self._api_key,
                    "Accept": "application/json",
                },
                params={"confidenceMinimum": str(self._min_confidence)},
                timeout=30,
            )
            data = response.json().get("data", [])
        except Exception:
            logger.warning("AbuseIPDB fetch failed", exc_info=True)
            return []

        now = time.time()
        indicators: list[IOCIndicator] = []
        for entry in data:
            ip = entry.get("ipAddress", "")
            if not ip:
                continue
            confidence = entry.get("abuseConfidenceScore", 0)
            severity = "critical" if confidence >= 95 else "high"
            indicators.append(IOCIndicator(
                ioc_type="ip",
                value=ip,
                source=self.name,
                severity=severity,
                first_seen=now,
                last_updated=now,
                metadata={
                    "abuse_confidence": confidence,
                    "country": entry.get("countryCode", ""),
                },
            ))
        return indicators


class VirusTotalFeed(ThreatFeed):
    """VirusTotal malicious hash feed.

    Requires an API key. Fetches file hashes flagged as malicious.
    Uses the /intelligence/search endpoint.
    """

    ENDPOINT = "https://www.virustotal.com/api/v3/intelligence/search"

    def __init__(
        self,
        api_key: str = "",
        http_client: Any = None,
    ) -> None:
        self._api_key = api_key
        self._http = http_client

    @property
    def name(self) -> str:
        return "virustotal"

    def fetch(self) -> list[IOCIndicator]:
        if not self._api_key:
            logger.warning("VirusTotal API key not configured")
            return []
        try:
            response = self._http.get(
                self.ENDPOINT,
                headers={"x-apikey": self._api_key},
                params={"query": "type:file p:10+ fs:7d-"},
                timeout=30,
            )
            data = response.json().get("data", [])
        except Exception:
            logger.warning("VirusTotal fetch failed", exc_info=True)
            return []

        now = time.time()
        indicators: list[IOCIndicator] = []
        for entry in data:
            sha256 = entry.get("id", "")
            if not sha256:
                continue
            attrs = entry.get("attributes", {})
            detections = attrs.get("last_analysis_stats", {})
            malicious_count = detections.get("malicious", 0)
            severity = "critical" if malicious_count >= 20 else "high"
            indicators.append(IOCIndicator(
                ioc_type="hash",
                value=sha256,
                source=self.name,
                severity=severity,
                first_seen=now,
                last_updated=now,
                metadata={
                    "malicious_count": malicious_count,
                    "file_type": attrs.get("type_description", ""),
                },
            ))
        return indicators


# ---------------------------------------------------------------------------
# ThreatFeedManager
# ---------------------------------------------------------------------------


class ThreatFeedManager:
    """Orchestrates threat feed updates and IOC lookups.

    Uses a Bloom filter for sub-microsecond negative lookups and
    falls back to SQLite for positive matches.

    Args:
        db: AegisDatabase instance.
        bloom_size: Expected number of IOCs for the Bloom filter.
    """

    def __init__(
        self,
        db: AegisDatabase,
        bloom_size: int = 1_000_000,
    ) -> None:
        self._db = db
        self._feeds: list[ThreatFeed] = []
        self._bloom = BloomFilterCache(
            estimated_size=bloom_size,
            fp_rate=0.01,
        )
        self._rebuild_bloom()

    def register_feed(self, feed: ThreatFeed) -> None:
        """Register a threat feed for periodic updates."""
        self._feeds.append(feed)
        logger.info("Registered feed: %s", feed.name)

    def update_feeds(self) -> int:
        """Fetch all registered feeds and store new IOCs.

        Returns:
            Total number of new/updated IOCs across all feeds.
        """
        total = 0
        for feed in self._feeds:
            try:
                indicators = feed.fetch()
                for ioc in indicators:
                    self._db.upsert_ioc(
                        ioc_type=ioc.ioc_type,
                        value=ioc.value,
                        source=ioc.source,
                        severity=ioc.severity,
                        metadata=ioc.metadata,
                    )
                    self._bloom.add(ioc.value)
                total += len(indicators)
                logger.info(
                    "Feed %s: %d indicators fetched",
                    feed.name,
                    len(indicators),
                )
            except Exception:
                logger.warning(
                    "Failed to update feed %s", feed.name,
                    exc_info=True,
                )
        return total

    def lookup(self, value: str) -> dict[str, Any] | None:
        """Look up a value against the IOC database.

        Uses Bloom filter for fast negative rejection.
        Returns the IOC record dict if found, or None.
        """
        if not self._bloom.contains(value):
            return None
        # Bloom says "maybe" — check the real DB
        results = self._db.lookup_ioc_by_value(value)
        return results[0] if results else None

    def lookup_batch(
        self, values: list[str],
    ) -> dict[str, dict[str, Any]]:
        """Look up multiple values. Returns dict of value -> IOC record."""
        results: dict[str, dict[str, Any]] = {}
        for v in values:
            match = self.lookup(v)
            if match is not None:
                results[v] = match
        return results

    @property
    def feed_count(self) -> int:
        """Number of registered feeds."""
        return len(self._feeds)

    @property
    def ioc_count(self) -> int:
        """Total IOC count in the database."""
        return self._db.ioc_count()

    def _rebuild_bloom(self) -> None:
        """Rebuild Bloom filter from all IOC values in the DB."""
        values = self._db.get_all_ioc_values()
        self._bloom.rebuild(values)
        logger.debug(
            "Bloom filter rebuilt with %d IOC values", len(values),
        )
