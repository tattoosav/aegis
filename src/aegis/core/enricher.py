"""Event enrichment layer for Aegis.

Enriches AegisEvent objects with threat intelligence IOC lookups,
connection reputation scores, and process context before events
reach the detection pipeline.  All enrichment is best-effort:
failures are logged and never propagate.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from aegis.core.models import AegisEvent

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

logger = logging.getLogger(__name__)

_NETWORK_IP_KEYS = ("dst_ip", "src_ip", "remote_addr")
_DNS_DOMAIN_KEYS = ("domain", "query_name", "hostname")
_FILE_HASH_KEYS = ("sha256", "md5", "sha1")
_THREAT_INTEL_KEYS = (
    "dst_ip", "src_ip", "domain", "query_name",
    "url", "sha256", "md5",
)


class EventEnricher:
    """Enrich events with threat intel and reputation data.

    All enrichment is best-effort: exceptions are logged and swallowed.
    Enrichment fields are added to ``event.data`` with underscore
    prefixes so they are easy to distinguish from raw sensor data.
    """

    def __init__(
        self,
        db: AegisDatabase | None = None,
        threat_feed_manager: Any = None,
    ) -> None:
        self._db = db
        self._threat_feed_manager = threat_feed_manager
        self._events_enriched: int = 0
        self._ioc_matches_found: int = 0
        self._reputation_lookups: int = 0
        self._threat_intel_hits: int = 0

    def enrich(self, event: AegisEvent) -> AegisEvent:
        """Enrich event data in-place.  Returns the same event."""
        data = event.data

        if any(k in data for k in _NETWORK_IP_KEYS):
            try:
                self._enrich_network(event)
            except Exception:
                logger.warning(
                    "Network enrichment failed for %s",
                    event.event_id, exc_info=True,
                )

        if any(k in data for k in _DNS_DOMAIN_KEYS):
            try:
                self._enrich_dns(event)
            except Exception:
                logger.warning(
                    "DNS enrichment failed for %s",
                    event.event_id, exc_info=True,
                )

        if (
            ("path" in data or "file_path" in data)
            and any(k in data for k in _FILE_HASH_KEYS)
        ):
            try:
                self._enrich_file(event)
            except Exception:
                logger.warning(
                    "File enrichment failed for %s",
                    event.event_id, exc_info=True,
                )

        if self._threat_feed_manager is not None:
            try:
                self._enrich_threat_intel(event)
            except Exception:
                logger.warning(
                    "Threat-intel enrichment failed for %s",
                    event.event_id, exc_info=True,
                )

        self._events_enriched += 1
        return event

    def get_stats(self) -> dict[str, int]:
        """Return enrichment statistics."""
        return {
            "events_enriched": self._events_enriched,
            "ioc_matches_found": self._ioc_matches_found,
            "reputation_lookups": self._reputation_lookups,
            "threat_intel_hits": self._threat_intel_hits,
        }

    def _enrich_network(self, event: AegisEvent) -> None:
        """Look up IPs in IOC table and connection reputation."""
        if self._db is None:
            return
        data = event.data
        for key in _NETWORK_IP_KEYS:
            ip = data.get(key)
            if not ip:
                continue
            # IOC lookup -- typed first, then by raw value
            ioc = self._db.lookup_ioc("ipv4-addr", ip)
            if ioc is None:
                matches = self._db.lookup_ioc_by_value(ip)
                if matches:
                    ioc = matches[0]
            if ioc is not None:
                data["_ioc_match"] = True
                data["_ioc_source"] = ioc["source"]
                data["_ioc_severity"] = ioc["severity"]
                self._ioc_matches_found += 1
            # Connection reputation (raw SQL)
            self._reputation_lookups += 1
            with self._db._lock:
                cursor = self._db._conn.execute(
                    "SELECT score FROM connection_reputation "
                    "WHERE address = ?",
                    (ip,),
                )
                row = cursor.fetchone()
            if row is not None:
                data["_reputation_score"] = row[0]

    def _enrich_dns(self, event: AegisEvent) -> None:
        """Look up domains in the IOC table."""
        if self._db is None:
            return
        data = event.data
        for key in _DNS_DOMAIN_KEYS:
            domain = data.get(key)
            if not domain:
                continue
            ioc = self._db.lookup_ioc("domain-name", domain)
            if ioc is None:
                matches = self._db.lookup_ioc_by_value(domain)
                if matches:
                    ioc = matches[0]
            if ioc is not None:
                data["_ioc_match"] = True
                data["_ioc_source"] = ioc["source"]
                data["_ioc_severity"] = ioc["severity"]
                self._ioc_matches_found += 1

    def _enrich_file(self, event: AegisEvent) -> None:
        """Look up file hashes in the IOC table."""
        if self._db is None:
            return
        data = event.data
        hash_type_map = {
            "sha256": "file:hashes.'SHA-256'",
            "md5": "file:hashes.'MD5'",
            "sha1": "file:hashes.'SHA-1'",
        }
        for key in _FILE_HASH_KEYS:
            file_hash = data.get(key)
            if not file_hash:
                continue
            ioc_type = hash_type_map.get(key, key)
            ioc = self._db.lookup_ioc(ioc_type, file_hash)
            if ioc is None:
                matches = self._db.lookup_ioc_by_value(file_hash)
                if matches:
                    ioc = matches[0]
            if ioc is not None:
                data["_ioc_match"] = True
                data["_ioc_source"] = ioc["source"]
                data["_ioc_severity"] = ioc["severity"]
                self._ioc_matches_found += 1
                break  # one match is sufficient

    def _enrich_threat_intel(self, event: AegisEvent) -> None:
        """Check event values against the threat-feed manager.

        Uses ``ThreatFeedManager.lookup()`` which internally checks
        the Bloom filter for fast rejection and falls back to DB.
        """
        data = event.data
        for key in _THREAT_INTEL_KEYS:
            value = data.get(key)
            if not value:
                continue
            result = self._threat_feed_manager.lookup(value)
            if result is not None:
                data["_threat_intel_hit"] = True
                data["_threat_intel_source"] = result.get(
                    "source", "",
                )
                data["_threat_intel_severity"] = result.get(
                    "severity", "",
                )
                self._threat_intel_hits += 1
                return  # one hit is enough
