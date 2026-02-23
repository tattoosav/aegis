"""Tests for EventEnricher — threat-intel IOC, reputation, and bloom-filter enrichment."""

from __future__ import annotations

import time
import uuid
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from aegis.core.database import AegisDatabase
from aegis.core.enricher import EventEnricher
from aegis.core.models import AegisEvent, SensorType, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    sensor: SensorType = SensorType.NETWORK,
    event_type: str = "test",
    data: dict | None = None,
) -> AegisEvent:
    """Create a throwaway AegisEvent for testing."""
    return AegisEvent(
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        timestamp=time.time(),
        sensor=sensor,
        event_type=event_type,
        severity=Severity.INFO,
        data=data or {},
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db(tmp_path):
    """Provide a real AegisDatabase backed by a temp SQLite file."""
    _db = AegisDatabase(tmp_path / "test.db")
    yield _db
    _db.close()


@pytest.fixture()
def enricher(db):
    """Provide an EventEnricher wired to a real database."""
    return EventEnricher(db=db)


@pytest.fixture()
def enricher_no_db():
    """Provide an EventEnricher with no database."""
    return EventEnricher()


# ===================================================================
# TestEnricherInit
# ===================================================================

class TestEnricherInit:
    """Verify constructor and initial state."""

    def test_init_with_db(self, db):
        e = EventEnricher(db=db)
        assert e._db is db

    def test_init_without_db(self):
        e = EventEnricher()
        assert e._db is None
        assert e._threat_feed_manager is None

    def test_init_stats_zero(self):
        e = EventEnricher()
        stats = e.get_stats()
        assert stats["events_enriched"] == 0
        assert stats["ioc_matches_found"] == 0
        assert stats["reputation_lookups"] == 0
        assert stats["threat_intel_hits"] == 0


# ===================================================================
# TestNetworkEnrichment
# ===================================================================

class TestNetworkEnrichment:
    """Enrichment of events carrying IP-address fields."""

    def test_enrich_network_ioc_match(self, db, enricher):
        db.upsert_ioc("ipv4-addr", "10.0.0.1", "unit-test", "high")
        event = _make_event(data={"dst_ip": "10.0.0.1"})
        enricher.enrich(event)

        assert event.data["_ioc_match"] is True
        assert event.data["_ioc_source"] == "unit-test"
        assert event.data["_ioc_severity"] == "high"

    def test_enrich_network_no_match(self, enricher):
        event = _make_event(data={"dst_ip": "192.168.1.1"})
        enricher.enrich(event)
        assert "_ioc_match" not in event.data

    def test_enrich_network_reputation_score(self, db, enricher):
        now = time.time()
        with db._lock:
            db._conn.execute(
                "INSERT INTO connection_reputation "
                "(address, address_type, score, first_seen, "
                "last_seen, total_connections) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("1.2.3.4", "ipv4", 85.0, now, now, 10),
            )
            db._conn.commit()

        event = _make_event(data={"dst_ip": "1.2.3.4"})
        enricher.enrich(event)
        assert event.data["_reputation_score"] == 85.0

    def test_enrich_network_src_ip(self, db, enricher):
        db.upsert_ioc("ipv4-addr", "172.16.0.5", "feed-a", "medium")
        event = _make_event(data={"src_ip": "172.16.0.5"})
        enricher.enrich(event)

        assert event.data["_ioc_match"] is True
        assert event.data["_ioc_source"] == "feed-a"

    def test_enrich_network_remote_addr(self, db, enricher):
        db.upsert_ioc("ipv4-addr", "8.8.8.8", "dns-feed", "low")
        event = _make_event(data={"remote_addr": "8.8.8.8"})
        enricher.enrich(event)

        assert event.data["_ioc_match"] is True
        assert event.data["_ioc_severity"] == "low"

    def test_enrich_network_ioc_by_value_fallback(self, db, enricher):
        # Insert IOC with a non-standard type so lookup_ioc misses,
        # but lookup_ioc_by_value finds it.
        db.upsert_ioc("ip-addr", "203.0.113.5", "fallback-src", "critical")
        event = _make_event(data={"dst_ip": "203.0.113.5"})
        enricher.enrich(event)

        assert event.data["_ioc_match"] is True
        assert event.data["_ioc_source"] == "fallback-src"
        assert event.data["_ioc_severity"] == "critical"

    def test_enrich_network_no_db(self, enricher_no_db):
        event = _make_event(data={"dst_ip": "10.0.0.1"})
        result = enricher_no_db.enrich(event)
        # Must not crash; event returned as-is
        assert result is event
        assert "_ioc_match" not in event.data

    def test_enrich_network_increments_stats(self, db, enricher):
        db.upsert_ioc("ipv4-addr", "10.1.1.1", "src", "high")
        event = _make_event(data={"dst_ip": "10.1.1.1"})
        enricher.enrich(event)

        stats = enricher.get_stats()
        assert stats["events_enriched"] == 1
        assert stats["ioc_matches_found"] >= 1
        assert stats["reputation_lookups"] >= 1


# ===================================================================
# TestDnsEnrichment
# ===================================================================

class TestDnsEnrichment:
    """Enrichment of events carrying domain-related fields."""

    def test_enrich_dns_ioc_match(self, db, enricher):
        db.upsert_ioc("domain-name", "evil.example.com", "dns-bl", "high")
        event = _make_event(
            sensor=SensorType.NETWORK,
            data={"domain": "evil.example.com"},
        )
        enricher.enrich(event)

        assert event.data["_ioc_match"] is True
        assert event.data["_ioc_source"] == "dns-bl"

    def test_enrich_dns_query_name(self, db, enricher):
        db.upsert_ioc(
            "domain-name", "malware.test", "feed-x", "medium",
        )
        event = _make_event(data={"query_name": "malware.test"})
        enricher.enrich(event)
        assert event.data["_ioc_match"] is True

    def test_enrich_dns_hostname(self, db, enricher):
        db.upsert_ioc(
            "domain-name", "c2.bad.org", "ti-feed", "critical",
        )
        event = _make_event(data={"hostname": "c2.bad.org"})
        enricher.enrich(event)

        assert event.data["_ioc_match"] is True
        assert event.data["_ioc_severity"] == "critical"

    def test_enrich_dns_no_match(self, db, enricher):
        event = _make_event(data={"domain": "safe.example.com"})
        enricher.enrich(event)
        assert "_ioc_match" not in event.data

    def test_enrich_dns_fallback_by_value(self, db, enricher):
        # Non-standard IOC type forces fallback to lookup_ioc_by_value
        db.upsert_ioc("hostname", "tricky.test", "fallback", "low")
        event = _make_event(data={"domain": "tricky.test"})
        enricher.enrich(event)

        assert event.data["_ioc_match"] is True
        assert event.data["_ioc_source"] == "fallback"

    def test_enrich_dns_no_db(self, enricher_no_db):
        event = _make_event(data={"domain": "anything.com"})
        result = enricher_no_db.enrich(event)
        assert result is event
        assert "_ioc_match" not in event.data


# ===================================================================
# TestFileEnrichment
# ===================================================================

class TestFileEnrichment:
    """Enrichment of events carrying file-path + hash fields."""

    _SHA256 = "a" * 64

    def test_enrich_file_sha256_match(self, db, enricher):
        db.upsert_ioc(
            "file:hashes.'SHA-256'", self._SHA256, "vt", "high",
        )
        event = _make_event(
            sensor=SensorType.FILE,
            data={"path": "C:\\mal.exe", "sha256": self._SHA256},
        )
        enricher.enrich(event)

        assert event.data["_ioc_match"] is True
        assert event.data["_ioc_source"] == "vt"

    def test_enrich_file_md5_match(self, db, enricher):
        md5 = "d" * 32
        db.upsert_ioc("file:hashes.'MD5'", md5, "md5-feed", "medium")
        event = _make_event(
            sensor=SensorType.FILE,
            data={"file_path": "C:\\tmp\\bad.dll", "md5": md5},
        )
        enricher.enrich(event)
        assert event.data["_ioc_match"] is True

    def test_enrich_file_no_match(self, db, enricher):
        event = _make_event(
            sensor=SensorType.FILE,
            data={"path": "C:\\clean.exe", "sha256": "b" * 64},
        )
        enricher.enrich(event)
        assert "_ioc_match" not in event.data

    def test_enrich_file_requires_path(self, db, enricher):
        # Hash present but no path/file_path key — file enrichment skipped
        db.upsert_ioc(
            "file:hashes.'SHA-256'", self._SHA256, "vt", "high",
        )
        event = _make_event(
            sensor=SensorType.FILE,
            data={"sha256": self._SHA256},
        )
        enricher.enrich(event)
        assert "_ioc_match" not in event.data

    def test_enrich_file_fallback_by_value(self, db, enricher):
        sha = "f" * 64
        db.upsert_ioc("custom-hash", sha, "custom-src", "low")
        event = _make_event(
            sensor=SensorType.FILE,
            data={"path": "C:\\x.exe", "sha256": sha},
        )
        enricher.enrich(event)

        assert event.data["_ioc_match"] is True
        assert event.data["_ioc_source"] == "custom-src"


# ===================================================================
# TestThreatIntelEnrichment
# ===================================================================

class TestThreatIntelEnrichment:
    """Enrichment via the bloom-filter on the threat_feed_manager."""

    def _make_manager(self, bloom_check_result: bool) -> MagicMock:
        """Build a mock threat_feed_manager with a bloom filter."""
        bloom = MagicMock()
        bloom.check.return_value = bloom_check_result
        manager = MagicMock()
        manager.bloom_filter = bloom
        return manager

    def test_enrich_threat_intel_hit(self, db):
        manager = self._make_manager(bloom_check_result=True)
        e = EventEnricher(db=db, threat_feed_manager=manager)
        event = _make_event(data={"dst_ip": "99.99.99.99"})
        e.enrich(event)

        assert event.data["_threat_intel_hit"] is True

    def test_enrich_threat_intel_no_hit(self, db):
        manager = self._make_manager(bloom_check_result=False)
        e = EventEnricher(db=db, threat_feed_manager=manager)
        event = _make_event(data={"dst_ip": "1.1.1.1"})
        e.enrich(event)

        assert "_threat_intel_hit" not in event.data

    def test_enrich_threat_intel_no_manager(self, enricher):
        event = _make_event(data={"dst_ip": "5.5.5.5"})
        enricher.enrich(event)
        assert "_threat_intel_hit" not in event.data

    def test_enrich_threat_intel_no_bloom(self, db):
        manager = MagicMock(spec=[])  # no bloom_filter attr
        e = EventEnricher(db=db, threat_feed_manager=manager)
        event = _make_event(data={"dst_ip": "5.5.5.5"})
        e.enrich(event)
        assert "_threat_intel_hit" not in event.data

    def test_enrich_threat_intel_increments_stats(self, db):
        manager = self._make_manager(bloom_check_result=True)
        e = EventEnricher(db=db, threat_feed_manager=manager)
        event = _make_event(data={"domain": "bad.test"})
        e.enrich(event)

        assert e.get_stats()["threat_intel_hits"] == 1


# ===================================================================
# TestBestEffortBehavior
# ===================================================================

class TestBestEffortBehavior:
    """All enrichment is wrapped in try/except — errors must not propagate."""

    def test_network_error_swallowed(self):
        mock_db = MagicMock()
        mock_db.lookup_ioc.side_effect = RuntimeError("db boom")
        mock_db._lock = MagicMock()
        e = EventEnricher(db=mock_db)
        event = _make_event(data={"dst_ip": "1.2.3.4"})
        result = e.enrich(event)
        assert result is event

    def test_dns_error_swallowed(self):
        mock_db = MagicMock()
        mock_db.lookup_ioc.side_effect = RuntimeError("db boom")
        e = EventEnricher(db=mock_db)
        event = _make_event(data={"domain": "fail.test"})
        result = e.enrich(event)
        assert result is event

    def test_file_error_swallowed(self):
        mock_db = MagicMock()
        mock_db.lookup_ioc.side_effect = RuntimeError("db boom")
        e = EventEnricher(db=mock_db)
        event = _make_event(
            data={"path": "C:\\x.exe", "sha256": "a" * 64},
        )
        result = e.enrich(event)
        assert result is event

    def test_threat_intel_error_swallowed(self):
        manager = MagicMock()
        bloom = MagicMock()
        bloom.check.side_effect = RuntimeError("bloom boom")
        manager.bloom_filter = bloom
        e = EventEnricher(threat_feed_manager=manager)
        event = _make_event(data={"dst_ip": "1.1.1.1"})
        result = e.enrich(event)
        assert result is event

    def test_enrich_always_returns_event(self):
        # Every possible enrichment path fails, still returns event
        mock_db = MagicMock()
        mock_db.lookup_ioc.side_effect = Exception("total failure")
        mock_db._lock = MagicMock()
        manager = MagicMock()
        manager.bloom_filter = MagicMock()
        manager.bloom_filter.check.side_effect = Exception("boom")

        e = EventEnricher(db=mock_db, threat_feed_manager=manager)
        event = _make_event(data={
            "dst_ip": "1.2.3.4",
            "domain": "evil.com",
            "path": "C:\\x.exe",
            "sha256": "c" * 64,
        })
        result = e.enrich(event)
        assert result is event
        assert result.event_id == event.event_id


# ===================================================================
# TestEnricherStats
# ===================================================================

class TestEnricherStats:
    """Verify stat counters accumulate correctly."""

    def test_stats_after_enrichment(self, db, enricher):
        db.upsert_ioc("ipv4-addr", "10.0.0.1", "src", "high")
        event = _make_event(data={"dst_ip": "10.0.0.1"})
        enricher.enrich(event)

        stats = enricher.get_stats()
        assert stats["events_enriched"] == 1
        assert stats["ioc_matches_found"] == 1
        assert stats["reputation_lookups"] == 1

    def test_stats_multiple_events(self, db, enricher):
        for i in range(5):
            event = _make_event(data={"dst_ip": f"192.168.0.{i}"})
            enricher.enrich(event)

        stats = enricher.get_stats()
        assert stats["events_enriched"] == 5
        assert stats["reputation_lookups"] == 5

    def test_ioc_match_counter(self, db, enricher):
        db.upsert_ioc("ipv4-addr", "10.0.0.1", "s1", "high")
        db.upsert_ioc("ipv4-addr", "10.0.0.2", "s2", "medium")

        enricher.enrich(_make_event(data={"dst_ip": "10.0.0.1"}))
        enricher.enrich(_make_event(data={"dst_ip": "10.0.0.2"}))
        enricher.enrich(_make_event(data={"dst_ip": "10.0.0.3"}))

        assert enricher.get_stats()["ioc_matches_found"] == 2

    def test_reputation_lookup_counter(self, db, enricher):
        enricher.enrich(_make_event(data={"dst_ip": "1.1.1.1"}))
        enricher.enrich(_make_event(data={"src_ip": "2.2.2.2"}))

        assert enricher.get_stats()["reputation_lookups"] == 2


# ===================================================================
# TestEnricherIntegration
# ===================================================================

class TestEnricherIntegration:
    """End-to-end enrichment covering multiple enrichment paths."""

    def test_full_enrichment_flow(self, db):
        ip = "44.44.44.44"
        domain = "c2.evil.org"
        sha = "e" * 64
        db.upsert_ioc("ipv4-addr", ip, "net-feed", "high")
        db.upsert_ioc("domain-name", domain, "dns-feed", "critical")
        db.upsert_ioc(
            "file:hashes.'SHA-256'", sha, "hash-feed", "medium",
        )

        manager = MagicMock()
        bloom = MagicMock()
        bloom.check.return_value = True
        manager.bloom_filter = bloom

        e = EventEnricher(db=db, threat_feed_manager=manager)
        event = _make_event(data={
            "dst_ip": ip,
            "domain": domain,
            "path": "C:\\payload.exe",
            "sha256": sha,
        })
        e.enrich(event)

        assert event.data["_ioc_match"] is True
        assert event.data["_threat_intel_hit"] is True
        stats = e.get_stats()
        assert stats["events_enriched"] == 1
        assert stats["ioc_matches_found"] >= 1
        assert stats["threat_intel_hits"] == 1

    def test_enrichment_preserves_original_data(self, db, enricher):
        event = _make_event(data={
            "dst_ip": "10.10.10.10",
            "custom_field": "keep_me",
            "count": 42,
        })
        enricher.enrich(event)

        assert event.data["dst_ip"] == "10.10.10.10"
        assert event.data["custom_field"] == "keep_me"
        assert event.data["count"] == 42

    def test_multiple_events_enriched(self, db, enricher):
        events = [
            _make_event(data={"dst_ip": f"10.0.0.{i}"})
            for i in range(10)
        ]
        for ev in events:
            result = enricher.enrich(ev)
            assert result is ev

        assert enricher.get_stats()["events_enriched"] == 10

    def test_mixed_event_types(self, db, enricher):
        db.upsert_ioc("ipv4-addr", "7.7.7.7", "mix-src", "high")
        db.upsert_ioc(
            "domain-name", "mixed.test", "mix-src", "medium",
        )

        net_event = _make_event(
            sensor=SensorType.NETWORK,
            data={"dst_ip": "7.7.7.7"},
        )
        dns_event = _make_event(
            sensor=SensorType.NETWORK,
            data={"domain": "mixed.test"},
        )
        file_event = _make_event(
            sensor=SensorType.FILE,
            data={"path": "C:\\ok.exe", "sha256": "b" * 64},
        )
        proc_event = _make_event(
            sensor=SensorType.PROCESS,
            data={"pid": 999, "name": "calc.exe"},
        )

        enricher.enrich(net_event)
        enricher.enrich(dns_event)
        enricher.enrich(file_event)
        enricher.enrich(proc_event)

        assert net_event.data["_ioc_match"] is True
        assert dns_event.data["_ioc_match"] is True
        assert "_ioc_match" not in file_event.data
        assert "_ioc_match" not in proc_event.data
        assert enricher.get_stats()["events_enriched"] == 4
