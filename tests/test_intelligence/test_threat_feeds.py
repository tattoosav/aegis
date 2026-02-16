"""Tests for the threat intelligence feed integration module."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

import pytest

from aegis.core.database import AegisDatabase
from aegis.intelligence.threat_feeds import (
    AbuseIPDBFeed,
    IOCIndicator,
    PhishTankFeed,
    ThreatFeedManager,
    VirusTotalFeed,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def db() -> AegisDatabase:
    """In-memory AegisDatabase for testing."""
    return AegisDatabase(":memory:")


@pytest.fixture()
def manager(db: AegisDatabase) -> ThreatFeedManager:
    """ThreatFeedManager backed by in-memory database."""
    return ThreatFeedManager(db, bloom_size=1000)


@dataclass
class _MockResponse:
    """Minimal mock HTTP response."""

    _json: Any

    def json(self) -> Any:
        return self._json


def _mock_http(return_json: Any) -> MagicMock:
    """Build a mock HTTP client whose .get() returns *return_json*."""
    client = MagicMock()
    client.get.return_value = _MockResponse(return_json)
    return client


# ---------------------------------------------------------------------------
# IOCIndicator dataclass
# ---------------------------------------------------------------------------


class TestIOCIndicator:
    """Tests for the IOCIndicator dataclass."""

    def test_defaults(self) -> None:
        ioc = IOCIndicator(ioc_type="ip", value="1.2.3.4", source="test")
        assert ioc.severity == "medium"
        assert ioc.first_seen == 0.0
        assert ioc.metadata == {}

    def test_custom_fields(self) -> None:
        ioc = IOCIndicator(
            ioc_type="url",
            value="https://evil.com",
            source="phishtank",
            severity="high",
            first_seen=1.0,
            last_updated=2.0,
            metadata={"phish_id": 123},
        )
        assert ioc.ioc_type == "url"
        assert ioc.value == "https://evil.com"
        assert ioc.metadata["phish_id"] == 123


# ---------------------------------------------------------------------------
# PhishTankFeed
# ---------------------------------------------------------------------------


class TestPhishTankFeed:
    """Tests for the PhishTank feed (mocked HTTP)."""

    def test_name(self) -> None:
        feed = PhishTankFeed()
        assert feed.name == "phishtank"

    def test_fetch_parses_results(self) -> None:
        mock_data = [
            {"url": "http://evil1.com/login", "phish_id": 100, "target": "PayPal"},
            {"url": "http://evil2.com/verify", "phish_id": 200, "target": "Apple"},
        ]
        feed = PhishTankFeed(http_client=_mock_http(mock_data))
        results = feed.fetch()
        assert len(results) == 2
        assert results[0].ioc_type == "url"
        assert results[0].value == "http://evil1.com/login"
        assert results[0].source == "phishtank"
        assert results[0].severity == "high"
        assert results[0].metadata["phish_id"] == 100

    def test_fetch_skips_empty_urls(self) -> None:
        mock_data = [
            {"url": "", "phish_id": 1},
            {"url": "http://valid.com", "phish_id": 2},
        ]
        feed = PhishTankFeed(http_client=_mock_http(mock_data))
        results = feed.fetch()
        assert len(results) == 1
        assert results[0].value == "http://valid.com"

    def test_fetch_returns_empty_on_error(self) -> None:
        client = MagicMock()
        client.get.side_effect = ConnectionError("timeout")
        feed = PhishTankFeed(http_client=client)
        results = feed.fetch()
        assert results == []

    def test_fetch_empty_response(self) -> None:
        feed = PhishTankFeed(http_client=_mock_http([]))
        results = feed.fetch()
        assert results == []


# ---------------------------------------------------------------------------
# AbuseIPDBFeed
# ---------------------------------------------------------------------------


class TestAbuseIPDBFeed:
    """Tests for the AbuseIPDB feed (mocked HTTP)."""

    def test_name(self) -> None:
        feed = AbuseIPDBFeed()
        assert feed.name == "abuseipdb"

    def test_fetch_no_api_key_returns_empty(self) -> None:
        feed = AbuseIPDBFeed(api_key="")
        assert feed.fetch() == []

    def test_fetch_parses_results(self) -> None:
        mock_data = {
            "data": [
                {
                    "ipAddress": "10.0.0.1",
                    "abuseConfidenceScore": 99,
                    "countryCode": "US",
                },
                {
                    "ipAddress": "10.0.0.2",
                    "abuseConfidenceScore": 91,
                    "countryCode": "RU",
                },
            ],
        }
        feed = AbuseIPDBFeed(
            api_key="test-key",
            http_client=_mock_http(mock_data),
        )
        results = feed.fetch()
        assert len(results) == 2
        assert results[0].ioc_type == "ip"
        assert results[0].value == "10.0.0.1"
        assert results[0].severity == "critical"  # confidence >= 95
        assert results[1].severity == "high"       # confidence < 95

    def test_fetch_skips_empty_ips(self) -> None:
        mock_data = {"data": [{"ipAddress": "", "abuseConfidenceScore": 99}]}
        feed = AbuseIPDBFeed(
            api_key="key",
            http_client=_mock_http(mock_data),
        )
        assert feed.fetch() == []

    def test_fetch_returns_empty_on_error(self) -> None:
        client = MagicMock()
        client.get.side_effect = Exception("network error")
        feed = AbuseIPDBFeed(api_key="key", http_client=client)
        assert feed.fetch() == []


# ---------------------------------------------------------------------------
# VirusTotalFeed
# ---------------------------------------------------------------------------


class TestVirusTotalFeed:
    """Tests for the VirusTotal feed (mocked HTTP)."""

    def test_name(self) -> None:
        feed = VirusTotalFeed()
        assert feed.name == "virustotal"

    def test_fetch_no_api_key_returns_empty(self) -> None:
        feed = VirusTotalFeed(api_key="")
        assert feed.fetch() == []

    def test_fetch_parses_results(self) -> None:
        mock_data = {
            "data": [
                {
                    "id": "abc123sha256hash",
                    "attributes": {
                        "last_analysis_stats": {"malicious": 25},
                        "type_description": "Win32 EXE",
                    },
                },
                {
                    "id": "def456sha256hash",
                    "attributes": {
                        "last_analysis_stats": {"malicious": 10},
                        "type_description": "PDF",
                    },
                },
            ],
        }
        feed = VirusTotalFeed(
            api_key="test-key",
            http_client=_mock_http(mock_data),
        )
        results = feed.fetch()
        assert len(results) == 2
        assert results[0].ioc_type == "hash"
        assert results[0].value == "abc123sha256hash"
        assert results[0].severity == "critical"   # malicious >= 20
        assert results[1].severity == "high"        # malicious < 20

    def test_fetch_skips_empty_ids(self) -> None:
        mock_data = {"data": [{"id": "", "attributes": {}}]}
        feed = VirusTotalFeed(
            api_key="key",
            http_client=_mock_http(mock_data),
        )
        assert feed.fetch() == []

    def test_fetch_returns_empty_on_error(self) -> None:
        client = MagicMock()
        client.get.side_effect = TimeoutError("slow")
        feed = VirusTotalFeed(api_key="key", http_client=client)
        assert feed.fetch() == []


# ---------------------------------------------------------------------------
# ThreatFeedManager
# ---------------------------------------------------------------------------


class TestThreatFeedManager:
    """Integration tests for the ThreatFeedManager."""

    def test_init_empty(self, manager: ThreatFeedManager) -> None:
        assert manager.feed_count == 0
        assert manager.ioc_count == 0

    def test_register_feed(self, manager: ThreatFeedManager) -> None:
        feed = PhishTankFeed()
        manager.register_feed(feed)
        assert manager.feed_count == 1

    def test_update_feeds_stores_iocs(
        self, manager: ThreatFeedManager,
    ) -> None:
        mock_data = [
            {"url": "http://evil.com/phish", "phish_id": 1, "target": "Bank"},
        ]
        feed = PhishTankFeed(http_client=_mock_http(mock_data))
        manager.register_feed(feed)
        count = manager.update_feeds()
        assert count == 1
        assert manager.ioc_count == 1

    def test_update_multiple_feeds(
        self, manager: ThreatFeedManager,
    ) -> None:
        phish_data = [{"url": "http://phish.com", "phish_id": 1, "target": ""}]
        abuse_data = {
            "data": [
                {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 99, "countryCode": "US"},
            ],
        }
        feed1 = PhishTankFeed(http_client=_mock_http(phish_data))
        feed2 = AbuseIPDBFeed(
            api_key="key",
            http_client=_mock_http(abuse_data),
        )
        manager.register_feed(feed1)
        manager.register_feed(feed2)
        count = manager.update_feeds()
        assert count == 2
        assert manager.ioc_count == 2

    def test_lookup_returns_match(
        self, manager: ThreatFeedManager,
    ) -> None:
        mock_data = [{"url": "http://evil.com", "phish_id": 1, "target": ""}]
        feed = PhishTankFeed(http_client=_mock_http(mock_data))
        manager.register_feed(feed)
        manager.update_feeds()

        result = manager.lookup("http://evil.com")
        assert result is not None
        assert result["value"] == "http://evil.com"
        assert result["ioc_type"] == "url"
        assert result["source"] == "phishtank"

    def test_lookup_returns_none_for_clean(
        self, manager: ThreatFeedManager,
    ) -> None:
        assert manager.lookup("http://safe.com") is None

    def test_lookup_batch(
        self, manager: ThreatFeedManager,
    ) -> None:
        mock_data = [
            {"url": "http://evil1.com", "phish_id": 1, "target": ""},
            {"url": "http://evil2.com", "phish_id": 2, "target": ""},
        ]
        feed = PhishTankFeed(http_client=_mock_http(mock_data))
        manager.register_feed(feed)
        manager.update_feeds()

        results = manager.lookup_batch([
            "http://evil1.com",
            "http://safe.com",
            "http://evil2.com",
        ])
        assert "http://evil1.com" in results
        assert "http://evil2.com" in results
        assert "http://safe.com" not in results

    def test_bloom_filter_fast_negative(
        self, manager: ThreatFeedManager,
    ) -> None:
        """Bloom filter should reject values not in the DB without a query."""
        mock_data = [{"url": "http://known.com", "phish_id": 1, "target": ""}]
        feed = PhishTankFeed(http_client=_mock_http(mock_data))
        manager.register_feed(feed)
        manager.update_feeds()

        # Lookup something not in bloom => should return None quickly
        assert manager.lookup("http://definitely-not-there.xyz") is None

    def test_update_handles_feed_failure(
        self, manager: ThreatFeedManager,
    ) -> None:
        """A failing feed should not block other feeds."""
        # First feed fails
        client_fail = MagicMock()
        client_fail.get.side_effect = Exception("down")
        feed_fail = PhishTankFeed(http_client=client_fail)

        # Second feed succeeds
        mock_data = {
            "data": [
                {"ipAddress": "5.6.7.8", "abuseConfidenceScore": 99, "countryCode": "US"},
            ],
        }
        feed_ok = AbuseIPDBFeed(api_key="key", http_client=_mock_http(mock_data))

        manager.register_feed(feed_fail)
        manager.register_feed(feed_ok)
        count = manager.update_feeds()
        assert count == 1  # Only the successful feed
        assert manager.ioc_count == 1

    def test_upsert_deduplicates(
        self, manager: ThreatFeedManager,
    ) -> None:
        """Inserting the same IOC twice should not create duplicates."""
        mock_data = [{"url": "http://dup.com", "phish_id": 1, "target": ""}]
        feed = PhishTankFeed(http_client=_mock_http(mock_data))
        manager.register_feed(feed)
        manager.update_feeds()
        manager.update_feeds()  # second run
        assert manager.ioc_count == 1  # still just one record

    def test_rebuild_bloom_on_init(self, db: AegisDatabase) -> None:
        """Bloom filter should be rebuilt from DB on manager init."""
        db.upsert_ioc("ip", "1.2.3.4", "manual", "high")
        mgr = ThreatFeedManager(db, bloom_size=1000)
        result = mgr.lookup("1.2.3.4")
        assert result is not None
        assert result["value"] == "1.2.3.4"
