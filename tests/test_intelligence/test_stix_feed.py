"""Tests for the STIX/TAXII threat intelligence feed integration module."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from aegis.intelligence.stix_feed import (
    STIXBundleFeed,
    TAXIIFeed,
    _extract_severity,
    parse_stix_indicators,
)
from aegis.intelligence.threat_feeds import IOCIndicator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_indicator(
    pattern: str,
    *,
    labels: list[str] | None = None,
    name: str = "",
    description: str = "",
    stix_id: str = "indicator--test-001",
    marking_refs: list[str] | None = None,
) -> dict[str, Any]:
    """Build a minimal STIX 2.1 indicator object for testing."""
    obj: dict[str, Any] = {
        "type": "indicator",
        "id": stix_id,
        "pattern": pattern,
    }
    if labels is not None:
        obj["labels"] = labels
    if name:
        obj["name"] = name
    if description:
        obj["description"] = description
    if marking_refs is not None:
        obj["object_marking_refs"] = marking_refs
    return obj


def _make_bundle(objects: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap objects in a STIX 2.1 bundle dict."""
    return {
        "type": "bundle",
        "id": "bundle--test-001",
        "objects": objects,
    }


def _mock_http_response(data: Any) -> MagicMock:
    """Build a mock HTTP response with a ``.json()`` method."""
    resp = MagicMock()
    resp.json.return_value = data
    return resp


def _mock_http_client(data: Any) -> MagicMock:
    """Build a mock HTTP client whose ``.get()`` returns *data*."""
    client = MagicMock()
    client.get.return_value = _mock_http_response(data)
    return client


# ---------------------------------------------------------------------------
# TestParseStixIndicators
# ---------------------------------------------------------------------------


class TestParseStixIndicators:
    """Tests for ``parse_stix_indicators``."""

    def test_extract_ipv4(self) -> None:
        """IPv4 addresses are extracted from ipv4-addr patterns."""
        bundle = _make_bundle([
            _make_indicator("[ipv4-addr:value = '10.0.0.1']"),
        ])
        result = parse_stix_indicators(bundle)
        assert len(result) == 1
        assert result[0].ioc_type == "ip"
        assert result[0].value == "10.0.0.1"

    def test_extract_ipv6(self) -> None:
        """IPv6 addresses are extracted from ipv6-addr patterns."""
        bundle = _make_bundle([
            _make_indicator("[ipv6-addr:value = '2001:db8::1']"),
        ])
        result = parse_stix_indicators(bundle)
        assert len(result) == 1
        assert result[0].ioc_type == "ip"
        assert result[0].value == "2001:db8::1"

    def test_extract_domain(self) -> None:
        """Domain names are extracted from domain-name patterns."""
        bundle = _make_bundle([
            _make_indicator("[domain-name:value = 'evil.example.com']"),
        ])
        result = parse_stix_indicators(bundle)
        assert len(result) == 1
        assert result[0].ioc_type == "domain"
        assert result[0].value == "evil.example.com"

    def test_extract_url(self) -> None:
        """URLs are extracted from url patterns."""
        bundle = _make_bundle([
            _make_indicator(
                "[url:value = 'https://phish.example.com/login']",
            ),
        ])
        result = parse_stix_indicators(bundle)
        assert len(result) == 1
        assert result[0].ioc_type == "url"
        assert result[0].value == "https://phish.example.com/login"

    def test_extract_sha256(self) -> None:
        """SHA-256 hashes are extracted from file:hashes patterns."""
        sha = "a" * 64
        bundle = _make_bundle([
            _make_indicator(
                f"[file:hashes.'SHA-256' = '{sha}']",
            ),
        ])
        result = parse_stix_indicators(bundle)
        assert len(result) == 1
        assert result[0].ioc_type == "hash"
        assert result[0].value == sha

    def test_extract_md5(self) -> None:
        """MD5 hashes are extracted from file:hashes patterns."""
        md5 = "d" * 32
        bundle = _make_bundle([
            _make_indicator(f"[file:hashes.'MD5' = '{md5}']"),
        ])
        result = parse_stix_indicators(bundle)
        assert len(result) == 1
        assert result[0].ioc_type == "hash"
        assert result[0].value == md5

    def test_extract_sha1(self) -> None:
        """SHA-1 hashes are extracted from file:hashes patterns."""
        sha1 = "b" * 40
        bundle = _make_bundle([
            _make_indicator(f"[file:hashes.'SHA-1' = '{sha1}']"),
        ])
        result = parse_stix_indicators(bundle)
        assert len(result) == 1
        assert result[0].ioc_type == "hash"
        assert result[0].value == sha1

    def test_empty_bundle(self) -> None:
        """An empty bundle returns no indicators."""
        bundle = _make_bundle([])
        result = parse_stix_indicators(bundle)
        assert result == []

    def test_no_indicator_objects(self) -> None:
        """Non-indicator objects are ignored."""
        bundle = _make_bundle([
            {"type": "malware", "id": "malware--001", "name": "BadBot"},
            {"type": "identity", "id": "identity--001", "name": "Corp"},
        ])
        result = parse_stix_indicators(bundle)
        assert result == []

    def test_mixed_objects(self) -> None:
        """Only indicator objects are parsed; others are skipped."""
        bundle = _make_bundle([
            {"type": "malware", "id": "malware--001", "name": "Trojan"},
            _make_indicator("[ipv4-addr:value = '192.168.1.1']"),
            {"type": "identity", "id": "identity--001", "name": "Org"},
        ])
        result = parse_stix_indicators(bundle)
        assert len(result) == 1
        assert result[0].value == "192.168.1.1"

    def test_multiple_indicators(self) -> None:
        """Multiple indicator objects each produce one IOC."""
        bundle = _make_bundle([
            _make_indicator(
                "[ipv4-addr:value = '1.1.1.1']",
                stix_id="indicator--a",
            ),
            _make_indicator(
                "[domain-name:value = 'bad.com']",
                stix_id="indicator--b",
            ),
            _make_indicator(
                "[url:value = 'http://evil.org/c2']",
                stix_id="indicator--c",
            ),
        ])
        result = parse_stix_indicators(bundle)
        assert len(result) == 3
        types = {r.ioc_type for r in result}
        assert types == {"ip", "domain", "url"}

    def test_source_tag(self) -> None:
        """The source parameter is applied to every indicator."""
        bundle = _make_bundle([
            _make_indicator("[ipv4-addr:value = '10.0.0.2']"),
        ])
        result = parse_stix_indicators(bundle, source="my_feed")
        assert result[0].source == "my_feed"

    def test_metadata_stix_id(self) -> None:
        """Metadata includes the STIX object id."""
        bundle = _make_bundle([
            _make_indicator(
                "[ipv4-addr:value = '10.0.0.3']",
                stix_id="indicator--meta-test",
            ),
        ])
        result = parse_stix_indicators(bundle)
        assert result[0].metadata["stix_id"] == "indicator--meta-test"

    def test_metadata_name_and_description(self) -> None:
        """Metadata includes stix_name and stix_description."""
        bundle = _make_bundle([
            _make_indicator(
                "[domain-name:value = 'c2.evil.com']",
                name="C2 Domain",
                description="Known command-and-control server",
            ),
        ])
        result = parse_stix_indicators(bundle)
        assert result[0].metadata["stix_name"] == "C2 Domain"
        assert "command-and-control" in result[0].metadata[
            "stix_description"
        ]

    def test_indicator_without_pattern_skipped(self) -> None:
        """Indicator objects without a pattern field are skipped."""
        bundle = _make_bundle([
            {"type": "indicator", "id": "indicator--no-pat"},
        ])
        result = parse_stix_indicators(bundle)
        assert result == []

    def test_bundle_missing_objects_key(self) -> None:
        """A bundle dict with no 'objects' key returns empty list."""
        result = parse_stix_indicators({"type": "bundle"})
        assert result == []


# ---------------------------------------------------------------------------
# TestExtractSeverity
# ---------------------------------------------------------------------------


class TestExtractSeverity:
    """Tests for ``_extract_severity``."""

    def test_critical_label(self) -> None:
        """Label containing 'critical' maps to critical severity."""
        obj = {"labels": ["severity-critical"]}
        assert _extract_severity(obj) == "critical"

    def test_high_label(self) -> None:
        """Label containing 'high' maps to high severity."""
        obj = {"labels": ["severity-high"]}
        assert _extract_severity(obj) == "high"

    def test_low_label(self) -> None:
        """Label containing 'low' maps to low severity."""
        obj = {"labels": ["severity-low"]}
        assert _extract_severity(obj) == "low"

    def test_tlp_white(self) -> None:
        """TLP:WHITE marking maps to low severity."""
        obj = {
            "labels": [],
            "object_marking_refs": [
                "marking-definition--tlp-white",
            ],
        }
        assert _extract_severity(obj) == "low"

    def test_tlp_green(self) -> None:
        """TLP:GREEN marking maps to medium severity."""
        obj = {
            "labels": [],
            "object_marking_refs": [
                "marking-definition--tlp-green",
            ],
        }
        assert _extract_severity(obj) == "medium"

    def test_tlp_amber(self) -> None:
        """TLP:AMBER marking maps to high severity."""
        obj = {
            "labels": [],
            "object_marking_refs": [
                "marking-definition--tlp-amber",
            ],
        }
        assert _extract_severity(obj) == "high"

    def test_tlp_red(self) -> None:
        """TLP:RED marking maps to critical severity."""
        obj = {
            "labels": [],
            "object_marking_refs": [
                "marking-definition--tlp-red",
            ],
        }
        assert _extract_severity(obj) == "critical"

    def test_malicious_activity_label(self) -> None:
        """'malicious-activity' label maps to high severity.

        Note: this is checked *after* explicit severity labels and
        TLP markings, so it acts as a fallback before the default.
        """
        obj = {"labels": ["malicious-activity"]}
        assert _extract_severity(obj) == "high"

    def test_default_medium(self) -> None:
        """No labels and no markings defaults to medium."""
        assert _extract_severity({}) == "medium"
        assert _extract_severity({"labels": []}) == "medium"

    def test_mixed_labels_first_match_wins(self) -> None:
        """When multiple labels exist, first matching label wins.

        Within each label the check order is critical > high > low,
        but labels are processed sequentially, so the first label
        that matches any severity keyword determines the result.
        """
        # "severity-critical" is checked first in this list
        obj_crit = {"labels": ["severity-critical", "severity-low"]}
        assert _extract_severity(obj_crit) == "critical"

        # "severity-low" appears first, matches "low" immediately
        obj_low = {"labels": ["severity-low", "severity-critical"]}
        assert _extract_severity(obj_low) == "low"

    def test_label_case_insensitive(self) -> None:
        """Labels are lowercased before comparison."""
        obj = {"labels": ["Severity-HIGH"]}
        assert _extract_severity(obj) == "high"


# ---------------------------------------------------------------------------
# TestSTIXBundleFeed
# ---------------------------------------------------------------------------


class TestSTIXBundleFeed:
    """Tests for ``STIXBundleFeed``."""

    def test_name_default(self) -> None:
        """Default feed name is 'stix_bundle'."""
        feed = STIXBundleFeed()
        assert feed.name == "stix_bundle"

    def test_name_custom(self) -> None:
        """Feed name can be customized."""
        feed = STIXBundleFeed(feed_name="my_stix")
        assert feed.name == "my_stix"

    def test_fetch_from_file(self, tmp_path: Path) -> None:
        """Indicators are parsed from a local JSON file."""
        bundle = _make_bundle([
            _make_indicator("[ipv4-addr:value = '10.20.30.40']"),
        ])
        bundle_file = tmp_path / "test_bundle.json"
        bundle_file.write_text(json.dumps(bundle), encoding="utf-8")

        feed = STIXBundleFeed(sources=[str(bundle_file)])
        result = feed.fetch()
        assert len(result) == 1
        assert result[0].value == "10.20.30.40"
        assert result[0].source == "stix_bundle"

    def test_fetch_from_url(self) -> None:
        """Indicators are fetched from a URL via http_client."""
        bundle = _make_bundle([
            _make_indicator(
                "[domain-name:value = 'malware.example.com']",
            ),
        ])
        client = _mock_http_client(bundle)
        feed = STIXBundleFeed(
            sources=["https://feeds.example.com/stix.json"],
            http_client=client,
        )
        result = feed.fetch()
        assert len(result) == 1
        assert result[0].value == "malware.example.com"
        client.get.assert_called_once_with(
            "https://feeds.example.com/stix.json",
            timeout=30,
        )

    def test_fetch_multiple_sources(self, tmp_path: Path) -> None:
        """Indicators from multiple sources are aggregated."""
        bundle_a = _make_bundle([
            _make_indicator("[ipv4-addr:value = '1.2.3.4']"),
        ])
        bundle_b = _make_bundle([
            _make_indicator("[domain-name:value = 'bad.org']"),
        ])

        file_a = tmp_path / "a.json"
        file_a.write_text(json.dumps(bundle_a), encoding="utf-8")
        file_b = tmp_path / "b.json"
        file_b.write_text(json.dumps(bundle_b), encoding="utf-8")

        feed = STIXBundleFeed(sources=[str(file_a), str(file_b)])
        result = feed.fetch()
        assert len(result) == 2
        values = {r.value for r in result}
        assert values == {"1.2.3.4", "bad.org"}

    def test_file_not_found_graceful(self, tmp_path: Path) -> None:
        """A missing file is logged and skipped without crashing."""
        missing = str(tmp_path / "nonexistent.json")
        feed = STIXBundleFeed(sources=[missing])
        result = feed.fetch()
        assert result == []

    def test_url_fetch_error_graceful(self) -> None:
        """A failing URL fetch is logged and skipped."""
        client = MagicMock()
        client.get.side_effect = ConnectionError("timeout")
        feed = STIXBundleFeed(
            sources=["https://down.example.com/stix.json"],
            http_client=client,
        )
        result = feed.fetch()
        assert result == []

    def test_empty_bundle_file(self, tmp_path: Path) -> None:
        """A file with an empty bundle produces no indicators."""
        bundle = _make_bundle([])
        bundle_file = tmp_path / "empty.json"
        bundle_file.write_text(json.dumps(bundle), encoding="utf-8")

        feed = STIXBundleFeed(sources=[str(bundle_file)])
        result = feed.fetch()
        assert result == []

    def test_multiple_bundles_mixed(self, tmp_path: Path) -> None:
        """Mix of file and URL sources are all processed."""
        file_bundle = _make_bundle([
            _make_indicator("[ipv4-addr:value = '192.168.0.1']"),
        ])
        url_bundle = _make_bundle([
            _make_indicator(
                "[url:value = 'http://c2.example.com/beacon']",
            ),
        ])

        local_file = tmp_path / "local.json"
        local_file.write_text(
            json.dumps(file_bundle), encoding="utf-8",
        )

        client = _mock_http_client(url_bundle)
        feed = STIXBundleFeed(
            sources=[
                str(local_file),
                "https://remote.example.com/feed.json",
            ],
            http_client=client,
        )
        result = feed.fetch()
        assert len(result) == 2

    def test_http_client_none_for_url(self) -> None:
        """URL source with no http_client returns None from _load_source."""
        feed = STIXBundleFeed(
            sources=["https://no-client.example.com/stix.json"],
            http_client=None,
        )
        result = feed.fetch()
        assert result == []

    def test_unknown_source_type(self) -> None:
        """A source that is neither file nor URL is skipped."""
        feed = STIXBundleFeed(sources=["ftp://weird-protocol/bundle"])
        result = feed.fetch()
        assert result == []

    def test_fetch_no_sources(self) -> None:
        """Feed with no sources returns empty list."""
        feed = STIXBundleFeed()
        assert feed.fetch() == []

    def test_fetch_sets_source_to_feed_name(
        self, tmp_path: Path,
    ) -> None:
        """Parsed indicators use the feed name as their source."""
        bundle = _make_bundle([
            _make_indicator("[ipv4-addr:value = '10.10.10.10']"),
        ])
        f = tmp_path / "named.json"
        f.write_text(json.dumps(bundle), encoding="utf-8")

        feed = STIXBundleFeed(
            sources=[str(f)], feed_name="custom_source",
        )
        result = feed.fetch()
        assert result[0].source == "custom_source"

    def test_fetch_from_file_multiple_indicators(
        self, tmp_path: Path,
    ) -> None:
        """A single file with multiple indicators parses all of them."""
        bundle = _make_bundle([
            _make_indicator(
                "[ipv4-addr:value = '1.1.1.1']",
                stix_id="indicator--1",
            ),
            _make_indicator(
                "[domain-name:value = 'x.com']",
                stix_id="indicator--2",
            ),
            _make_indicator(
                "[url:value = 'http://y.com']",
                stix_id="indicator--3",
            ),
        ])
        f = tmp_path / "multi.json"
        f.write_text(json.dumps(bundle), encoding="utf-8")

        feed = STIXBundleFeed(sources=[str(f)])
        result = feed.fetch()
        assert len(result) == 3

    def test_is_threat_feed_subclass(self) -> None:
        """STIXBundleFeed is a ThreatFeed."""
        from aegis.intelligence.threat_feeds import ThreatFeed
        assert issubclass(STIXBundleFeed, ThreatFeed)

    def test_fetch_resilient_to_partial_failure(
        self, tmp_path: Path,
    ) -> None:
        """One bad source does not prevent others from loading."""
        good_bundle = _make_bundle([
            _make_indicator("[ipv4-addr:value = '8.8.8.8']"),
        ])
        good_file = tmp_path / "good.json"
        good_file.write_text(
            json.dumps(good_bundle), encoding="utf-8",
        )

        bad_file = tmp_path / "bad.json"
        bad_file.write_text("NOT VALID JSON {{{", encoding="utf-8")

        feed = STIXBundleFeed(
            sources=[str(bad_file), str(good_file)],
        )
        result = feed.fetch()
        assert len(result) == 1
        assert result[0].value == "8.8.8.8"


# ---------------------------------------------------------------------------
# TestTAXIIFeed
# ---------------------------------------------------------------------------


class TestTAXIIFeed:
    """Tests for ``TAXIIFeed``."""

    def test_name_default(self) -> None:
        """Default feed name is 'taxii'."""
        feed = TAXIIFeed()
        assert feed.name == "taxii"

    def test_name_custom(self) -> None:
        """Custom feed name is respected."""
        feed = TAXIIFeed(feed_name="my_taxii")
        assert feed.name == "my_taxii"

    def test_is_available_when_installed(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """is_available is True when taxii2-client is installed."""
        import aegis.intelligence.stix_feed as mod
        monkeypatch.setattr(mod, "_HAS_TAXII", True)
        feed = TAXIIFeed()
        assert feed.is_available is True

    def test_is_available_when_missing(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """is_available is False when taxii2-client is absent."""
        import aegis.intelligence.stix_feed as mod
        monkeypatch.setattr(mod, "_HAS_TAXII", False)
        feed = TAXIIFeed()
        assert feed.is_available is False

    def test_fetch_returns_empty_when_unavailable(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """fetch() returns [] when taxii2-client is not installed."""
        import aegis.intelligence.stix_feed as mod
        monkeypatch.setattr(mod, "_HAS_TAXII", False)
        feed = TAXIIFeed(
            server_url="https://taxii.example.com",
            collection_id="col-001",
        )
        result = feed.fetch()
        assert result == []

    def test_fetch_returns_empty_missing_server_url(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """fetch() returns [] when server_url is empty."""
        import aegis.intelligence.stix_feed as mod
        monkeypatch.setattr(mod, "_HAS_TAXII", True)
        feed = TAXIIFeed(
            server_url="",
            collection_id="col-001",
        )
        assert feed.fetch() == []

    def test_fetch_returns_empty_missing_collection_id(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """fetch() returns [] when collection_id is empty."""
        import aegis.intelligence.stix_feed as mod
        monkeypatch.setattr(mod, "_HAS_TAXII", True)
        feed = TAXIIFeed(
            server_url="https://taxii.example.com",
            collection_id="",
        )
        assert feed.fetch() == []

    def test_fetch_success(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Successful TAXII poll parses indicators from response."""
        import aegis.intelligence.stix_feed as mod

        monkeypatch.setattr(mod, "_HAS_TAXII", True)

        bundle = _make_bundle([
            _make_indicator("[ipv4-addr:value = '172.16.0.1']"),
            _make_indicator("[domain-name:value = 'threat.org']"),
        ])
        mock_response = MagicMock()
        mock_response.text = json.dumps(bundle)

        mock_collection_cls = MagicMock()
        mock_collection_instance = MagicMock()
        mock_collection_instance.get_objects.return_value = (
            mock_response
        )
        mock_collection_cls.return_value = mock_collection_instance

        monkeypatch.setattr(
            mod, "TAXIICollection", mock_collection_cls, raising=False,
        )

        feed = TAXIIFeed(
            server_url="https://taxii.example.com",
            collection_id="col-123",
            username="user",
            password="pass",
            feed_name="my_taxii",
        )
        result = feed.fetch()
        assert len(result) == 2
        assert result[0].source == "my_taxii"

        mock_collection_cls.assert_called_once_with(
            url="https://taxii.example.com/collections/col-123",
            user="user",
            password="pass",
        )

    def test_fetch_error_handling(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exceptions during TAXII polling return [] gracefully."""
        import aegis.intelligence.stix_feed as mod

        monkeypatch.setattr(mod, "_HAS_TAXII", True)

        mock_collection_cls = MagicMock()
        mock_collection_cls.return_value.get_objects.side_effect = (
            ConnectionError("server down")
        )
        monkeypatch.setattr(
            mod, "TAXIICollection", mock_collection_cls, raising=False,
        )

        feed = TAXIIFeed(
            server_url="https://taxii.example.com",
            collection_id="col-001",
        )
        result = feed.fetch()
        assert result == []

    def test_is_threat_feed_subclass(self) -> None:
        """TAXIIFeed is a ThreatFeed."""
        from aegis.intelligence.threat_feeds import ThreatFeed
        assert issubclass(TAXIIFeed, ThreatFeed)

    def test_fetch_no_credentials(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TAXII feed passes None for empty username/password."""
        import aegis.intelligence.stix_feed as mod

        monkeypatch.setattr(mod, "_HAS_TAXII", True)

        bundle = _make_bundle([
            _make_indicator("[ipv4-addr:value = '10.0.0.99']"),
        ])
        mock_response = MagicMock()
        mock_response.text = json.dumps(bundle)

        mock_collection_cls = MagicMock()
        mock_collection_cls.return_value.get_objects.return_value = (
            mock_response
        )
        monkeypatch.setattr(
            mod, "TAXIICollection", mock_collection_cls, raising=False,
        )

        feed = TAXIIFeed(
            server_url="https://taxii.example.com",
            collection_id="col-456",
        )
        result = feed.fetch()
        assert len(result) == 1

        # Empty strings should be converted to None
        mock_collection_cls.assert_called_once_with(
            url="https://taxii.example.com/collections/col-456",
            user=None,
            password=None,
        )
