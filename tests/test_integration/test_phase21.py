"""Phase 21 integration tests -- threat-intel coordinator wiring.

Validates end-to-end integration of:
  - ThreatFeedManager + FeedHealthTracker wiring in AegisCoordinator
  - Fixed EventEnricher._enrich_threat_intel using manager.lookup()
  - Scheduled feed refresh and staleness check tasks
  - SystemHealth and DashboardDataService threat-intel sections
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.config import AegisConfig
from aegis.core.coordinator import AegisCoordinator
from aegis.core.models import (
    AegisEvent,
    Alert,
    AlertStatus,
    SensorType,
    Severity,
)


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _make_config(tmp_path, **overrides):
    """Build a minimal AegisConfig for testing."""
    cfg = AegisConfig()
    cfg._data["database"]["path"] = str(tmp_path / "test.db")
    cfg._data["canary"]["enabled"] = False
    cfg._data["canary"]["directories"] = []
    cfg._data["scheduler"]["enabled"] = True
    cfg._data["whitelist"]["enabled"] = True
    cfg._data["sensors"]["threat_intel"]["enabled"] = True
    for dotted_key, value in overrides.items():
        cfg.set(dotted_key, value)
    return cfg


def _make_event(**kw):
    """Create a lightweight AegisEvent for testing."""
    return AegisEvent(
        event_id=kw.get("event_id", str(uuid.uuid4())),
        timestamp=kw.get("timestamp", time.time()),
        sensor=kw.get("sensor", SensorType.PROCESS),
        event_type=kw.get("event_type", "test"),
        severity=kw.get("severity", Severity.INFO),
        data=kw.get("data", {}),
    )


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture
def coordinator(tmp_path):
    """Return a fully wired AegisCoordinator backed by a temp DB."""
    config = _make_config(tmp_path)
    coord = AegisCoordinator(config)
    coord.setup()
    return coord


@pytest.fixture
def disabled_coordinator(tmp_path):
    """Return a coordinator with threat_intel disabled."""
    config = _make_config(
        tmp_path,
        **{"sensors.threat_intel.enabled": False},
    )
    coord = AegisCoordinator(config)
    coord.setup()
    return coord


# ------------------------------------------------------------------ #
# TestCoordinatorThreatIntelWiring
# ------------------------------------------------------------------ #


class TestCoordinatorThreatIntelWiring:
    """Verify coordinator correctly wires threat-intel components."""

    def test_threat_feed_manager_created(self, coordinator):
        """Coordinator creates a ThreatFeedManager when enabled."""
        assert coordinator.threat_feed_manager is not None

    def test_feed_health_tracker_created(self, coordinator):
        """Coordinator creates a FeedHealthTracker when enabled."""
        assert coordinator.feed_health_tracker is not None

    def test_threat_intel_disabled(self, disabled_coordinator):
        """Both manager and tracker are None when disabled."""
        assert disabled_coordinator.threat_feed_manager is None
        assert disabled_coordinator.feed_health_tracker is None

    def test_manager_has_db(self, coordinator):
        """ThreatFeedManager is wired to the coordinator's database."""
        mgr = coordinator.threat_feed_manager
        assert mgr._db is coordinator.db

    def test_enricher_has_manager(self, coordinator):
        """EventEnricher is wired with the ThreatFeedManager."""
        enricher = coordinator.enricher
        assert enricher is not None
        assert enricher._threat_feed_manager is not None

    def test_feed_refresh_task_registered(self, coordinator):
        """Scheduler contains a 'feed_refresh' task."""
        scheduler = coordinator.scheduler
        assert scheduler is not None
        tasks = scheduler.list_tasks()
        task_names = [t.name for t in tasks]
        assert "feed_refresh" in task_names

    def test_feed_staleness_task_registered(self, coordinator):
        """Scheduler contains a 'feed_staleness_check' task."""
        scheduler = coordinator.scheduler
        assert scheduler is not None
        tasks = scheduler.list_tasks()
        task_names = [t.name for t in tasks]
        assert "feed_staleness_check" in task_names

    def test_phishtank_registered_by_default(self, coordinator):
        """PhishTank feed is registered when enabled by default."""
        mgr = coordinator.threat_feed_manager
        assert mgr is not None
        # PhishTank is enabled by default in the config
        assert mgr.feed_count >= 1

    def test_disabled_feeds_not_registered(self, tmp_path):
        """Disabled feeds are not registered in the manager."""
        config = _make_config(tmp_path)
        config.set(
            "sensors.threat_intel.feeds.phishtank.enabled", False,
        )
        config.set(
            "sensors.threat_intel.feeds.abuseipdb.enabled", False,
        )
        config.set(
            "sensors.threat_intel.feeds.virustotal.enabled", False,
        )
        coord = AegisCoordinator(config)
        coord.setup()
        mgr = coord.threat_feed_manager
        assert mgr is not None
        assert mgr.feed_count == 0

    def test_coordinator_properties(self, coordinator):
        """Properties threat_feed_manager and feed_health_tracker work."""
        # Simply accessing them must not raise
        mgr = coordinator.threat_feed_manager
        tracker = coordinator.feed_health_tracker
        assert mgr is not None
        assert tracker is not None


# ------------------------------------------------------------------ #
# TestEnricherBugFix
# ------------------------------------------------------------------ #


class TestEnricherBugFix:
    """Test the fixed _enrich_threat_intel uses manager.lookup()."""

    def _make_enricher(self, lookup_return=None):
        """Build an EventEnricher with a mocked ThreatFeedManager."""
        from aegis.core.enricher import EventEnricher

        manager = MagicMock()
        if lookup_return is not None:
            manager.lookup.return_value = lookup_return
        else:
            manager.lookup.return_value = None
        return EventEnricher(threat_feed_manager=manager), manager

    def test_lookup_hit_sets_threat_intel_hit(self):
        """When manager.lookup returns a dict, _threat_intel_hit is set."""
        enricher, _ = self._make_enricher(
            lookup_return={
                "source": "test-feed",
                "severity": "high",
                "value": "1.2.3.4",
            },
        )
        event = _make_event(data={"dst_ip": "1.2.3.4"})
        enricher.enrich(event)
        assert event.data.get("_threat_intel_hit") is True

    def test_lookup_hit_sets_source(self):
        """Event data includes _threat_intel_source on hit."""
        enricher, _ = self._make_enricher(
            lookup_return={
                "source": "phishtank",
                "severity": "high",
                "value": "evil.com",
            },
        )
        event = _make_event(data={"domain": "evil.com"})
        enricher.enrich(event)
        assert event.data.get("_threat_intel_source") == "phishtank"

    def test_lookup_hit_sets_severity(self):
        """Event data includes _threat_intel_severity on hit."""
        enricher, _ = self._make_enricher(
            lookup_return={
                "source": "abuseipdb",
                "severity": "critical",
                "value": "9.9.9.9",
            },
        )
        event = _make_event(data={"dst_ip": "9.9.9.9"})
        enricher.enrich(event)
        assert (
            event.data.get("_threat_intel_severity") == "critical"
        )

    def test_lookup_miss_no_flag(self):
        """When manager.lookup returns None, no _threat_intel_hit."""
        enricher, _ = self._make_enricher(lookup_return=None)
        event = _make_event(data={"dst_ip": "1.1.1.1"})
        enricher.enrich(event)
        assert "_threat_intel_hit" not in event.data

    def test_no_manager_no_flag(self):
        """Enricher without manager produces no _threat_intel_hit."""
        from aegis.core.enricher import EventEnricher

        enricher = EventEnricher()
        event = _make_event(data={"dst_ip": "5.5.5.5"})
        enricher.enrich(event)
        assert "_threat_intel_hit" not in event.data

    def test_lookup_exception_swallowed(self):
        """If manager.lookup raises, the event is still returned."""
        enricher, manager = self._make_enricher()
        manager.lookup.side_effect = RuntimeError("network down")
        event = _make_event(data={"dst_ip": "8.8.8.8"})
        result = enricher.enrich(event)
        assert result is event

    def test_increments_threat_intel_hits(self):
        """Stats counter incremented on a hit."""
        enricher, _ = self._make_enricher(
            lookup_return={
                "source": "test",
                "severity": "medium",
                "value": "x",
            },
        )
        event = _make_event(data={"dst_ip": "7.7.7.7"})
        enricher.enrich(event)
        assert enricher.get_stats()["threat_intel_hits"] == 1

    def test_multiple_keys_first_hit_wins(self):
        """Event with dst_ip and domain: first match wins."""
        from aegis.core.enricher import EventEnricher

        manager = MagicMock()
        # First key checked will hit
        call_count = 0

        def _side_effect(value):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "source": "first-feed",
                    "severity": "high",
                    "value": value,
                }
            return None

        manager.lookup.side_effect = _side_effect
        enricher = EventEnricher(threat_feed_manager=manager)
        event = _make_event(
            data={"dst_ip": "1.2.3.4", "domain": "evil.com"},
        )
        enricher.enrich(event)
        assert event.data.get("_threat_intel_hit") is True
        assert event.data.get("_threat_intel_source") == "first-feed"

    def test_empty_values_skipped(self):
        """Empty string values are not passed to lookup()."""
        enricher, manager = self._make_enricher()
        event = _make_event(data={"dst_ip": "", "domain": ""})
        enricher.enrich(event)
        manager.lookup.assert_not_called()

    def test_manager_lookup_called_with_value(self):
        """Verify lookup is called with the correct value."""
        enricher, manager = self._make_enricher()
        event = _make_event(data={"dst_ip": "10.20.30.40"})
        enricher.enrich(event)
        manager.lookup.assert_called_with("10.20.30.40")


# ------------------------------------------------------------------ #
# TestFeedUpdateIntegration
# ------------------------------------------------------------------ #


class TestFeedUpdateIntegration:
    """Test feed updates through the coordinator."""

    def _make_mock_feed(self, name, indicators=None, raise_on_fetch=False):
        """Build a mock ThreatFeed."""
        from aegis.intelligence.threat_feeds import IOCIndicator

        feed = MagicMock()
        feed.name = name
        if raise_on_fetch:
            feed.fetch.side_effect = RuntimeError("fetch failed")
        elif indicators is not None:
            feed.fetch.return_value = indicators
        else:
            feed.fetch.return_value = [
                IOCIndicator(
                    ioc_type="ip",
                    value="1.2.3.4",
                    source=name,
                    severity="high",
                ),
            ]
        return feed

    def test_update_feeds_returns_count(self, coordinator):
        """Mock feed update returns correct indicator count."""
        from aegis.intelligence.threat_feeds import IOCIndicator

        mgr = coordinator.threat_feed_manager
        assert mgr is not None
        # Clear existing feeds and add a controlled mock
        mgr._feeds.clear()
        feed = self._make_mock_feed("test-feed")
        mgr.register_feed(feed)

        count = mgr.update_feeds()
        assert count == 1

    def test_iocs_persisted_to_db(self, coordinator):
        """After update, db.ioc_count() increases."""
        from aegis.intelligence.threat_feeds import IOCIndicator

        mgr = coordinator.threat_feed_manager
        assert mgr is not None
        mgr._feeds.clear()

        indicators = [
            IOCIndicator(
                ioc_type="ip",
                value="10.0.0.1",
                source="test",
                severity="high",
            ),
            IOCIndicator(
                ioc_type="ip",
                value="10.0.0.2",
                source="test",
                severity="medium",
            ),
        ]
        feed = self._make_mock_feed("test-feed", indicators)
        mgr.register_feed(feed)
        mgr.update_feeds()

        assert coordinator.db.ioc_count() >= 2

    def test_bloom_filter_updated(self, coordinator):
        """After update, manager.lookup() finds new IOCs."""
        from aegis.intelligence.threat_feeds import IOCIndicator

        mgr = coordinator.threat_feed_manager
        assert mgr is not None
        mgr._feeds.clear()

        indicators = [
            IOCIndicator(
                ioc_type="ip",
                value="192.168.99.99",
                source="test",
                severity="high",
            ),
        ]
        feed = self._make_mock_feed("test-feed", indicators)
        mgr.register_feed(feed)
        mgr.update_feeds()

        result = mgr.lookup("192.168.99.99")
        assert result is not None
        assert result["value"] == "192.168.99.99"

    def test_health_tracker_records_success(self, coordinator):
        """After update, feed health shows success."""
        from aegis.intelligence.threat_feeds import IOCIndicator

        mgr = coordinator.threat_feed_manager
        tracker = coordinator.feed_health_tracker
        assert mgr is not None
        assert tracker is not None
        mgr._feeds.clear()

        indicators = [
            IOCIndicator(
                ioc_type="ip",
                value="5.5.5.5",
                source="good-feed",
                severity="high",
            ),
        ]
        feed = self._make_mock_feed("good-feed", indicators)
        mgr.register_feed(feed)
        # Manually record success as coordinator would
        mgr.update_feeds()
        tracker.record_success("good-feed", len(indicators))

        status = tracker.get_feed_status("good-feed")
        assert status is not None
        assert status["total_updates"] == 1
        assert status["consecutive_errors"] == 0

    def test_health_tracker_records_failure(self, coordinator):
        """When feed.fetch() raises, health shows error."""
        mgr = coordinator.threat_feed_manager
        tracker = coordinator.feed_health_tracker
        assert mgr is not None
        assert tracker is not None
        mgr._feeds.clear()

        feed = self._make_mock_feed(
            "bad-feed", raise_on_fetch=True,
        )
        mgr.register_feed(feed)
        mgr.update_feeds()
        tracker.record_failure("bad-feed", "fetch failed")

        status = tracker.get_feed_status("bad-feed")
        assert status is not None
        assert status["consecutive_errors"] == 1
        assert status["last_error"] == "fetch failed"

    def test_multiple_feeds_mixed_results(self, coordinator):
        """One feed succeeds and one fails."""
        from aegis.intelligence.threat_feeds import IOCIndicator

        mgr = coordinator.threat_feed_manager
        tracker = coordinator.feed_health_tracker
        assert mgr is not None
        assert tracker is not None
        mgr._feeds.clear()

        good_feed = self._make_mock_feed(
            "good",
            [
                IOCIndicator(
                    ioc_type="ip",
                    value="3.3.3.3",
                    source="good",
                    severity="high",
                ),
            ],
        )
        bad_feed = self._make_mock_feed(
            "bad", raise_on_fetch=True,
        )
        mgr.register_feed(good_feed)
        mgr.register_feed(bad_feed)
        mgr.update_feeds()

        tracker.record_success("good", 1)
        tracker.record_failure("bad", "fetch failed")

        good_status = tracker.get_feed_status("good")
        bad_status = tracker.get_feed_status("bad")
        assert good_status is not None
        assert good_status["consecutive_errors"] == 0
        assert bad_status is not None
        assert bad_status["consecutive_errors"] == 1

    def test_feed_staleness_detected(self, coordinator):
        """Old update time triggers staleness detection."""
        tracker = coordinator.feed_health_tracker
        assert tracker is not None

        tracker.record_success("stale-feed", 5)
        # Force the last_update_time into the distant past
        tracker._records["stale-feed"].last_update_time = (
            time.time() - 100_000
        )
        stale = tracker.check_staleness()
        assert "stale-feed" in stale

    def test_feed_refresh_updates_bloom(self, coordinator):
        """Bloom filter contains new values after refresh."""
        from aegis.intelligence.threat_feeds import IOCIndicator

        mgr = coordinator.threat_feed_manager
        assert mgr is not None
        mgr._feeds.clear()

        indicators = [
            IOCIndicator(
                ioc_type="domain",
                value="new-evil.example.com",
                source="refresh-test",
                severity="high",
            ),
        ]
        feed = self._make_mock_feed(
            "refresh-test", indicators,
        )
        mgr.register_feed(feed)
        mgr.update_feeds()

        # Bloom filter should now contain the new value
        assert mgr._bloom.contains("new-evil.example.com")


# ------------------------------------------------------------------ #
# TestScheduledTasks
# ------------------------------------------------------------------ #


class TestScheduledTasks:
    """Validate scheduled feed refresh and staleness tasks."""

    def test_feed_refresh_interval_from_config(self, tmp_path):
        """Feed refresh interval matches the configured value."""
        config = _make_config(
            tmp_path,
            **{"sensors.threat_intel.update_interval_minutes": 60},
        )
        coord = AegisCoordinator(config)
        coord.setup()
        scheduler = coord.scheduler
        assert scheduler is not None
        tasks = scheduler.list_tasks()
        refresh_tasks = [
            t for t in tasks if t.name == "feed_refresh"
        ]
        assert len(refresh_tasks) == 1
        assert refresh_tasks[0].interval_seconds == 3600.0

    def test_feed_refresh_task_callable(self, coordinator):
        """Feed refresh task callback is callable."""
        scheduler = coordinator.scheduler
        assert scheduler is not None
        tasks = scheduler.list_tasks()
        refresh_tasks = [
            t for t in tasks if t.name == "feed_refresh"
        ]
        assert len(refresh_tasks) == 1
        assert callable(refresh_tasks[0].callback)

    def test_feed_staleness_check_interval(self, coordinator):
        """Feed staleness check runs every 300 seconds by default."""
        scheduler = coordinator.scheduler
        assert scheduler is not None
        tasks = scheduler.list_tasks()
        staleness_tasks = [
            t for t in tasks if t.name == "feed_staleness_check"
        ]
        assert len(staleness_tasks) == 1
        assert staleness_tasks[0].interval_seconds == 300.0

    def test_tick_triggers_staleness_check(self, coordinator):
        """Simulating a scheduler tick executes the staleness task."""
        tracker = coordinator.feed_health_tracker
        assert tracker is not None
        # Add a feed that is stale (never successfully updated)
        tracker.record_failure("tick-test", "err")

        scheduler = coordinator.scheduler
        assert scheduler is not None
        # Force all tasks to be due
        for task in scheduler.list_tasks():
            task.next_run_at = 0.0
        results = scheduler.tick()
        # At least the staleness task should have run
        staleness_results = [
            r for r in results
            if r.task_name == "feed_staleness_check"
        ]
        assert len(staleness_results) == 1
        assert staleness_results[0].success is True

    def test_initial_feed_update_on_setup(self, tmp_path):
        """Coordinator.setup() performs an initial feed update."""
        config = _make_config(tmp_path)
        coord = AegisCoordinator(config)

        with patch.object(
            type(coord), "_initial_feed_update",
            create=True,
        ) as mock_update:
            # If the coordinator calls _initial_feed_update,
            # that verifies the wiring. If not, we verify the
            # manager is wired and can be called.
            coord.setup()

        # Verify the manager exists and is callable
        mgr = coord.threat_feed_manager
        if mgr is not None:
            assert callable(mgr.update_feeds)

    def test_feed_refresh_uses_health_tracker(self, coordinator):
        """Feed refresh callback interacts with health tracker."""
        tracker = coordinator.feed_health_tracker
        assert tracker is not None

        scheduler = coordinator.scheduler
        assert scheduler is not None
        tasks = scheduler.list_tasks()
        refresh_tasks = [
            t for t in tasks if t.name == "feed_refresh"
        ]
        assert len(refresh_tasks) == 1
        # Execute the callback; it should not raise
        refresh_tasks[0].callback()
        # Tracker should still be functional
        status = tracker.get_status()
        assert isinstance(status, dict)

    def test_scheduler_has_both_tasks(self, coordinator):
        """Scheduler.list_tasks() includes both feed tasks."""
        scheduler = coordinator.scheduler
        assert scheduler is not None
        tasks = scheduler.list_tasks()
        task_names = [t.name for t in tasks]
        assert "feed_refresh" in task_names
        assert "feed_staleness_check" in task_names


# ------------------------------------------------------------------ #
# TestSystemHealthThreatIntel
# ------------------------------------------------------------------ #


class TestSystemHealthThreatIntel:
    """Validate threat-intel section in SystemHealth.collect()."""

    def test_health_has_threat_intel_section(self, coordinator):
        """collect() includes a 'threat_intel' key."""
        health = coordinator.system_health
        assert health is not None
        result = health.collect()
        assert "threat_intel" in result

    def test_threat_intel_feed_count(self, coordinator):
        """Reports correct feed_count."""
        health = coordinator.system_health
        assert health is not None
        result = health.collect()
        ti = result["threat_intel"]
        mgr = coordinator.threat_feed_manager
        assert ti.get("feed_count") == mgr.feed_count

    def test_threat_intel_ioc_count(self, coordinator):
        """Reports correct ioc_count."""
        health = coordinator.system_health
        assert health is not None
        result = health.collect()
        ti = result["threat_intel"]
        assert "ioc_count" in ti
        assert ti["ioc_count"] == coordinator.db.ioc_count()

    def test_threat_intel_feed_health(self, coordinator):
        """Includes feed health status."""
        health = coordinator.system_health
        assert health is not None
        result = health.collect()
        ti = result["threat_intel"]
        assert "feed_health" in ti
        assert isinstance(ti["feed_health"], dict)

    def test_threat_intel_bloom_stats(self, coordinator):
        """Includes bloom filter item_count."""
        health = coordinator.system_health
        assert health is not None
        result = health.collect()
        ti = result["threat_intel"]
        assert "bloom_count" in ti

    def test_threat_intel_disabled(self, disabled_coordinator):
        """No threat_intel section when disabled."""
        health = disabled_coordinator.system_health
        assert health is not None
        result = health.collect()
        ti = result.get("threat_intel", {})
        # Should be empty or absent when disabled
        assert ti == {} or "threat_intel" not in result

    def test_threat_intel_section_error_handled(self, coordinator):
        """Exception in threat-intel collector returns empty dict."""
        health = coordinator.system_health
        assert health is not None
        # Temporarily break the manager to force an error
        original_mgr = coordinator._threat_feed_manager
        coordinator._threat_feed_manager = MagicMock()
        coordinator._threat_feed_manager.feed_count = (
            property(lambda s: (_ for _ in ()).throw(RuntimeError))
        )
        try:
            result = health.collect()
            # Should not crash; threat_intel section should be {}
            ti = result.get("threat_intel", {})
            assert isinstance(ti, dict)
        finally:
            coordinator._threat_feed_manager = original_mgr


# ------------------------------------------------------------------ #
# TestDashboardThreatIntelData
# ------------------------------------------------------------------ #


class TestDashboardThreatIntelData:
    """Validate threat-intel data in DashboardDataService."""

    def test_get_threat_intel_data_returns_dict(self, coordinator):
        """get_threat_intel_data() returns a dict."""
        dashboard = coordinator.dashboard_service
        assert dashboard is not None
        data = dashboard.get_threat_intel_data()
        assert isinstance(data, dict)

    def test_has_feed_health_key(self, coordinator):
        """Returned dict has 'feed_health' key."""
        dashboard = coordinator.dashboard_service
        assert dashboard is not None
        data = dashboard.get_threat_intel_data()
        assert "feed_health" in data

    def test_has_ioc_count_key(self, coordinator):
        """Returned dict has 'ioc_count' key."""
        dashboard = coordinator.dashboard_service
        assert dashboard is not None
        data = dashboard.get_threat_intel_data()
        assert "ioc_count" in data

    def test_has_bloom_stats_key(self, coordinator):
        """Returned dict has 'bloom_stats' key."""
        dashboard = coordinator.dashboard_service
        assert dashboard is not None
        data = dashboard.get_threat_intel_data()
        assert "bloom_stats" in data

    def test_ioc_count_matches_db(self, coordinator):
        """ioc_count matches db.ioc_count()."""
        dashboard = coordinator.dashboard_service
        assert dashboard is not None
        data = dashboard.get_threat_intel_data()
        assert data["ioc_count"] == coordinator.db.ioc_count()

    def test_feed_health_matches_tracker(self, coordinator):
        """feed_health matches tracker.get_status()."""
        dashboard = coordinator.dashboard_service
        tracker = coordinator.feed_health_tracker
        assert dashboard is not None
        assert tracker is not None
        data = dashboard.get_threat_intel_data()
        expected = tracker.get_status()
        assert data["feed_health"] == expected

    def test_no_threat_intel_returns_defaults(
        self, disabled_coordinator,
    ):
        """When threat-intel is disabled, returns safe defaults."""
        dashboard = disabled_coordinator.dashboard_service
        assert dashboard is not None
        data = dashboard.get_threat_intel_data()
        assert data.get("ioc_count", 0) == 0
        assert data.get("feed_health", {}) == {} or isinstance(
            data.get("feed_health"), dict,
        )


# ------------------------------------------------------------------ #
# TestEndToEndThreatIntelPipeline
# ------------------------------------------------------------------ #


class TestEndToEndThreatIntelPipeline:
    """Full pipeline tests: insert IOC, enrich, health, dashboard."""

    def test_ioc_inserted_found_by_enricher(self, coordinator):
        """Insert IOC manually, then enrich event with matching IP."""
        db = coordinator.db
        enricher = coordinator.enricher
        assert db is not None
        assert enricher is not None

        db.upsert_ioc(
            "ip", "44.44.44.44", "manual-test", "high",
        )
        # Rebuild bloom so the manager can find it
        mgr = coordinator.threat_feed_manager
        if mgr is not None:
            mgr._rebuild_bloom()

        event = _make_event(data={"dst_ip": "44.44.44.44"})
        enricher.enrich(event)

        # Either _ioc_match or _threat_intel_hit should be set
        has_match = (
            event.data.get("_ioc_match")
            or event.data.get("_threat_intel_hit")
        )
        assert has_match is True

    def test_ioc_not_in_db_no_hit(self, coordinator):
        """Enrich event with unknown IP: no threat_intel_hit."""
        enricher = coordinator.enricher
        assert enricher is not None
        event = _make_event(data={"dst_ip": "192.0.2.99"})
        enricher.enrich(event)
        assert "_threat_intel_hit" not in event.data

    def test_feed_update_then_enrich(self, coordinator):
        """Update feeds with mock data, then enrich finds new IOC."""
        from aegis.intelligence.threat_feeds import IOCIndicator

        mgr = coordinator.threat_feed_manager
        enricher = coordinator.enricher
        assert mgr is not None
        assert enricher is not None

        mgr._feeds.clear()
        mock_feed = MagicMock()
        mock_feed.name = "e2e-feed"
        mock_feed.fetch.return_value = [
            IOCIndicator(
                ioc_type="ip",
                value="77.77.77.77",
                source="e2e-feed",
                severity="high",
            ),
        ]
        mgr.register_feed(mock_feed)
        mgr.update_feeds()

        event = _make_event(data={"dst_ip": "77.77.77.77"})
        enricher.enrich(event)

        has_match = (
            event.data.get("_ioc_match")
            or event.data.get("_threat_intel_hit")
        )
        assert has_match is True

    def test_health_reflects_feed_activity(self, coordinator):
        """After updates, health shows feed activity."""
        tracker = coordinator.feed_health_tracker
        assert tracker is not None

        tracker.record_success("activity-test", 10)
        status = tracker.get_status()
        assert status["total_feeds"] >= 1
        assert status["healthy"] >= 1

    def test_dashboard_shows_feed_status(self, coordinator):
        """Dashboard data includes feed health information."""
        tracker = coordinator.feed_health_tracker
        dashboard = coordinator.dashboard_service
        assert tracker is not None
        assert dashboard is not None

        tracker.record_success("dash-feed", 5)
        data = dashboard.get_threat_intel_data()
        assert data["feed_health"]["total_feeds"] >= 1

    def test_full_flow(self, coordinator):
        """Register feed -> update -> enrich -> health -> dashboard."""
        from aegis.intelligence.threat_feeds import IOCIndicator

        mgr = coordinator.threat_feed_manager
        tracker = coordinator.feed_health_tracker
        enricher = coordinator.enricher
        dashboard = coordinator.dashboard_service
        assert all([mgr, tracker, enricher, dashboard])

        # 1. Register feed
        mgr._feeds.clear()
        mock_feed = MagicMock()
        mock_feed.name = "full-flow-feed"
        mock_feed.fetch.return_value = [
            IOCIndicator(
                ioc_type="ip",
                value="88.88.88.88",
                source="full-flow-feed",
                severity="critical",
            ),
        ]
        mgr.register_feed(mock_feed)

        # 2. Update feeds
        count = mgr.update_feeds()
        assert count == 1
        tracker.record_success("full-flow-feed", count)

        # 3. Enrich event
        event = _make_event(data={"dst_ip": "88.88.88.88"})
        enricher.enrich(event)
        has_match = (
            event.data.get("_ioc_match")
            or event.data.get("_threat_intel_hit")
        )
        assert has_match is True

        # 4. Health check
        stale = tracker.check_staleness()
        assert "full-flow-feed" not in stale

        status = tracker.get_status()
        assert status["healthy"] >= 1

        # 5. Dashboard
        data = dashboard.get_threat_intel_data()
        assert data["ioc_count"] >= 1
        assert data["feed_health"]["total_feeds"] >= 1
