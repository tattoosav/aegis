"""Tests for the FeedHealthTracker module.

Validates per-feed health tracking, staleness detection, error
counting, and aggregate status reporting used by the threat
intelligence subsystem.
"""

from __future__ import annotations

import time

import pytest

from aegis.intelligence.feed_health import (
    FeedHealthRecord,
    FeedHealthTracker,
)


# ------------------------------------------------------------------ #
# TestFeedHealthRecordDataclass
# ------------------------------------------------------------------ #


class TestFeedHealthRecordDataclass:
    """Tests for the FeedHealthRecord dataclass defaults."""

    def test_default_values(self) -> None:
        """All defaults should be zero / empty / False."""
        rec = FeedHealthRecord(feed_name="test")
        assert rec.feed_name == "test"
        assert rec.last_update_time == 0.0
        assert rec.last_update_count == 0
        assert rec.total_updates == 0
        assert rec.total_iocs_added == 0
        assert rec.consecutive_errors == 0
        assert rec.last_error == ""
        assert rec.is_stale is False

    def test_custom_values(self) -> None:
        """Explicit construction with custom fields."""
        rec = FeedHealthRecord(
            feed_name="custom",
            last_update_time=100.0,
            last_update_count=42,
            total_updates=5,
            total_iocs_added=200,
            consecutive_errors=3,
            last_error="timeout",
            is_stale=True,
        )
        assert rec.feed_name == "custom"
        assert rec.last_update_time == 100.0
        assert rec.last_update_count == 42
        assert rec.total_updates == 5
        assert rec.total_iocs_added == 200
        assert rec.consecutive_errors == 3
        assert rec.last_error == "timeout"
        assert rec.is_stale is True

    def test_is_stale_default_false(self) -> None:
        """is_stale defaults to False."""
        rec = FeedHealthRecord(feed_name="x")
        assert rec.is_stale is False

    def test_last_error_default_empty(self) -> None:
        """last_error defaults to empty string."""
        rec = FeedHealthRecord(feed_name="x")
        assert rec.last_error == ""

    def test_consecutive_errors_default_zero(self) -> None:
        """consecutive_errors defaults to 0."""
        rec = FeedHealthRecord(feed_name="x")
        assert rec.consecutive_errors == 0


# ------------------------------------------------------------------ #
# TestFeedHealthTrackerInit
# ------------------------------------------------------------------ #


class TestFeedHealthTrackerInit:
    """Tests for FeedHealthTracker construction."""

    def test_default_threshold(self) -> None:
        """Default staleness threshold is 7200 seconds."""
        tracker = FeedHealthTracker()
        assert tracker._threshold == 7200.0

    def test_custom_threshold(self) -> None:
        """Staleness threshold can be overridden."""
        tracker = FeedHealthTracker(
            staleness_threshold_seconds=3600.0,
        )
        assert tracker._threshold == 3600.0

    def test_empty_initially(self) -> None:
        """Tracker starts with zero feeds."""
        tracker = FeedHealthTracker()
        assert tracker.feed_count == 0

    def test_get_status_empty(self) -> None:
        """get_status on empty tracker returns all-zero dict."""
        tracker = FeedHealthTracker()
        status = tracker.get_status()
        assert status == {
            "total_feeds": 0,
            "healthy": 0,
            "stale": 0,
            "errored": 0,
            "feeds": [],
        }


# ------------------------------------------------------------------ #
# TestRecordSuccess
# ------------------------------------------------------------------ #


class TestRecordSuccess:
    """Tests for FeedHealthTracker.record_success()."""

    def test_creates_new_record(self) -> None:
        """record_success for an unknown feed creates a new record."""
        tracker = FeedHealthTracker()
        tracker.record_success("alpha", 10)
        assert tracker.feed_count == 1

    def test_updates_last_update_time(self) -> None:
        """last_update_time is set to approximately now."""
        tracker = FeedHealthTracker()
        before = time.time()
        tracker.record_success("alpha", 5)
        after = time.time()
        status = tracker.get_feed_status("alpha")
        assert status is not None
        assert before <= status["last_update_time"] <= after

    def test_updates_ioc_count(self) -> None:
        """last_update_count reflects the most recent call."""
        tracker = FeedHealthTracker()
        tracker.record_success("alpha", 42)
        status = tracker.get_feed_status("alpha")
        assert status is not None
        assert status["last_update_count"] == 42

    def test_increments_total_updates(self) -> None:
        """Two calls produce total_updates == 2."""
        tracker = FeedHealthTracker()
        tracker.record_success("alpha", 1)
        tracker.record_success("alpha", 2)
        status = tracker.get_feed_status("alpha")
        assert status is not None
        assert status["total_updates"] == 2

    def test_accumulates_total_iocs(self) -> None:
        """IOC counts accumulate across calls (5 + 3 = 8)."""
        tracker = FeedHealthTracker()
        tracker.record_success("alpha", 5)
        tracker.record_success("alpha", 3)
        status = tracker.get_feed_status("alpha")
        assert status is not None
        assert status["total_iocs_added"] == 8

    def test_resets_consecutive_errors(self) -> None:
        """A success after failure resets consecutive_errors to 0."""
        tracker = FeedHealthTracker()
        tracker.record_failure("alpha", "err1")
        tracker.record_failure("alpha", "err2")
        tracker.record_success("alpha", 10)
        status = tracker.get_feed_status("alpha")
        assert status is not None
        assert status["consecutive_errors"] == 0

    def test_clears_last_error(self) -> None:
        """A success clears the last_error string."""
        tracker = FeedHealthTracker()
        tracker.record_failure("alpha", "timeout")
        tracker.record_success("alpha", 5)
        status = tracker.get_feed_status("alpha")
        assert status is not None
        assert status["last_error"] == ""

    def test_clears_is_stale(self) -> None:
        """A success sets is_stale to False."""
        tracker = FeedHealthTracker()
        # Force stale via a failure-only record + staleness check
        tracker.record_failure("alpha", "err")
        tracker.check_staleness()
        status_before = tracker.get_feed_status("alpha")
        assert status_before is not None
        assert status_before["is_stale"] is True

        tracker.record_success("alpha", 1)
        status_after = tracker.get_feed_status("alpha")
        assert status_after is not None
        assert status_after["is_stale"] is False


# ------------------------------------------------------------------ #
# TestRecordFailure
# ------------------------------------------------------------------ #


class TestRecordFailure:
    """Tests for FeedHealthTracker.record_failure()."""

    def test_creates_new_record(self) -> None:
        """record_failure for an unknown feed creates a new record."""
        tracker = FeedHealthTracker()
        tracker.record_failure("beta", "connect error")
        assert tracker.feed_count == 1

    def test_increments_consecutive_errors(self) -> None:
        """Three failures produce consecutive_errors == 3."""
        tracker = FeedHealthTracker()
        tracker.record_failure("beta", "e1")
        tracker.record_failure("beta", "e2")
        tracker.record_failure("beta", "e3")
        status = tracker.get_feed_status("beta")
        assert status is not None
        assert status["consecutive_errors"] == 3

    def test_stores_last_error_message(self) -> None:
        """last_error reflects the most recent failure message."""
        tracker = FeedHealthTracker()
        tracker.record_failure("beta", "first")
        tracker.record_failure("beta", "second")
        status = tracker.get_feed_status("beta")
        assert status is not None
        assert status["last_error"] == "second"

    def test_preserves_last_update_time(self) -> None:
        """A failure does not overwrite last_update_time."""
        tracker = FeedHealthTracker()
        tracker.record_success("beta", 10)
        s1 = tracker.get_feed_status("beta")
        assert s1 is not None
        update_time = s1["last_update_time"]

        tracker.record_failure("beta", "err")
        s2 = tracker.get_feed_status("beta")
        assert s2 is not None
        assert s2["last_update_time"] == update_time

    def test_preserves_total_updates(self) -> None:
        """A failure does not change total_updates."""
        tracker = FeedHealthTracker()
        tracker.record_success("beta", 5)
        tracker.record_failure("beta", "err")
        status = tracker.get_feed_status("beta")
        assert status is not None
        assert status["total_updates"] == 1

    def test_preserves_total_iocs(self) -> None:
        """A failure does not change total_iocs_added."""
        tracker = FeedHealthTracker()
        tracker.record_success("beta", 7)
        tracker.record_failure("beta", "err")
        status = tracker.get_feed_status("beta")
        assert status is not None
        assert status["total_iocs_added"] == 7


# ------------------------------------------------------------------ #
# TestCheckStaleness
# ------------------------------------------------------------------ #


class TestCheckStaleness:
    """Tests for FeedHealthTracker.check_staleness()."""

    def test_empty_returns_empty(self) -> None:
        """No feeds registered -> empty stale list."""
        tracker = FeedHealthTracker()
        assert tracker.check_staleness() == []

    def test_never_updated_is_stale(self) -> None:
        """A feed with only failures (last_update_time == 0) is stale."""
        tracker = FeedHealthTracker()
        tracker.record_failure("gamma", "err")
        stale = tracker.check_staleness()
        assert "gamma" in stale

    def test_recent_update_not_stale(self) -> None:
        """A recently updated feed is not stale."""
        tracker = FeedHealthTracker(
            staleness_threshold_seconds=7200.0,
        )
        tracker.record_success("gamma", 10)
        now = time.time()
        stale = tracker.check_staleness(now=now)
        assert "gamma" not in stale

    def test_old_update_is_stale(self) -> None:
        """A feed updated beyond the threshold is stale."""
        tracker = FeedHealthTracker(
            staleness_threshold_seconds=100.0,
        )
        tracker.record_success("gamma", 5)
        # Simulate time passing well beyond threshold
        future = time.time() + 200.0
        stale = tracker.check_staleness(now=future)
        assert "gamma" in stale

    def test_threshold_boundary_not_stale(self) -> None:
        """Exactly at the threshold boundary is NOT stale (uses >)."""
        tracker = FeedHealthTracker(
            staleness_threshold_seconds=100.0,
        )
        tracker.record_success("gamma", 5)
        status = tracker.get_feed_status("gamma")
        assert status is not None
        at_boundary = status["last_update_time"] + 100.0
        stale = tracker.check_staleness(now=at_boundary)
        assert "gamma" not in stale

    def test_threshold_boundary_plus_one_stale(self) -> None:
        """One second past the threshold IS stale."""
        tracker = FeedHealthTracker(
            staleness_threshold_seconds=100.0,
        )
        tracker.record_success("gamma", 5)
        status = tracker.get_feed_status("gamma")
        assert status is not None
        past_boundary = status["last_update_time"] + 101.0
        stale = tracker.check_staleness(now=past_boundary)
        assert "gamma" in stale

    def test_multiple_feeds_mixed(self) -> None:
        """One stale and one fresh feed in the same tracker."""
        tracker = FeedHealthTracker(
            staleness_threshold_seconds=100.0,
        )
        tracker.record_success("fresh", 10)
        tracker.record_success("old", 5)

        fresh_status = tracker.get_feed_status("fresh")
        assert fresh_status is not None
        # Check at a time where 'old' is stale but 'fresh' is not
        # We set 'old' update time to be far in the past
        tracker._records["old"].last_update_time = (
            time.time() - 200.0
        )
        stale = tracker.check_staleness()
        assert "old" in stale
        assert "fresh" not in stale

    def test_updates_is_stale_flag(self) -> None:
        """check_staleness sets rec.is_stale on each record."""
        tracker = FeedHealthTracker(
            staleness_threshold_seconds=100.0,
        )
        tracker.record_success("delta", 5)
        # Not stale yet
        tracker.check_staleness()
        s1 = tracker.get_feed_status("delta")
        assert s1 is not None
        assert s1["is_stale"] is False

        # Now make it stale
        future = time.time() + 200.0
        tracker.check_staleness(now=future)
        s2 = tracker.get_feed_status("delta")
        assert s2 is not None
        assert s2["is_stale"] is True


# ------------------------------------------------------------------ #
# TestGetStatus
# ------------------------------------------------------------------ #


class TestGetStatus:
    """Tests for FeedHealthTracker.get_status()."""

    def test_returns_dict_with_all_keys(self) -> None:
        """Returned dict has all expected top-level keys."""
        tracker = FeedHealthTracker()
        tracker.record_success("a", 1)
        status = tracker.get_status()
        assert set(status.keys()) == {
            "total_feeds",
            "healthy",
            "stale",
            "errored",
            "feeds",
        }

    def test_total_feeds_count(self) -> None:
        """total_feeds matches the number of tracked feeds."""
        tracker = FeedHealthTracker()
        tracker.record_success("a", 1)
        tracker.record_success("b", 2)
        tracker.record_failure("c", "err")
        status = tracker.get_status()
        assert status["total_feeds"] == 3

    def test_healthy_count(self) -> None:
        """Two healthy feeds (no errors, not stale)."""
        tracker = FeedHealthTracker()
        tracker.record_success("a", 1)
        tracker.record_success("b", 2)
        status = tracker.get_status()
        assert status["healthy"] == 2

    def test_stale_count(self) -> None:
        """One stale feed (is_stale=True, no errors)."""
        tracker = FeedHealthTracker(
            staleness_threshold_seconds=100.0,
        )
        tracker.record_success("a", 1)
        # Make it stale
        tracker._records["a"].last_update_time = (
            time.time() - 200.0
        )
        tracker.check_staleness()
        status = tracker.get_status()
        assert status["stale"] == 1

    def test_errored_count(self) -> None:
        """One errored feed (consecutive_errors > 0)."""
        tracker = FeedHealthTracker()
        tracker.record_success("healthy", 1)
        tracker.record_failure("broken", "err")
        status = tracker.get_status()
        assert status["errored"] == 1
        assert status["healthy"] == 1

    def test_feeds_list_shape(self) -> None:
        """Each entry in feeds has all expected keys."""
        tracker = FeedHealthTracker()
        tracker.record_success("alpha", 10)
        status = tracker.get_status()
        expected_keys = {
            "feed_name",
            "last_update_time",
            "last_update_count",
            "total_updates",
            "total_iocs_added",
            "consecutive_errors",
            "last_error",
            "is_stale",
        }
        assert len(status["feeds"]) == 1
        assert set(status["feeds"][0].keys()) == expected_keys


# ------------------------------------------------------------------ #
# TestGetFeedStatus
# ------------------------------------------------------------------ #


class TestGetFeedStatus:
    """Tests for FeedHealthTracker.get_feed_status()."""

    def test_existing_feed(self) -> None:
        """Returns a dict with all expected keys for a known feed."""
        tracker = FeedHealthTracker()
        tracker.record_success("alpha", 5)
        status = tracker.get_feed_status("alpha")
        assert status is not None
        expected_keys = {
            "feed_name",
            "last_update_time",
            "last_update_count",
            "total_updates",
            "total_iocs_added",
            "consecutive_errors",
            "last_error",
            "is_stale",
        }
        assert set(status.keys()) == expected_keys

    def test_unknown_feed(self) -> None:
        """Returns None for an unknown feed name."""
        tracker = FeedHealthTracker()
        assert tracker.get_feed_status("nonexistent") is None

    def test_after_success(self) -> None:
        """Status after a successful update has correct values."""
        tracker = FeedHealthTracker()
        tracker.record_success("alpha", 15)
        status = tracker.get_feed_status("alpha")
        assert status is not None
        assert status["feed_name"] == "alpha"
        assert status["last_update_count"] == 15
        assert status["total_updates"] == 1
        assert status["total_iocs_added"] == 15
        assert status["consecutive_errors"] == 0
        assert status["last_error"] == ""
        assert status["is_stale"] is False

    def test_after_failure(self) -> None:
        """Status after a failure has correct error fields."""
        tracker = FeedHealthTracker()
        tracker.record_failure("alpha", "connection refused")
        status = tracker.get_feed_status("alpha")
        assert status is not None
        assert status["consecutive_errors"] == 1
        assert status["last_error"] == "connection refused"
        assert status["last_update_time"] == 0.0

    def test_matches_get_status_entry(self) -> None:
        """Single feed status matches corresponding entry in get_status."""
        tracker = FeedHealthTracker()
        tracker.record_success("alpha", 10)
        tracker.record_failure("alpha", "err")

        single = tracker.get_feed_status("alpha")
        overall = tracker.get_status()
        feed_entry = overall["feeds"][0]

        assert single == feed_entry
