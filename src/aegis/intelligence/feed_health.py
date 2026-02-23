"""Threat feed health tracking for Aegis.

Tracks per-feed update status, error counts, and staleness
for the threat intelligence subsystem.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FeedHealthRecord:
    """Health record for a single threat feed."""
    feed_name: str
    last_update_time: float = 0.0
    last_update_count: int = 0
    total_updates: int = 0
    total_iocs_added: int = 0
    consecutive_errors: int = 0
    last_error: str = ""
    is_stale: bool = False


class FeedHealthTracker:
    """Track health and staleness of registered threat feeds.

    Parameters
    ----------
    staleness_threshold_seconds:
        A feed is marked stale if it hasn't been successfully
        updated within this many seconds.  Default is 7200 (2 hours).
    """

    def __init__(
        self,
        staleness_threshold_seconds: float = 7200.0,
    ) -> None:
        self._threshold = staleness_threshold_seconds
        self._records: dict[str, FeedHealthRecord] = {}
        self._lock = threading.Lock()

    def record_success(
        self, feed_name: str, ioc_count: int,
    ) -> None:
        """Record a successful feed update."""
        with self._lock:
            rec = self._records.get(feed_name)
            if rec is None:
                rec = FeedHealthRecord(feed_name=feed_name)
                self._records[feed_name] = rec
            rec.last_update_time = time.time()
            rec.last_update_count = ioc_count
            rec.total_updates += 1
            rec.total_iocs_added += ioc_count
            rec.consecutive_errors = 0
            rec.last_error = ""
            rec.is_stale = False

    def record_failure(
        self, feed_name: str, error_msg: str,
    ) -> None:
        """Record a failed feed update."""
        with self._lock:
            rec = self._records.get(feed_name)
            if rec is None:
                rec = FeedHealthRecord(feed_name=feed_name)
                self._records[feed_name] = rec
            rec.consecutive_errors += 1
            rec.last_error = str(error_msg)

    def check_staleness(
        self, now: float | None = None,
    ) -> list[str]:
        """Check all feeds for staleness. Returns list of stale feed names."""
        now = now or time.time()
        stale: list[str] = []
        with self._lock:
            for name, rec in self._records.items():
                if rec.last_update_time == 0.0:
                    # Never updated — stale
                    rec.is_stale = True
                    stale.append(name)
                elif (now - rec.last_update_time) > self._threshold:
                    rec.is_stale = True
                    stale.append(name)
                else:
                    rec.is_stale = False
        return stale

    def get_status(self) -> dict[str, Any]:
        """Return overall feed health status."""
        with self._lock:
            feeds = []
            healthy = 0
            stale = 0
            errored = 0
            for rec in self._records.values():
                entry = {
                    "feed_name": rec.feed_name,
                    "last_update_time": rec.last_update_time,
                    "last_update_count": rec.last_update_count,
                    "total_updates": rec.total_updates,
                    "total_iocs_added": rec.total_iocs_added,
                    "consecutive_errors": rec.consecutive_errors,
                    "last_error": rec.last_error,
                    "is_stale": rec.is_stale,
                }
                feeds.append(entry)
                if rec.consecutive_errors > 0:
                    errored += 1
                elif rec.is_stale:
                    stale += 1
                else:
                    healthy += 1
            return {
                "total_feeds": len(self._records),
                "healthy": healthy,
                "stale": stale,
                "errored": errored,
                "feeds": feeds,
            }

    def get_feed_status(
        self, feed_name: str,
    ) -> dict[str, Any] | None:
        """Return status for a single feed, or None if not tracked."""
        with self._lock:
            rec = self._records.get(feed_name)
            if rec is None:
                return None
            return {
                "feed_name": rec.feed_name,
                "last_update_time": rec.last_update_time,
                "last_update_count": rec.last_update_count,
                "total_updates": rec.total_updates,
                "total_iocs_added": rec.total_iocs_added,
                "consecutive_errors": rec.consecutive_errors,
                "last_error": rec.last_error,
                "is_stale": rec.is_stale,
            }

    @property
    def feed_count(self) -> int:
        """Number of tracked feeds."""
        with self._lock:
            return len(self._records)
