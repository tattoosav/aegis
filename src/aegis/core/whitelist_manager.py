"""Whitelist & Exclusion Manager for Aegis.

Provides CRUD operations for managing process, file, IP, domain, and
device whitelists.  Includes a ``BaselineLearner`` that automatically
builds initial whitelists from observed normal behaviour during the
learning period.

Fast in-memory set caches ensure ``is_whitelisted()`` lookups are O(1).
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

from aegis.core.models import AegisEvent

logger = logging.getLogger(__name__)


class WhitelistType(Enum):
    """Categories of whitelist entries."""

    PROCESS = "process"
    FILE = "file"
    IP = "ip"
    DOMAIN = "domain"
    DEVICE = "device"


@dataclass
class WhitelistEntry:
    """A single whitelist entry with metadata."""

    entry_id: str
    entry_type: WhitelistType
    value: str
    reason: str = ""
    added_by: str = "user"  # "user", "auto_baseline", "import"
    added_at: float = field(default_factory=time.time)
    expires_at: float = 0.0  # 0 = never expires
    enabled: bool = True


class WhitelistManager:
    """Manage process/file/IP/domain/device whitelists.

    Uses in-memory set caches for O(1) lookups via is_whitelisted().
    Changes are persisted to the database and the cache is rebuilt.
    """

    def __init__(self, db: AegisDatabase | None = None) -> None:
        self._db = db
        self._entries: dict[str, WhitelistEntry] = {}
        # Cache: {WhitelistType: set of values}
        self._cache: dict[WhitelistType, set[str]] = {
            wt: set() for wt in WhitelistType
        }

    @property
    def entry_count(self) -> int:
        """Return total number of whitelist entries."""
        return len(self._entries)

    def add_entry(
        self,
        entry_type: WhitelistType,
        value: str,
        reason: str = "",
        added_by: str = "user",
        expires_at: float = 0.0,
    ) -> WhitelistEntry:
        """Add a new whitelist entry. Returns the created entry."""
        entry_id = f"wl-{uuid.uuid4().hex[:8]}"
        entry = WhitelistEntry(
            entry_id=entry_id,
            entry_type=entry_type,
            value=value,
            reason=reason,
            added_by=added_by,
            expires_at=expires_at,
        )
        self._entries[entry_id] = entry
        if entry.enabled:
            self._cache[entry_type].add(value)
        return entry

    def remove_entry(self, entry_id: str) -> bool:
        """Remove a whitelist entry. Returns True if found."""
        entry = self._entries.pop(entry_id, None)
        if entry is None:
            return False
        self._cache[entry.entry_type].discard(entry.value)
        return True

    def update_entry(
        self,
        entry_id: str,
        reason: str | None = None,
        enabled: bool | None = None,
        expires_at: float | None = None,
    ) -> WhitelistEntry | None:
        """Update an existing entry. Returns updated entry or None."""
        entry = self._entries.get(entry_id)
        if entry is None:
            return None
        if reason is not None:
            entry.reason = reason
        if expires_at is not None:
            entry.expires_at = expires_at
        if enabled is not None:
            entry.enabled = enabled
            # Rebuild cache for this type
            self._rebuild_cache(entry.entry_type)
        return entry

    def get_entry(self, entry_id: str) -> WhitelistEntry | None:
        """Return a single entry by ID, or None if not found."""
        return self._entries.get(entry_id)

    def list_entries(
        self,
        entry_type: WhitelistType | None = None,
        enabled_only: bool = False,
    ) -> list[WhitelistEntry]:
        """List entries, optionally filtered by type and status."""
        entries = list(self._entries.values())
        if entry_type is not None:
            entries = [
                e for e in entries if e.entry_type == entry_type
            ]
        if enabled_only:
            entries = [e for e in entries if e.enabled]
        return entries

    def is_whitelisted(
        self, entry_type: WhitelistType, value: str,
    ) -> bool:
        """Fast O(1) check if a value is whitelisted."""
        return value in self._cache.get(entry_type, set())

    def check_event(self, event: AegisEvent) -> bool:
        """Check if an event should be suppressed based on whitelists.

        Examines event data for whitelisted processes, files, IPs,
        domains, and devices.
        Returns True if the event matches a whitelist entry (should
        be suppressed).
        """
        data = event.data

        # Check process whitelist
        for key in ("exe", "process_path", "name"):
            val = data.get(key)
            if val and self.is_whitelisted(
                WhitelistType.PROCESS, val,
            ):
                return True

        # Check file whitelist
        for key in ("path", "file_path"):
            val = data.get(key)
            if val and self.is_whitelisted(
                WhitelistType.FILE, val,
            ):
                return True

        # Check IP whitelist
        for key in ("dst_ip", "src_ip", "remote_addr", "ip"):
            val = data.get(key)
            if val and self.is_whitelisted(WhitelistType.IP, val):
                return True

        # Check domain whitelist
        for key in ("domain", "query_name", "hostname"):
            val = data.get(key)
            if val and self.is_whitelisted(
                WhitelistType.DOMAIN, val,
            ):
                return True

        # Check device whitelist
        for key in ("device_id", "device_name"):
            val = data.get(key)
            if val and self.is_whitelisted(
                WhitelistType.DEVICE, val,
            ):
                return True

        return False

    def import_entries(self, entries: list[dict[str, Any]]) -> int:
        """Bulk import whitelist entries from dicts.

        Returns count imported.
        """
        count = 0
        for d in entries:
            try:
                entry_type = WhitelistType(d["entry_type"])
                self.add_entry(
                    entry_type=entry_type,
                    value=d["value"],
                    reason=d.get("reason", ""),
                    added_by=d.get("added_by", "import"),
                    expires_at=d.get("expires_at", 0.0),
                )
                count += 1
            except (KeyError, ValueError):
                logger.warning(
                    "Skipping invalid whitelist entry: %s", d,
                )
        return count

    def export_entries(
        self, entry_type: WhitelistType | None = None,
    ) -> list[dict[str, Any]]:
        """Export entries as list of dicts."""
        entries = self.list_entries(entry_type=entry_type)
        return [
            {
                "entry_id": e.entry_id,
                "entry_type": e.entry_type.value,
                "value": e.value,
                "reason": e.reason,
                "added_by": e.added_by,
                "added_at": e.added_at,
                "expires_at": e.expires_at,
                "enabled": e.enabled,
            }
            for e in entries
        ]

    def prune_expired(self, now: float | None = None) -> int:
        """Remove entries past their TTL. Returns count removed."""
        if now is None:
            now = time.time()
        expired_ids = [
            e.entry_id
            for e in self._entries.values()
            if e.expires_at > 0 and e.expires_at <= now
        ]
        for eid in expired_ids:
            self.remove_entry(eid)
        return len(expired_ids)

    def _rebuild_cache(self, entry_type: WhitelistType) -> None:
        """Rebuild the in-memory cache for a given type."""
        self._cache[entry_type] = {
            e.value
            for e in self._entries.values()
            if e.entry_type == entry_type and e.enabled
        }


class BaselineLearner:
    """Automatic whitelist learning during the baseline period.

    Observes normal system behaviour for a configurable number of
    days and generates whitelist entries for commonly seen processes,
    files, IPs, and domains.

    Parameters
    ----------
    whitelist_manager:
        The WhitelistManager to populate with learned entries.
    learning_period_days:
        Number of days to observe before finalizing.
    min_observations:
        Minimum times a value must be seen to be auto-whitelisted.
    """

    def __init__(
        self,
        whitelist_manager: WhitelistManager,
        learning_period_days: int = 7,
        min_observations: int = 3,
    ) -> None:
        self._wl = whitelist_manager
        self._learning_days = learning_period_days
        self._min_obs = min_observations
        self._start_time = time.time()
        self._observations: dict[str, dict[str, int]] = {
            wt.value: {} for wt in WhitelistType
        }
        self._finalized = False

    @property
    def is_learning_active(self) -> bool:
        """Whether the learning period is still active."""
        if self._finalized:
            return False
        elapsed = time.time() - self._start_time
        return elapsed < self._learning_days * 86400

    def record_observation(self, event: AegisEvent) -> None:
        """Record values from an event as baseline observations."""
        if not self.is_learning_active:
            return

        data = event.data

        # Process observations
        for key in ("exe", "process_path", "name"):
            val = data.get(key)
            if val and isinstance(val, str):
                self._observations["process"][val] = (
                    self._observations["process"].get(val, 0) + 1
                )

        # File observations
        for key in ("path", "file_path"):
            val = data.get(key)
            if val and isinstance(val, str):
                self._observations["file"][val] = (
                    self._observations["file"].get(val, 0) + 1
                )

        # IP observations
        for key in ("dst_ip", "src_ip", "remote_addr"):
            val = data.get(key)
            if val and isinstance(val, str):
                self._observations["ip"][val] = (
                    self._observations["ip"].get(val, 0) + 1
                )

        # Domain observations
        for key in ("domain", "query_name", "hostname"):
            val = data.get(key)
            if val and isinstance(val, str):
                self._observations["domain"][val] = (
                    self._observations["domain"].get(val, 0)
                    + 1
                )

    def get_learning_progress(self) -> dict[str, Any]:
        """Return learning status and progress."""
        elapsed = time.time() - self._start_time
        days_elapsed = min(elapsed / 86400, self._learning_days)
        total_obs = sum(
            sum(counts.values())
            for counts in self._observations.values()
        )
        return {
            "status": (
                "finalized"
                if self._finalized
                else "active"
                if self.is_learning_active
                else "ready"
            ),
            "days_elapsed": round(days_elapsed, 1),
            "days_remaining": round(
                max(0, self._learning_days - days_elapsed), 1,
            ),
            "total_observations": total_obs,
            "unique_values": sum(
                len(counts)
                for counts in self._observations.values()
            ),
            "finalized": self._finalized,
        }

    def finalize_baseline(self) -> int:
        """Convert observations to whitelist entries.

        Only values seen >= min_observations times are whitelisted.
        Returns count of entries created.
        """
        if self._finalized:
            return 0

        count = 0
        for type_str, observations in self._observations.items():
            wl_type = WhitelistType(type_str)
            for value, obs_count in observations.items():
                if obs_count >= self._min_obs:
                    self._wl.add_entry(
                        entry_type=wl_type,
                        value=value,
                        reason=(
                            f"Auto-baseline"
                            f" ({obs_count} observations)"
                        ),
                        added_by="auto_baseline",
                    )
                    count += 1

        self._finalized = True
        logger.info(
            "Baseline finalized: %d entries created", count,
        )
        return count
