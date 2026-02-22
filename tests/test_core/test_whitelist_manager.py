"""Tests for the Aegis whitelist manager and baseline learner."""

import time

import pytest

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.core.whitelist_manager import (
    BaselineLearner,
    WhitelistEntry,
    WhitelistManager,
    WhitelistType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    sensor: SensorType = SensorType.PROCESS,
    event_type: str = "test_event",
    data: dict | None = None,
    severity: Severity = Severity.INFO,
) -> AegisEvent:
    """Create an AegisEvent with sensible defaults for testing."""
    return AegisEvent(
        sensor=sensor,
        event_type=event_type,
        data=data or {},
        severity=severity,
    )


# ===================================================================
# TestWhitelistManagerInit
# ===================================================================

class TestWhitelistManagerInit:
    """Verify initial state of WhitelistManager."""

    def test_init_without_db(self) -> None:
        """Manager can be created without a database."""
        mgr = WhitelistManager(db=None)
        assert mgr is not None

    def test_entry_count_starts_at_zero(self) -> None:
        """A fresh manager has zero entries."""
        mgr = WhitelistManager()
        assert mgr.entry_count == 0

    def test_cache_empty_on_init(self) -> None:
        """All per-type caches should be empty sets on init."""
        mgr = WhitelistManager()
        for wt in WhitelistType:
            assert mgr.is_whitelisted(wt, "anything") is False


# ===================================================================
# TestAddRemoveEntry
# ===================================================================

class TestAddRemoveEntry:
    """CRUD: adding and removing whitelist entries."""

    def test_add_entry_increments_count(self) -> None:
        """Adding an entry increases entry_count by one."""
        mgr = WhitelistManager()
        mgr.add_entry(WhitelistType.PROCESS, "notepad.exe")
        assert mgr.entry_count == 1

    def test_add_entries_of_multiple_types(self) -> None:
        """Entries of different types are tracked independently."""
        mgr = WhitelistManager()
        mgr.add_entry(WhitelistType.PROCESS, "svchost.exe")
        mgr.add_entry(WhitelistType.FILE, "C:\\safe.txt")
        mgr.add_entry(WhitelistType.IP, "192.168.1.1")
        mgr.add_entry(WhitelistType.DOMAIN, "example.com")
        mgr.add_entry(WhitelistType.DEVICE, "USB\\VID_1234")
        assert mgr.entry_count == 5

    def test_remove_existing_entry(self) -> None:
        """Removing an existing entry returns True."""
        mgr = WhitelistManager()
        entry = mgr.add_entry(WhitelistType.IP, "10.0.0.1")
        assert mgr.remove_entry(entry.entry_id) is True
        assert mgr.entry_count == 0

    def test_remove_nonexistent_entry(self) -> None:
        """Removing an entry that does not exist returns False."""
        mgr = WhitelistManager()
        assert mgr.remove_entry("wl-doesnotexist") is False

    def test_entry_properties_correct(self) -> None:
        """Returned entry has the expected field values."""
        mgr = WhitelistManager()
        entry = mgr.add_entry(
            WhitelistType.DOMAIN,
            "safe.example.com",
            reason="Known CDN",
            added_by="admin",
            expires_at=9999999999.0,
        )
        assert entry.entry_type == WhitelistType.DOMAIN
        assert entry.value == "safe.example.com"
        assert entry.reason == "Known CDN"
        assert entry.added_by == "admin"
        assert entry.expires_at == 9999999999.0
        assert entry.enabled is True
        assert isinstance(entry.added_at, float)

    def test_entry_id_format(self) -> None:
        """Entry IDs follow the 'wl-<hex8>' pattern."""
        mgr = WhitelistManager()
        entry = mgr.add_entry(WhitelistType.PROCESS, "cmd.exe")
        assert entry.entry_id.startswith("wl-")
        # 'wl-' prefix + 8 hex chars
        assert len(entry.entry_id) == 11

    def test_cache_updated_on_add(self) -> None:
        """Adding an enabled entry puts it in the cache."""
        mgr = WhitelistManager()
        mgr.add_entry(WhitelistType.FILE, "C:\\trusted.dll")
        assert mgr.is_whitelisted(
            WhitelistType.FILE, "C:\\trusted.dll",
        ) is True

    def test_cache_updated_on_remove(self) -> None:
        """Removing an entry clears it from the cache."""
        mgr = WhitelistManager()
        entry = mgr.add_entry(
            WhitelistType.FILE, "C:\\trusted.dll",
        )
        mgr.remove_entry(entry.entry_id)
        assert mgr.is_whitelisted(
            WhitelistType.FILE, "C:\\trusted.dll",
        ) is False


# ===================================================================
# TestIsWhitelisted
# ===================================================================

class TestIsWhitelisted:
    """Fast O(1) cache lookups via is_whitelisted()."""

    def test_whitelisted_value_returns_true(self) -> None:
        """A value that was added is whitelisted."""
        mgr = WhitelistManager()
        mgr.add_entry(WhitelistType.IP, "127.0.0.1")
        assert mgr.is_whitelisted(WhitelistType.IP, "127.0.0.1")

    def test_non_whitelisted_value_returns_false(self) -> None:
        """A value that was never added is not whitelisted."""
        mgr = WhitelistManager()
        assert mgr.is_whitelisted(
            WhitelistType.IP, "10.10.10.10",
        ) is False

    def test_different_types_are_independent(self) -> None:
        """Whitelisting a value under one type does not affect others."""
        mgr = WhitelistManager()
        mgr.add_entry(WhitelistType.PROCESS, "explorer.exe")
        assert mgr.is_whitelisted(
            WhitelistType.PROCESS, "explorer.exe",
        ) is True
        # Same string under FILE type should not be whitelisted
        assert mgr.is_whitelisted(
            WhitelistType.FILE, "explorer.exe",
        ) is False

    def test_after_removal_returns_false(self) -> None:
        """After removal, the value is no longer whitelisted."""
        mgr = WhitelistManager()
        entry = mgr.add_entry(WhitelistType.DOMAIN, "evil.com")
        mgr.remove_entry(entry.entry_id)
        assert mgr.is_whitelisted(
            WhitelistType.DOMAIN, "evil.com",
        ) is False

    def test_disabled_entry_not_in_cache(self) -> None:
        """Disabling an entry removes it from the cache."""
        mgr = WhitelistManager()
        entry = mgr.add_entry(
            WhitelistType.PROCESS, "safe.exe",
        )
        mgr.update_entry(entry.entry_id, enabled=False)
        assert mgr.is_whitelisted(
            WhitelistType.PROCESS, "safe.exe",
        ) is False

    def test_re_enabled_entry_appears_in_cache(self) -> None:
        """Re-enabling a disabled entry puts it back in the cache."""
        mgr = WhitelistManager()
        entry = mgr.add_entry(
            WhitelistType.PROCESS, "safe.exe",
        )
        mgr.update_entry(entry.entry_id, enabled=False)
        mgr.update_entry(entry.entry_id, enabled=True)
        assert mgr.is_whitelisted(
            WhitelistType.PROCESS, "safe.exe",
        ) is True


# ===================================================================
# TestCheckEvent
# ===================================================================

class TestCheckEvent:
    """check_event() inspects AegisEvent data against whitelists."""

    def test_process_exe_match(self) -> None:
        """Event with a whitelisted 'exe' key is suppressed."""
        mgr = WhitelistManager()
        mgr.add_entry(WhitelistType.PROCESS, "svchost.exe")
        event = _make_event(
            sensor=SensorType.PROCESS,
            data={"exe": "svchost.exe", "pid": 1024},
        )
        assert mgr.check_event(event) is True

    def test_file_path_match(self) -> None:
        """Event with a whitelisted 'path' key is suppressed."""
        mgr = WhitelistManager()
        mgr.add_entry(
            WhitelistType.FILE, "C:\\Windows\\System32\\config",
        )
        event = _make_event(
            sensor=SensorType.FILE,
            data={"path": "C:\\Windows\\System32\\config"},
        )
        assert mgr.check_event(event) is True

    def test_ip_match(self) -> None:
        """Event with a whitelisted 'dst_ip' key is suppressed."""
        mgr = WhitelistManager()
        mgr.add_entry(WhitelistType.IP, "8.8.8.8")
        event = _make_event(
            sensor=SensorType.NETWORK,
            data={"dst_ip": "8.8.8.8", "port": 53},
        )
        assert mgr.check_event(event) is True

    def test_domain_match(self) -> None:
        """Event with a whitelisted 'domain' key is suppressed."""
        mgr = WhitelistManager()
        mgr.add_entry(WhitelistType.DOMAIN, "microsoft.com")
        event = _make_event(
            sensor=SensorType.NETWORK,
            data={"domain": "microsoft.com"},
        )
        assert mgr.check_event(event) is True

    def test_device_match(self) -> None:
        """Event with a whitelisted 'device_id' key is suppressed."""
        mgr = WhitelistManager()
        mgr.add_entry(
            WhitelistType.DEVICE, "USB\\VID_04F2&PID_B604",
        )
        event = _make_event(
            sensor=SensorType.HARDWARE,
            data={"device_id": "USB\\VID_04F2&PID_B604"},
        )
        assert mgr.check_event(event) is True

    def test_no_match_returns_false(self) -> None:
        """Event without any whitelisted values is not suppressed."""
        mgr = WhitelistManager()
        mgr.add_entry(WhitelistType.PROCESS, "svchost.exe")
        event = _make_event(
            sensor=SensorType.PROCESS,
            data={"exe": "malware.exe", "pid": 666},
        )
        assert mgr.check_event(event) is False

    def test_multiple_data_keys_checked(self) -> None:
        """check_event looks at all relevant keys for each type."""
        mgr = WhitelistManager()
        mgr.add_entry(WhitelistType.IP, "10.0.0.5")
        # The IP is under 'src_ip', not 'dst_ip'
        event = _make_event(
            sensor=SensorType.NETWORK,
            data={"src_ip": "10.0.0.5", "dst_ip": "1.2.3.4"},
        )
        assert mgr.check_event(event) is True


# ===================================================================
# TestUpdateEntry
# ===================================================================

class TestUpdateEntry:
    """Updating existing whitelist entries."""

    def test_update_reason(self) -> None:
        """Updating the reason changes only that field."""
        mgr = WhitelistManager()
        entry = mgr.add_entry(
            WhitelistType.IP, "192.168.0.1", reason="old",
        )
        updated = mgr.update_entry(
            entry.entry_id, reason="new reason",
        )
        assert updated is not None
        assert updated.reason == "new reason"
        assert updated.enabled is True  # unchanged

    def test_update_enabled_disables_cache(self) -> None:
        """Disabling an entry removes it from the lookup cache."""
        mgr = WhitelistManager()
        entry = mgr.add_entry(
            WhitelistType.DOMAIN, "cdn.example.com",
        )
        mgr.update_entry(entry.entry_id, enabled=False)
        assert mgr.is_whitelisted(
            WhitelistType.DOMAIN, "cdn.example.com",
        ) is False
        # Entry still exists in storage
        assert mgr.get_entry(entry.entry_id) is not None

    def test_update_expires_at(self) -> None:
        """Updating expires_at changes the expiration timestamp."""
        mgr = WhitelistManager()
        entry = mgr.add_entry(
            WhitelistType.FILE, "C:\\temp\\log.txt",
        )
        future = time.time() + 86400
        updated = mgr.update_entry(
            entry.entry_id, expires_at=future,
        )
        assert updated is not None
        assert updated.expires_at == future

    def test_update_nonexistent_returns_none(self) -> None:
        """Updating a non-existent entry returns None."""
        mgr = WhitelistManager()
        result = mgr.update_entry("wl-00000000", reason="nope")
        assert result is None


# ===================================================================
# TestImportExport
# ===================================================================

class TestImportExport:
    """Bulk import and export of whitelist entries."""

    def test_import_valid_entries(self) -> None:
        """Import a list of well-formed entry dicts."""
        mgr = WhitelistManager()
        entries = [
            {
                "entry_type": "process",
                "value": "svchost.exe",
                "reason": "System process",
            },
            {
                "entry_type": "ip",
                "value": "8.8.4.4",
                "reason": "Google DNS",
            },
        ]
        count = mgr.import_entries(entries)
        assert count == 2
        assert mgr.entry_count == 2
        assert mgr.is_whitelisted(
            WhitelistType.PROCESS, "svchost.exe",
        )
        assert mgr.is_whitelisted(WhitelistType.IP, "8.8.4.4")

    def test_import_skips_invalid_entries(self) -> None:
        """Invalid entries (missing keys / bad type) are skipped."""
        mgr = WhitelistManager()
        entries = [
            {"entry_type": "process", "value": "ok.exe"},
            {"entry_type": "INVALID_TYPE", "value": "bad"},
            {"reason": "missing required keys"},
            {"entry_type": "ip", "value": "1.2.3.4"},
        ]
        count = mgr.import_entries(entries)
        # Only the first and last entries are valid
        assert count == 2
        assert mgr.entry_count == 2

    def test_export_all_entries(self) -> None:
        """Export returns serialised dicts for every entry."""
        mgr = WhitelistManager()
        mgr.add_entry(
            WhitelistType.PROCESS, "a.exe", reason="A",
        )
        mgr.add_entry(WhitelistType.IP, "1.1.1.1", reason="B")
        exported = mgr.export_entries()
        assert len(exported) == 2
        # Each dict should have required keys
        for d in exported:
            assert "entry_id" in d
            assert "entry_type" in d
            assert "value" in d
            assert "enabled" in d

    def test_export_filtered_by_type(self) -> None:
        """Export can be filtered to a single WhitelistType."""
        mgr = WhitelistManager()
        mgr.add_entry(WhitelistType.PROCESS, "a.exe")
        mgr.add_entry(WhitelistType.IP, "1.1.1.1")
        mgr.add_entry(WhitelistType.IP, "2.2.2.2")
        exported = mgr.export_entries(
            entry_type=WhitelistType.IP,
        )
        assert len(exported) == 2
        assert all(
            d["entry_type"] == "ip" for d in exported
        )


# ===================================================================
# TestEntryExpiration
# ===================================================================

class TestEntryExpiration:
    """Expiration and pruning of time-limited entries."""

    def test_prune_removes_expired_entries(self) -> None:
        """prune_expired removes entries past their TTL."""
        mgr = WhitelistManager()
        past = time.time() - 3600  # 1 hour ago
        mgr.add_entry(
            WhitelistType.IP, "10.0.0.99", expires_at=past,
        )
        removed = mgr.prune_expired()
        assert removed == 1
        assert mgr.entry_count == 0

    def test_prune_keeps_non_expired(self) -> None:
        """prune_expired keeps entries that have not yet expired."""
        mgr = WhitelistManager()
        future = time.time() + 86400
        mgr.add_entry(
            WhitelistType.IP, "10.0.0.1", expires_at=future,
        )
        removed = mgr.prune_expired()
        assert removed == 0
        assert mgr.entry_count == 1

    def test_zero_expires_at_never_expires(self) -> None:
        """Entries with expires_at=0 are never pruned."""
        mgr = WhitelistManager()
        mgr.add_entry(
            WhitelistType.DOMAIN, "forever.com", expires_at=0.0,
        )
        # Even with a very large 'now', entry should survive
        removed = mgr.prune_expired(now=9999999999.0)
        assert removed == 0
        assert mgr.entry_count == 1

    def test_explicit_now_parameter(self) -> None:
        """prune_expired uses the provided 'now' for comparison."""
        mgr = WhitelistManager()
        # Entry expires at timestamp 1000
        mgr.add_entry(
            WhitelistType.FILE, "C:\\tmp.log", expires_at=1000.0,
        )
        # now=500: not yet expired
        assert mgr.prune_expired(now=500.0) == 0
        assert mgr.entry_count == 1
        # now=1001: past expiry
        assert mgr.prune_expired(now=1001.0) == 1
        assert mgr.entry_count == 0


# ===================================================================
# TestBaselineLearner
# ===================================================================

class TestBaselineLearner:
    """Automatic baseline learning and whitelist generation."""

    def test_learning_active_during_period(self) -> None:
        """is_learning_active is True right after creation."""
        mgr = WhitelistManager()
        learner = BaselineLearner(mgr, learning_period_days=7)
        assert learner.is_learning_active is True

    def test_learning_inactive_after_period(self) -> None:
        """is_learning_active is False once the period elapses."""
        mgr = WhitelistManager()
        learner = BaselineLearner(mgr, learning_period_days=7)
        # Simulate the learning period having already passed
        learner._start_time = time.time() - (8 * 86400)
        assert learner.is_learning_active is False

    def test_record_observation_collects_values(self) -> None:
        """Observations from events are counted correctly."""
        mgr = WhitelistManager()
        learner = BaselineLearner(mgr)
        event = _make_event(
            sensor=SensorType.PROCESS,
            data={"exe": "notepad.exe"},
        )
        learner.record_observation(event)
        learner.record_observation(event)
        assert (
            learner._observations["process"]["notepad.exe"] == 2
        )

    def test_get_learning_progress(self) -> None:
        """Progress dict contains expected keys and values."""
        mgr = WhitelistManager()
        learner = BaselineLearner(
            mgr, learning_period_days=7, min_observations=3,
        )
        event = _make_event(
            sensor=SensorType.NETWORK,
            data={"dst_ip": "1.2.3.4"},
        )
        learner.record_observation(event)

        progress = learner.get_learning_progress()
        assert progress["status"] == "active"
        assert "days_elapsed" in progress
        assert "days_remaining" in progress
        assert progress["total_observations"] >= 1
        assert progress["unique_values"] >= 1
        assert progress["finalized"] is False

    def test_finalize_creates_entries_above_threshold(
        self,
    ) -> None:
        """Only values observed >= min_observations are added."""
        mgr = WhitelistManager()
        learner = BaselineLearner(
            mgr, learning_period_days=7, min_observations=3,
        )

        frequent_event = _make_event(
            sensor=SensorType.PROCESS,
            data={"exe": "frequent.exe"},
        )
        rare_event = _make_event(
            sensor=SensorType.PROCESS,
            data={"exe": "rare.exe"},
        )

        # frequent.exe seen 5 times (above threshold)
        for _ in range(5):
            learner.record_observation(frequent_event)
        # rare.exe seen 2 times (below threshold of 3)
        for _ in range(2):
            learner.record_observation(rare_event)

        count = learner.finalize_baseline()
        assert count == 1  # only frequent.exe qualifies
        assert mgr.is_whitelisted(
            WhitelistType.PROCESS, "frequent.exe",
        )
        assert not mgr.is_whitelisted(
            WhitelistType.PROCESS, "rare.exe",
        )

    def test_finalize_twice_returns_zero(self) -> None:
        """Calling finalize_baseline a second time returns 0."""
        mgr = WhitelistManager()
        learner = BaselineLearner(
            mgr, learning_period_days=7, min_observations=1,
        )
        event = _make_event(
            sensor=SensorType.PROCESS,
            data={"exe": "app.exe"},
        )
        learner.record_observation(event)

        first = learner.finalize_baseline()
        assert first == 1
        second = learner.finalize_baseline()
        assert second == 0
        # Entry count unchanged after second finalize
        assert mgr.entry_count == 1
