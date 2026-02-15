"""Tests for the File Integrity Monitor sensor."""

import hashlib
import os
from pathlib import Path

from aegis.core.models import SensorType, Severity
from aegis.sensors.file_integrity import (
    _CANARY_PREFIX,
    FileIntegritySensor,
    _file_entropy,
    _iter_directory,
    _sha256_file,
    _shannon_entropy,
)

# ------------------------------------------------------------------ #
# Shannon entropy helper
# ------------------------------------------------------------------ #


class TestShannonEntropy:
    def test_empty_data_returns_zero(self):
        assert _shannon_entropy(b"") == 0.0

    def test_uniform_data_low_entropy(self):
        """All identical bytes should yield entropy of 0.0."""
        data = bytes([0xAA]) * 1024
        assert _shannon_entropy(data) == 0.0

    def test_random_data_high_entropy(self):
        """Cryptographically random bytes should produce entropy near 8.0."""
        data = os.urandom(10_000)
        entropy = _shannon_entropy(data)
        assert entropy >= 7.5
        assert entropy <= 8.0

    def test_known_text_moderate_entropy(self):
        """Plain English text should have moderate entropy (roughly 3-5)."""
        text = (
            b"The quick brown fox jumps over the lazy dog. "
            b"This sentence is repeated to generate enough data. "
        ) * 20
        entropy = _shannon_entropy(text)
        assert 2.5 <= entropy <= 5.5

    def test_result_rounded_to_four_decimals(self):
        """The function rounds to four decimal places."""
        data = b"abcabc"
        entropy = _shannon_entropy(data)
        # Verify it has at most 4 decimal digits
        assert entropy == round(entropy, 4)

    def test_single_byte(self):
        """A single byte always has 0.0 entropy (only one symbol)."""
        assert _shannon_entropy(b"x") == 0.0

    def test_two_distinct_bytes_equal_frequency(self):
        """Two equally frequent bytes should yield exactly 1.0 bit of entropy."""
        data = b"\x00\x01" * 500
        assert _shannon_entropy(data) == 1.0


# ------------------------------------------------------------------ #
# SHA-256 file hash helper
# ------------------------------------------------------------------ #


class TestSha256File:
    def test_hash_known_content(self, tmp_path: Path):
        """SHA-256 of known bytes must match the hashlib reference."""
        content = b"aegis test file content"
        expected = hashlib.sha256(content).hexdigest()
        f = tmp_path / "known.bin"
        f.write_bytes(content)
        assert _sha256_file(f) == expected

    def test_empty_file(self, tmp_path: Path):
        """SHA-256 of an empty file must match the empty-data digest."""
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert _sha256_file(f) == expected

    def test_nonexistent_file_returns_none(self, tmp_path: Path):
        missing = tmp_path / "does_not_exist.txt"
        assert _sha256_file(missing) is None

    def test_unreadable_file_returns_none(self, tmp_path: Path):
        """If a file cannot be read, the function returns None.

        On Windows, making a file truly unreadable with chmod is unreliable,
        so we also accept that nonexistent paths return None (already covered).
        This test exercises the OSError / PermissionError catch path by
        pointing at a directory instead of a file (stat succeeds but open fails).
        """
        d = tmp_path / "subdir"
        d.mkdir()
        # Passing a directory to _sha256_file: stat() works but open('rb') fails
        result = _sha256_file(d)
        assert result is None


# ------------------------------------------------------------------ #
# File entropy helper
# ------------------------------------------------------------------ #


class TestFileEntropy:
    def test_returns_float(self, tmp_path: Path):
        f = tmp_path / "sample.txt"
        f.write_bytes(b"hello world")
        result = _file_entropy(f)
        assert isinstance(result, float)

    def test_high_entropy_for_random_data(self, tmp_path: Path):
        f = tmp_path / "random.bin"
        f.write_bytes(os.urandom(4096))
        assert _file_entropy(f) >= 7.5

    def test_zero_for_nonexistent_file(self, tmp_path: Path):
        missing = tmp_path / "nope.bin"
        assert _file_entropy(missing) == 0.0


# ------------------------------------------------------------------ #
# Directory iteration
# ------------------------------------------------------------------ #


class TestIterDirectory:
    def test_empty_directory(self, tmp_path: Path):
        result = _iter_directory(tmp_path)
        assert result == []

    def test_finds_files_in_directory(self, tmp_path: Path):
        (tmp_path / "a.txt").write_text("aaa")
        (tmp_path / "b.txt").write_text("bbb")
        result = _iter_directory(tmp_path)
        names = {p.name for p in result}
        assert names == {"a.txt", "b.txt"}

    def test_respects_max_depth(self, tmp_path: Path):
        """Files deeper than max_depth should not be returned."""
        # depth 0 = root, depth 1 = child dir, depth 2 = grandchild
        level1 = tmp_path / "d1"
        level1.mkdir()
        level2 = level1 / "d2"
        level2.mkdir()
        level3 = level2 / "d3"
        level3.mkdir()

        (level1 / "f1.txt").write_text("one")
        (level2 / "f2.txt").write_text("two")
        (level3 / "f3.txt").write_text("three")

        # max_depth=2 means root(0) -> d1(1) -> d2(2), but d3 would be depth 3
        result = _iter_directory(tmp_path, max_depth=2)
        names = {p.name for p in result}
        assert "f1.txt" in names
        assert "f2.txt" in names
        assert "f3.txt" not in names

    def test_respects_max_files_limit(self, tmp_path: Path):
        for i in range(20):
            (tmp_path / f"file_{i:03d}.txt").write_text(f"content {i}")
        result = _iter_directory(tmp_path, max_files=5)
        assert len(result) == 5

    def test_nonexistent_directory_returns_empty(self, tmp_path: Path):
        missing = tmp_path / "no_such_dir"
        result = _iter_directory(missing)
        assert result == []

    def test_returns_only_files_not_dirs(self, tmp_path: Path):
        (tmp_path / "file.txt").write_text("data")
        (tmp_path / "subdir").mkdir()
        result = _iter_directory(tmp_path)
        assert all(p.is_file() for p in result)

    def test_max_depth_zero_only_root_files(self, tmp_path: Path):
        (tmp_path / "root.txt").write_text("root")
        child = tmp_path / "child"
        child.mkdir()
        (child / "nested.txt").write_text("nested")
        result = _iter_directory(tmp_path, max_depth=0)
        names = {p.name for p in result}
        assert "root.txt" in names
        assert "nested.txt" not in names


# ------------------------------------------------------------------ #
# FileIntegritySensor — init and properties
# ------------------------------------------------------------------ #


class TestFileIntegritySensorInit:
    def test_sensor_type_is_file(self):
        sensor = FileIntegritySensor(watched_dirs=[])
        assert sensor.sensor_type == SensorType.FILE

    def test_sensor_name(self):
        sensor = FileIntegritySensor(watched_dirs=[])
        assert sensor.sensor_name == "file_integrity_monitor"

    def test_default_interval_30(self):
        sensor = FileIntegritySensor(watched_dirs=[])
        assert sensor._interval == 30.0

    def test_custom_watched_dirs(self, tmp_path: Path):
        dirs = [str(tmp_path)]
        sensor = FileIntegritySensor(watched_dirs=dirs)
        assert sensor._watched_dirs == [tmp_path]

    def test_custom_interval(self):
        sensor = FileIntegritySensor(interval=60.0, watched_dirs=[])
        assert sensor._interval == 60.0

    def test_enable_canary_default_true(self):
        sensor = FileIntegritySensor(watched_dirs=[])
        assert sensor._enable_canary is True

    def test_enable_canary_false(self):
        sensor = FileIntegritySensor(watched_dirs=[], enable_canary=False)
        assert sensor._enable_canary is False


# ------------------------------------------------------------------ #
# FileIntegritySensor — lifecycle (setup / collect / teardown)
# ------------------------------------------------------------------ #


class TestFileIntegritySensorLifecycle:
    def test_setup_builds_baseline(self, tmp_path: Path):
        (tmp_path / "alpha.txt").write_text("alpha content")
        (tmp_path / "beta.txt").write_text("beta content")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        assert len(sensor._baseline) == 2
        assert any("alpha.txt" in k for k in sensor._baseline)
        assert any("beta.txt" in k for k in sensor._baseline)

    def test_collect_no_changes_returns_snapshot_only(self, tmp_path: Path):
        (tmp_path / "stable.txt").write_text("stable")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()
        events = sensor.collect()

        # Should have at least the file_snapshot event
        snapshot_events = [e for e in events if e.event_type == "file_snapshot"]
        assert len(snapshot_events) == 1

        snapshot = snapshot_events[0]
        assert snapshot.data["total_changes"] == 0
        assert snapshot.data["files_new"] == 0
        assert snapshot.data["files_modified"] == 0
        assert snapshot.data["files_deleted"] == 0

    def test_collect_detects_new_file(self, tmp_path: Path):
        (tmp_path / "original.txt").write_text("original")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        # Create a new file after baseline
        (tmp_path / "newcomer.txt").write_text("new stuff")
        events = sensor.collect()

        change_events = [
            e
            for e in events
            if e.event_type == "file_change" and e.data["change_type"] == "created"
        ]
        assert len(change_events) == 1
        assert "newcomer.txt" in change_events[0].data["path"]

    def test_collect_detects_modified_file(self, tmp_path: Path):
        target = tmp_path / "mutable.txt"
        target.write_text("version 1")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        target.write_text("version 2 -- changed")
        events = sensor.collect()

        modified = [
            e
            for e in events
            if e.event_type == "file_change" and e.data["change_type"] == "modified"
        ]
        assert len(modified) == 1
        assert modified[0].data["old_hash"] != modified[0].data["new_hash"]

    def test_collect_detects_deleted_file(self, tmp_path: Path):
        victim = tmp_path / "to_delete.txt"
        victim.write_text("bye bye")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        victim.unlink()
        events = sensor.collect()

        deleted = [
            e
            for e in events
            if e.event_type == "file_change" and e.data["change_type"] == "deleted"
        ]
        assert len(deleted) == 1
        assert "to_delete.txt" in deleted[0].data["path"]

    def test_modified_file_severity_high_for_high_entropy(self, tmp_path: Path):
        """When a modified file has very high entropy, severity should be HIGH."""
        target = tmp_path / "target.bin"
        target.write_bytes(b"low entropy data" * 10)

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        # Overwrite with random data (high entropy)
        target.write_bytes(os.urandom(4096))
        events = sensor.collect()

        modified = [
            e
            for e in events
            if e.event_type == "file_change" and e.data["change_type"] == "modified"
        ]
        assert len(modified) == 1
        assert modified[0].severity == Severity.HIGH

    def test_new_file_severity_is_low(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        (tmp_path / "newfile.txt").write_text("hello")
        events = sensor.collect()

        created = [
            e
            for e in events
            if e.event_type == "file_change" and e.data["change_type"] == "created"
        ]
        assert len(created) == 1
        assert created[0].severity == Severity.LOW

    def test_deleted_file_severity_is_medium(self, tmp_path: Path):
        f = tmp_path / "goner.txt"
        f.write_text("data")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        f.unlink()
        events = sensor.collect()

        deleted = [
            e
            for e in events
            if e.event_type == "file_change" and e.data["change_type"] == "deleted"
        ]
        assert len(deleted) == 1
        assert deleted[0].severity == Severity.MEDIUM

    def test_collect_updates_baseline(self, tmp_path: Path):
        """After collect(), the baseline should reflect the current state."""
        (tmp_path / "file.txt").write_text("v1")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        (tmp_path / "file.txt").write_text("v2")
        sensor.collect()

        # Second collect should show no changes since baseline was updated
        events = sensor.collect()
        snapshot = [e for e in events if e.event_type == "file_snapshot"][0]
        assert snapshot.data["total_changes"] == 0

    def test_all_events_have_file_sensor_type(self, tmp_path: Path):
        (tmp_path / "a.txt").write_text("a")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        (tmp_path / "b.txt").write_text("b")
        events = sensor.collect()

        for event in events:
            assert event.sensor == SensorType.FILE


# ------------------------------------------------------------------ #
# Canary system
# ------------------------------------------------------------------ #


class TestCanarySystem:
    def test_canaries_deployed_on_setup(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=True
        )
        sensor.setup()

        assert len(sensor._canary_paths) >= 1
        for canary in sensor._canary_paths:
            assert canary.exists()
            assert _CANARY_PREFIX in canary.name

    def test_canary_content_contains_signature(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=True
        )
        sensor.setup()

        canary = sensor._canary_paths[0]
        content = canary.read_bytes()
        assert b"AEGIS SECURITY CANARY" in content

    def test_canary_deletion_triggers_critical(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=True
        )
        sensor.setup()
        assert len(sensor._canary_paths) >= 1

        # Delete the canary
        canary = sensor._canary_paths[0]
        canary.unlink()

        events = sensor.collect()
        canary_events = [e for e in events if e.event_type == "canary_triggered"]
        assert len(canary_events) >= 1
        assert canary_events[0].severity == Severity.CRITICAL
        assert canary_events[0].data["reason"] == "deleted"

    def test_canary_modification_triggers_critical(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=True
        )
        sensor.setup()

        canary = sensor._canary_paths[0]
        # Overwrite with content that lacks the signature
        canary.write_bytes(b"this file has been encrypted by ransomware")

        events = sensor.collect()
        canary_events = [e for e in events if e.event_type == "canary_triggered"]
        assert len(canary_events) >= 1
        assert canary_events[0].severity == Severity.CRITICAL
        assert canary_events[0].data["reason"] == "modified"

    def test_canaries_cleaned_on_teardown(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=True
        )
        sensor.setup()

        canary_paths = list(sensor._canary_paths)
        assert all(c.exists() for c in canary_paths)

        sensor.teardown()

        for c in canary_paths:
            assert not c.exists()
        assert len(sensor._canary_paths) == 0

    def test_canaries_not_deployed_when_disabled(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()
        assert len(sensor._canary_paths) == 0

    def test_canary_not_in_baseline(self, tmp_path: Path):
        """Canary files should be excluded from the file hash baseline."""
        (tmp_path / "real_file.txt").write_text("real content")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=True
        )
        sensor.setup()

        # Baseline should contain the real file but NOT the canary
        assert any("real_file.txt" in k for k in sensor._baseline)
        for key in sensor._baseline:
            assert _CANARY_PREFIX not in key

    def test_canary_deletion_not_reported_as_file_change(self, tmp_path: Path):
        """A deleted canary should trigger canary_triggered, NOT file_change."""
        (tmp_path / "normal.txt").write_text("normal")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=True
        )
        sensor.setup()

        canary = sensor._canary_paths[0]
        canary.unlink()

        events = sensor.collect()
        deleted_changes = [
            e
            for e in events
            if e.event_type == "file_change" and e.data.get("change_type") == "deleted"
        ]
        # Canary deletion should NOT appear in file_change events
        for evt in deleted_changes:
            assert _CANARY_PREFIX not in evt.data["path"]

    def test_snapshot_severity_critical_when_canary_triggered(self, tmp_path: Path):
        """Snapshot severity should be CRITICAL when a canary is triggered."""
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=True
        )
        sensor.setup()

        canary = sensor._canary_paths[0]
        canary.unlink()

        events = sensor.collect()
        snapshot = [e for e in events if e.event_type == "file_snapshot"][0]
        assert snapshot.severity == Severity.CRITICAL
        assert snapshot.data["canary_alerts"] >= 1


# ------------------------------------------------------------------ #
# Feature extraction
# ------------------------------------------------------------------ #


class TestFeatureExtraction:
    def test_snapshot_has_feature_fields(self, tmp_path: Path):
        (tmp_path / "file.txt").write_text("data")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()
        events = sensor.collect()

        snapshot = [e for e in events if e.event_type == "file_snapshot"][0]
        data = snapshot.data

        assert "files_changed_per_minute" in data
        assert "file_types_changed" in data
        assert "entropy_increase_rate" in data
        assert "critical_dir_changes" in data

    def test_files_changed_per_minute_nonzero_after_changes(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        for i in range(5):
            (tmp_path / f"new_{i}.txt").write_text(f"content {i}")

        events = sensor.collect()
        snapshot = [e for e in events if e.event_type == "file_snapshot"][0]
        assert snapshot.data["files_changed_per_minute"] > 0

    def test_file_types_changed_lists_extensions(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        (tmp_path / "doc.pdf").write_bytes(b"fake pdf")
        (tmp_path / "script.py").write_text("print('hi')")

        events = sensor.collect()
        snapshot = [e for e in events if e.event_type == "file_snapshot"][0]
        extensions = snapshot.data["file_types_changed"]
        assert ".pdf" in extensions
        assert ".py" in extensions

    def test_entropy_increase_rate_zero_for_no_changes(self, tmp_path: Path):
        (tmp_path / "file.txt").write_text("hello")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()
        events = sensor.collect()

        snapshot = [e for e in events if e.event_type == "file_snapshot"][0]
        assert snapshot.data["entropy_increase_rate"] == 0.0

    def test_critical_dir_changes_zero_for_non_critical_path(self, tmp_path: Path):
        """Changes in a non-critical directory should not count."""
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()

        (tmp_path / "harmless.txt").write_text("nothing special")
        events = sensor.collect()

        snapshot = [e for e in events if e.event_type == "file_snapshot"][0]
        assert snapshot.data["critical_dir_changes"] == 0

    def test_snapshot_tracks_total_files(self, tmp_path: Path):
        for i in range(3):
            (tmp_path / f"f{i}.txt").write_text(f"data {i}")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()
        events = sensor.collect()

        snapshot = [e for e in events if e.event_type == "file_snapshot"][0]
        assert snapshot.data["total_files_tracked"] == 3

    def test_snapshot_watched_dirs_field(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()
        events = sensor.collect()

        snapshot = [e for e in events if e.event_type == "file_snapshot"][0]
        assert str(tmp_path) in snapshot.data["watched_dirs"]


# ------------------------------------------------------------------ #
# Teardown
# ------------------------------------------------------------------ #


class TestTeardown:
    def test_teardown_clears_baseline(self, tmp_path: Path):
        (tmp_path / "file.txt").write_text("data")

        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=False
        )
        sensor.setup()
        assert len(sensor._baseline) > 0

        sensor.teardown()
        assert len(sensor._baseline) == 0

    def test_teardown_clears_canary_list(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=True
        )
        sensor.setup()
        assert len(sensor._canary_paths) > 0

        sensor.teardown()
        assert len(sensor._canary_paths) == 0

    def test_teardown_idempotent(self, tmp_path: Path):
        sensor = FileIntegritySensor(
            watched_dirs=[str(tmp_path)], enable_canary=True
        )
        sensor.setup()
        sensor.teardown()
        # Second teardown should not raise
        sensor.teardown()
        assert len(sensor._baseline) == 0
        assert len(sensor._canary_paths) == 0
