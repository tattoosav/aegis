"""Tests for the Windows Registry Monitor sensor.

Covers:
- RegistryValue dataclass construction and fields
- _hash_value deterministic hashing
- _value_entropy Shannon entropy calculations
- _hive_name mapping constants to labels
- MONITORED_KEYS structure validation
- RegistrySensor init, setup, collect, teardown lifecycle
- Change detection: created, modified, deleted values
- Event data schema and severity mapping
- Graceful degradation on non-Windows platforms
- Start/stop threaded lifecycle
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import fields
from unittest.mock import MagicMock, patch

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.registry import (
    MONITORED_KEYS,
    RegistrySensor,
    RegistryValue,
    _hash_value,
    _HKCU,
    _HKLM,
    _hive_name,
    _value_entropy,
)

# --------------------------------------------------------------------------- #
# Helper: module path for patching
# --------------------------------------------------------------------------- #
_MOD = "aegis.sensors.registry"


def _make_reg_value(
    hive: str = "HKLM",
    key_path: str = r"SOFTWARE\Test",
    value_name: str = "TestVal",
    value_data: str = "hello",
    value_type: int = 1,
    category: str = "persistence",
    mitre_id: str = "T1547.001",
) -> RegistryValue:
    """Convenience factory for RegistryValue with sensible defaults."""
    return RegistryValue(
        hive=hive,
        key_path=key_path,
        value_name=value_name,
        value_data=value_data,
        value_type=value_type,
        data_hash=_hash_value(value_data),
        category=category,
        mitre_id=mitre_id,
    )


# =========================================================================== #
# TestRegistryValueDataclass
# =========================================================================== #


class TestRegistryValueDataclass:
    """Unit tests for the RegistryValue dataclass."""

    def test_has_expected_fields(self):
        """RegistryValue must expose all required fields."""
        names = {f.name for f in fields(RegistryValue)}
        expected = {
            "hive", "key_path", "value_name", "value_data",
            "value_type", "data_hash", "category", "mitre_id",
        }
        assert names == expected

    def test_construct_with_positional_args(self):
        """All fields can be set via positional arguments."""
        rv = RegistryValue(
            "HKLM", r"SOFTWARE\Run", "MyApp",
            "C:\\app.exe", 1, "abc123", "persistence", "T1547.001",
        )
        assert rv.hive == "HKLM"
        assert rv.key_path == r"SOFTWARE\Run"
        assert rv.value_name == "MyApp"
        assert rv.value_data == "C:\\app.exe"
        assert rv.value_type == 1
        assert rv.data_hash == "abc123"
        assert rv.category == "persistence"
        assert rv.mitre_id == "T1547.001"

    def test_construct_with_keyword_args(self):
        """All fields can be set via keyword arguments."""
        rv = _make_reg_value(hive="HKCU", value_name="Browser")
        assert rv.hive == "HKCU"
        assert rv.value_name == "Browser"

    def test_equality_same_values(self):
        """Two RegistryValues with identical fields should be equal."""
        a = _make_reg_value(value_data="same")
        b = _make_reg_value(value_data="same")
        assert a == b

    def test_inequality_different_data(self):
        """Different value_data should make instances unequal."""
        a = _make_reg_value(value_data="alpha")
        b = _make_reg_value(value_data="bravo")
        assert a != b

    def test_value_type_is_int(self):
        """value_type field stores an integer registry type constant."""
        rv = _make_reg_value(value_type=4)
        assert isinstance(rv.value_type, int)
        assert rv.value_type == 4

    def test_data_hash_stored_as_string(self):
        """data_hash should be a string."""
        rv = _make_reg_value()
        assert isinstance(rv.data_hash, str)


# =========================================================================== #
# TestHashValue
# =========================================================================== #


class TestHashValue:
    """Unit tests for the _hash_value helper function."""

    def test_deterministic(self):
        """Same input must always produce the same hash."""
        assert _hash_value("test") == _hash_value("test")

    def test_different_inputs_different_hashes(self):
        """Different inputs must yield different hashes."""
        assert _hash_value("alpha") != _hash_value("bravo")

    def test_returns_16_char_hex(self):
        """Output should be a 16-character hex string (first 16 of SHA-256)."""
        result = _hash_value("data")
        assert len(result) == 16
        assert all(c in "0123456789abcdef" for c in result)

    def test_known_hash(self):
        """Verify against a known SHA-256 prefix."""
        expected = hashlib.sha256(b"hello").hexdigest()[:16]
        assert _hash_value("hello") == expected

    def test_empty_string(self):
        """Empty string should produce a valid 16-char hex hash."""
        result = _hash_value("")
        assert len(result) == 16
        assert all(c in "0123456789abcdef" for c in result)

    def test_integer_input(self):
        """Integer data should be serialised to string and hashed."""
        result = _hash_value(42)
        expected = hashlib.sha256(b"42").hexdigest()[:16]
        assert result == expected

    def test_none_input(self):
        """None should be serialised as 'None' and hashed."""
        result = _hash_value(None)
        expected = hashlib.sha256(b"None").hexdigest()[:16]
        assert result == expected

    def test_bytes_input(self):
        """Bytes input should be serialised via str() and hashed."""
        result = _hash_value(b"\x00\x01\x02")
        assert len(result) == 16


# =========================================================================== #
# TestValueEntropy
# =========================================================================== #


class TestValueEntropy:
    """Unit tests for the _value_entropy Shannon entropy function."""

    def test_empty_string_returns_zero(self):
        """Empty string should yield 0.0 entropy."""
        assert _value_entropy("") == 0.0

    def test_single_char_string_returns_zero(self):
        """A single repeated character has zero entropy."""
        assert _value_entropy("aaaa") == 0.0

    def test_two_chars_equal_frequency(self):
        """Equal frequency of two characters should yield entropy of 1.0."""
        result = _value_entropy("ab")
        assert abs(result - 1.0) < 0.01

    def test_positive_for_varied_data(self):
        """Varied data should have positive entropy."""
        result = _value_entropy("Hello, World!")
        assert result > 0.0

    def test_high_entropy_for_random_data(self):
        """Random-like data should have high entropy (> 3.0)."""
        random_data = "".join(chr(i) for i in range(32, 127))
        result = _value_entropy(random_data)
        assert result > 3.0

    def test_returns_float(self):
        """Return type must be float."""
        result = _value_entropy("test")
        assert isinstance(result, float)

    def test_entropy_bounded(self):
        """Entropy of UTF-8 encoded data should be in [0, 8]."""
        result = _value_entropy("some test data with variety 123!@#")
        assert 0.0 <= result <= 8.0

    def test_integer_data_works(self):
        """Integer input should be handled without error."""
        result = _value_entropy(12345)
        assert isinstance(result, float)
        assert result > 0.0


# =========================================================================== #
# TestHiveName
# =========================================================================== #


class TestHiveName:
    """Unit tests for the _hive_name helper."""

    def test_hklm(self):
        """_HKLM constant should map to 'HKLM'."""
        assert _hive_name(_HKLM) == "HKLM"

    def test_hkcu(self):
        """_HKCU constant should map to 'HKCU'."""
        assert _hive_name(_HKCU) == "HKCU"

    def test_unknown_defaults_to_hkcu(self):
        """Any non-HKLM value should default to 'HKCU'."""
        assert _hive_name(0x99999999) == "HKCU"

    def test_hklm_hex_value(self):
        """_HKLM should be 0x80000002."""
        assert _HKLM == 0x80000002

    def test_hkcu_hex_value(self):
        """_HKCU should be 0x80000001."""
        assert _HKCU == 0x80000001


# =========================================================================== #
# TestMonitoredKeys
# =========================================================================== #


class TestMonitoredKeys:
    """Validate MONITORED_KEYS module constant."""

    def test_is_list(self):
        """MONITORED_KEYS should be a list."""
        assert isinstance(MONITORED_KEYS, list)

    def test_not_empty(self):
        """There must be at least one monitored key."""
        assert len(MONITORED_KEYS) > 0

    def test_each_entry_is_4_tuple(self):
        """Every entry should be a 4-tuple: (hive, path, category, mitre)."""
        for entry in MONITORED_KEYS:
            assert isinstance(entry, tuple)
            assert len(entry) == 4

    def test_hive_values_are_ints(self):
        """Hive constants should be integers."""
        for hive, _path, _cat, _mitre in MONITORED_KEYS:
            assert isinstance(hive, int)
            assert hive in (_HKLM, _HKCU)

    def test_key_paths_are_strings(self):
        """Key paths should be non-empty strings."""
        for _hive, path, _cat, _mitre in MONITORED_KEYS:
            assert isinstance(path, str)
            assert len(path) > 0

    def test_categories_are_strings(self):
        """Category values should be non-empty strings."""
        for _hive, _path, cat, _mitre in MONITORED_KEYS:
            assert isinstance(cat, str)
            assert len(cat) > 0

    def test_mitre_ids_have_correct_format(self):
        """MITRE ATT&CK IDs should start with 'T' and contain digits."""
        for _hive, _path, _cat, mitre in MONITORED_KEYS:
            assert isinstance(mitre, str)
            assert mitre.startswith("T")
            assert any(c.isdigit() for c in mitre)

    def test_contains_run_key(self):
        """MONITORED_KEYS should include the classic Run key."""
        paths = [path for _, path, _, _ in MONITORED_KEYS]
        assert any("CurrentVersion\\Run" in p for p in paths)

    def test_contains_services_key(self):
        """MONITORED_KEYS should include the Services key."""
        paths = [path for _, path, _, _ in MONITORED_KEYS]
        assert any("Services" in p for p in paths)


# =========================================================================== #
# TestRegistrySensorInit
# =========================================================================== #


class TestRegistrySensorInit:
    """Tests for RegistrySensor instantiation and class attributes."""

    def test_sensor_type_is_registry(self):
        """sensor_type class var must be SensorType.REGISTRY."""
        sensor = RegistrySensor(interval=999)
        assert sensor.sensor_type == SensorType.REGISTRY

    def test_sensor_name(self):
        """sensor_name must be 'registry_monitor'."""
        sensor = RegistrySensor(interval=999)
        assert sensor.sensor_name == "registry_monitor"

    def test_default_interval_is_10(self):
        """Default interval should be 10.0 seconds."""
        sensor = RegistrySensor()
        assert sensor._interval == 10.0

    def test_custom_interval(self):
        """Custom interval should be respected."""
        sensor = RegistrySensor(interval=30.0)
        assert sensor._interval == 30.0

    def test_default_monitored_keys(self):
        """Without explicit keys, sensor uses MONITORED_KEYS."""
        sensor = RegistrySensor(interval=999)
        assert sensor._monitored_keys is MONITORED_KEYS

    def test_custom_monitored_keys(self):
        """Custom keys list should override MONITORED_KEYS."""
        custom = [(_HKLM, r"SOFTWARE\Custom", "test", "T0000")]
        sensor = RegistrySensor(interval=999, monitored_keys=custom)
        assert sensor._monitored_keys == custom
        assert sensor._monitored_keys is not MONITORED_KEYS

    def test_initial_baseline_empty(self):
        """Freshly constructed sensor should have empty baseline."""
        sensor = RegistrySensor(interval=999)
        assert sensor._baseline == {}

    def test_initial_cycle_zero(self):
        """Cycle counter should start at zero."""
        sensor = RegistrySensor(interval=999)
        assert sensor._cycle == 0

    def test_on_event_callback_stored(self):
        """on_event callback should be stored by BaseSensor."""
        cb = lambda e: None  # noqa: E731
        sensor = RegistrySensor(interval=999, on_event=cb)
        assert sensor._on_event is cb


# =========================================================================== #
# TestRegistrySensorSetup
# =========================================================================== #


class TestRegistrySensorSetup:
    """Tests for the setup() lifecycle method."""

    def test_setup_builds_baseline(self):
        """setup() should populate _baseline from _read_key_values."""
        vals = [_make_reg_value(value_name="App1")]
        sensor = RegistrySensor(
            interval=999,
            monitored_keys=[(_HKLM, r"SOFTWARE\Run", "persistence", "T1547.001")],
        )
        with patch.object(sensor, "_read_key_values", return_value=vals):
            sensor.setup()
        assert len(sensor._baseline) == 1
        key = r"HKLM\SOFTWARE\Test\App1"
        assert key in sensor._baseline

    def test_setup_multiple_keys(self):
        """setup() should scan all monitored keys."""
        val_a = _make_reg_value(value_name="ValA", key_path=r"Path\A")
        val_b = _make_reg_value(value_name="ValB", key_path=r"Path\B")

        sensor = RegistrySensor(
            interval=999,
            monitored_keys=[
                (_HKLM, r"Path\A", "persistence", "T1547.001"),
                (_HKLM, r"Path\B", "persistence", "T1547.001"),
            ],
        )
        side_effects = [[val_a], [val_b]]
        with patch.object(
            sensor, "_read_key_values", side_effect=side_effects,
        ):
            sensor.setup()
        assert len(sensor._baseline) == 2

    def test_setup_with_empty_key(self):
        """setup() should handle keys with no values gracefully."""
        sensor = RegistrySensor(
            interval=999,
            monitored_keys=[(_HKLM, r"SOFTWARE\Empty", "test", "T0000")],
        )
        with patch.object(sensor, "_read_key_values", return_value=[]):
            sensor.setup()
        assert sensor._baseline == {}


# =========================================================================== #
# TestRegistrySensorCollect
# =========================================================================== #


class TestRegistrySensorCollect:
    """Tests for the collect() method — core change detection."""

    def _make_sensor_with_baseline(
        self,
        baseline_vals: list[RegistryValue],
    ) -> RegistrySensor:
        """Create a sensor with a pre-populated baseline."""
        sensor = RegistrySensor(
            interval=999,
            monitored_keys=[
                (_HKLM, r"SOFTWARE\Run", "persistence", "T1547.001"),
            ],
        )
        for val in baseline_vals:
            key = f"{val.hive}\\{val.key_path}\\{val.value_name}"
            sensor._baseline[key] = val
        return sensor

    def test_collect_returns_snapshot_event(self):
        """collect() must always include a registry_snapshot event."""
        sensor = self._make_sensor_with_baseline([])
        with patch.object(sensor, "_read_key_values", return_value=[]):
            events = sensor.collect()
        types = [e.event_type for e in events]
        assert "registry_snapshot" in types

    def test_snapshot_has_expected_data_keys(self):
        """The snapshot event data must contain cycle and counter fields."""
        sensor = self._make_sensor_with_baseline([])
        with patch.object(sensor, "_read_key_values", return_value=[]):
            events = sensor.collect()
        snapshot = [e for e in events if e.event_type == "registry_snapshot"][0]
        assert "cycle" in snapshot.data
        assert "total_values" in snapshot.data
        assert "created" in snapshot.data
        assert "modified" in snapshot.data
        assert "deleted" in snapshot.data

    def test_snapshot_severity_is_info(self):
        """The snapshot event should have INFO severity."""
        sensor = self._make_sensor_with_baseline([])
        with patch.object(sensor, "_read_key_values", return_value=[]):
            events = sensor.collect()
        snapshot = [e for e in events if e.event_type == "registry_snapshot"][0]
        assert snapshot.severity == Severity.INFO

    def test_snapshot_sensor_is_registry(self):
        """The snapshot event sensor field must be REGISTRY."""
        sensor = self._make_sensor_with_baseline([])
        with patch.object(sensor, "_read_key_values", return_value=[]):
            events = sensor.collect()
        snapshot = [e for e in events if e.event_type == "registry_snapshot"][0]
        assert snapshot.sensor == SensorType.REGISTRY

    def test_collect_increments_cycle(self):
        """Each call to collect() should increment the cycle counter."""
        sensor = self._make_sensor_with_baseline([])
        with patch.object(sensor, "_read_key_values", return_value=[]):
            sensor.collect()
            assert sensor._cycle == 1
            sensor.collect()
            assert sensor._cycle == 2
            sensor.collect()
            assert sensor._cycle == 3

    def test_collect_no_changes_no_change_events(self):
        """When baseline matches current, no registry_change events."""
        val = _make_reg_value(value_name="Stable")
        sensor = self._make_sensor_with_baseline([val])
        with patch.object(sensor, "_read_key_values", return_value=[val]):
            events = sensor.collect()
        change_events = [
            e for e in events if e.event_type == "registry_change"
        ]
        assert len(change_events) == 0

    def test_collect_detects_created_value(self):
        """A value present in current but not baseline should be 'created'."""
        sensor = self._make_sensor_with_baseline([])
        new_val = _make_reg_value(value_name="NewApp")
        with patch.object(
            sensor, "_read_key_values", return_value=[new_val],
        ):
            events = sensor.collect()
        changes = [
            e for e in events if e.event_type == "registry_change"
        ]
        assert len(changes) == 1
        assert changes[0].data["change_type"] == "created"
        assert changes[0].data["value_name"] == "NewApp"

    def test_created_severity_is_high(self):
        """Created registry values should trigger HIGH severity."""
        sensor = self._make_sensor_with_baseline([])
        new_val = _make_reg_value(value_name="Malware")
        with patch.object(
            sensor, "_read_key_values", return_value=[new_val],
        ):
            events = sensor.collect()
        change = [
            e for e in events if e.event_type == "registry_change"
        ][0]
        assert change.severity == Severity.HIGH

    def test_collect_detects_modified_value(self):
        """A value whose hash changed should be 'modified'."""
        old_val = _make_reg_value(value_name="Config", value_data="old")
        sensor = self._make_sensor_with_baseline([old_val])
        new_val = _make_reg_value(value_name="Config", value_data="new")
        with patch.object(
            sensor, "_read_key_values", return_value=[new_val],
        ):
            events = sensor.collect()
        changes = [
            e for e in events if e.event_type == "registry_change"
        ]
        assert len(changes) == 1
        assert changes[0].data["change_type"] == "modified"

    def test_modified_severity_is_medium(self):
        """Modified registry values should trigger MEDIUM severity."""
        old_val = _make_reg_value(value_name="Cfg", value_data="v1")
        sensor = self._make_sensor_with_baseline([old_val])
        new_val = _make_reg_value(value_name="Cfg", value_data="v2")
        with patch.object(
            sensor, "_read_key_values", return_value=[new_val],
        ):
            events = sensor.collect()
        change = [
            e for e in events if e.event_type == "registry_change"
        ][0]
        assert change.severity == Severity.MEDIUM

    def test_collect_detects_deleted_value(self):
        """A value in baseline but missing from current should be 'deleted'."""
        old_val = _make_reg_value(value_name="Removed")
        sensor = self._make_sensor_with_baseline([old_val])
        with patch.object(sensor, "_read_key_values", return_value=[]):
            events = sensor.collect()
        changes = [
            e for e in events if e.event_type == "registry_change"
        ]
        assert len(changes) == 1
        assert changes[0].data["change_type"] == "deleted"

    def test_deleted_severity_is_medium(self):
        """Deleted registry values should trigger MEDIUM severity."""
        old_val = _make_reg_value(value_name="Gone")
        sensor = self._make_sensor_with_baseline([old_val])
        with patch.object(sensor, "_read_key_values", return_value=[]):
            events = sensor.collect()
        change = [
            e for e in events if e.event_type == "registry_change"
        ][0]
        assert change.severity == Severity.MEDIUM

    def test_snapshot_counts_match_changes(self):
        """Snapshot data counters should reflect actual change counts."""
        old_val = _make_reg_value(value_name="Old", value_data="v1")
        sensor = self._make_sensor_with_baseline([old_val])

        modified_val = _make_reg_value(value_name="Old", value_data="v2")
        new_val = _make_reg_value(value_name="Brand", value_data="new")

        with patch.object(
            sensor, "_read_key_values",
            return_value=[modified_val, new_val],
        ):
            events = sensor.collect()

        snapshot = [
            e for e in events if e.event_type == "registry_snapshot"
        ][0]
        assert snapshot.data["created"] == 1
        assert snapshot.data["modified"] == 1
        assert snapshot.data["deleted"] == 0

    def test_collect_updates_baseline(self):
        """After collect(), baseline should reflect the current state."""
        sensor = self._make_sensor_with_baseline([])
        val = _make_reg_value(value_name="New")
        with patch.object(sensor, "_read_key_values", return_value=[val]):
            sensor.collect()

        key = f"{val.hive}\\{val.key_path}\\{val.value_name}"
        assert key in sensor._baseline
        assert sensor._baseline[key] == val

    def test_collect_returns_list_of_aegis_events(self):
        """All items returned by collect() must be AegisEvent instances."""
        sensor = self._make_sensor_with_baseline([])
        with patch.object(sensor, "_read_key_values", return_value=[]):
            events = sensor.collect()
        assert isinstance(events, list)
        for event in events:
            assert isinstance(event, AegisEvent)
            assert event.sensor == SensorType.REGISTRY

    def test_collect_multiple_changes_at_once(self):
        """Detect created, modified, and deleted in the same collect cycle."""
        old_a = _make_reg_value(value_name="ModMe", value_data="orig")
        old_b = _make_reg_value(value_name="DelMe", value_data="bye")
        sensor = self._make_sensor_with_baseline([old_a, old_b])

        mod_a = _make_reg_value(value_name="ModMe", value_data="changed")
        new_c = _make_reg_value(value_name="NewVal", value_data="fresh")

        with patch.object(
            sensor, "_read_key_values",
            return_value=[mod_a, new_c],
        ):
            events = sensor.collect()

        changes = [
            e for e in events if e.event_type == "registry_change"
        ]
        change_types = [c.data["change_type"] for c in changes]
        assert "created" in change_types
        assert "modified" in change_types
        assert "deleted" in change_types


# =========================================================================== #
# TestMakeChangeEvent
# =========================================================================== #


class TestMakeChangeEvent:
    """Tests for the _make_change_event method."""

    def _make_sensor(self) -> RegistrySensor:
        return RegistrySensor(interval=999)

    def test_returns_aegis_event(self):
        """_make_change_event should return an AegisEvent."""
        sensor = self._make_sensor()
        val = _make_reg_value()
        event = sensor._make_change_event(val, "created")
        assert isinstance(event, AegisEvent)

    def test_event_type_is_registry_change(self):
        """Event type should always be 'registry_change'."""
        sensor = self._make_sensor()
        val = _make_reg_value()
        event = sensor._make_change_event(val, "modified")
        assert event.event_type == "registry_change"

    def test_sensor_is_registry(self):
        """Sensor field should be SensorType.REGISTRY."""
        sensor = self._make_sensor()
        val = _make_reg_value()
        event = sensor._make_change_event(val, "created")
        assert event.sensor == SensorType.REGISTRY

    def test_created_severity_high(self):
        """'created' change type should map to HIGH severity."""
        sensor = self._make_sensor()
        val = _make_reg_value()
        event = sensor._make_change_event(val, "created")
        assert event.severity == Severity.HIGH

    def test_modified_severity_medium(self):
        """'modified' change type should map to MEDIUM severity."""
        sensor = self._make_sensor()
        val = _make_reg_value()
        event = sensor._make_change_event(val, "modified")
        assert event.severity == Severity.MEDIUM

    def test_deleted_severity_medium(self):
        """'deleted' change type should map to MEDIUM severity."""
        sensor = self._make_sensor()
        val = _make_reg_value()
        event = sensor._make_change_event(val, "deleted")
        assert event.severity == Severity.MEDIUM

    def test_event_data_contains_all_fields(self):
        """Change event data dict must include all expected keys."""
        sensor = self._make_sensor()
        val = _make_reg_value(
            hive="HKLM",
            key_path=r"SOFTWARE\Run",
            value_name="Evil",
            value_data="C:\\evil.exe",
            value_type=1,
            category="persistence",
            mitre_id="T1547.001",
        )
        event = sensor._make_change_event(val, "created")

        expected_keys = {
            "hive", "key_path", "value_name", "value_data",
            "value_type", "data_hash", "category", "mitre_id",
            "change_type", "entropy",
        }
        assert set(event.data.keys()) == expected_keys

    def test_event_data_values_match_input(self):
        """Change event data values should match the input RegistryValue."""
        sensor = self._make_sensor()
        val = _make_reg_value(
            hive="HKCU",
            key_path=r"SOFTWARE\Test",
            value_name="MyVal",
            value_data="payload",
            value_type=2,
            category="execution",
            mitre_id="T1546.001",
        )
        event = sensor._make_change_event(val, "deleted")

        assert event.data["hive"] == "HKCU"
        assert event.data["key_path"] == r"SOFTWARE\Test"
        assert event.data["value_name"] == "MyVal"
        assert event.data["value_data"] == "payload"
        assert event.data["value_type"] == 2
        assert event.data["category"] == "execution"
        assert event.data["mitre_id"] == "T1546.001"
        assert event.data["change_type"] == "deleted"

    def test_event_data_includes_entropy(self):
        """Change event data should include an 'entropy' float."""
        sensor = self._make_sensor()
        val = _make_reg_value(value_data="some data")
        event = sensor._make_change_event(val, "created")
        assert "entropy" in event.data
        assert isinstance(event.data["entropy"], float)

    def test_event_has_event_id(self):
        """Every AegisEvent should have a non-empty event_id."""
        sensor = self._make_sensor()
        val = _make_reg_value()
        event = sensor._make_change_event(val, "created")
        assert isinstance(event.event_id, str)
        assert len(event.event_id) > 0

    def test_event_has_timestamp(self):
        """Every AegisEvent should have a float timestamp."""
        sensor = self._make_sensor()
        val = _make_reg_value()
        event = sensor._make_change_event(val, "created")
        assert isinstance(event.timestamp, float)
        assert event.timestamp > 0


# =========================================================================== #
# TestRegistrySensorTeardown
# =========================================================================== #


class TestRegistrySensorTeardown:
    """Tests for the teardown() lifecycle method."""

    def test_teardown_clears_baseline(self):
        """teardown() should empty the baseline dict."""
        sensor = RegistrySensor(interval=999)
        sensor._baseline = {"key": _make_reg_value()}
        sensor.teardown()
        assert sensor._baseline == {}

    def test_teardown_on_empty_baseline(self):
        """teardown() should be safe to call on an empty baseline."""
        sensor = RegistrySensor(interval=999)
        sensor.teardown()
        assert sensor._baseline == {}


# =========================================================================== #
# TestGracefulDegradation
# =========================================================================== #


class TestGracefulDegradation:
    """Tests for non-Windows graceful degradation."""

    def test_read_key_values_stub_returns_empty(self):
        """The stub method should return an empty list."""
        sensor = RegistrySensor(interval=999)
        result = sensor._read_key_values_stub(
            _HKLM, r"SOFTWARE\Run", "persistence", "T1547.001",
        )
        assert result == []
        assert isinstance(result, list)

    @patch(f"{_MOD}._HAS_WINREG", False)
    def test_read_key_values_falls_back_to_stub(self):
        """When winreg is unavailable, _read_key_values uses stub."""
        sensor = RegistrySensor(interval=999)
        result = sensor._read_key_values(
            _HKLM, r"SOFTWARE\Run", "persistence", "T1547.001",
        )
        assert result == []

    @patch(f"{_MOD}._HAS_WINREG", False)
    def test_full_collect_cycle_without_winreg(self):
        """Sensor should complete setup/collect/teardown without winreg."""
        sensor = RegistrySensor(interval=999)
        sensor.setup()
        assert sensor._baseline == {}

        events = sensor.collect()
        assert isinstance(events, list)
        snapshots = [
            e for e in events if e.event_type == "registry_snapshot"
        ]
        assert len(snapshots) == 1
        assert snapshots[0].data["total_values"] == 0

        sensor.teardown()
        assert sensor._baseline == {}


# =========================================================================== #
# TestRegistrySensorLifecycle
# =========================================================================== #


class TestRegistrySensorLifecycle:
    """Integration-style tests for start/stop threaded lifecycle."""

    def test_start_and_stop(self):
        """Sensor starts, collects at least once, and stops cleanly."""
        collected: list[AegisEvent] = []
        sensor = RegistrySensor(
            interval=0.1,
            monitored_keys=[],
            on_event=lambda e: collected.append(e),
        )
        with patch.object(sensor, "_read_key_values", return_value=[]):
            sensor.start()
            assert sensor.is_running

            for _ in range(50):
                if len(collected) > 0:
                    break
                time.sleep(0.05)

            sensor.stop()

        assert not sensor.is_running
        assert len(collected) > 0, "Expected at least one event"

    def test_emitted_events_are_registry_type(self):
        """All events via callback should have REGISTRY sensor type."""
        collected: list[AegisEvent] = []
        sensor = RegistrySensor(
            interval=0.1,
            monitored_keys=[],
            on_event=lambda e: collected.append(e),
        )
        with patch.object(sensor, "_read_key_values", return_value=[]):
            sensor.start()
            for _ in range(50):
                if len(collected) > 0:
                    break
                time.sleep(0.05)
            sensor.stop()

        for evt in collected:
            assert isinstance(evt, AegisEvent)
            assert evt.sensor == SensorType.REGISTRY

    def test_start_idempotent(self):
        """Calling start() twice should not create a second thread."""
        sensor = RegistrySensor(
            interval=0.1, monitored_keys=[],
        )
        with patch.object(sensor, "_read_key_values", return_value=[]):
            sensor.start()
            thread1 = sensor._thread
            sensor.start()
            thread2 = sensor._thread
            sensor.stop()
        assert thread1 is thread2

    def test_stop_without_start(self):
        """Calling stop() without start() should not raise."""
        sensor = RegistrySensor(interval=999)
        sensor.stop()
        assert not sensor.is_running
