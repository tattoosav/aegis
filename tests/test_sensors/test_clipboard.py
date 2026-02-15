"""Tests for the Clipboard & Screen Monitor sensor."""

import hashlib
import time
from unittest.mock import MagicMock, patch

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.clipboard import (
    _HIJACK_CHANGE_THRESHOLD,
    _HIJACK_WINDOW_SECS,
    _SCREEN_CAPTURE_NAMES,
    _SENSITIVE_PATTERNS,
    ClipboardSensor,
    _detect_sensitive_patterns,
    _find_screen_capture_processes,
    _sha256,
)

# --------------------------------------------------------------------------- #
# Helper: module path for patching clipboard functions
# --------------------------------------------------------------------------- #
_MOD = "aegis.sensors.clipboard"


# =========================================================================== #
# TestSha256
# =========================================================================== #


class TestSha256:
    """Unit tests for the _sha256 helper function."""

    def test_deterministic(self):
        """Same input must always produce the same digest."""
        text = "consistent input"
        assert _sha256(text) == _sha256(text)

    def test_different_inputs_different_hashes(self):
        """Different inputs must yield different digests."""
        assert _sha256("alpha") != _sha256("bravo")

    def test_known_hash(self):
        """Verify against the well-known SHA-256 of 'hello'."""
        expected = hashlib.sha256(b"hello").hexdigest()
        assert _sha256("hello") == expected

    def test_empty_string(self):
        """Empty string should still produce a valid 64-char hex digest."""
        result = _sha256("")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_unicode_text(self):
        """Non-ASCII text should be handled without error."""
        result = _sha256("clipboard content")
        assert isinstance(result, str)
        assert len(result) == 64


# =========================================================================== #
# TestSensitivePatternDetection
# =========================================================================== #


class TestSensitivePatternDetection:
    """Unit tests for _detect_sensitive_patterns."""

    def test_detects_credit_card(self):
        """Credit card number with spaces should be detected."""
        findings = _detect_sensitive_patterns("4111 1111 1111 1111")
        pattern_names = [f["pattern"] for f in findings]
        assert "credit_card" in pattern_names

    def test_detects_credit_card_with_dashes(self):
        """Credit card number with dashes should also match."""
        findings = _detect_sensitive_patterns("4111-1111-1111-1111")
        pattern_names = [f["pattern"] for f in findings]
        assert "credit_card" in pattern_names

    def test_detects_ssn(self):
        """Social security number pattern should be detected."""
        findings = _detect_sensitive_patterns("SSN: 123-45-6789")
        pattern_names = [f["pattern"] for f in findings]
        assert "ssn" in pattern_names

    def test_detects_api_key(self):
        """A 32+ character alphanumeric string should match as an API key."""
        long_key = "A" * 32
        findings = _detect_sensitive_patterns(f"key={long_key}")
        pattern_names = [f["pattern"] for f in findings]
        assert "api_key" in pattern_names

    def test_detects_btc_address(self):
        """Valid Bitcoin address format should be detected."""
        # Standard BTC address starting with 1, 26-34 chars from Base58 set
        btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        findings = _detect_sensitive_patterns(btc)
        pattern_names = [f["pattern"] for f in findings]
        assert "crypto_btc" in pattern_names

    def test_detects_eth_address(self):
        """Ethereum address (0x + 40 hex chars) should be detected."""
        eth = "0x" + "a1b2c3d4e5" * 4  # 40 hex chars
        findings = _detect_sensitive_patterns(eth)
        pattern_names = [f["pattern"] for f in findings]
        assert "crypto_eth" in pattern_names

    def test_no_match_for_normal_text(self):
        """Ordinary text should not trigger any pattern matches."""
        findings = _detect_sensitive_patterns("Hello world")
        assert findings == []

    def test_multiple_patterns_in_one_text(self):
        """Text containing multiple sensitive patterns should report all of them."""
        text = "CC: 4111 1111 1111 1111, SSN: 123-45-6789"
        findings = _detect_sensitive_patterns(text)
        pattern_names = [f["pattern"] for f in findings]
        assert "credit_card" in pattern_names
        assert "ssn" in pattern_names

    def test_findings_include_count(self):
        """Each finding dict must include a 'count' key with the match count."""
        text = "4111 1111 1111 1111 and 5500 0000 0000 0004"
        findings = _detect_sensitive_patterns(text)
        cc_findings = [f for f in findings if f["pattern"] == "credit_card"]
        assert len(cc_findings) == 1
        assert cc_findings[0]["count"] == 2

    def test_returns_list_of_dicts(self):
        """Return type must always be a list of dicts."""
        result = _detect_sensitive_patterns("nothing special")
        assert isinstance(result, list)
        result_with_match = _detect_sensitive_patterns("4111 1111 1111 1111")
        for item in result_with_match:
            assert isinstance(item, dict)
            assert "pattern" in item
            assert "count" in item


# =========================================================================== #
# TestModuleConstants
# =========================================================================== #


class TestModuleConstants:
    """Verify module-level constants are set correctly."""

    def test_sensitive_patterns_is_dict(self):
        assert isinstance(_SENSITIVE_PATTERNS, dict)
        assert len(_SENSITIVE_PATTERNS) > 0

    def test_screen_capture_names_is_list(self):
        assert isinstance(_SCREEN_CAPTURE_NAMES, list)
        assert len(_SCREEN_CAPTURE_NAMES) > 0

    def test_hijack_change_threshold(self):
        assert _HIJACK_CHANGE_THRESHOLD == 5

    def test_hijack_window_secs(self):
        assert _HIJACK_WINDOW_SECS == 60.0


# =========================================================================== #
# TestClipboardSensorInit
# =========================================================================== #


class TestClipboardSensorInit:
    """Tests for ClipboardSensor instantiation and class attributes."""

    def test_sensor_type(self):
        sensor = ClipboardSensor(interval=999)
        assert sensor.sensor_type == SensorType.CLIPBOARD

    def test_sensor_name(self):
        sensor = ClipboardSensor(interval=999)
        assert sensor.sensor_name == "clipboard_monitor"

    def test_default_interval_5(self):
        sensor = ClipboardSensor()
        assert sensor._interval == 5.0

    def test_custom_interval(self):
        sensor = ClipboardSensor(interval=10.0)
        assert sensor._interval == 10.0

    def test_initial_state(self):
        """Freshly constructed sensor should have empty tracking state."""
        sensor = ClipboardSensor(interval=999)
        assert sensor._prev_hash is None
        assert sensor._prev_content_length == 0
        assert sensor._prev_content_type == "unknown"
        assert sensor._change_timestamps == []
        assert sensor._known_capture_pids == set()


# =========================================================================== #
# TestClipboardSensorSetup
# =========================================================================== #


class TestClipboardSensorSetup:
    """Tests for the setup() lifecycle method."""

    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    def test_setup_initializes_state_no_text(self, mock_clip):
        """When clipboard is empty/unavailable, setup records None hash."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()
        assert sensor._prev_hash is None
        assert sensor._prev_content_length == 0
        assert sensor._prev_content_type == "empty"

    @patch(f"{_MOD}._get_clipboard_text", return_value="initial text")
    def test_setup_initializes_state_with_text(self, mock_clip):
        """When clipboard has text, setup records its hash and length."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()
        assert sensor._prev_hash == _sha256("initial text")
        assert sensor._prev_content_length == len("initial text")
        assert sensor._prev_content_type == "text"

    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    def test_setup_clears_timestamps(self, mock_clip):
        """setup() should clear any pre-existing change timestamps."""
        sensor = ClipboardSensor(interval=999)
        sensor._change_timestamps = [1.0, 2.0, 3.0]
        sensor._known_capture_pids = {100, 200}
        sensor.setup()
        assert sensor._change_timestamps == []
        assert sensor._known_capture_pids == set()


# =========================================================================== #
# TestClipboardSensorCollect
# =========================================================================== #


class TestClipboardSensorCollect:
    """Tests for the collect() method — core event production."""

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    def test_collect_returns_snapshot(self, mock_clip, mock_capture):
        """collect() must always emit at least a clipboard_snapshot event."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        event_types = [e.event_type for e in events]
        assert "clipboard_snapshot" in event_types

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    def test_collect_no_change_no_change_event(self, mock_clip, mock_capture):
        """When clipboard hasn't changed, no clipboard_change event should appear."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()
        # First collect sets baseline (no change from setup)
        events = sensor.collect()
        event_types = [e.event_type for e in events]
        assert "clipboard_change" not in event_types

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text")
    def test_collect_emits_change_event(self, mock_clip, mock_capture):
        """When clipboard text changes, a clipboard_change event should be emitted."""
        sensor = ClipboardSensor(interval=999)

        # Setup with initial text
        mock_clip.return_value = "initial"
        sensor.setup()

        # Clipboard changes
        mock_clip.return_value = "changed"
        events = sensor.collect()
        event_types = [e.event_type for e in events]
        assert "clipboard_change" in event_types

        change_event = [e for e in events if e.event_type == "clipboard_change"][0]
        assert change_event.severity == Severity.LOW
        assert change_event.sensor == SensorType.CLIPBOARD
        assert change_event.data["content_hash"] == _sha256("changed")
        assert change_event.data["content_length"] == len("changed")

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    def test_collect_returns_list_of_aegis_events(self, mock_clip, mock_capture):
        """All items returned by collect() must be AegisEvent instances."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        assert isinstance(events, list)
        for event in events:
            assert isinstance(event, AegisEvent)
            assert event.sensor == SensorType.CLIPBOARD

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    def test_snapshot_contains_expected_data_keys(self, mock_clip, mock_capture):
        """The clipboard_snapshot event should contain well-known data fields."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        snapshot = [e for e in events if e.event_type == "clipboard_snapshot"][0]
        assert "content_hash" in snapshot.data
        assert "content_type" in snapshot.data
        assert "content_length" in snapshot.data
        assert "changed_since_last" in snapshot.data
        assert "changes_in_last_minute" in snapshot.data
        assert "screen_capture_processes" in snapshot.data
        assert "win32_available" in snapshot.data

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text")
    def test_collect_updates_prev_hash(self, mock_clip, mock_capture):
        """After collect(), _prev_hash should reflect the current clipboard content."""
        sensor = ClipboardSensor(interval=999)
        mock_clip.return_value = "first"
        sensor.setup()
        assert sensor._prev_hash == _sha256("first")

        mock_clip.return_value = "second"
        sensor.collect()
        assert sensor._prev_hash == _sha256("second")

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text")
    def test_no_duplicate_change_on_same_content(self, mock_clip, mock_capture):
        """If clipboard content stays the same between collects, no change event."""
        sensor = ClipboardSensor(interval=999)
        mock_clip.return_value = "constant"
        sensor.setup()

        sensor.collect()  # first collect establishes baseline
        events2 = sensor.collect()
        change_events = [e for e in events2 if e.event_type == "clipboard_change"]
        assert len(change_events) == 0


# =========================================================================== #
# TestClipboardHijackDetection
# =========================================================================== #


class TestClipboardHijackDetection:
    """Tests for clipboard hijacking detection (rapid change threshold)."""

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text", return_value="text")
    def test_rapid_changes_trigger_hijack(self, mock_clip, mock_capture):
        """Simulate >5 clipboard changes within 60s by manipulating timestamps."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()

        now = time.time()
        # Inject 6 timestamps within the window (exceeds threshold of 5)
        sensor._change_timestamps = [now - i for i in range(6)]

        # Force a change so collect() appends another timestamp
        sensor._prev_hash = "stale_hash_to_force_change"
        events = sensor.collect()
        event_types = [e.event_type for e in events]
        assert "clipboard_hijack" in event_types

        hijack = [e for e in events if e.event_type == "clipboard_hijack"][0]
        assert hijack.severity == Severity.HIGH
        assert hijack.data["threshold"] == _HIJACK_CHANGE_THRESHOLD
        assert hijack.data["window_seconds"] == _HIJACK_WINDOW_SECS

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text", return_value="text")
    def test_normal_changes_no_hijack(self, mock_clip, mock_capture):
        """Fewer than threshold changes should not trigger hijack."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()

        now = time.time()
        # Only 3 changes — well below threshold of 5
        sensor._change_timestamps = [now - i for i in range(3)]
        sensor._prev_hash = "stale_hash_to_force_change"
        events = sensor.collect()
        event_types = [e.event_type for e in events]
        assert "clipboard_hijack" not in event_types

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text", return_value="text")
    def test_old_timestamps_pruned(self, mock_clip, mock_capture):
        """Timestamps older than the window should be pruned and not count."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()

        now = time.time()
        # 10 timestamps, but all older than the window
        sensor._change_timestamps = [now - 120.0 - i for i in range(10)]
        sensor._prev_hash = "stale_hash_to_force_change"
        events = sensor.collect()
        event_types = [e.event_type for e in events]
        # After pruning old ones, only the new change from this collect remains
        assert "clipboard_hijack" not in event_types

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    def test_no_change_no_hijack(self, mock_clip, mock_capture):
        """When clipboard is unchanged, no hijack detection regardless of history."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()

        # Even with many old timestamps, no new change means no new timestamp added
        now = time.time()
        sensor._change_timestamps = [now - i for i in range(4)]
        events = sensor.collect()
        event_types = [e.event_type for e in events]
        assert "clipboard_hijack" not in event_types


# =========================================================================== #
# TestClipboardSensitiveData
# =========================================================================== #


class TestClipboardSensitiveData:
    """Tests for sensitive data detection events during collect()."""

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text")
    def test_sensitive_data_event_on_change(self, mock_clip, mock_capture):
        """When clipboard changes to contain a CC number, a sensitive_data event fires."""
        sensor = ClipboardSensor(interval=999)
        mock_clip.return_value = "nothing"
        sensor.setup()

        mock_clip.return_value = "Card: 4111 1111 1111 1111"
        events = sensor.collect()
        event_types = [e.event_type for e in events]
        assert "sensitive_data" in event_types

        sensitive = [e for e in events if e.event_type == "sensitive_data"][0]
        assert sensitive.severity == Severity.MEDIUM
        assert sensitive.sensor == SensorType.CLIPBOARD
        assert "patterns_found" in sensitive.data
        patterns = [p["pattern"] for p in sensitive.data["patterns_found"]]
        assert "credit_card" in patterns

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text")
    def test_sensitive_data_not_emitted_without_change(self, mock_clip, mock_capture):
        """If clipboard content has NOT changed, sensitive_data should not fire."""
        sensor = ClipboardSensor(interval=999)
        # Setup with sensitive text already in clipboard
        mock_clip.return_value = "Card: 4111 1111 1111 1111"
        sensor.setup()

        # Same content, no change -> no sensitive_data event
        events = sensor.collect()
        event_types = [e.event_type for e in events]
        assert "sensitive_data" not in event_types

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text")
    def test_sensitive_data_ssn_detected(self, mock_clip, mock_capture):
        """SSN pattern in new clipboard text should trigger sensitive_data."""
        sensor = ClipboardSensor(interval=999)
        mock_clip.return_value = "empty"
        sensor.setup()

        mock_clip.return_value = "SSN: 123-45-6789"
        events = sensor.collect()
        sensitive_events = [e for e in events if e.event_type == "sensitive_data"]
        assert len(sensitive_events) == 1
        patterns = [p["pattern"] for p in sensitive_events[0].data["patterns_found"]]
        assert "ssn" in patterns

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text")
    def test_sensitive_data_includes_content_hash(self, mock_clip, mock_capture):
        """sensitive_data event should carry content_hash and content_length."""
        sensor = ClipboardSensor(interval=999)
        mock_clip.return_value = "nothing"
        sensor.setup()

        cc_text = "4111 1111 1111 1111"
        mock_clip.return_value = cc_text
        events = sensor.collect()
        sensitive = [e for e in events if e.event_type == "sensitive_data"][0]
        assert sensitive.data["content_hash"] == _sha256(cc_text)
        assert sensitive.data["content_length"] == len(cc_text)

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text")
    def test_no_sensitive_data_for_benign_text(self, mock_clip, mock_capture):
        """Benign clipboard text should not produce sensitive_data events."""
        sensor = ClipboardSensor(interval=999)
        mock_clip.return_value = "nothing"
        sensor.setup()

        mock_clip.return_value = "Just a normal sentence with no secrets."
        events = sensor.collect()
        event_types = [e.event_type for e in events]
        assert "sensitive_data" not in event_types


# =========================================================================== #
# TestScreenCaptureDetection
# =========================================================================== #


class TestScreenCaptureDetection:
    """Tests for screen capture process detection during collect()."""

    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    @patch(f"{_MOD}._find_screen_capture_processes")
    def test_capture_process_emits_event(self, mock_capture, mock_clip):
        """When a screen capture process is found, a screen_capture event fires."""
        mock_capture.return_value = [
            {"pid": 9999, "name": "ScreenCapture.exe", "match_fragment": "capture"},
        ]
        sensor = ClipboardSensor(interval=999)
        sensor.setup()

        events = sensor.collect()
        event_types = [e.event_type for e in events]
        assert "screen_capture" in event_types

        capture_evt = [e for e in events if e.event_type == "screen_capture"][0]
        assert capture_evt.severity == Severity.MEDIUM
        assert capture_evt.sensor == SensorType.CLIPBOARD
        assert len(capture_evt.data["new_processes"]) == 1
        assert capture_evt.data["new_processes"][0]["pid"] == 9999

    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    def test_no_capture_process_no_event(self, mock_capture, mock_clip):
        """When no capture processes are found, no screen_capture event is emitted."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()

        events = sensor.collect()
        event_types = [e.event_type for e in events]
        assert "screen_capture" not in event_types

    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    @patch(f"{_MOD}._find_screen_capture_processes")
    def test_known_capture_pid_not_re_reported(self, mock_capture, mock_clip):
        """Already-known capture PIDs should not trigger a new event."""
        mock_capture.return_value = [
            {"pid": 1234, "name": "obs64.exe", "match_fragment": "obs"},
        ]
        sensor = ClipboardSensor(interval=999)
        sensor.setup()

        # First collect discovers the process
        events1 = sensor.collect()
        assert any(e.event_type == "screen_capture" for e in events1)

        # Second collect with same PID — no new screen_capture event
        events2 = sensor.collect()
        assert not any(e.event_type == "screen_capture" for e in events2)

    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    @patch(f"{_MOD}._find_screen_capture_processes")
    def test_new_capture_pid_is_reported(self, mock_capture, mock_clip):
        """A newly appearing capture PID should trigger an event even after first collect."""
        sensor = ClipboardSensor(interval=999)
        sensor.setup()

        mock_capture.return_value = [
            {"pid": 1000, "name": "snipping.exe", "match_fragment": "snip"},
        ]
        sensor.collect()

        # New PID appears alongside the old one
        mock_capture.return_value = [
            {"pid": 1000, "name": "snipping.exe", "match_fragment": "snip"},
            {"pid": 2000, "name": "screencap.exe", "match_fragment": "capture"},
        ]
        events = sensor.collect()
        capture_events = [e for e in events if e.event_type == "screen_capture"]
        assert len(capture_events) == 1
        new_pids = [p["pid"] for p in capture_events[0].data["new_processes"]]
        assert 2000 in new_pids
        assert 1000 not in new_pids


# =========================================================================== #
# TestFindScreenCaptureProcesses
# =========================================================================== #


class TestFindScreenCaptureProcesses:
    """Unit tests for the _find_screen_capture_processes helper."""

    @patch(f"{_MOD}._HAS_PSUTIL", False)
    def test_returns_empty_without_psutil(self):
        """Without psutil, the function should return an empty list."""
        result = _find_screen_capture_processes()
        assert result == []

    @patch(f"{_MOD}._HAS_PSUTIL", True)
    @patch(f"{_MOD}.psutil")
    def test_finds_matching_process(self, mock_psutil):
        """Processes matching capture name fragments should be returned."""
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 42, "name": "ScreenshotTool.exe"}
        mock_psutil.process_iter.return_value = [mock_proc]

        result = _find_screen_capture_processes()
        assert len(result) == 1
        assert result[0]["pid"] == 42
        assert result[0]["name"] == "ScreenshotTool.exe"
        assert result[0]["match_fragment"] == "screenshot"

    @patch(f"{_MOD}._HAS_PSUTIL", True)
    @patch(f"{_MOD}.psutil")
    def test_ignores_non_matching_process(self, mock_psutil):
        """Processes that do not match any capture fragment should be skipped."""
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 100, "name": "notepad.exe"}
        mock_psutil.process_iter.return_value = [mock_proc]

        result = _find_screen_capture_processes()
        assert result == []


# =========================================================================== #
# TestClipboardSensorTeardown
# =========================================================================== #


class TestClipboardSensorTeardown:
    """Tests for teardown() lifecycle method."""

    def test_teardown_clears_state(self):
        """teardown() should reset internal tracking state."""
        sensor = ClipboardSensor(interval=999)
        sensor._change_timestamps = [1.0, 2.0]
        sensor._known_capture_pids = {10, 20}
        sensor._prev_hash = "somehash"

        sensor.teardown()

        assert sensor._change_timestamps == []
        assert sensor._known_capture_pids == set()
        assert sensor._prev_hash is None


# =========================================================================== #
# TestClipboardSensorLifecycle
# =========================================================================== #


class TestClipboardSensorLifecycle:
    """Integration-style tests for start/stop lifecycle."""

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    def test_start_and_stop(self, mock_clip, mock_capture):
        """Sensor starts, collects at least once, and stops cleanly."""
        collected: list[AegisEvent] = []
        sensor = ClipboardSensor(
            interval=0.1,
            on_event=lambda e: collected.append(e),
        )
        sensor.start()
        assert sensor.is_running

        # Wait for at least one collection cycle
        for _ in range(50):
            if len(collected) > 0:
                break
            time.sleep(0.05)

        sensor.stop()
        assert not sensor.is_running
        assert len(collected) > 0, "Expected at least one event"

    @patch(f"{_MOD}._find_screen_capture_processes", return_value=[])
    @patch(f"{_MOD}._get_clipboard_text", return_value=None)
    def test_emitted_events_are_clipboard_type(self, mock_clip, mock_capture):
        """All events emitted via callback should have CLIPBOARD sensor type."""
        collected: list[AegisEvent] = []
        sensor = ClipboardSensor(
            interval=0.1,
            on_event=lambda e: collected.append(e),
        )
        sensor.start()
        for _ in range(50):
            if len(collected) > 0:
                break
            time.sleep(0.05)
        sensor.stop()

        for evt in collected:
            assert isinstance(evt, AegisEvent)
            assert evt.sensor == SensorType.CLIPBOARD
