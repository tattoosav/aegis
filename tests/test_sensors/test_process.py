"""Tests for the Process Watchdog sensor."""

import time
import pytest
from unittest.mock import patch, MagicMock

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.process import ProcessSensor


class TestProcessSensorInit:
    def test_sensor_type_is_process(self):
        sensor = ProcessSensor(interval=999)
        assert sensor.sensor_type == SensorType.PROCESS

    def test_sensor_name(self):
        sensor = ProcessSensor(interval=999)
        assert sensor.sensor_name == "process_watchdog"

    def test_default_interval(self):
        sensor = ProcessSensor()
        assert sensor._interval == 5.0


class TestProcessSensorCollection:
    def test_collect_returns_events(self):
        sensor = ProcessSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        assert isinstance(events, list)
        for event in events:
            assert isinstance(event, AegisEvent)
            assert event.sensor == SensorType.PROCESS
        sensor.teardown()

    def test_collect_snapshot_has_processes(self):
        """collect() should find at least a few running processes."""
        sensor = ProcessSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        # A running system always has processes — expect at least one snapshot event
        snapshot_events = [e for e in events if e.event_type == "process_snapshot"]
        assert len(snapshot_events) >= 1
        # Each snapshot event should have process data
        for evt in snapshot_events:
            assert "pid" in evt.data
            assert "name" in evt.data
            assert "status" in evt.data
        sensor.teardown()

    def test_collect_detects_new_processes(self):
        """Second collect() after first should detect new/gone processes."""
        sensor = ProcessSensor(interval=999)
        sensor.setup()
        # First collect builds baseline
        sensor.collect()
        # Second collect detects changes (may have new/gone events depending on system)
        events = sensor.collect()
        # Events should be well-formed regardless of changes
        for evt in events:
            assert evt.sensor == SensorType.PROCESS
            assert evt.event_type in (
                "process_snapshot", "process_new", "process_gone"
            )
        sensor.teardown()

    def test_snapshot_has_feature_fields(self):
        """Process snapshots should include feature extraction fields."""
        sensor = ProcessSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        snapshots = [e for e in events if e.event_type == "process_snapshot"]
        assert len(snapshots) > 0
        snap = snapshots[0]
        # Core fields from design spec
        assert "pid" in snap.data
        assert "name" in snap.data
        assert "exe" in snap.data
        assert "cmdline" in snap.data
        assert "ppid" in snap.data
        assert "cpu_percent" in snap.data
        assert "memory_mb" in snap.data
        assert "num_threads" in snap.data
        assert "status" in snap.data
        sensor.teardown()

    def test_collect_handles_zombie_processes_gracefully(self):
        """Sensor should not crash on AccessDenied or NoSuchProcess."""
        sensor = ProcessSensor(interval=999)
        sensor.setup()
        # If we get here without crash, zombie handling works
        events = sensor.collect()
        assert isinstance(events, list)
        sensor.teardown()


class TestProcessSensorFeatures:
    def test_cmdline_entropy_calculated(self):
        """Snapshot events should include command-line entropy."""
        sensor = ProcessSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        snapshots = [e for e in events if e.event_type == "process_snapshot"]
        for snap in snapshots:
            if snap.data.get("cmdline"):
                assert "cmdline_entropy" in snap.data
                assert isinstance(snap.data["cmdline_entropy"], float)
                assert 0.0 <= snap.data["cmdline_entropy"] <= 8.0
        sensor.teardown()

    def test_masquerade_detection_field(self):
        """Each process should have an is_masquerading field."""
        sensor = ProcessSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        snapshots = [e for e in events if e.event_type == "process_snapshot"]
        for snap in snapshots:
            assert "is_masquerading" in snap.data
            assert isinstance(snap.data["is_masquerading"], bool)
        sensor.teardown()

    def test_lineage_depth_field(self):
        """Each process should report its lineage depth."""
        sensor = ProcessSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        snapshots = [e for e in events if e.event_type == "process_snapshot"]
        for snap in snapshots:
            assert "lineage_depth" in snap.data
            assert isinstance(snap.data["lineage_depth"], int)
            assert snap.data["lineage_depth"] >= 0
        sensor.teardown()


class TestProcessSensorLifecycle:
    def test_start_and_stop(self):
        """Process sensor starts, collects at least once, and stops cleanly.

        Note: process collection can take 10-30s on Windows due to full
        process enumeration + feature extraction, so we allow generous time.
        """
        collected = []
        sensor = ProcessSensor(interval=1.0, on_event=lambda e: collected.append(e))
        sensor.start()
        assert sensor.is_running
        # Wait long enough for at least one full collect cycle
        # (process enumeration on Windows can take 10-30s)
        for _ in range(60):
            if len(collected) > 0:
                break
            time.sleep(1.0)
        sensor.stop()
        assert not sensor.is_running
        assert len(collected) > 0, "Expected at least one event within 60s"

    def test_emits_events_via_callback(self):
        collected = []
        sensor = ProcessSensor(interval=1.0, on_event=lambda e: collected.append(e))
        sensor.start()
        for _ in range(60):
            if len(collected) > 0:
                break
            time.sleep(1.0)
        sensor.stop()
        assert len(collected) > 0, "Expected events within 60s"
        for evt in collected:
            assert isinstance(evt, AegisEvent)
            assert evt.sensor == SensorType.PROCESS
