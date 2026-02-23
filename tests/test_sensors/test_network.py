"""Tests for the Network Sensor."""

import time

from aegis.core.models import AegisEvent, SensorType
from aegis.sensors.network import NetworkSensor


class TestNetworkSensorInit:
    def test_sensor_type_is_network(self):
        sensor = NetworkSensor(interval=999)
        assert sensor.sensor_type == SensorType.NETWORK

    def test_sensor_name(self):
        sensor = NetworkSensor(interval=999)
        assert sensor.sensor_name == "network_monitor"

    def test_default_interval(self):
        sensor = NetworkSensor()
        assert sensor._interval == 5.0


class TestNetworkSensorCollection:
    def test_collect_returns_events(self):
        sensor = NetworkSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        assert isinstance(events, list)
        for event in events:
            assert isinstance(event, AegisEvent)
            assert event.sensor == SensorType.NETWORK
        sensor.teardown()

    def test_collect_captures_connections(self):
        """Should capture at least some network connections on a live system."""
        sensor = NetworkSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        # A running system with internet usually has connections
        conn_events = [e for e in events if e.event_type == "connection_snapshot"]
        # May be empty on isolated test environments, but format should be correct
        for evt in conn_events:
            assert "local_addr" in evt.data
            assert "local_port" in evt.data
            assert "status" in evt.data
            assert "pid" in evt.data
        sensor.teardown()

    def test_collect_generates_flow_stats(self):
        """Should produce a network_flow_stats summary event."""
        sensor = NetworkSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        flow_events = [e for e in events if e.event_type == "network_flow_stats"]
        assert len(flow_events) == 1
        stats = flow_events[0].data
        assert "total_connections" in stats
        assert "unique_remote_ips" in stats
        assert "unique_remote_ports" in stats
        assert "connections_by_status" in stats
        assert "connections_by_protocol" in stats
        sensor.teardown()

    def test_flow_stats_fields_are_numeric(self):
        """Flow stats should contain numeric values."""
        sensor = NetworkSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        flow_events = [e for e in events if e.event_type == "network_flow_stats"]
        assert len(flow_events) == 1
        stats = flow_events[0].data
        assert isinstance(stats["total_connections"], int)
        assert isinstance(stats["unique_remote_ips"], int)
        assert isinstance(stats["unique_remote_ports"], int)
        sensor.teardown()

    def test_collect_detects_new_connections(self):
        """Second collect after first should detect new/closed connections."""
        sensor = NetworkSensor(interval=999)
        sensor.setup()
        sensor.collect()  # baseline
        events = sensor.collect()
        for evt in events:
            assert evt.sensor == SensorType.NETWORK
            assert evt.event_type in (
                "connection_snapshot", "connection_new", "connection_closed",
                "network_flow_stats",
            )
        sensor.teardown()


class TestNetworkSensorFeatures:
    def test_connection_has_process_info(self):
        """Connection snapshots should include owning process info."""
        sensor = NetworkSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        conn_events = [e for e in events if e.event_type == "connection_snapshot"]
        for evt in conn_events:
            assert "pid" in evt.data
            assert "process_name" in evt.data
        sensor.teardown()

    def test_port_entropy_in_flow_stats(self):
        """Flow stats should include port entropy metric."""
        sensor = NetworkSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        flow_events = [e for e in events if e.event_type == "network_flow_stats"]
        assert len(flow_events) == 1
        stats = flow_events[0].data
        assert "port_entropy" in stats
        assert isinstance(stats["port_entropy"], float)
        assert stats["port_entropy"] >= 0.0
        sensor.teardown()

    def test_new_destination_rate_in_flow_stats(self):
        """Flow stats should include new destination rate."""
        sensor = NetworkSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        flow_events = [e for e in events if e.event_type == "network_flow_stats"]
        stats = flow_events[0].data
        assert "new_destination_rate" in stats
        assert isinstance(stats["new_destination_rate"], (int, float))
        sensor.teardown()

    def test_dns_info_field_exists(self):
        """Flow stats should include DNS query tracking."""
        sensor = NetworkSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        flow_events = [e for e in events if e.event_type == "network_flow_stats"]
        stats = flow_events[0].data
        assert "dns_query_count" in stats
        sensor.teardown()


class TestNetworkSensorLifecycle:
    def test_start_and_stop(self):
        collected = []
        sensor = NetworkSensor(interval=0.5, on_event=lambda e: collected.append(e))
        sensor.start()
        assert sensor.is_running
        time.sleep(1.5)
        sensor.stop()
        assert not sensor.is_running
        assert len(collected) > 0

    def test_emits_events_via_callback(self):
        collected = []
        sensor = NetworkSensor(interval=0.5, on_event=lambda e: collected.append(e))
        sensor.start()
        time.sleep(1.5)
        sensor.stop()
        for evt in collected:
            assert isinstance(evt, AegisEvent)
            assert evt.sensor == SensorType.NETWORK


class TestNetworkSensorBeaconTracking:
    """Tests for per-destination timestamp tracking (beacon detection)."""

    def test_collect_includes_dest_timestamps(self):
        """Network events should include destination timestamps."""
        sensor = NetworkSensor()
        sensor.setup()
        sensor.collect()
        # At minimum, the sensor should have the tracking dict
        assert hasattr(sensor, '_dest_timestamps')

    def test_timestamps_capped_at_200(self):
        """Each destination should store at most 200 timestamps."""
        sensor = NetworkSensor()
        sensor.setup()
        # Add 250 timestamps for a single destination
        for i in range(250):
            sensor._dest_timestamps["1.2.3.4"].append(float(i))
        sensor._cap_timestamps()
        assert len(sensor._dest_timestamps["1.2.3.4"]) <= 200

    def test_dest_timestamps_in_flow_stats(self):
        """Flow stats should include dest_timestamps data."""
        sensor = NetworkSensor()
        sensor.setup()
        events = sensor.collect()
        flow_events = [
            e for e in events if e.event_type == "network_flow_stats"
        ]
        assert len(flow_events) == 1
        stats = flow_events[0].data
        assert "dest_timestamps" in stats

    def test_dest_timestamps_is_dict(self):
        """dest_timestamps should be a dict of IP -> list[float]."""
        sensor = NetworkSensor()
        sensor.setup()
        events = sensor.collect()
        flow_events = [
            e for e in events if e.event_type == "network_flow_stats"
        ]
        stats = flow_events[0].data
        assert isinstance(stats["dest_timestamps"], dict)

    def test_timestamps_are_floats(self):
        """Recorded timestamps should be float values (time.time())."""
        sensor = NetworkSensor()
        sensor.setup()
        # Manually add a timestamp to verify type
        sensor._dest_timestamps["10.0.0.1"].append(time.time())
        for ts_list in sensor._dest_timestamps.values():
            for ts in ts_list:
                assert isinstance(ts, float)

    def test_teardown_clears_dest_timestamps(self):
        """Teardown should clear the _dest_timestamps dict."""
        sensor = NetworkSensor()
        sensor.setup()
        sensor._dest_timestamps["1.2.3.4"].append(1.0)
        sensor.teardown()
        assert len(sensor._dest_timestamps) == 0

    def test_cap_timestamps_keeps_most_recent(self):
        """_cap_timestamps should keep the 200 most recent entries."""
        sensor = NetworkSensor()
        sensor.setup()
        # Add 250 timestamps (0.0 through 249.0)
        for i in range(250):
            sensor._dest_timestamps["1.2.3.4"].append(float(i))
        sensor._cap_timestamps()
        timestamps = sensor._dest_timestamps["1.2.3.4"]
        assert len(timestamps) == 200
        # Should keep the last 200 (50.0 through 249.0)
        assert timestamps[0] == 50.0
        assert timestamps[-1] == 249.0
