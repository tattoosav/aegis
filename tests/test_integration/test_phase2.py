"""Integration tests: Phase 2 — sensors wired to Event Engine."""

import random
import time

from aegis.core.bus import EventPublisher
from aegis.core.config import AegisConfig
from aegis.core.engine import EventEngine
from aegis.core.models import SensorType
from aegis.sensors.network import NetworkSensor
from aegis.sensors.process import ProcessSensor


def _rand_ports():
    base = random.randint(55000, 64000)
    return base, base + 1


class TestSensorToEnginePipeline:
    """Test that real sensors publish events through the bus to the engine."""

    def test_process_sensor_events_reach_engine(self, tmp_data_dir):
        """ProcessSensor -> ZMQ Bus -> EventEngine -> Database."""
        pp, sp = _rand_ports()
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "proc_integration.db"))

        engine = EventEngine(config=config, pub_port=pp, sub_port=sp)
        engine.start()
        time.sleep(0.5)

        # Create a publisher that the sensor will use
        pub = EventPublisher(port=pp, topic="sensor.process")
        time.sleep(0.5)

        # Create sensor and manually route its events through the publisher
        sensor = ProcessSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        assert len(events) > 0, "ProcessSensor should produce events"

        # Send first 5 events through the bus
        sent_ids = []
        for evt in events[:5]:
            pub.send(evt)
            sent_ids.append(evt.event_id)
            time.sleep(0.05)

        time.sleep(2.0)

        # Verify events arrived in the database
        for eid in sent_ids:
            stored = engine.db.get_event(eid)
            assert stored is not None, f"Event {eid} not found in database"
            assert stored.sensor == SensorType.PROCESS

        sensor.teardown()
        pub.close()
        engine.stop()

    def test_network_sensor_events_reach_engine(self, tmp_data_dir):
        """NetworkSensor -> ZMQ Bus -> EventEngine -> Database."""
        pp, sp = _rand_ports()
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "net_integration.db"))

        engine = EventEngine(config=config, pub_port=pp, sub_port=sp)
        engine.start()
        time.sleep(0.5)

        pub = EventPublisher(port=pp, topic="sensor.network")
        time.sleep(0.5)

        sensor = NetworkSensor(interval=999)
        sensor.setup()
        events = sensor.collect()
        assert len(events) > 0, "NetworkSensor should produce events"

        sent_ids = []
        for evt in events[:5]:
            pub.send(evt)
            sent_ids.append(evt.event_id)
            time.sleep(0.05)

        time.sleep(2.0)

        for eid in sent_ids:
            stored = engine.db.get_event(eid)
            assert stored is not None, f"Event {eid} not found in database"
            assert stored.sensor == SensorType.NETWORK

        sensor.teardown()
        pub.close()
        engine.stop()

    def test_both_sensors_coexist(self, tmp_data_dir):
        """Both sensors can publish to the same engine simultaneously."""
        pp, sp = _rand_ports()
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "both_integration.db"))

        engine = EventEngine(config=config, pub_port=pp, sub_port=sp)
        engine.start()
        time.sleep(0.5)

        pub_proc = EventPublisher(port=pp, topic="sensor.process")
        pub_net = EventPublisher(port=pp, topic="sensor.network")
        time.sleep(0.5)

        # Collect from both sensors
        proc_sensor = ProcessSensor(interval=999)
        proc_sensor.setup()
        proc_events = proc_sensor.collect()

        net_sensor = NetworkSensor(interval=999)
        net_sensor.setup()
        net_events = net_sensor.collect()

        # Send events from both
        all_sent = []
        for evt in proc_events[:3]:
            pub_proc.send(evt)
            all_sent.append(evt.event_id)
            time.sleep(0.05)
        for evt in net_events[:3]:
            pub_net.send(evt)
            all_sent.append(evt.event_id)
            time.sleep(0.05)

        time.sleep(2.0)

        for eid in all_sent:
            stored = engine.db.get_event(eid)
            assert stored is not None, f"Event {eid} not found in database"

        # Verify engine counted all
        assert engine.events_processed >= len(all_sent)

        proc_sensor.teardown()
        net_sensor.teardown()
        pub_proc.close()
        pub_net.close()
        engine.stop()
