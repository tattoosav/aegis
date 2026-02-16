"""Tests for the Aegis Event Engine."""

import random
import time

from aegis.core.config import AegisConfig
from aegis.core.engine import EventEngine
from aegis.core.models import AegisEvent, SensorType


def _rand_ports():
    base = random.randint(40000, 55000)
    return base, base + 1


class TestEventEngine:
    def test_engine_starts_and_stops(self, tmp_data_dir):
        pp, sp = _rand_ports()
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "test.db"))
        engine = EventEngine(config=config, pub_port=pp, sub_port=sp)
        engine.start()
        assert engine.is_running
        time.sleep(0.3)
        engine.stop()
        assert not engine.is_running

    def test_engine_provides_database(self, tmp_data_dir):
        pp, sp = _rand_ports()
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "test2.db"))
        engine = EventEngine(config=config, pub_port=pp, sub_port=sp)
        engine.start()
        assert engine.db is not None
        assert engine.db.list_tables()
        engine.stop()

    def test_engine_receives_and_stores_events(self, tmp_data_dir):
        pp, sp = _rand_ports()
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "test3.db"))
        engine = EventEngine(config=config, pub_port=pp, sub_port=sp)
        engine.start()
        # Allow bus proxy and subscriber to fully connect
        time.sleep(0.5)

        from aegis.core.bus import EventPublisher
        pub = EventPublisher(port=pp, topic="sensor.process")
        # Allow publisher to connect and subscription to propagate
        time.sleep(0.5)

        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_created",
            data={"pid": 9999, "name": "test.exe"},
        )
        pub.send(event)
        # Allow time for message to route through proxy and be processed
        time.sleep(2.0)

        stored = engine.db.get_event(event.event_id)
        assert stored is not None, (
            f"Event {event.event_id} not found. "
            f"Engine processed {engine.events_processed} events."
        )
        assert stored.data["pid"] == 9999

        pub.close()
        engine.stop()

    def test_engine_tracks_event_count(self, tmp_data_dir):
        pp, sp = _rand_ports()
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "test4.db"))
        engine = EventEngine(config=config, pub_port=pp, sub_port=sp)
        engine.start()
        # Allow bus proxy and subscriber to fully connect
        time.sleep(0.5)

        from aegis.core.bus import EventPublisher
        pub = EventPublisher(port=pp, topic="sensor.network")
        # Allow publisher to connect and subscription to propagate
        time.sleep(0.5)

        for i in range(5):
            pub.send(AegisEvent(
                sensor=SensorType.NETWORK, event_type="conn", data={"i": i}
            ))
            time.sleep(0.1)  # Small gap between sends
        # Allow time for all messages to be processed
        time.sleep(2.0)

        assert engine.events_processed >= 5, (
            f"Expected >= 5 events processed, got {engine.events_processed}"
        )

        pub.close()
        engine.stop()
