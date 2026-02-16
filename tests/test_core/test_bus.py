"""Tests for Aegis ZeroMQ message bus."""

import random
import time

from aegis.core.bus import EventBus, EventPublisher, EventSubscriber
from aegis.core.models import AegisEvent, SensorType


def _rand_ports():
    """Generate a random pair of ports to avoid conflicts between tests."""
    base = random.randint(20000, 40000)
    return base, base + 1


class TestEventBus:
    def test_pub_sub_single_message(self):
        pub_port, sub_port = _rand_ports()
        bus = EventBus(pub_port=pub_port, sub_port=sub_port)
        bus.start()
        time.sleep(0.3)

        received = []

        def on_event(event: AegisEvent):
            received.append(event)

        sub = EventSubscriber(
            port=sub_port, topics=["sensor.process"], callback=on_event
        )
        sub.start()
        time.sleep(0.3)

        pub = EventPublisher(port=pub_port, topic="sensor.process")
        time.sleep(0.1)
        event = AegisEvent(
            sensor=SensorType.PROCESS, event_type="test", data={"msg": "hello"}
        )
        pub.send(event)
        time.sleep(0.8)

        assert len(received) == 1
        assert received[0].event_type == "test"
        assert received[0].data["msg"] == "hello"

        sub.stop()
        pub.close()
        bus.stop()

    def test_topic_filtering(self):
        pub_port, sub_port = _rand_ports()
        bus = EventBus(pub_port=pub_port, sub_port=sub_port)
        bus.start()
        time.sleep(0.3)

        received = []
        sub = EventSubscriber(
            port=sub_port, topics=["sensor.network"],
            callback=lambda e: received.append(e),
        )
        sub.start()
        time.sleep(0.3)

        pub_net = EventPublisher(port=pub_port, topic="sensor.network")
        pub_proc = EventPublisher(port=pub_port, topic="sensor.process")
        time.sleep(0.1)

        pub_net.send(AegisEvent(
            sensor=SensorType.NETWORK, event_type="conn", data={}
        ))
        pub_proc.send(AegisEvent(
            sensor=SensorType.PROCESS, event_type="proc", data={}
        ))
        time.sleep(0.8)

        assert len(received) == 1
        assert received[0].sensor == SensorType.NETWORK

        sub.stop()
        pub_net.close()
        pub_proc.close()
        bus.stop()

    def test_multiple_subscribers(self):
        pub_port, sub_port = _rand_ports()
        bus = EventBus(pub_port=pub_port, sub_port=sub_port)
        bus.start()
        time.sleep(0.3)

        received_a = []
        received_b = []
        sub_a = EventSubscriber(
            port=sub_port, topics=["sensor.file"],
            callback=lambda e: received_a.append(e),
        )
        sub_b = EventSubscriber(
            port=sub_port, topics=["sensor.file"],
            callback=lambda e: received_b.append(e),
        )
        sub_a.start()
        sub_b.start()
        time.sleep(0.3)

        pub = EventPublisher(port=pub_port, topic="sensor.file")
        time.sleep(0.1)
        pub.send(AegisEvent(
            sensor=SensorType.FILE, event_type="changed", data={}
        ))
        time.sleep(0.8)

        assert len(received_a) == 1
        assert len(received_b) == 1

        sub_a.stop()
        sub_b.stop()
        pub.close()
        bus.stop()
