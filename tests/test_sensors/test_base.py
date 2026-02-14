"""Tests for the abstract sensor base class."""

import pytest
import time
from aegis.sensors.base import BaseSensor
from aegis.core.models import AegisEvent, SensorType


class MockSensor(BaseSensor):
    """Concrete implementation for testing."""

    sensor_type = SensorType.PROCESS
    sensor_name = "mock_sensor"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.tick_count = 0

    def setup(self) -> None:
        pass

    def collect(self) -> list[AegisEvent]:
        self.tick_count += 1
        return [
            AegisEvent(
                sensor=self.sensor_type,
                event_type="mock_tick",
                data={"tick": self.tick_count},
            )
        ]

    def teardown(self) -> None:
        pass


class TestBaseSensor:
    def test_sensor_starts_and_stops(self):
        sensor = MockSensor(interval=0.1)
        sensor.start()
        assert sensor.is_running
        time.sleep(0.5)
        sensor.stop()
        assert not sensor.is_running
        assert sensor.tick_count > 0

    def test_sensor_collects_on_interval(self):
        sensor = MockSensor(interval=0.1)
        sensor.start()
        time.sleep(0.55)
        sensor.stop()
        assert 3 <= sensor.tick_count <= 8

    def test_sensor_emits_events(self):
        emitted = []
        sensor = MockSensor(interval=0.1, on_event=lambda e: emitted.append(e))
        sensor.start()
        time.sleep(0.35)
        sensor.stop()
        assert len(emitted) > 0
        assert all(isinstance(e, AegisEvent) for e in emitted)
        assert all(e.sensor == SensorType.PROCESS for e in emitted)

    def test_sensor_name_and_type(self):
        sensor = MockSensor(interval=1.0)
        assert sensor.sensor_name == "mock_sensor"
        assert sensor.sensor_type == SensorType.PROCESS
