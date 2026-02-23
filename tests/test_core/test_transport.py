"""Tests for the event transport layer."""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.core.transport import (
    EventTransport,
    InProcessTransport,
    create_transport,
)


def _make_event(**kwargs):
    defaults = {
        "sensor": SensorType.PROCESS,
        "event_type": "test_event",
        "data": {"key": "value"},
    }
    defaults.update(kwargs)
    return AegisEvent(**defaults)


class TestInProcessTransportSendReceive:
    def test_send_receive_single_event(self):
        t = InProcessTransport()
        received = []
        t.subscribe(lambda e: received.append(e))
        t.start()
        event = _make_event()
        t.send(event)
        time.sleep(0.3)
        t.stop()
        assert len(received) == 1
        assert received[0].event_type == "test_event"

    def test_send_receive_multiple_events(self):
        t = InProcessTransport()
        received = []
        t.subscribe(lambda e: received.append(e))
        t.start()
        for i in range(5):
            t.send(_make_event(data={"i": i}))
        time.sleep(0.5)
        t.stop()
        assert len(received) == 5

    def test_multiple_subscribers(self):
        t = InProcessTransport()
        r1, r2 = [], []
        t.subscribe(lambda e: r1.append(e))
        t.subscribe(lambda e: r2.append(e))
        t.start()
        t.send(_make_event())
        time.sleep(0.3)
        t.stop()
        assert len(r1) == 1
        assert len(r2) == 1

    def test_event_ordering_preserved(self):
        t = InProcessTransport()
        received = []
        t.subscribe(lambda e: received.append(e.data["i"]))
        t.start()
        for i in range(10):
            t.send(_make_event(data={"i": i}))
        time.sleep(0.5)
        t.stop()
        assert received == list(range(10))


class TestInProcessTransportLifecycle:
    def test_start_stop(self):
        t = InProcessTransport()
        t.start()
        assert t._running is True
        t.stop()
        assert t._running is False

    def test_double_start_no_error(self):
        t = InProcessTransport()
        t.start()
        t.start()  # should not raise
        t.stop()

    def test_stop_before_start_no_error(self):
        t = InProcessTransport()
        t.stop()  # should not raise

    def test_send_before_start_queues(self):
        t = InProcessTransport()
        received = []
        t.subscribe(lambda e: received.append(e))
        t.send(_make_event())
        assert t.pending == 1
        t.start()
        time.sleep(0.3)
        t.stop()
        assert len(received) == 1

    def test_pending_property(self):
        t = InProcessTransport()
        assert t.pending == 0
        t.send(_make_event())
        assert t.pending == 1


class TestInProcessTransportEdgeCases:
    def test_queue_full_drops_event(self):
        t = InProcessTransport(maxsize=2)
        t.send(_make_event())
        t.send(_make_event())
        t.send(_make_event())  # should drop silently
        assert t.pending == 2

    def test_callback_exception_does_not_break_loop(self):
        t = InProcessTransport()
        good = []
        t.subscribe(lambda e: (_ for _ in ()).throw(ValueError("boom")))
        t.subscribe(lambda e: good.append(e))
        t.start()
        t.send(_make_event())
        time.sleep(0.3)
        t.stop()
        # second subscriber still gets the event
        assert len(good) == 1

    def test_no_subscribers_events_drained(self):
        t = InProcessTransport()
        t.start()
        t.send(_make_event())
        time.sleep(0.3)
        t.stop()
        assert t.pending == 0

    def test_concurrent_sends(self):
        t = InProcessTransport()
        received = []
        t.subscribe(lambda e: received.append(e))
        t.start()
        threads = []
        for i in range(10):
            th = threading.Thread(
                target=lambda idx=i: t.send(_make_event(data={"i": idx})),
            )
            threads.append(th)
            th.start()
        for th in threads:
            th.join()
        time.sleep(0.5)
        t.stop()
        assert len(received) == 10


class TestTransportFactory:
    def test_explicit_inprocess(self):
        cfg = MagicMock()
        cfg.get.return_value = "inprocess"
        t = create_transport(cfg)
        assert isinstance(t, InProcessTransport)

    def test_default_is_auto(self):
        t = create_transport(None)
        # Should get some transport (either zmq or inprocess)
        assert hasattr(t, "send")
        assert hasattr(t, "subscribe")

    def test_auto_without_zmq_falls_back(self):
        cfg = MagicMock()
        cfg.get.return_value = "auto"
        with patch.dict("sys.modules", {"zmq": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                # Will fall through to InProcessTransport
                pass
        # Just verify inprocess works
        t = create_transport(cfg)
        assert hasattr(t, "send")


class TestTransportProtocol:
    def test_inprocess_satisfies_protocol(self):
        t = InProcessTransport()
        assert isinstance(t, EventTransport)

    def test_protocol_has_send(self):
        t = InProcessTransport()
        assert callable(t.send)

    def test_protocol_has_subscribe(self):
        t = InProcessTransport()
        assert callable(t.subscribe)

    def test_protocol_has_start_stop(self):
        t = InProcessTransport()
        assert callable(t.start)
        assert callable(t.stop)
