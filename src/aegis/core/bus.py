"""ZeroMQ-based event bus for inter-process communication.

Architecture:
  - EventBus: Central broker using XPUB/XSUB proxy pattern
  - EventPublisher: Sensors use this to publish events
  - EventSubscriber: Detection engines use this to receive events
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

import zmq

from aegis.core.models import AegisEvent

logger = logging.getLogger(__name__)

# Shared ZMQ context — one per process is ideal
_global_context = zmq.Context.instance()


class EventBus:
    """Central ZeroMQ broker using XSUB/XPUB proxy.

    Publishers connect to pub_port (XSUB side).
    Subscribers connect to sub_port (XPUB side).
    The proxy forwards all messages between them.
    """

    def __init__(self, pub_port: int = 15555, sub_port: int = 15556):
        self._pub_port = pub_port
        self._sub_port = sub_port
        self._context = zmq.Context()
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        """Start the proxy in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._run_proxy, daemon=True)
        self._thread.start()
        logger.info(f"EventBus started (pub={self._pub_port}, sub={self._sub_port})")

    def _run_proxy(self) -> None:
        xsub = self._context.socket(zmq.XSUB)
        xpub = self._context.socket(zmq.XPUB)
        xsub.setsockopt(zmq.LINGER, 0)
        xpub.setsockopt(zmq.LINGER, 0)
        xsub.bind(f"tcp://127.0.0.1:{self._pub_port}")
        xpub.bind(f"tcp://127.0.0.1:{self._sub_port}")
        try:
            zmq.proxy(xsub, xpub)
        except zmq.ContextTerminated:
            pass
        except zmq.ZMQError:
            pass
        finally:
            xsub.close()
            xpub.close()

    def stop(self) -> None:
        """Stop the proxy by terminating its context."""
        self._running = False
        self._context.term()
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("EventBus stopped")


class EventPublisher:
    """Publishes events to the EventBus.

    Each sensor creates one publisher with its topic prefix.
    """

    def __init__(self, port: int = 15555, topic: str = "sensor.generic"):
        self._topic = topic
        self._context = zmq.Context()
        self._socket = self._context.socket(zmq.PUB)
        self._socket.setsockopt(zmq.LINGER, 0)
        self._socket.connect(f"tcp://127.0.0.1:{port}")

    def send(self, event: AegisEvent) -> None:
        """Send an event with the configured topic prefix."""
        topic_bytes = self._topic.encode("utf-8")
        event_bytes = event.to_bytes()
        self._socket.send_multipart([topic_bytes, event_bytes])

    def close(self) -> None:
        self._socket.close()
        self._context.term()


class EventSubscriber:
    """Subscribes to events from the EventBus.

    Detection engines and the UI use this to receive events.
    """

    def __init__(
        self,
        port: int = 15556,
        topics: list[str] | None = None,
        callback: Callable[[AegisEvent], None] | None = None,
    ):
        self._port = port
        self._topics = topics or [""]
        self._callback = callback
        self._context = zmq.Context()
        self._socket = self._context.socket(zmq.SUB)
        self._socket.setsockopt(zmq.LINGER, 0)
        self._running = False
        self._thread: threading.Thread | None = None

        for topic in self._topics:
            self._socket.subscribe(topic.encode("utf-8"))
        self._socket.connect(f"tcp://127.0.0.1:{port}")

    def start(self) -> None:
        """Start receiving events in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()

    def _listen(self) -> None:
        poller = zmq.Poller()
        poller.register(self._socket, zmq.POLLIN)
        while self._running:
            socks = dict(poller.poll(timeout=100))
            if self._socket in socks:
                try:
                    parts = self._socket.recv_multipart(zmq.NOBLOCK)
                    if len(parts) == 2:
                        event = AegisEvent.from_bytes(parts[1])
                        if self._callback:
                            self._callback(event)
                except zmq.ZMQError:
                    pass

    def stop(self) -> None:
        """Stop receiving events."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        self._socket.close()
        self._context.term()
