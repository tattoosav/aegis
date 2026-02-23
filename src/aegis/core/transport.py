"""Event transport abstraction for Aegis.

Provides an in-process queue-based transport as default, with an
optional ZeroMQ transport when the ``zmq`` package is installed.
The :func:`create_transport` factory selects the best backend
automatically.
"""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from aegis.core.models import AegisEvent

logger = logging.getLogger(__name__)


@runtime_checkable
class EventTransport(Protocol):
    """Protocol that all transport backends must satisfy."""

    def send(self, event: AegisEvent) -> None: ...
    def subscribe(self, callback: Callable[[AegisEvent], None]) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...


class InProcessTransport:
    """Thread-safe in-process event transport using a queue.

    Parameters
    ----------
    maxsize:
        Maximum queue depth.  Events are dropped when full.
    """

    def __init__(self, maxsize: int = 10_000) -> None:
        self._queue: queue.Queue[AegisEvent] = queue.Queue(
            maxsize=maxsize,
        )
        self._callbacks: list[Callable[[AegisEvent], None]] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    def send(self, event: AegisEvent) -> None:
        """Enqueue an event for delivery to subscribers."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            logger.warning("Transport queue full, dropping event")

    def subscribe(
        self, callback: Callable[[AegisEvent], None],
    ) -> None:
        """Register a callback to receive events."""
        with self._lock:
            self._callbacks.append(callback)

    def start(self) -> None:
        """Start the consumer thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._consumer_loop,
            daemon=True,
            name="transport-consumer",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the consumer thread."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _consumer_loop(self) -> None:
        while self._running:
            try:
                event = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            with self._lock:
                for cb in self._callbacks:
                    try:
                        cb(event)
                    except Exception:
                        logger.debug(
                            "Transport callback error",
                            exc_info=True,
                        )

    @property
    def pending(self) -> int:
        """Number of events waiting in the queue."""
        return self._queue.qsize()


class ZmqTransport:
    """ZeroMQ PUB/SUB transport wrapping the existing bus layer.

    Parameters
    ----------
    pub_port:
        Port for the XSUB (publisher) side.
    sub_port:
        Port for the XPUB (subscriber) side.
    """

    def __init__(
        self,
        pub_port: int = 15555,
        sub_port: int = 15556,
    ) -> None:
        from aegis.core.bus import (
            EventBus,
            EventPublisher,
            EventSubscriber,
        )

        self._bus = EventBus(pub_port, sub_port)
        self._publisher = EventPublisher(port=pub_port)
        self._sub_port = sub_port
        self._EventSubscriber = EventSubscriber
        self._subscribers: list[Any] = []

    def send(self, event: AegisEvent) -> None:
        """Publish an event via ZeroMQ."""
        self._publisher.send(event)

    def subscribe(
        self, callback: Callable[[AegisEvent], None],
    ) -> None:
        """Register a subscriber callback."""
        sub = self._EventSubscriber(
            port=self._sub_port,
            topics=["sensor."],
            callback=callback,
        )
        self._subscribers.append(sub)

    def start(self) -> None:
        """Start the bus and all subscribers."""
        self._bus.start()
        for sub in self._subscribers:
            sub.start()

    def stop(self) -> None:
        """Stop all subscribers and the bus."""
        for sub in self._subscribers:
            try:
                sub.stop()
            except Exception:
                pass
        try:
            self._publisher.close()
        except Exception:
            pass
        try:
            self._bus.stop()
        except Exception:
            pass


def create_transport(
    config: Any = None,
) -> InProcessTransport | ZmqTransport:
    """Create the best available transport backend.

    Parameters
    ----------
    config:
        Optional AegisConfig.  Reads ``transport.backend`` which
        can be ``"auto"`` (default), ``"zmq"``, or ``"inprocess"``.
    """
    backend = "auto"
    if config is not None:
        backend = config.get("transport.backend", "auto")

    if backend == "inprocess":
        return InProcessTransport()

    if backend == "zmq":
        return ZmqTransport()

    # auto — try zmq, fall back to inprocess
    try:
        import zmq  # noqa: F401
        return ZmqTransport()
    except ImportError:
        logger.info(
            "ZeroMQ not available, using in-process transport",
        )
        return InProcessTransport()
