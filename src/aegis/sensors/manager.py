"""Sensor lifecycle manager for Aegis.

Orchestrates creation, startup, shutdown, and health monitoring
of all sensor modules based on configuration.
"""

from __future__ import annotations

import importlib
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from aegis.core.models import AegisEvent, SensorType
from aegis.sensors.health import SensorHealth

logger = logging.getLogger(__name__)

# Registry of known sensors: config_key -> (module, class, type)
SENSOR_REGISTRY: dict[str, tuple[str, str, SensorType]] = {
    "process": (
        "aegis.sensors.process",
        "ProcessSensor",
        SensorType.PROCESS,
    ),
    "network": (
        "aegis.sensors.network",
        "NetworkSensor",
        SensorType.NETWORK,
    ),
    "fim": (
        "aegis.sensors.file_integrity",
        "FileIntegritySensor",
        SensorType.FILE,
    ),
    "eventlog": (
        "aegis.sensors.eventlog",
        "EventLogSensor",
        SensorType.EVENTLOG,
    ),
    "registry": (
        "aegis.sensors.registry",
        "RegistrySensor",
        SensorType.REGISTRY,
    ),
    "clipboard": (
        "aegis.sensors.clipboard",
        "ClipboardSensor",
        SensorType.CLIPBOARD,
    ),
    "hardware": (
        "aegis.sensors.hardware",
        "HardwareSensor",
        SensorType.HARDWARE,
    ),
}

# Config keys that map to sensor __init__ interval parameter
_INTERVAL_KEYS: dict[str, str] = {
    "process": "sensors.process.scan_interval_seconds",
    "network": "sensors.network.flow_window_seconds",
    "fim": "sensors.fim.scan_interval_seconds",
    "eventlog": "sensors.eventlog.scan_interval_seconds",
    "registry": "sensors.registry.scan_interval_seconds",
    "clipboard": "sensors.clipboard.scan_interval_seconds",
    "hardware": "sensors.hardware.scan_interval_seconds",
}


class SensorManager:
    """Manage the lifecycle of all Aegis sensor modules.

    Parameters
    ----------
    config:
        Aegis configuration object.
    transport:
        EventTransport for sending sensor events to the engine.
    """

    def __init__(
        self,
        config: Any,
        transport: Any,
    ) -> None:
        self._config = config
        self._transport = transport
        self._sensors: dict[str, Any] = {}
        self._health: dict[str, SensorHealth] = {}
        self._lock = threading.Lock()
        self._running = False
        self._monitor_thread: threading.Thread | None = None
        self._monitor_interval: float = 10.0
        if config is not None:
            self._monitor_interval = config.get(
                "sensors.health_check_interval", 10.0,
            )
        self._max_consecutive_errors: int = 10
        if config is not None:
            self._max_consecutive_errors = config.get(
                "sensors.max_consecutive_errors", 10,
            )

    def setup(self) -> None:
        """Create sensor instances for all enabled sensors."""
        for key, (module_path, class_name, sensor_type) in (
            SENSOR_REGISTRY.items()
        ):
            enabled = False
            if self._config is not None:
                enabled = self._config.get(
                    f"sensors.{key}.enabled", False,
                )
            if not enabled:
                logger.info("Sensor %s disabled via config", key)
                continue
            try:
                mod = importlib.import_module(module_path)
                sensor_cls = getattr(mod, class_name)

                interval = 5.0
                interval_key = _INTERVAL_KEYS.get(key)
                if interval_key and self._config is not None:
                    interval = self._config.get(
                        interval_key, 5.0,
                    )

                health = SensorHealth(
                    sensor_name=key,
                    sensor_type=sensor_type,
                    enabled=True,
                )
                callback = self._make_event_callback(key, health)
                sensor = sensor_cls(
                    interval=interval,
                    on_event=callback,
                )
                with self._lock:
                    self._sensors[key] = sensor
                    self._health[key] = health
                logger.info(
                    "Sensor %s created (interval=%.1fs)",
                    key,
                    interval,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to create sensor %s: %s", key, exc,
                )

    def _make_event_callback(
        self,
        sensor_name: str,
        health: SensorHealth,
    ) -> Callable[[AegisEvent], None]:
        """Create a callback that sends events and updates health."""
        def _callback(event: AegisEvent) -> None:
            try:
                self._transport.send(event)
                health.events_emitted += 1
                health.last_event_time = time.time()
                health.consecutive_errors = 0
            except Exception as exc:
                health.errors += 1
                health.consecutive_errors += 1
                health.last_error_time = time.time()
                health.last_error_message = str(exc)[:200]
                logger.warning(
                    "Transport send failed for %s: %s",
                    sensor_name,
                    exc,
                )
        return _callback

    def start(self) -> None:
        """Start all registered sensors and the health monitor."""
        self._running = True
        for name, sensor in self._sensors.items():
            try:
                sensor.start()
                health = self._health[name]
                health.is_running = True
                health.started_at = time.time()
                logger.info("Sensor %s started", name)
            except Exception as exc:
                logger.error(
                    "Sensor %s failed to start: %s", name, exc,
                )
                self._health[name].errors += 1

        self._monitor_thread = threading.Thread(
            target=self._health_monitor_loop,
            daemon=True,
            name="sensor-health-monitor",
        )
        self._monitor_thread.start()

    def stop(self) -> None:
        """Stop all sensors and the health monitor."""
        self._running = False
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=5.0)
            self._monitor_thread = None
        for name, sensor in self._sensors.items():
            try:
                sensor.stop()
                self._health[name].is_running = False
                logger.info("Sensor %s stopped", name)
            except Exception as exc:
                logger.warning(
                    "Sensor %s stop error: %s", name, exc,
                )

    def _health_monitor_loop(self) -> None:
        """Periodically check sensor health."""
        while self._running:
            time.sleep(self._monitor_interval)
            if not self._running:
                break
            for name in list(self._sensors.keys()):
                sensor = self._sensors.get(name)
                health = self._health.get(name)
                if sensor is None or health is None:
                    continue
                if health.is_running and not sensor.is_running:
                    logger.warning(
                        "Sensor %s thread died, restarting", name,
                    )
                    self._restart_sensor(name)
                if (
                    health.consecutive_errors
                    >= self._max_consecutive_errors
                ):
                    logger.warning(
                        "Sensor %s hit %d consecutive errors",
                        name,
                        health.consecutive_errors,
                    )
                    self._restart_sensor(name)

    def _restart_sensor(self, name: str) -> None:
        """Stop and restart a single sensor."""
        sensor = self._sensors.get(name)
        health = self._health.get(name)
        if sensor is None or health is None:
            return
        try:
            sensor.stop()
        except Exception:
            pass
        try:
            sensor.start()
            health.is_running = True
            health.restarts += 1
            health.consecutive_errors = 0
            logger.info(
                "Sensor %s restarted (restart #%d)",
                name,
                health.restarts,
            )
        except Exception as exc:
            health.is_running = False
            logger.error(
                "Sensor %s restart failed: %s", name, exc,
            )

    # -- Query methods ---------------------------------------------------

    def get_health(self, name: str) -> SensorHealth | None:
        """Return health record for a named sensor."""
        return self._health.get(name)

    def get_all_health(self) -> dict[str, SensorHealth]:
        """Return health records for all sensors."""
        return dict(self._health)

    def get_sensor(self, name: str) -> Any:
        """Return a sensor instance by name, or None."""
        return self._sensors.get(name)

    @property
    def sensor_names(self) -> list[str]:
        """Names of all registered sensors."""
        return list(self._sensors.keys())

    @property
    def sensor_count(self) -> int:
        """Number of registered sensors."""
        return len(self._sensors)

    def get_status(self) -> dict[str, Any]:
        """Return overall sensor manager status."""
        return {
            "sensor_count": len(self._sensors),
            "running": self._running,
            "sensors": {
                name: health.to_dict()
                for name, health in self._health.items()
            },
        }
