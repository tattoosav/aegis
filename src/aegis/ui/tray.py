"""System tray icon and state management for Aegis.

The tray icon is Aegis's always-visible presence on the taskbar.
States: green (all clear), yellow (warning), red (critical), grey (learning).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class _TrayStateInfo:
    color: str
    tooltip: str


class TrayState(Enum):
    """System tray icon states."""

    ALL_CLEAR = _TrayStateInfo(color="green", tooltip="Aegis — All clear")
    WARNING = _TrayStateInfo(color="yellow", tooltip="Aegis — Warning: alert pending review")
    CRITICAL = _TrayStateInfo(color="red", tooltip="Aegis — Critical alert!")
    LEARNING = _TrayStateInfo(color="grey", tooltip="Aegis — Learning your baseline")

    @property
    def color(self) -> str:
        return self.value.color

    @property
    def tooltip(self) -> str:
        return self.value.tooltip


class AegisTrayManager:
    """Manages tray icon state and sensor status.

    In headless mode (for testing), no Qt widgets are created.
    In normal mode, creates QSystemTrayIcon with context menu.
    """

    def __init__(self, headless: bool = False):
        self._headless = headless
        self._state = TrayState.LEARNING
        self._sensor_statuses: dict[str, bool] = {}
        self._tray_icon: Any = None

        if not headless:
            self._init_tray()

    def _init_tray(self) -> None:
        """Initialize the Qt system tray icon."""
        try:
            from PySide6.QtWidgets import QSystemTrayIcon  # noqa: F401
            logger.info("Tray manager initialized (GUI mode)")
        except ImportError:
            logger.warning("PySide6 not available, falling back to headless mode")
            self._headless = True

    @property
    def state(self) -> TrayState:
        return self._state

    @property
    def sensor_statuses(self) -> dict[str, bool]:
        return dict(self._sensor_statuses)

    def set_state(self, state: TrayState) -> None:
        """Update the tray icon state."""
        self._state = state
        logger.info(f"Tray state changed to: {state.name} ({state.color})")
        if not self._headless and self._tray_icon:
            self._update_icon()

    def update_sensor_status(self, sensor_name: str, running: bool) -> None:
        """Update the running status of a sensor."""
        self._sensor_statuses[sensor_name] = running

    def _update_icon(self) -> None:
        """Update the actual tray icon (Qt). Only in GUI mode."""
        pass
