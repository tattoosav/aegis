"""System tray icon and state management for Aegis.

The tray icon is Aegis's always-visible presence on the taskbar.
``AegisTray`` is a full PySide6 QSystemTrayIcon with a context menu,
shield icon that changes colour per security status, and signals for
dashboard navigation.

``TrayState`` and ``AegisTrayManager`` provide a headless-friendly
abstraction used by the rest of the system (and tests) that do not
need a live Qt event loop.

States: green (all clear), yellow (warning), red (critical),
grey (learning).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# -- Colour constants used by both the headless manager and the Qt
#    tray icon.  Kept at module level for easy reuse. ------------------

STATUS_COLORS: dict[str, str] = {
    "clear": "#2ecc71",
    "warning": "#f39c12",
    "critical": "#e74c3c",
    "learning": "#95a5a6",
}


# ======================================================================
# Headless helpers (no Qt dependency)
# ======================================================================

@dataclass
class _TrayStateInfo:
    color: str
    tooltip: str


class TrayState(Enum):
    """System tray icon states."""

    ALL_CLEAR = _TrayStateInfo(
        color="green",
        tooltip="Aegis \u2014 All clear",
    )
    WARNING = _TrayStateInfo(
        color="yellow",
        tooltip="Aegis \u2014 Warning: alert pending review",
    )
    CRITICAL = _TrayStateInfo(
        color="red",
        tooltip="Aegis \u2014 Critical alert!",
    )
    LEARNING = _TrayStateInfo(
        color="grey",
        tooltip="Aegis \u2014 Learning your baseline",
    )

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
            from PySide6.QtWidgets import (  # noqa: F401
                QSystemTrayIcon,
            )

            logger.info("Tray manager initialized (GUI mode)")
        except ImportError:
            logger.warning(
                "PySide6 not available, falling back to headless"
            )
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
        logger.info(
            "Tray state changed to: %s (%s)",
            state.name,
            state.color,
        )
        if not self._headless and self._tray_icon:
            self._update_icon()

    def update_sensor_status(
        self, sensor_name: str, running: bool
    ) -> None:
        """Update the running status of a sensor."""
        self._sensor_statuses[sensor_name] = running

    def _update_icon(self) -> None:
        """Update the actual tray icon (Qt).  Only in GUI mode."""
        pass


# ======================================================================
# Full PySide6 system-tray widget
# ======================================================================

try:
    from PySide6.QtCore import QPointF, Qt, Signal
    from PySide6.QtGui import (
        QAction,
        QBrush,
        QColor,
        QIcon,
        QPainter,
        QPen,
        QPixmap,
        QPolygonF,
    )
    from PySide6.QtWidgets import (
        QApplication,
        QMenu,
        QSystemTrayIcon,
    )

    _HAS_PYSIDE6 = True
except ImportError:  # pragma: no cover
    _HAS_PYSIDE6 = False

if _HAS_PYSIDE6:

    class AegisTray(QSystemTrayIcon):
        """PySide6 system-tray icon for the Aegis dashboard.

        Provides a coloured shield icon that reflects the current
        security posture, a right-click context menu, and signals
        for higher-level UI navigation.
        """

        # -- Signals --------------------------------------------------
        dashboard_requested = Signal()
        summary_requested = Signal()
        settings_requested = Signal()

        # -- Construction ---------------------------------------------

        def __init__(self, parent: Any = None) -> None:
            super().__init__(parent)

            self._current_status: str = "clear"
            self._sensor_actions: dict[str, QAction] = {}

            # Default icon & tooltip
            self.setIcon(
                self._create_shield_icon(STATUS_COLORS["clear"])
            )
            self.setToolTip("Aegis \u2014 All clear")

            # Build the right-click context menu
            self._menu = self._build_context_menu()
            self.setContextMenu(self._menu)

        # -- Public API -----------------------------------------------

        def set_status(self, status: str) -> None:
            """Change the tray icon colour to match *status*.

            Parameters
            ----------
            status : str
                One of ``"clear"``, ``"warning"``,
                ``"critical"``, or ``"learning"``.
            """
            status = status.lower()
            color = STATUS_COLORS.get(status, STATUS_COLORS["clear"])
            self.setIcon(self._create_shield_icon(color))
            self._current_status = status
            logger.debug("Tray icon status set to %s", status)

        def show_notification(
            self,
            title: str,
            message: str,
            severity: str = "info",
        ) -> None:
            """Display a tray balloon / notification.

            Parameters
            ----------
            title : str
                Notification title.
            message : str
                Notification body text.
            severity : str
                ``"info"``, ``"warning"``, or ``"critical"``.
                Controls the icon shown in the balloon.
            """
            icon_map: dict[str, QSystemTrayIcon.MessageIcon] = {
                "info": QSystemTrayIcon.MessageIcon.Information,
                "warning": QSystemTrayIcon.MessageIcon.Warning,
                "critical": QSystemTrayIcon.MessageIcon.Critical,
            }
            icon = icon_map.get(
                severity.lower(),
                QSystemTrayIcon.MessageIcon.Information,
            )
            self.showMessage(title, message, icon)

        def set_tooltip(self, text: str) -> None:
            """Update the tray icon tooltip.

            Parameters
            ----------
            text : str
                New tooltip string.
            """
            self.setToolTip(text)

        def update_sensor_action(
            self,
            sensor_name: str,
            running: bool,
        ) -> None:
            """Add or update a sensor entry in the Sensor Status
            submenu.

            Parameters
            ----------
            sensor_name : str
                Human-readable sensor name.
            running : bool
                Whether the sensor is currently active.
            """
            label = (
                f"{sensor_name}: Running"
                if running
                else f"{sensor_name}: Stopped"
            )
            if sensor_name in self._sensor_actions:
                self._sensor_actions[sensor_name].setText(label)
            else:
                action = self._sensor_menu.addAction(label)
                action.setEnabled(False)
                self._sensor_actions[sensor_name] = action

        # -- Icon drawing ---------------------------------------------

        def _create_shield_icon(self, color: str) -> QIcon:
            """Draw a 32x32 shield polygon filled with *color*.

            Parameters
            ----------
            color : str
                A CSS-style colour string (e.g. ``"#2ecc71"``).

            Returns
            -------
            QIcon
                The rendered shield icon.
            """
            pixmap = QPixmap(32, 32)
            pixmap.fill(Qt.GlobalColor.transparent)

            painter = QPainter(pixmap)
            painter.setRenderHint(
                QPainter.RenderHint.Antialiasing
            )

            shield = QPolygonF(
                [
                    QPointF(16, 2),    # top centre
                    QPointF(28, 8),    # right shoulder
                    QPointF(26, 22),   # right lower
                    QPointF(16, 30),   # bottom point
                    QPointF(6, 22),    # left lower
                    QPointF(4, 8),     # left shoulder
                ]
            )

            fill = QColor(color)
            painter.setBrush(QBrush(fill))
            painter.setPen(QPen(fill.darker(120), 1))
            painter.drawPolygon(shield)
            painter.end()

            return QIcon(pixmap)

        # -- Context menu construction --------------------------------

        def _build_context_menu(self) -> QMenu:
            """Create the right-click context menu.

            Layout
            ------
            Open Dashboard
            ---
            Sensor Status  >  (submenu, populated dynamically)
            ---
            Pause Monitoring  >  5 min | 15 min | 1 hour
            ---
            Today's Summary
            Settings
            ---
            Exit Aegis
            """
            menu = QMenu()

            # -- Open Dashboard
            open_action = menu.addAction("Open Dashboard")
            open_action.triggered.connect(
                self.dashboard_requested.emit
            )

            menu.addSeparator()

            # -- Sensor Status submenu
            self._sensor_menu = QMenu("Sensor Status", menu)
            menu.addMenu(self._sensor_menu)

            menu.addSeparator()

            # -- Pause Monitoring submenu
            pause_menu = QMenu("Pause Monitoring", menu)
            pause_menu.addAction("5 min")
            pause_menu.addAction("15 min")
            pause_menu.addAction("1 hour")
            menu.addMenu(pause_menu)

            menu.addSeparator()

            # -- Today's Summary
            summary_action = menu.addAction("Today's Summary")
            summary_action.triggered.connect(
                self.summary_requested.emit
            )

            # -- Settings
            settings_action = menu.addAction("Settings")
            settings_action.triggered.connect(
                self.settings_requested.emit
            )

            menu.addSeparator()

            # -- Exit Aegis
            exit_action = menu.addAction("Exit Aegis")
            exit_action.triggered.connect(QApplication.quit)

            return menu
