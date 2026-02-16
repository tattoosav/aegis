"""Settings page -- configuration management for Aegis.

Provides a tabbed interface with Sensors, Alerts, Performance,
and About sections for viewing and editing Aegis configuration.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aegis.core.config import AegisConfig

logger = logging.getLogger(__name__)

_SENSOR_DEFINITIONS: list[tuple[str, str]] = [
    ("Network", "sensors.network.enabled"),
    ("Process", "sensors.process.enabled"),
    ("File Integrity", "sensors.fim.enabled"),
    ("Event Log", "sensors.eventlog.enabled"),
    ("Hardware", "sensors.hardware.enabled"),
    ("Clipboard", "sensors.clipboard.enabled"),
]


class SettingsPage(QWidget):
    """Configuration management page.

    Displays a tabbed interface for editing sensor toggles,
    alert thresholds, performance settings, and about info.
    """

    def __init__(
        self,
        config: AegisConfig | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._sensor_checks: dict[str, QCheckBox] = {}
        self._setup_ui()
        self.refresh()

    # ------------------------------------------------------------------ #
    #  UI construction
    # ------------------------------------------------------------------ #

    def _setup_ui(self) -> None:
        """Build the full page layout."""
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # Header
        title = QLabel("Settings")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        root.addWidget(title)

        # Tab widget
        self._tabs = QTabWidget()
        self._tabs.setObjectName("settingsTabs")
        self._tabs.addTab(self._build_sensors_tab(), "Sensors")
        self._tabs.addTab(self._build_alerts_tab(), "Alerts")
        self._tabs.addTab(
            self._build_performance_tab(), "Performance"
        )
        self._tabs.addTab(self._build_about_tab(), "About")
        root.addWidget(self._tabs, stretch=1)

        # Save button
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._save_btn = QPushButton("Save Settings")
        self._save_btn.setObjectName("saveBtn")
        self._save_btn.clicked.connect(self.save_settings)
        btn_row.addWidget(self._save_btn)
        root.addLayout(btn_row)

    # -- Sensors tab --------------------------------------------------- #

    def _build_sensors_tab(self) -> QWidget:
        """Build the Sensors configuration tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        for display_name, config_key in _SENSOR_DEFINITIONS:
            group = QGroupBox(display_name)
            group_layout = QVBoxLayout(group)
            cb = QCheckBox("Enabled")
            cb.setObjectName(f"sensor_{display_name}")
            self._sensor_checks[config_key] = cb
            group_layout.addWidget(cb)
            layout.addWidget(group)

        layout.addStretch()
        return tab

    # -- Alerts tab ---------------------------------------------------- #

    def _build_alerts_tab(self) -> QWidget:
        """Build the Alerts configuration tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # Dedup window
        dedup_row = QHBoxLayout()
        dedup_row.addWidget(
            QLabel("Deduplication window (seconds):")
        )
        self._dedup_window = QSpinBox()
        self._dedup_window.setObjectName("dedupWindow")
        self._dedup_window.setRange(1, 3600)
        self._dedup_window.setValue(60)
        dedup_row.addWidget(self._dedup_window)
        dedup_row.addStretch()
        layout.addLayout(dedup_row)

        # Max alerts per hour
        max_row = QHBoxLayout()
        max_row.addWidget(QLabel("Max alerts per hour:"))
        self._max_alerts = QSpinBox()
        self._max_alerts.setObjectName("maxAlerts")
        self._max_alerts.setRange(1, 10000)
        self._max_alerts.setValue(100)
        max_row.addWidget(self._max_alerts)
        max_row.addStretch()
        layout.addLayout(max_row)

        # Desktop notifications
        self._desktop_notifications = QCheckBox(
            "Enable desktop notifications"
        )
        self._desktop_notifications.setObjectName(
            "desktopNotifications"
        )
        self._desktop_notifications.setChecked(True)
        layout.addWidget(self._desktop_notifications)

        layout.addStretch()
        return tab

    # -- Performance tab ----------------------------------------------- #

    def _build_performance_tab(self) -> QWidget:
        """Build the Performance configuration tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # Max events per second
        eps_row = QHBoxLayout()
        eps_row.addWidget(QLabel("Max events per second:"))
        self._max_eps = QSpinBox()
        self._max_eps.setObjectName("maxEps")
        self._max_eps.setRange(1, 100000)
        self._max_eps.setValue(1000)
        eps_row.addWidget(self._max_eps)
        eps_row.addStretch()
        layout.addLayout(eps_row)

        # Baseline window
        baseline_row = QHBoxLayout()
        baseline_row.addWidget(
            QLabel("Baseline window (minutes):")
        )
        self._baseline_window = QSpinBox()
        self._baseline_window.setObjectName("baselineWindow")
        self._baseline_window.setRange(1, 1440)
        self._baseline_window.setValue(60)
        baseline_row.addWidget(self._baseline_window)
        baseline_row.addStretch()
        layout.addLayout(baseline_row)

        layout.addStretch()
        return tab

    # -- About tab ----------------------------------------------------- #

    def _build_about_tab(self) -> QWidget:
        """Build the About information tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(16)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        name_label = QLabel("Aegis Security Defense System")
        name_label.setObjectName("aboutName")
        name_font = QFont()
        name_font.setPointSize(14)
        name_font.setBold(True)
        name_label.setFont(name_font)
        layout.addWidget(name_label)

        version_label = QLabel("Version 1.0.0")
        version_label.setObjectName("aboutVersion")
        layout.addWidget(version_label)

        tech_label = QLabel("Built with Python, sklearn, PySide6")
        tech_label.setObjectName("aboutTech")
        tech_label.setStyleSheet("color: #888;")
        layout.addWidget(tech_label)

        layout.addStretch()
        return tab

    # ------------------------------------------------------------------ #
    #  Public interface
    # ------------------------------------------------------------------ #

    def refresh(self) -> None:
        """Reload widget values from the config object."""
        if self._config is None:
            return

        # Sensors
        for config_key, cb in self._sensor_checks.items():
            val = self._config.get(config_key, False)
            cb.setChecked(bool(val))

        # Alerts
        dedup = self._config.get(
            "alerting.dedup_window", 60
        )
        self._dedup_window.setValue(int(dedup))

        max_alerts = self._config.get(
            "alerting.max_alerts_per_hour", 100
        )
        self._max_alerts.setValue(int(max_alerts))

        notif = self._config.get(
            "alerting.desktop_notifications", True
        )
        self._desktop_notifications.setChecked(bool(notif))

        # Performance
        max_eps = self._config.get(
            "performance.max_events_per_second", 1000
        )
        self._max_eps.setValue(int(max_eps))

        baseline = self._config.get(
            "performance.baseline_window_minutes", 60
        )
        self._baseline_window.setValue(int(baseline))

    def save_settings(self) -> None:
        """Write current widget values back to the config object."""
        if self._config is None:
            logger.warning("No config object; cannot save.")
            return

        # Sensors
        for config_key, cb in self._sensor_checks.items():
            self._config.set(config_key, cb.isChecked())

        # Alerts
        self._config.set(
            "alerting.dedup_window",
            self._dedup_window.value(),
        )
        self._config.set(
            "alerting.max_alerts_per_hour",
            self._max_alerts.value(),
        )
        self._config.set(
            "alerting.desktop_notifications",
            self._desktop_notifications.isChecked(),
        )

        # Performance
        self._config.set(
            "performance.max_events_per_second",
            self._max_eps.value(),
        )
        self._config.set(
            "performance.baseline_window_minutes",
            self._baseline_window.value(),
        )

        logger.info("Settings saved to config.")
