"""First-run wizard configuration logic and optional Qt UI.

Provides a pure-data WizardConfig dataclass that captures user choices
during the first-run wizard, and an apply_wizard_config function that
translates those choices into AegisConfig writes.

When PySide6 is available, also provides a full FirstRunWizard (QWizard)
with eight configuration pages.
"""

from __future__ import annotations

import logging as _logging
from dataclasses import dataclass, field

from aegis.core.config import AegisConfig

# Mapping from sensitivity label to anomaly-detection threshold.
# Lower threshold = more sensitive (more anomalies flagged).
SENSITIVITY_THRESHOLDS: dict[str, float] = {
    "low": 0.8,
    "medium": 0.6,
    "high": 0.4,
}


def _default_sensors_enabled() -> dict[str, bool]:
    """Return the default sensor-enabled map (all True)."""
    return {
        "network": True,
        "process": True,
        "fim": True,
        "eventlog": True,
        "threat_intel": True,
        "hardware": True,
        "clipboard": True,
    }


def _default_feeds_enabled() -> dict[str, bool]:
    """Return the default threat-intel feed-enabled map."""
    return {
        "virustotal": False,
        "abuseipdb": False,
        "phishtank": True,
    }


def _default_api_keys() -> dict[str, str]:
    """Return the default (empty) API key map for threat-intel feeds."""
    return {
        "virustotal": "",
        "abuseipdb": "",
        "phishtank": "",
    }


@dataclass
class WizardConfig:
    """Pure-data container for first-run wizard user choices.

    The anomaly_threshold property is derived from the sensitivity string
    so callers never have to compute it manually.
    """

    sensors_enabled: dict[str, bool] = field(
        default_factory=_default_sensors_enabled,
    )
    sensitivity: str = "medium"
    feeds_enabled: dict[str, bool] = field(
        default_factory=_default_feeds_enabled,
    )
    api_keys: dict[str, str] = field(
        default_factory=_default_api_keys,
    )
    excluded_processes: list[str] = field(default_factory=list)
    excluded_dirs: list[str] = field(default_factory=list)
    excluded_ips: list[str] = field(default_factory=list)
    install_sysmon: bool = False

    @property
    def anomaly_threshold(self) -> float:
        """Map sensitivity label to a numeric anomaly threshold."""
        return SENSITIVITY_THRESHOLDS.get(self.sensitivity, 0.6)


def apply_wizard_config(
    config: AegisConfig,
    wizard_config: WizardConfig,
) -> None:
    """Write all wizard choices into *config* and mark first-run complete.

    Parameters
    ----------
    config:
        The live AegisConfig instance to update.
    wizard_config:
        The WizardConfig populated by the wizard UI.
    """
    # --- Sensor enable/disable ---
    for sensor, enabled in wizard_config.sensors_enabled.items():
        config.set(f"sensors.{sensor}.enabled", enabled)

    # --- Detection sensitivity ---
    config.set("detection.sensitivity", wizard_config.sensitivity)
    config.set(
        "detection.isolation_forest.anomaly_threshold",
        wizard_config.anomaly_threshold,
    )

    # --- Threat-intel feeds ---
    for feed, enabled in wizard_config.feeds_enabled.items():
        config.set(
            f"sensors.threat_intel.feeds.{feed}.enabled",
            enabled,
        )
    for feed, key in wizard_config.api_keys.items():
        config.set(
            f"sensors.threat_intel.feeds.{feed}.api_key",
            key,
        )

    # --- Exclusions ---
    config.set("exclusions.processes", list(wizard_config.excluded_processes))
    config.set("exclusions.directories", list(wizard_config.excluded_dirs))
    config.set("exclusions.ips", list(wizard_config.excluded_ips))

    # --- Sysmon ---
    config.set("sysmon.installed", wizard_config.install_sysmon)

    # --- Mark first run complete ---
    config.set("first_run_complete", True)


# ------------------------------------------------------------------ #
# Qt UI — only defined when PySide6 is available
# ------------------------------------------------------------------ #

_qt_logger = _logging.getLogger(__name__)

try:
    from PySide6.QtCore import Qt, QThread, Signal, Slot
    from PySide6.QtWidgets import (
        QCheckBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QProgressBar,
        QPushButton,
        QSlider,
        QTextEdit,
        QVBoxLayout,
        QWizard,
        QWizardPage,
    )

    _HAS_QT = True
except ImportError:  # pragma: no cover
    _HAS_QT = False


if _HAS_QT:

    # -------------------------------------------------------------- #
    # Background workers (QThread)
    # -------------------------------------------------------------- #

    class _BaselineScanWorker(QThread):
        """Run a baseline scan in a background thread."""

        progress = Signal(str)
        finished = Signal(object)  # BaselineSnapshot or None

        def run(self) -> None:
            """Execute the scan and emit results."""
            try:
                from aegis.core.baseline_scanner import (
                    BaselineScanner,
                )

                self.progress.emit("Scanning processes...")
                scanner = BaselineScanner()
                snapshot = scanner.scan()
                self.progress.emit("Scan complete.")
                self.finished.emit(snapshot)
            except Exception as exc:
                _qt_logger.error(
                    "Baseline scan failed: %s", exc,
                )
                self.progress.emit(f"Error: {exc}")
                self.finished.emit(None)

    class _SysmonInstallWorker(QThread):
        """Install Sysmon in a background thread."""

        finished = Signal(bool)

        def run(self) -> None:
            """Run the Sysmon installer."""
            try:
                from aegis.core.sysmon_manager import (
                    SysmonManager,
                )

                mgr = SysmonManager()
                ok = mgr.install()
                self.finished.emit(ok)
            except Exception as exc:
                _qt_logger.error(
                    "Sysmon install failed: %s", exc,
                )
                self.finished.emit(False)

    # -------------------------------------------------------------- #
    # Wizard pages
    # -------------------------------------------------------------- #

    class WelcomePage(QWizardPage):
        """Page 1: Welcome branding page."""

        def __init__(
            self, parent: QWizard | None = None,
        ) -> None:
            super().__init__(parent)
            self.setTitle("Welcome to Aegis")
            self.setSubTitle(
                "AI-powered security defense for your PC"
            )
            layout = QVBoxLayout(self)
            lbl = QLabel(
                "<h1>Aegis</h1>"
                "<p>This wizard will help you configure "
                "Aegis for first-time use.</p>"
                "<p>Click <b>Next</b> to begin.</p>"
            )
            lbl.setWordWrap(True)
            layout.addWidget(lbl)

    class SensorPage(QWizardPage):
        """Page 2: Enable/disable individual sensors."""

        def __init__(
            self, parent: QWizard | None = None,
        ) -> None:
            super().__init__(parent)
            self.setTitle("Sensors")
            self.setSubTitle(
                "Choose which sensors to enable."
            )
            layout = QVBoxLayout(self)
            self._checks: dict[str, QCheckBox] = {}
            defaults = _default_sensors_enabled()
            for name, enabled in defaults.items():
                cb = QCheckBox(name.replace("_", " ").title())
                cb.setChecked(enabled)
                layout.addWidget(cb)
                self._checks[name] = cb

        def get_sensors(self) -> dict[str, bool]:
            """Return sensor-enabled map from checkboxes."""
            return {
                k: cb.isChecked()
                for k, cb in self._checks.items()
            }

    class ThreatIntelPage(QWizardPage):
        """Page 3: Threat-intel feed toggles + API keys."""

        def __init__(
            self, parent: QWizard | None = None,
        ) -> None:
            super().__init__(parent)
            self.setTitle("Threat Intelligence")
            self.setSubTitle(
                "Configure threat-intelligence feeds."
            )
            layout = QVBoxLayout(self)
            self._checks: dict[str, QCheckBox] = {}
            self._keys: dict[str, QLineEdit] = {}
            defaults = _default_feeds_enabled()
            for feed, enabled in defaults.items():
                row = QHBoxLayout()
                cb = QCheckBox(feed.title())
                cb.setChecked(enabled)
                row.addWidget(cb)
                key_input = QLineEdit()
                key_input.setPlaceholderText(
                    f"{feed} API key (optional)"
                )
                row.addWidget(key_input)
                layout.addLayout(row)
                self._checks[feed] = cb
                self._keys[feed] = key_input

        def get_feeds(self) -> dict[str, bool]:
            """Return feed-enabled map."""
            return {
                k: cb.isChecked()
                for k, cb in self._checks.items()
            }

        def get_api_keys(self) -> dict[str, str]:
            """Return API key map."""
            return {
                k: le.text()
                for k, le in self._keys.items()
            }

    class TuningPage(QWizardPage):
        """Page 4: Detection sensitivity slider."""

        _LABELS = ["low", "medium", "high"]

        def __init__(
            self, parent: QWizard | None = None,
        ) -> None:
            super().__init__(parent)
            self.setTitle("Detection Tuning")
            self.setSubTitle(
                "Set the anomaly detection sensitivity."
            )
            layout = QVBoxLayout(self)

            self._label = QLabel("Sensitivity: medium")
            layout.addWidget(self._label)

            self._slider = QSlider()
            self._slider.setOrientation(Qt.Horizontal)
            self._slider.setMinimum(0)
            self._slider.setMaximum(2)
            self._slider.setValue(1)  # medium
            self._slider.setTickInterval(1)
            self._slider.valueChanged.connect(
                self._on_slider_changed,
            )
            layout.addWidget(self._slider)

        @Slot(int)
        def _on_slider_changed(self, value: int) -> None:
            label = self._LABELS[value]
            self._label.setText(f"Sensitivity: {label}")

        def get_sensitivity(self) -> str:
            """Return the selected sensitivity label."""
            return self._LABELS[self._slider.value()]

    class SysmonPage(QWizardPage):
        """Page 5: Sysmon status check + install button."""

        def __init__(
            self, parent: QWizard | None = None,
        ) -> None:
            super().__init__(parent)
            self.setTitle("Sysmon")
            self.setSubTitle(
                "Check Sysmon status and optionally install."
            )
            layout = QVBoxLayout(self)
            self._status_label = QLabel("Checking Sysmon...")
            layout.addWidget(self._status_label)

            self._install_btn = QPushButton("Install Sysmon")
            self._install_btn.clicked.connect(
                self._on_install,
            )
            layout.addWidget(self._install_btn)

            self._installed = False
            self._worker: _SysmonInstallWorker | None = None

        def initializePage(self) -> None:  # noqa: N802
            """Refresh Sysmon status when page is shown."""
            try:
                from aegis.core.sysmon_manager import (
                    SysmonManager,
                )

                mgr = SysmonManager()
                if mgr.is_installed():
                    ver = mgr.get_version() or "unknown"
                    self._status_label.setText(
                        f"Sysmon installed (v{ver})"
                    )
                    self._install_btn.setEnabled(False)
                    self._installed = True
                else:
                    self._status_label.setText(
                        "Sysmon is not installed."
                    )
            except Exception as exc:
                self._status_label.setText(
                    f"Could not check Sysmon: {exc}"
                )

        @Slot()
        def _on_install(self) -> None:
            self._install_btn.setEnabled(False)
            self._status_label.setText("Installing Sysmon...")
            self._worker = _SysmonInstallWorker()
            self._worker.finished.connect(
                self._on_install_done,
            )
            self._worker.start()

        @Slot(bool)
        def _on_install_done(self, ok: bool) -> None:
            if ok:
                self._status_label.setText(
                    "Sysmon installed successfully."
                )
                self._installed = True
            else:
                self._status_label.setText(
                    "Sysmon installation failed."
                )
                self._install_btn.setEnabled(True)

        def get_install_sysmon(self) -> bool:
            """Return whether Sysmon was installed."""
            return self._installed

    class BaselinePage(QWizardPage):
        """Page 6: Baseline scan with progress bar."""

        def __init__(
            self, parent: QWizard | None = None,
        ) -> None:
            super().__init__(parent)
            self.setTitle("Baseline Scan")
            self.setSubTitle(
                "Scan your system to establish a baseline."
            )
            layout = QVBoxLayout(self)

            self._progress = QProgressBar()
            self._progress.setRange(0, 0)  # indeterminate
            self._progress.setVisible(False)
            layout.addWidget(self._progress)

            self._scan_btn = QPushButton("Start Scan")
            self._scan_btn.clicked.connect(self._on_scan)
            layout.addWidget(self._scan_btn)

            self._results = QTextEdit()
            self._results.setReadOnly(True)
            layout.addWidget(self._results)

            self._snapshot = None
            self._worker: _BaselineScanWorker | None = None

        @Slot()
        def _on_scan(self) -> None:
            self._scan_btn.setEnabled(False)
            self._progress.setVisible(True)
            self._results.clear()
            self._worker = _BaselineScanWorker()
            self._worker.progress.connect(
                self._on_progress,
            )
            self._worker.finished.connect(
                self._on_scan_done,
            )
            self._worker.start()

        @Slot(str)
        def _on_progress(self, msg: str) -> None:
            self._results.append(msg)

        @Slot(object)
        def _on_scan_done(self, snapshot: object) -> None:
            self._progress.setVisible(False)
            self._snapshot = snapshot
            if snapshot is not None:
                self._results.append(
                    f"Processes: {len(snapshot.processes)}"
                )
                self._results.append(
                    f"Connections: "
                    f"{len(snapshot.connections)}"
                )
                self._results.append(
                    f"Services: {len(snapshot.services)}"
                )
            self._scan_btn.setEnabled(True)
            self._scan_btn.setText("Rescan")

    class ExclusionsPage(QWizardPage):
        """Page 7: Exclusion list widgets."""

        def __init__(
            self, parent: QWizard | None = None,
        ) -> None:
            super().__init__(parent)
            self.setTitle("Exclusions")
            self.setSubTitle(
                "Add processes, directories, or IPs to "
                "exclude from monitoring."
            )
            layout = QVBoxLayout(self)

            self._proc_list = self._make_list_section(
                layout, "Excluded Processes",
            )
            self._dir_list = self._make_list_section(
                layout, "Excluded Directories",
            )
            self._ip_list = self._make_list_section(
                layout, "Excluded IPs",
            )

        def _make_list_section(
            self,
            parent_layout: QVBoxLayout,
            title: str,
        ) -> QListWidget:
            """Create a labelled list widget with add/remove."""
            parent_layout.addWidget(QLabel(f"<b>{title}</b>"))
            lw = QListWidget()
            parent_layout.addWidget(lw)

            row = QHBoxLayout()
            entry = QLineEdit()
            entry.setPlaceholderText(f"Add {title.lower()}...")
            add_btn = QPushButton("Add")
            remove_btn = QPushButton("Remove")

            add_btn.clicked.connect(
                lambda: self._add_item(entry, lw),
            )
            remove_btn.clicked.connect(
                lambda: self._remove_item(lw),
            )

            row.addWidget(entry)
            row.addWidget(add_btn)
            row.addWidget(remove_btn)
            parent_layout.addLayout(row)
            return lw

        @staticmethod
        def _add_item(
            entry: QLineEdit, lw: QListWidget,
        ) -> None:
            text = entry.text().strip()
            if text:
                lw.addItem(text)
                entry.clear()

        @staticmethod
        def _remove_item(lw: QListWidget) -> None:
            for item in lw.selectedItems():
                lw.takeItem(lw.row(item))

        def _items(self, lw: QListWidget) -> list[str]:
            return [
                lw.item(i).text() for i in range(lw.count())
            ]

        def get_excluded_processes(self) -> list[str]:
            """Return excluded process names."""
            return self._items(self._proc_list)

        def get_excluded_dirs(self) -> list[str]:
            """Return excluded directories."""
            return self._items(self._dir_list)

        def get_excluded_ips(self) -> list[str]:
            """Return excluded IPs."""
            return self._items(self._ip_list)

    class SummaryPage(QWizardPage):
        """Page 8: Read-only summary of all wizard choices."""

        def __init__(
            self, parent: QWizard | None = None,
        ) -> None:
            super().__init__(parent)
            self.setTitle("Summary")
            self.setSubTitle(
                "Review your configuration before applying."
            )
            layout = QVBoxLayout(self)
            self._text = QTextEdit()
            self._text.setReadOnly(True)
            layout.addWidget(self._text)

        def set_summary(self, text: str) -> None:
            """Replace the summary display text."""
            self._text.setPlainText(text)

    # -------------------------------------------------------------- #
    # Main wizard
    # -------------------------------------------------------------- #

    class FirstRunWizard(QWizard):
        """Eight-page first-run configuration wizard.

        Collects user choices into a :class:`WizardConfig` and
        calls :func:`apply_wizard_config` when the user clicks
        *Finish*.
        """

        def __init__(
            self,
            config: AegisConfig,
            parent: object | None = None,
        ) -> None:
            super().__init__(parent)
            self.setWindowTitle("Aegis First-Run Wizard")
            self._config = config

            # Create pages
            self._welcome = WelcomePage(self)
            self._sensors = SensorPage(self)
            self._threat_intel = ThreatIntelPage(self)
            self._tuning = TuningPage(self)
            self._sysmon = SysmonPage(self)
            self._baseline = BaselinePage(self)
            self._exclusions = ExclusionsPage(self)
            self._summary = SummaryPage(self)

            self.addPage(self._welcome)
            self.addPage(self._sensors)
            self.addPage(self._threat_intel)
            self.addPage(self._tuning)
            self.addPage(self._sysmon)
            self.addPage(self._baseline)
            self.addPage(self._exclusions)
            self.addPage(self._summary)

            self.currentIdChanged.connect(
                self._on_page_changed,
            )

        @Slot(int)
        def _on_page_changed(self, page_id: int) -> None:
            """Update summary when the user reaches it."""
            page = self.page(page_id)
            if isinstance(page, SummaryPage):
                wc = self._collect_config()
                page.set_summary(self._format_summary(wc))

        def _collect_config(self) -> WizardConfig:
            """Build a WizardConfig from current page state."""
            return WizardConfig(
                sensors_enabled=(
                    self._sensors.get_sensors()
                ),
                sensitivity=(
                    self._tuning.get_sensitivity()
                ),
                feeds_enabled=(
                    self._threat_intel.get_feeds()
                ),
                api_keys=(
                    self._threat_intel.get_api_keys()
                ),
                excluded_processes=(
                    self._exclusions.get_excluded_processes()
                ),
                excluded_dirs=(
                    self._exclusions.get_excluded_dirs()
                ),
                excluded_ips=(
                    self._exclusions.get_excluded_ips()
                ),
                install_sysmon=(
                    self._sysmon.get_install_sysmon()
                ),
            )

        @staticmethod
        def _format_summary(wc: WizardConfig) -> str:
            """Render a WizardConfig as readable text."""
            lines: list[str] = []
            lines.append("=== Sensors ===")
            for name, on in wc.sensors_enabled.items():
                tag = "ON" if on else "OFF"
                lines.append(f"  {name}: {tag}")

            lines.append(
                f"\n=== Sensitivity: {wc.sensitivity} ==="
            )
            lines.append(
                f"  Anomaly threshold: "
                f"{wc.anomaly_threshold}"
            )

            lines.append("\n=== Threat Intel Feeds ===")
            for feed, on in wc.feeds_enabled.items():
                tag = "ON" if on else "OFF"
                key = wc.api_keys.get(feed, "")
                masked = "***" if key else "(none)"
                lines.append(
                    f"  {feed}: {tag}  key={masked}"
                )

            lines.append("\n=== Exclusions ===")
            lines.append(
                f"  Processes: {wc.excluded_processes}"
            )
            lines.append(
                f"  Directories: {wc.excluded_dirs}"
            )
            lines.append(f"  IPs: {wc.excluded_ips}")

            sysmon = "Yes" if wc.install_sysmon else "No"
            lines.append(f"\n=== Sysmon: {sysmon} ===")
            return "\n".join(lines)

        def accept(self) -> None:
            """Collect config from pages and apply."""
            wc = self._collect_config()
            apply_wizard_config(self._config, wc)
            _qt_logger.info(
                "First-run wizard config applied "
                "(sensitivity=%s)",
                wc.sensitivity,
            )
            super().accept()
