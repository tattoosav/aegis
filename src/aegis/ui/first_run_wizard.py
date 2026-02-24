"""First-run wizard configuration logic (no Qt dependency).

Provides a pure-data WizardConfig dataclass that captures user choices
during the first-run wizard, and an apply_wizard_config function that
translates those choices into AegisConfig writes.
"""

from __future__ import annotations

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
