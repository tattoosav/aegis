"""Tests for first-run wizard logic (no Qt required)."""
from __future__ import annotations

from aegis.core.config import AegisConfig
from aegis.ui.first_run_wizard import (
    WizardConfig,
    apply_wizard_config,
)


class TestWizardConfig:
    def test_default_sensors_all_enabled(self):
        wc = WizardConfig()
        assert wc.sensors_enabled["network"] is True
        assert wc.sensors_enabled["process"] is True

    def test_default_sensors_include_all_sensor_types(self):
        wc = WizardConfig()
        expected = {
            "network", "process", "fim", "eventlog",
            "threat_intel", "hardware", "clipboard",
        }
        assert set(wc.sensors_enabled.keys()) == expected

    def test_sensitivity_defaults_to_medium(self):
        wc = WizardConfig()
        assert wc.sensitivity == "medium"
        assert wc.anomaly_threshold == 0.6

    def test_sensitivity_maps_to_threshold_low(self):
        wc = WizardConfig(sensitivity="low")
        assert wc.anomaly_threshold == 0.8

    def test_sensitivity_maps_to_threshold_medium(self):
        wc = WizardConfig(sensitivity="medium")
        assert wc.anomaly_threshold == 0.6

    def test_sensitivity_maps_to_threshold_high(self):
        wc = WizardConfig(sensitivity="high")
        assert wc.anomaly_threshold == 0.4

    def test_default_feeds_disabled(self):
        wc = WizardConfig()
        assert wc.feeds_enabled["virustotal"] is False
        assert wc.feeds_enabled["abuseipdb"] is False

    def test_default_api_keys_empty(self):
        wc = WizardConfig()
        assert wc.api_keys["virustotal"] == ""
        assert wc.api_keys["abuseipdb"] == ""

    def test_default_exclusions_empty(self):
        wc = WizardConfig()
        assert wc.excluded_processes == []
        assert wc.excluded_dirs == []
        assert wc.excluded_ips == []

    def test_default_install_sysmon_false(self):
        wc = WizardConfig()
        assert wc.install_sysmon is False


class TestApplyWizardConfig:
    def test_applies_sensor_settings(self):
        config = AegisConfig()
        wc = WizardConfig()
        wc.sensors_enabled["network"] = False
        apply_wizard_config(config, wc)
        assert config.get("sensors.network.enabled") is False

    def test_applies_all_sensor_settings(self):
        config = AegisConfig()
        wc = WizardConfig()
        wc.sensors_enabled["process"] = False
        wc.sensors_enabled["fim"] = False
        apply_wizard_config(config, wc)
        assert config.get("sensors.process.enabled") is False
        assert config.get("sensors.fim.enabled") is False
        assert config.get("sensors.network.enabled") is True

    def test_applies_sensitivity(self):
        config = AegisConfig()
        wc = WizardConfig(sensitivity="high")
        apply_wizard_config(config, wc)
        assert config.get("detection.sensitivity") == "high"
        assert config.get("detection.isolation_forest.anomaly_threshold") == 0.4

    def test_applies_exclusions(self):
        config = AegisConfig()
        wc = WizardConfig()
        wc.excluded_processes = ["steam.exe"]
        apply_wizard_config(config, wc)
        assert "steam.exe" in config.get("exclusions.processes")

    def test_applies_directory_exclusions(self):
        config = AegisConfig()
        wc = WizardConfig()
        wc.excluded_dirs = ["C:\\Games"]
        apply_wizard_config(config, wc)
        assert "C:\\Games" in config.get("exclusions.directories")

    def test_applies_ip_exclusions(self):
        config = AegisConfig()
        wc = WizardConfig()
        wc.excluded_ips = ["192.168.1.100"]
        apply_wizard_config(config, wc)
        assert "192.168.1.100" in config.get("exclusions.ips")

    def test_applies_feed_settings(self):
        config = AegisConfig()
        wc = WizardConfig()
        wc.feeds_enabled["virustotal"] = True
        wc.api_keys["virustotal"] = "abc123"
        apply_wizard_config(config, wc)
        assert config.get("sensors.threat_intel.feeds.virustotal.enabled") is True
        assert config.get("sensors.threat_intel.feeds.virustotal.api_key") == "abc123"

    def test_applies_sysmon_setting(self):
        config = AegisConfig()
        wc = WizardConfig()
        wc.install_sysmon = True
        apply_wizard_config(config, wc)
        assert config.get("sysmon.installed") is True

    def test_marks_first_run_complete(self):
        config = AegisConfig()
        wc = WizardConfig()
        apply_wizard_config(config, wc)
        assert config.get("first_run_complete") is True
