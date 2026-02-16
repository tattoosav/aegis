"""Tests for Aegis configuration manager."""

import yaml

from aegis.core.config import AegisConfig


class TestAegisConfig:
    def test_default_config_has_all_sections(self):
        config = AegisConfig()
        assert "sensors" in config
        assert "detection" in config
        assert "alerting" in config
        assert "database" in config
        assert "performance" in config

    def test_default_sensors_enabled(self):
        config = AegisConfig()
        assert config["sensors"]["network"]["enabled"] is True
        assert config["sensors"]["process"]["enabled"] is True
        assert config["sensors"]["fim"]["enabled"] is True
        assert config["sensors"]["eventlog"]["enabled"] is True
        assert config["sensors"]["threat_intel"]["enabled"] is True
        assert config["sensors"]["hardware"]["enabled"] is False
        assert config["sensors"]["clipboard"]["enabled"] is False

    def test_get_nested_value(self):
        config = AegisConfig()
        assert config.get("sensors.network.enabled") is True
        assert config.get("performance.cpu_limit_percent") == 15

    def test_get_missing_key_returns_default(self):
        config = AegisConfig()
        assert config.get("nonexistent.key", "fallback") == "fallback"

    def test_set_nested_value(self):
        config = AegisConfig()
        config.set("sensors.network.enabled", False)
        assert config.get("sensors.network.enabled") is False

    def test_save_and_load(self, tmp_data_dir):
        config = AegisConfig()
        config.set("sensors.hardware.enabled", True)
        config_path = tmp_data_dir / "config.yaml"
        config.save(config_path)

        loaded = AegisConfig.load(config_path)
        assert loaded.get("sensors.hardware.enabled") is True

    def test_load_nonexistent_returns_defaults(self, tmp_data_dir):
        config = AegisConfig.load(tmp_data_dir / "nonexistent.yaml")
        assert config.get("sensors.network.enabled") is True

    def test_load_merges_with_defaults(self, tmp_data_dir):
        config_path = tmp_data_dir / "partial.yaml"
        config_path.write_text(yaml.dump({"sensors": {"network": {"enabled": False}}}))
        config = AegisConfig.load(config_path)
        assert config.get("sensors.network.enabled") is False
        assert config.get("sensors.process.enabled") is True
        assert config.get("performance.cpu_limit_percent") == 15
