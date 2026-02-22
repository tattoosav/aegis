"""Configuration manager for Aegis.

Loads config from YAML, merges with defaults, provides dot-notation access.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "sensors": {
        "network": {
            "enabled": True,
            "capture_interface": "auto",
            "flow_window_seconds": 30,
        },
        "process": {
            "enabled": True,
            "scan_interval_seconds": 5,
        },
        "fim": {
            "enabled": True,
            "monitored_dirs": [
                "C:\\Windows\\System32",
                "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            ],
            "deploy_canaries": True,
        },
        "eventlog": {
            "enabled": True,
            "sources": ["Security", "System", "Microsoft-Windows-PowerShell/Operational"],
        },
        "threat_intel": {
            "enabled": True,
            "update_interval_minutes": 30,
            "feeds": {
                "virustotal": {"enabled": False, "api_key": ""},
                "abuseipdb": {"enabled": False, "api_key": ""},
                "phishtank": {"enabled": True, "api_key": ""},
            },
            "stix_taxii": {
                "enabled": False,
                "stix_bundles": [],
                "taxii_server_url": "",
                "taxii_collection_id": "",
                "taxii_username": "",
                "taxii_password": "",
            },
        },
        "hardware": {
            "enabled": False,
        },
        "clipboard": {
            "enabled": False,
        },
        "registry": {
            "enabled": True,
            "scan_interval_seconds": 10,
        },
    },
    "detection": {
        "rule_engine": {"enabled": True},
        "yara_scanner": {
            "enabled": True,
            "rules_dir": "rules/yara",
            "scan_timeout_seconds": 30,
            "max_file_size_mb": 50,
        },
        "sigma_rules": {
            "enabled": True,
            "rules_dirs": ["rules/sigma"],
        },
        "dns_analyzer": {
            "enabled": True,
            "tunneling_entropy_threshold": 3.5,
            "dga_entropy_threshold": 3.8,
            "doh_detection": True,
        },
        "isolation_forest": {
            "enabled": True,
            "anomaly_threshold": 0.6,
            "n_estimators": 100,
        },
        "autoencoder": {"enabled": True},
        "lstm": {"enabled": True},
        "url_classifier": {"enabled": True},
        "graph_analyzer": {
            "enabled": True,
            "scan_interval_seconds": 5,
        },
    },
    "alerting": {
        "notification_sound": True,
        "critical_fullscreen": True,
        "daily_digest": True,
        "auto_suppress_after_dismissals": 3,
    },
    "response": {
        "playbooks": {
            "enabled": True,
            "playbooks_dir": "rules/playbooks",
        },
        "reports": {
            "enabled": True,
            "output_dir": "%APPDATA%/Aegis/reports",
        },
    },
    "database": {
        "path": "%APPDATA%/Aegis/aegis.db",
        "event_retention_days": 30,
        "alert_retention_days": 365,
    },
    "performance": {
        "cpu_limit_percent": 15,
        "max_ram_mb": 400,
        "throttle_enabled": True,
    },
    "cloud": {
        "claude_api": {"enabled": False, "api_key": ""},
    },
    "baseline": {
        "learning_period_days": 7,
        "status": "not_started",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Override values win."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


class AegisConfig:
    """Configuration manager with dot-notation access and YAML persistence."""

    def __init__(self, data: dict[str, Any] | None = None):
        self._data = copy.deepcopy(data or DEFAULT_CONFIG)

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Get a value using dot-notation (e.g., 'sensors.network.enabled')."""
        keys = dotted_key.split(".")
        current = self._data
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        return current

    def set(self, dotted_key: str, value: Any) -> None:
        """Set a value using dot-notation."""
        keys = dotted_key.split(".")
        current = self._data
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value

    def save(self, path: Path) -> None:
        """Save configuration to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(self._data, f, default_flow_style=False, sort_keys=False)

    @classmethod
    def load(cls, path: Path) -> AegisConfig:
        """Load config from YAML, merging with defaults for missing keys."""
        path = Path(path)
        if not path.exists():
            return cls()
        with open(path) as f:
            user_data = yaml.safe_load(f) or {}
        merged = _deep_merge(DEFAULT_CONFIG, user_data)
        return cls(data=merged)
