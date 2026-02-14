# Aegis Phase 1: Foundation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the core infrastructure that all sensors, detection engines, and UI components depend on — project scaffolding, event bus, database, config, and a working system tray app.

**Architecture:** Microservice architecture with ZeroMQ PUB/SUB message bus connecting independent sensor processes to a central Event Engine. SQLite (WAL mode) for persistence. PySide6 desktop app with system tray icon as the user-facing surface.

**Tech Stack:** Python 3.11+, PySide6, pyzmq, SQLite3, pyyaml, pytest

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `CLAUDE.md`
- Create: `src/aegis/__init__.py`
- Create: `src/aegis/__main__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

**Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "aegis"
version = "0.1.0"
description = "Autonomous AI Security Defense System for Windows"
readme = "README.md"
license = "MIT"
requires-python = ">=3.11"
authors = [
    { name = "Aegis Contributors" },
]

dependencies = [
    "pyzmq>=25.0",
    "PySide6>=6.6",
    "psutil>=5.9",
    "pyyaml>=6.0",
    "win10toast-reborn>=1.0; sys_platform == 'win32'",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
    "pytest-asyncio>=0.21",
    "ruff>=0.1",
]
ml = [
    "scikit-learn>=1.3",
    "torch>=2.0",
    "onnxruntime>=1.16",
]
network = [
    "scapy>=2.5",
]
windows = [
    "pywin32>=306; sys_platform == 'win32'",
    "WMI>=1.5; sys_platform == 'win32'",
    "yara-python>=4.3",
]

[project.scripts]
aegis = "aegis.__main__:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
addopts = "-v --tb=short"

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "N", "UP"]
```

**Step 2: Create CLAUDE.md**

```markdown
# Aegis — AI Security Defense System

## Project Overview
Aegis is an autonomous AI security defense system for Windows PCs.
See `docs/plans/2026-02-14-aegis-design.md` for full design.

## Commands
- `pytest` — run all tests
- `pytest tests/test_core/` — run core tests only
- `python -m aegis` — launch Aegis
- `ruff check src/` — lint

## Architecture
- Microservice: independent sensor processes communicate via ZeroMQ PUB/SUB
- Central Event Engine coordinates all data flow
- SQLite (WAL mode) for persistence
- PySide6 desktop app with system tray

## Code Conventions
- Python 3.11+, type hints on all public functions
- All modules have docstrings
- Tests use pytest, follow TDD (test first)
- Imports: stdlib → third-party → local (enforced by ruff isort)
- Max line length: 100 chars
```

**Step 3: Create src/aegis/__init__.py**

```python
"""Aegis — Autonomous AI Security Defense System."""

__version__ = "0.1.0"
```

**Step 4: Create src/aegis/__main__.py**

```python
"""Entry point for Aegis."""

import sys


def main() -> int:
    """Launch Aegis."""
    print(f"Aegis v0.1.0 — starting...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

**Step 5: Create tests/__init__.py and tests/conftest.py**

`tests/__init__.py`: empty file

```python
# tests/conftest.py
"""Shared test fixtures for Aegis."""

import pytest
import tempfile
import os


@pytest.fixture
def tmp_data_dir(tmp_path):
    """Provide a temporary directory for test data (database, configs, etc.)."""
    data_dir = tmp_path / "aegis_data"
    data_dir.mkdir()
    return data_dir


@pytest.fixture
def sample_event():
    """Provide a sample event dict matching the Aegis event schema."""
    return {
        "timestamp": 1707900000.0,
        "sensor": "process",
        "event_type": "process_created",
        "severity": "info",
        "data": {
            "pid": 1234,
            "name": "notepad.exe",
            "path": "C:\\Windows\\System32\\notepad.exe",
            "cmdline": "notepad.exe test.txt",
            "parent_pid": 5678,
            "parent_name": "explorer.exe",
        },
    }
```

**Step 6: Install in dev mode and verify**

Run: `pip install -e ".[dev]" && python -m aegis`
Expected: prints "Aegis v0.1.0 — starting..."

**Step 7: Run tests (empty but verifies setup)**

Run: `pytest`
Expected: "no tests ran" or "0 passed" — no errors

**Step 8: Commit**

```bash
git add pyproject.toml CLAUDE.md src/ tests/
git commit -m "feat: project scaffolding with pyproject.toml, entry point, and test setup"
```

---

### Task 2: Event Schema and Data Models

**Files:**
- Create: `src/aegis/core/__init__.py`
- Create: `src/aegis/core/models.py`
- Create: `tests/test_core/__init__.py`
- Create: `tests/test_core/test_models.py`

**Step 1: Write the failing tests**

```python
# tests/test_core/test_models.py
"""Tests for Aegis event data models."""

import time
import pytest
from aegis.core.models import (
    AegisEvent,
    Alert,
    SensorType,
    Severity,
    AlertStatus,
)


class TestAegisEvent:
    def test_create_event_with_required_fields(self):
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_created",
            data={"pid": 1234, "name": "notepad.exe"},
        )
        assert event.sensor == SensorType.PROCESS
        assert event.event_type == "process_created"
        assert event.data["pid"] == 1234
        assert event.severity == Severity.INFO  # default
        assert event.timestamp > 0

    def test_event_generates_unique_id(self):
        e1 = AegisEvent(sensor=SensorType.NETWORK, event_type="connection", data={})
        e2 = AegisEvent(sensor=SensorType.NETWORK, event_type="connection", data={})
        assert e1.event_id != e2.event_id

    def test_event_to_dict_roundtrip(self):
        event = AegisEvent(
            sensor=SensorType.FILE,
            event_type="file_modified",
            severity=Severity.HIGH,
            data={"path": "C:\\test.txt", "hash": "abc123"},
        )
        d = event.to_dict()
        assert d["sensor"] == "file"
        assert d["severity"] == "high"
        assert d["data"]["path"] == "C:\\test.txt"

        restored = AegisEvent.from_dict(d)
        assert restored.sensor == SensorType.FILE
        assert restored.severity == Severity.HIGH
        assert restored.event_id == event.event_id

    def test_event_to_json_bytes(self):
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="test",
            data={"key": "value"},
        )
        raw = event.to_bytes()
        assert isinstance(raw, bytes)
        restored = AegisEvent.from_bytes(raw)
        assert restored.event_id == event.event_id
        assert restored.data == event.data


class TestAlert:
    def test_create_alert(self):
        alert = Alert(
            event_id="evt-123",
            sensor=SensorType.NETWORK,
            alert_type="port_scan",
            severity=Severity.HIGH,
            title="Port scan detected",
            description="Host 192.168.1.100 scanned 500 ports in 10 seconds.",
            confidence=0.85,
            data={"source_ip": "192.168.1.100", "ports_scanned": 500},
        )
        assert alert.severity == Severity.HIGH
        assert alert.confidence == 0.85
        assert alert.status == AlertStatus.NEW
        assert alert.priority_score > 0

    def test_alert_priority_scoring(self):
        critical = Alert(
            event_id="e1",
            sensor=SensorType.FILE,
            alert_type="ransomware",
            severity=Severity.CRITICAL,
            title="Ransomware",
            description="test",
            confidence=0.95,
            data={},
        )
        low = Alert(
            event_id="e2",
            sensor=SensorType.PROCESS,
            alert_type="anomaly",
            severity=Severity.LOW,
            title="Anomaly",
            description="test",
            confidence=0.4,
            data={},
        )
        assert critical.priority_score > low.priority_score

    def test_alert_to_dict_roundtrip(self):
        alert = Alert(
            event_id="evt-456",
            sensor=SensorType.EVENTLOG,
            alert_type="brute_force",
            severity=Severity.MEDIUM,
            title="Brute force attempt",
            description="50 failed logins.",
            confidence=0.7,
            data={"failed_count": 50},
        )
        d = alert.to_dict()
        restored = Alert.from_dict(d)
        assert restored.alert_id == alert.alert_id
        assert restored.confidence == 0.7
        assert restored.status == AlertStatus.NEW


class TestSeverity:
    def test_severity_ordering(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFO.weight

    def test_severity_from_string(self):
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("info") == Severity.INFO
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_core/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'aegis.core.models'`

**Step 3: Write minimal implementation**

```python
# src/aegis/core/__init__.py
"""Aegis core infrastructure."""
```

```python
# src/aegis/core/models.py
"""Data models for Aegis events and alerts."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SensorType(Enum):
    """Sensor module identifiers."""

    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    EVENTLOG = "eventlog"
    THREAT_INTEL = "threat_intel"
    HARDWARE = "hardware"
    CLIPBOARD = "clipboard"

    @classmethod
    def from_string(cls, value: str) -> "SensorType":
        return cls(value.lower())


class Severity(Enum):
    """Alert severity levels with numeric weights for scoring."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        weights = {
            "info": 0.1,
            "low": 0.2,
            "medium": 0.5,
            "high": 0.8,
            "critical": 1.0,
        }
        return weights[self.value]

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        return cls(value.lower())


class AlertStatus(Enum):
    """Alert lifecycle states."""

    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    AUTO_SUPPRESSED = "auto_suppressed"


@dataclass
class AegisEvent:
    """A single event emitted by a sensor module.

    Events are the atomic unit of data in Aegis. Every sensor produces
    events that flow through the Event Engine to detection engines.
    """

    sensor: SensorType
    event_type: str
    data: dict[str, Any]
    severity: Severity = Severity.INFO
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "sensor": self.sensor.value,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AegisEvent":
        """Deserialize from dictionary."""
        return cls(
            event_id=d["event_id"],
            timestamp=d["timestamp"],
            sensor=SensorType.from_string(d["sensor"]),
            event_type=d["event_type"],
            severity=Severity.from_string(d["severity"]),
            data=d["data"],
        )

    def to_bytes(self) -> bytes:
        """Serialize to bytes for ZeroMQ transport."""
        return json.dumps(self.to_dict()).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "AegisEvent":
        """Deserialize from bytes."""
        return cls.from_dict(json.loads(raw.decode("utf-8")))


@dataclass
class Alert:
    """A security alert generated by a detection engine.

    Alerts represent potential threats that need user attention.
    They include severity, confidence, explanation, and recommended actions.
    """

    event_id: str
    sensor: SensorType
    alert_type: str
    severity: Severity
    title: str
    description: str
    confidence: float
    data: dict[str, Any]
    status: AlertStatus = AlertStatus.NEW
    timestamp: float = field(default_factory=time.time)
    alert_id: str = field(default_factory=lambda: f"alt-{uuid.uuid4().hex[:12]}")
    mitre_ids: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    dismiss_count: int = 0

    @property
    def priority_score(self) -> float:
        """Calculate alert priority score (0-100).

        Formula: base_severity * confidence * 100
        Context and threat intel multipliers are applied by the alert manager.
        """
        base = self.severity.weight * self.confidence * 100
        return min(100.0, max(0.0, base))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "alert_id": self.alert_id,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "sensor": self.sensor.value,
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "confidence": self.confidence,
            "status": self.status.value,
            "data": self.data,
            "mitre_ids": self.mitre_ids,
            "recommended_actions": self.recommended_actions,
            "priority_score": self.priority_score,
            "dismiss_count": self.dismiss_count,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Alert":
        """Deserialize from dictionary."""
        return cls(
            alert_id=d["alert_id"],
            event_id=d["event_id"],
            timestamp=d["timestamp"],
            sensor=SensorType.from_string(d["sensor"]),
            alert_type=d["alert_type"],
            severity=Severity.from_string(d["severity"]),
            title=d["title"],
            description=d["description"],
            confidence=d["confidence"],
            status=AlertStatus(d["status"]),
            data=d["data"],
            mitre_ids=d.get("mitre_ids", []),
            recommended_actions=d.get("recommended_actions", []),
            dismiss_count=d.get("dismiss_count", 0),
        )
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_core/test_models.py -v`
Expected: All 8 tests PASS

**Step 5: Commit**

```bash
git add src/aegis/core/ tests/test_core/
git commit -m "feat: add event and alert data models with serialization"
```

---

### Task 3: Configuration Manager

**Files:**
- Create: `src/aegis/core/config.py`
- Create: `tests/test_core/test_config.py`

**Step 1: Write the failing tests**

```python
# tests/test_core/test_config.py
"""Tests for Aegis configuration manager."""

import pytest
import yaml
from pathlib import Path
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
        # These default to off
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
        """Partial config file should be merged with defaults."""
        config_path = tmp_data_dir / "partial.yaml"
        config_path.write_text(yaml.dump({"sensors": {"network": {"enabled": False}}}))
        config = AegisConfig.load(config_path)
        # Overridden value
        assert config.get("sensors.network.enabled") is False
        # Default value still present
        assert config.get("sensors.process.enabled") is True
        assert config.get("performance.cpu_limit_percent") == 15
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_core/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'aegis.core.config'`

**Step 3: Write minimal implementation**

```python
# src/aegis/core/config.py
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
        },
        "hardware": {
            "enabled": False,
        },
        "clipboard": {
            "enabled": False,
        },
    },
    "detection": {
        "rule_engine": {"enabled": True},
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
    def load(cls, path: Path) -> "AegisConfig":
        """Load config from YAML, merging with defaults for missing keys."""
        path = Path(path)
        if not path.exists():
            return cls()
        with open(path) as f:
            user_data = yaml.safe_load(f) or {}
        merged = _deep_merge(DEFAULT_CONFIG, user_data)
        return cls(data=merged)
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_core/test_config.py -v`
Expected: All 8 tests PASS

**Step 5: Commit**

```bash
git add src/aegis/core/config.py tests/test_core/test_config.py
git commit -m "feat: add configuration manager with YAML persistence and dot-notation access"
```

---

### Task 4: SQLite Database Layer

**Files:**
- Create: `src/aegis/core/database.py`
- Create: `tests/test_core/test_database.py`

**Step 1: Write the failing tests**

```python
# tests/test_core/test_database.py
"""Tests for Aegis SQLite database layer."""

import pytest
import time
from aegis.core.database import AegisDatabase
from aegis.core.models import AegisEvent, Alert, SensorType, Severity, AlertStatus


class TestDatabaseInit:
    def test_creates_database_file(self, tmp_data_dir):
        db_path = tmp_data_dir / "test.db"
        db = AegisDatabase(db_path)
        assert db_path.exists()
        db.close()

    def test_creates_all_tables(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        tables = db.list_tables()
        assert "events" in tables
        assert "alerts" in tables
        assert "connection_reputation" in tables
        assert "device_whitelist" in tables
        assert "process_whitelist" in tables
        assert "user_feedback" in tables
        assert "audit_log" in tables
        db.close()

    def test_uses_wal_mode(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        assert db.journal_mode == "wal"
        db.close()


class TestEventStorage:
    def test_insert_and_retrieve_event(self, tmp_data_dir, sample_event):
        db = AegisDatabase(tmp_data_dir / "test.db")
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_created",
            data=sample_event["data"],
        )
        db.insert_event(event)
        retrieved = db.get_event(event.event_id)
        assert retrieved is not None
        assert retrieved.event_id == event.event_id
        assert retrieved.sensor == SensorType.PROCESS
        assert retrieved.data["pid"] == 1234
        db.close()

    def test_query_events_by_sensor(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        for i in range(5):
            db.insert_event(AegisEvent(
                sensor=SensorType.NETWORK, event_type="connection", data={"i": i}
            ))
        for i in range(3):
            db.insert_event(AegisEvent(
                sensor=SensorType.PROCESS, event_type="process_created", data={"i": i}
            ))
        net_events = db.query_events(sensor=SensorType.NETWORK)
        assert len(net_events) == 5
        proc_events = db.query_events(sensor=SensorType.PROCESS)
        assert len(proc_events) == 3
        db.close()

    def test_query_events_by_time_range(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        now = time.time()
        db.insert_event(AegisEvent(
            sensor=SensorType.NETWORK, event_type="old", data={},
            timestamp=now - 3600,
        ))
        db.insert_event(AegisEvent(
            sensor=SensorType.NETWORK, event_type="recent", data={},
            timestamp=now - 60,
        ))
        recent = db.query_events(since=now - 300)
        assert len(recent) == 1
        assert recent[0].event_type == "recent"
        db.close()

    def test_event_count(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        for i in range(10):
            db.insert_event(AegisEvent(
                sensor=SensorType.FILE, event_type="changed", data={"i": i}
            ))
        assert db.event_count() == 10
        assert db.event_count(sensor=SensorType.FILE) == 10
        assert db.event_count(sensor=SensorType.NETWORK) == 0
        db.close()


class TestAlertStorage:
    def _make_alert(self, **kwargs):
        defaults = {
            "event_id": "evt-test",
            "sensor": SensorType.NETWORK,
            "alert_type": "test",
            "severity": Severity.MEDIUM,
            "title": "Test Alert",
            "description": "A test alert.",
            "confidence": 0.75,
            "data": {},
        }
        defaults.update(kwargs)
        return Alert(**defaults)

    def test_insert_and_retrieve_alert(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        alert = self._make_alert()
        db.insert_alert(alert)
        retrieved = db.get_alert(alert.alert_id)
        assert retrieved is not None
        assert retrieved.title == "Test Alert"
        assert retrieved.confidence == 0.75
        db.close()

    def test_query_alerts_by_status(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        db.insert_alert(self._make_alert(title="New1"))
        alert2 = self._make_alert(title="Dismissed")
        alert2.status = AlertStatus.DISMISSED
        db.insert_alert(alert2)

        new_alerts = db.query_alerts(status=AlertStatus.NEW)
        assert len(new_alerts) == 1
        assert new_alerts[0].title == "New1"
        db.close()

    def test_update_alert_status(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        alert = self._make_alert()
        db.insert_alert(alert)
        db.update_alert_status(alert.alert_id, AlertStatus.INVESTIGATING)
        updated = db.get_alert(alert.alert_id)
        assert updated.status == AlertStatus.INVESTIGATING
        db.close()

    def test_alert_count(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        for i in range(5):
            db.insert_alert(self._make_alert(title=f"Alert {i}"))
        assert db.alert_count() == 5
        assert db.alert_count(severity=Severity.MEDIUM) == 5
        assert db.alert_count(severity=Severity.CRITICAL) == 0
        db.close()


class TestAuditLog:
    def test_write_and_read_audit(self, tmp_data_dir):
        db = AegisDatabase(tmp_data_dir / "test.db")
        db.audit("sensor.network", "started", "Network sensor initialized")
        db.audit("sensor.process", "started", "Process sensor initialized")
        entries = db.get_audit_log(limit=10)
        assert len(entries) == 2
        assert entries[0]["component"] == "sensor.process"  # most recent first
        db.close()
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_core/test_database.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'aegis.core.database'`

**Step 3: Write minimal implementation**

```python
# src/aegis/core/database.py
"""SQLite database layer for Aegis.

Uses WAL mode for concurrent read/write from multiple processes.
Stores events, alerts, baselines, feedback, and audit logs.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from aegis.core.models import (
    AegisEvent,
    Alert,
    AlertStatus,
    SensorType,
    Severity,
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    sensor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_sensor ON events(sensor);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    sensor TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    confidence REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    data TEXT NOT NULL,
    mitre_ids TEXT NOT NULL DEFAULT '[]',
    recommended_actions TEXT NOT NULL DEFAULT '[]',
    priority_score REAL NOT NULL DEFAULT 0,
    dismiss_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);

CREATE TABLE IF NOT EXISTS connection_reputation (
    address TEXT PRIMARY KEY,
    address_type TEXT NOT NULL,
    score REAL NOT NULL DEFAULT 50.0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    total_connections INTEGER NOT NULL DEFAULT 0,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS device_whitelist (
    device_id TEXT PRIMARY KEY,
    device_type TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    added_at REAL NOT NULL,
    approved_by TEXT NOT NULL DEFAULT 'auto'
);

CREATE TABLE IF NOT EXISTS process_whitelist (
    process_hash TEXT PRIMARY KEY,
    process_name TEXT NOT NULL,
    process_path TEXT NOT NULL,
    added_at REAL NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS user_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    sensor TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp REAL NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_feedback_alert_type ON user_feedback(alert_type);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    component TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
"""


class AegisDatabase:
    """SQLite database manager for Aegis.

    Uses WAL journal mode for concurrent access from multiple processes
    (sensors, detection engines, UI can all read/write simultaneously).
    """

    def __init__(self, db_path: str | Path):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    @property
    def journal_mode(self) -> str:
        cursor = self._conn.execute("PRAGMA journal_mode")
        return cursor.fetchone()[0]

    def close(self) -> None:
        self._conn.close()

    def list_tables(self) -> list[str]:
        cursor = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        return [row[0] for row in cursor.fetchall()]

    # --- Events ---

    def insert_event(self, event: AegisEvent) -> None:
        self._conn.execute(
            "INSERT INTO events (event_id, timestamp, sensor, event_type, severity, data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.timestamp,
                event.sensor.value,
                event.event_type,
                event.severity.value,
                json.dumps(event.data),
            ),
        )
        self._conn.commit()

    def get_event(self, event_id: str) -> AegisEvent | None:
        cursor = self._conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_event(row)

    def query_events(
        self,
        sensor: SensorType | None = None,
        since: float | None = None,
        limit: int = 1000,
    ) -> list[AegisEvent]:
        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []
        if sensor is not None:
            query += " AND sensor = ?"
            params.append(sensor.value)
        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cursor = self._conn.execute(query, params)
        return [self._row_to_event(row) for row in cursor.fetchall()]

    def event_count(self, sensor: SensorType | None = None) -> int:
        if sensor is not None:
            cursor = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE sensor = ?", (sensor.value,)
            )
        else:
            cursor = self._conn.execute("SELECT COUNT(*) FROM events")
        return cursor.fetchone()[0]

    def _row_to_event(self, row: sqlite3.Row) -> AegisEvent:
        return AegisEvent(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            sensor=SensorType.from_string(row["sensor"]),
            event_type=row["event_type"],
            severity=Severity.from_string(row["severity"]),
            data=json.loads(row["data"]),
        )

    # --- Alerts ---

    def insert_alert(self, alert: Alert) -> None:
        self._conn.execute(
            "INSERT INTO alerts "
            "(alert_id, event_id, timestamp, sensor, alert_type, severity, "
            "title, description, confidence, status, data, mitre_ids, "
            "recommended_actions, priority_score, dismiss_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.alert_id,
                alert.event_id,
                alert.timestamp,
                alert.sensor.value,
                alert.alert_type,
                alert.severity.value,
                alert.title,
                alert.description,
                alert.confidence,
                alert.status.value,
                json.dumps(alert.data),
                json.dumps(alert.mitre_ids),
                json.dumps(alert.recommended_actions),
                alert.priority_score,
                alert.dismiss_count,
            ),
        )
        self._conn.commit()

    def get_alert(self, alert_id: str) -> Alert | None:
        cursor = self._conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_alert(row)

    def query_alerts(
        self,
        status: AlertStatus | None = None,
        severity: Severity | None = None,
        limit: int = 100,
    ) -> list[Alert]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if status is not None:
            query += " AND status = ?"
            params.append(status.value)
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity.value)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cursor = self._conn.execute(query, params)
        return [self._row_to_alert(row) for row in cursor.fetchall()]

    def update_alert_status(self, alert_id: str, status: AlertStatus) -> None:
        self._conn.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?",
            (status.value, alert_id),
        )
        self._conn.commit()

    def alert_count(self, severity: Severity | None = None) -> int:
        if severity is not None:
            cursor = self._conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity = ?", (severity.value,)
            )
        else:
            cursor = self._conn.execute("SELECT COUNT(*) FROM alerts")
        return cursor.fetchone()[0]

    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        return Alert(
            alert_id=row["alert_id"],
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            sensor=SensorType.from_string(row["sensor"]),
            alert_type=row["alert_type"],
            severity=Severity.from_string(row["severity"]),
            title=row["title"],
            description=row["description"],
            confidence=row["confidence"],
            status=AlertStatus(row["status"]),
            data=json.loads(row["data"]),
            mitre_ids=json.loads(row["mitre_ids"]),
            recommended_actions=json.loads(row["recommended_actions"]),
            dismiss_count=row["dismiss_count"],
        )

    # --- Audit Log ---

    def audit(self, component: str, action: str, detail: str = "") -> None:
        self._conn.execute(
            "INSERT INTO audit_log (timestamp, component, action, detail) VALUES (?, ?, ?, ?)",
            (time.time(), component, action, detail),
        )
        self._conn.commit()

    def get_audit_log(self, limit: int = 50) -> list[dict[str, Any]]:
        cursor = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return [
            {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "component": row["component"],
                "action": row["action"],
                "detail": row["detail"],
            }
            for row in cursor.fetchall()
        ]
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_core/test_database.py -v`
Expected: All 12 tests PASS

**Step 5: Commit**

```bash
git add src/aegis/core/database.py tests/test_core/test_database.py
git commit -m "feat: add SQLite database layer with WAL mode, event/alert CRUD, and audit log"
```

---

### Task 5: ZeroMQ Message Bus

**Files:**
- Create: `src/aegis/core/bus.py`
- Create: `tests/test_core/test_bus.py`

**Step 1: Write the failing tests**

```python
# tests/test_core/test_bus.py
"""Tests for Aegis ZeroMQ message bus."""

import pytest
import time
import threading
from aegis.core.bus import EventBus, EventSubscriber, EventPublisher
from aegis.core.models import AegisEvent, SensorType


class TestEventBus:
    def test_pub_sub_single_message(self):
        """Publisher sends one event, subscriber receives it."""
        bus = EventBus(pub_port=15555, sub_port=15556)
        bus.start()
        time.sleep(0.2)  # let sockets bind

        received = []

        def on_event(event: AegisEvent):
            received.append(event)

        sub = EventSubscriber(
            port=15556, topics=["sensor.process"], callback=on_event
        )
        sub.start()
        time.sleep(0.2)  # let subscription propagate

        pub = EventPublisher(port=15555, topic="sensor.process")
        event = AegisEvent(
            sensor=SensorType.PROCESS, event_type="test", data={"msg": "hello"}
        )
        pub.send(event)
        time.sleep(0.5)  # let message propagate

        assert len(received) == 1
        assert received[0].event_type == "test"
        assert received[0].data["msg"] == "hello"

        sub.stop()
        pub.close()
        bus.stop()

    def test_topic_filtering(self):
        """Subscriber only receives events matching its topic."""
        bus = EventBus(pub_port=15557, sub_port=15558)
        bus.start()
        time.sleep(0.2)

        received = []
        sub = EventSubscriber(
            port=15558, topics=["sensor.network"], callback=lambda e: received.append(e)
        )
        sub.start()
        time.sleep(0.2)

        pub_net = EventPublisher(port=15557, topic="sensor.network")
        pub_proc = EventPublisher(port=15557, topic="sensor.process")

        pub_net.send(AegisEvent(sensor=SensorType.NETWORK, event_type="conn", data={}))
        pub_proc.send(AegisEvent(sensor=SensorType.PROCESS, event_type="proc", data={}))
        time.sleep(0.5)

        # Should only receive the network event
        assert len(received) == 1
        assert received[0].sensor == SensorType.NETWORK

        sub.stop()
        pub_net.close()
        pub_proc.close()
        bus.stop()

    def test_multiple_subscribers(self):
        """Multiple subscribers can receive the same event."""
        bus = EventBus(pub_port=15559, sub_port=15560)
        bus.start()
        time.sleep(0.2)

        received_a = []
        received_b = []
        sub_a = EventSubscriber(
            port=15560, topics=["sensor.file"], callback=lambda e: received_a.append(e)
        )
        sub_b = EventSubscriber(
            port=15560, topics=["sensor.file"], callback=lambda e: received_b.append(e)
        )
        sub_a.start()
        sub_b.start()
        time.sleep(0.2)

        pub = EventPublisher(port=15559, topic="sensor.file")
        pub.send(AegisEvent(sensor=SensorType.FILE, event_type="changed", data={}))
        time.sleep(0.5)

        assert len(received_a) == 1
        assert len(received_b) == 1

        sub_a.stop()
        sub_b.stop()
        pub.close()
        bus.stop()
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_core/test_bus.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'aegis.core.bus'`

**Step 3: Write minimal implementation**

```python
# src/aegis/core/bus.py
"""ZeroMQ-based event bus for inter-process communication.

Architecture:
  - EventBus: Central broker using XPUB/XSUB proxy pattern
  - EventPublisher: Sensors use this to publish events
  - EventSubscriber: Detection engines use this to receive events

The XPUB/XSUB proxy allows many-to-many pub/sub without publishers
needing to know about subscribers or vice versa.
"""

from __future__ import annotations

import threading
import logging
from typing import Callable

import zmq

from aegis.core.models import AegisEvent

logger = logging.getLogger(__name__)


class EventBus:
    """Central ZeroMQ broker using XSUB/XPUB proxy.

    Publishers connect to pub_port (XSUB side).
    Subscribers connect to sub_port (XPUB side).
    The proxy forwards all messages between them.
    """

    def __init__(self, pub_port: int = 15555, sub_port: int = 15556):
        self._pub_port = pub_port
        self._sub_port = sub_port
        self._context = zmq.Context()
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        """Start the proxy in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._run_proxy, daemon=True)
        self._thread.start()
        logger.info(f"EventBus started (pub={self._pub_port}, sub={self._sub_port})")

    def _run_proxy(self) -> None:
        xsub = self._context.socket(zmq.XSUB)
        xpub = self._context.socket(zmq.XPUB)
        xsub.bind(f"tcp://127.0.0.1:{self._pub_port}")
        xpub.bind(f"tcp://127.0.0.1:{self._sub_port}")
        try:
            zmq.proxy(xsub, xpub)
        except zmq.ContextTerminated:
            pass
        finally:
            xsub.close()
            xpub.close()

    def stop(self) -> None:
        """Stop the proxy."""
        self._running = False
        self._context.term()
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("EventBus stopped")


class EventPublisher:
    """Publishes events to the EventBus.

    Each sensor creates one publisher with its topic prefix.
    Topic format: 'sensor.<type>' (e.g., 'sensor.network', 'sensor.process').
    """

    def __init__(self, port: int = 15555, topic: str = "sensor.generic"):
        self._topic = topic
        self._context = zmq.Context()
        self._socket = self._context.socket(zmq.PUB)
        self._socket.connect(f"tcp://127.0.0.1:{port}")

    def send(self, event: AegisEvent) -> None:
        """Send an event with the configured topic prefix."""
        topic_bytes = self._topic.encode("utf-8")
        event_bytes = event.to_bytes()
        self._socket.send_multipart([topic_bytes, event_bytes])

    def close(self) -> None:
        self._socket.close()
        self._context.term()


class EventSubscriber:
    """Subscribes to events from the EventBus.

    Detection engines and the UI use this to receive events.
    Runs a listener loop in a background thread.
    """

    def __init__(
        self,
        port: int = 15556,
        topics: list[str] | None = None,
        callback: Callable[[AegisEvent], None] | None = None,
    ):
        self._port = port
        self._topics = topics or [""]  # empty string = subscribe to all
        self._callback = callback
        self._context = zmq.Context()
        self._socket = self._context.socket(zmq.SUB)
        self._running = False
        self._thread: threading.Thread | None = None

        for topic in self._topics:
            self._socket.subscribe(topic.encode("utf-8"))
        self._socket.connect(f"tcp://127.0.0.1:{port}")

    def start(self) -> None:
        """Start receiving events in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()

    def _listen(self) -> None:
        poller = zmq.Poller()
        poller.register(self._socket, zmq.POLLIN)
        while self._running:
            socks = dict(poller.poll(timeout=100))  # 100ms timeout for clean shutdown
            if self._socket in socks:
                try:
                    parts = self._socket.recv_multipart(zmq.NOBLOCK)
                    if len(parts) == 2:
                        event = AegisEvent.from_bytes(parts[1])
                        if self._callback:
                            self._callback(event)
                except zmq.ZMQError:
                    pass

    def stop(self) -> None:
        """Stop receiving events."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        self._socket.close()
        self._context.term()
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_core/test_bus.py -v`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add src/aegis/core/bus.py tests/test_core/test_bus.py
git commit -m "feat: add ZeroMQ event bus with pub/sub proxy, publisher, and subscriber"
```

---

### Task 6: Event Engine (Central Coordinator)

**Files:**
- Create: `src/aegis/core/engine.py`
- Create: `tests/test_core/test_engine.py`

**Step 1: Write the failing tests**

```python
# tests/test_core/test_engine.py
"""Tests for the Aegis Event Engine."""

import pytest
import time
from unittest.mock import MagicMock
from aegis.core.engine import EventEngine
from aegis.core.config import AegisConfig
from aegis.core.models import AegisEvent, SensorType


class TestEventEngine:
    def test_engine_starts_and_stops(self, tmp_data_dir):
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "test.db"))
        engine = EventEngine(config=config, pub_port=16661, sub_port=16662)
        engine.start()
        assert engine.is_running
        time.sleep(0.3)
        engine.stop()
        assert not engine.is_running

    def test_engine_provides_database(self, tmp_data_dir):
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "test.db"))
        engine = EventEngine(config=config, pub_port=16663, sub_port=16664)
        engine.start()
        assert engine.db is not None
        assert engine.db.list_tables()  # tables exist
        engine.stop()

    def test_engine_receives_and_stores_events(self, tmp_data_dir):
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "test.db"))
        engine = EventEngine(config=config, pub_port=16665, sub_port=16666)
        engine.start()
        time.sleep(0.3)

        # Simulate a sensor publishing an event
        from aegis.core.bus import EventPublisher
        pub = EventPublisher(port=16665, topic="sensor.process")
        time.sleep(0.2)

        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_created",
            data={"pid": 9999, "name": "test.exe"},
        )
        pub.send(event)
        time.sleep(0.5)

        # Event should be stored in database
        stored = engine.db.get_event(event.event_id)
        assert stored is not None
        assert stored.data["pid"] == 9999

        pub.close()
        engine.stop()

    def test_engine_tracks_event_count(self, tmp_data_dir):
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "test.db"))
        engine = EventEngine(config=config, pub_port=16667, sub_port=16668)
        engine.start()
        time.sleep(0.3)

        from aegis.core.bus import EventPublisher
        pub = EventPublisher(port=16667, topic="sensor.network")
        time.sleep(0.2)

        for i in range(5):
            pub.send(AegisEvent(
                sensor=SensorType.NETWORK, event_type="conn", data={"i": i}
            ))
        time.sleep(1.0)

        assert engine.events_processed >= 5

        pub.close()
        engine.stop()
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_core/test_engine.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'aegis.core.engine'`

**Step 3: Write minimal implementation**

```python
# src/aegis/core/engine.py
"""Event Engine — the central coordinator of Aegis.

Responsibilities:
- Runs the ZeroMQ event bus
- Subscribes to all sensor events
- Stores events in the database
- Feeds events to detection engines (future)
- Maintains the context graph (future)
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from aegis.core.bus import EventBus, EventSubscriber
from aegis.core.config import AegisConfig
from aegis.core.database import AegisDatabase
from aegis.core.models import AegisEvent

logger = logging.getLogger(__name__)


class EventEngine:
    """Central coordinator that ties sensors, detection, and storage together."""

    def __init__(
        self,
        config: AegisConfig,
        pub_port: int = 15555,
        sub_port: int = 15556,
    ):
        self._config = config
        self._pub_port = pub_port
        self._sub_port = sub_port
        self._bus: EventBus | None = None
        self._subscriber: EventSubscriber | None = None
        self._db: AegisDatabase | None = None
        self._running = False
        self._events_processed = 0
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def db(self) -> AegisDatabase | None:
        return self._db

    @property
    def events_processed(self) -> int:
        with self._lock:
            return self._events_processed

    def start(self) -> None:
        """Start the event engine, bus, and database."""
        logger.info("EventEngine starting...")

        # Initialize database
        db_path = self._config.get("database.path", "aegis.db")
        db_path = str(db_path).replace("%APPDATA%", str(Path.home() / "AppData" / "Roaming"))
        self._db = AegisDatabase(db_path)
        self._db.audit("engine", "starting", "Event Engine initializing")

        # Start message bus
        self._bus = EventBus(pub_port=self._pub_port, sub_port=self._sub_port)
        self._bus.start()

        # Subscribe to all sensor events
        self._subscriber = EventSubscriber(
            port=self._sub_port,
            topics=["sensor."],  # subscribe to all sensor.* topics
            callback=self._on_event,
        )
        self._subscriber.start()

        self._running = True
        self._db.audit("engine", "started", "Event Engine ready")
        logger.info("EventEngine started")

    def _on_event(self, event: AegisEvent) -> None:
        """Handle an incoming event from any sensor."""
        try:
            # Store in database
            if self._db:
                self._db.insert_event(event)

            with self._lock:
                self._events_processed += 1

            # TODO: Feed to context graph
            # TODO: Feed to detection engines

        except Exception as e:
            logger.error(f"Error processing event {event.event_id}: {e}")

    def stop(self) -> None:
        """Stop the event engine cleanly."""
        logger.info("EventEngine stopping...")
        self._running = False

        if self._subscriber:
            self._subscriber.stop()
        if self._bus:
            self._bus.stop()
        if self._db:
            self._db.audit("engine", "stopped", "Event Engine shutdown")
            self._db.close()

        logger.info("EventEngine stopped")
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_core/test_engine.py -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add src/aegis/core/engine.py tests/test_core/test_engine.py
git commit -m "feat: add Event Engine central coordinator with bus, database, and event routing"
```

---

### Task 7: Sensor Base Class

**Files:**
- Create: `src/aegis/sensors/__init__.py`
- Create: `src/aegis/sensors/base.py`
- Create: `tests/test_sensors/__init__.py`
- Create: `tests/test_sensors/test_base.py`

**Step 1: Write the failing tests**

```python
# tests/test_sensors/test_base.py
"""Tests for the abstract sensor base class."""

import pytest
import time
from aegis.sensors.base import BaseSensor
from aegis.core.models import AegisEvent, SensorType


class MockSensor(BaseSensor):
    """Concrete implementation for testing."""

    sensor_type = SensorType.PROCESS
    sensor_name = "mock_sensor"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.tick_count = 0

    def setup(self) -> None:
        pass

    def collect(self) -> list[AegisEvent]:
        self.tick_count += 1
        return [
            AegisEvent(
                sensor=self.sensor_type,
                event_type="mock_tick",
                data={"tick": self.tick_count},
            )
        ]

    def teardown(self) -> None:
        pass


class TestBaseSensor:
    def test_sensor_starts_and_stops(self):
        sensor = MockSensor(interval=0.1)
        sensor.start()
        assert sensor.is_running
        time.sleep(0.5)
        sensor.stop()
        assert not sensor.is_running
        assert sensor.tick_count > 0

    def test_sensor_collects_on_interval(self):
        sensor = MockSensor(interval=0.1)
        sensor.start()
        time.sleep(0.55)
        sensor.stop()
        # At 0.1s interval over 0.55s, expect 4-6 ticks
        assert 3 <= sensor.tick_count <= 8

    def test_sensor_emits_events(self):
        emitted = []
        sensor = MockSensor(interval=0.1, on_event=lambda e: emitted.append(e))
        sensor.start()
        time.sleep(0.35)
        sensor.stop()
        assert len(emitted) > 0
        assert all(isinstance(e, AegisEvent) for e in emitted)
        assert all(e.sensor == SensorType.PROCESS for e in emitted)

    def test_sensor_name_and_type(self):
        sensor = MockSensor(interval=1.0)
        assert sensor.sensor_name == "mock_sensor"
        assert sensor.sensor_type == SensorType.PROCESS
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_sensors/test_base.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write minimal implementation**

```python
# src/aegis/sensors/__init__.py
"""Aegis sensor modules."""
```

```python
# src/aegis/sensors/base.py
"""Abstract base class for all Aegis sensor modules.

Each sensor runs in its own thread (or process), collects data at a
configured interval, and emits AegisEvent objects via a callback.
"""

from __future__ import annotations

import abc
import logging
import threading
import time
from typing import Callable

from aegis.core.models import AegisEvent, SensorType

logger = logging.getLogger(__name__)


class BaseSensor(abc.ABC):
    """Abstract base class for sensor modules.

    Subclasses must implement:
      - sensor_type: SensorType class variable
      - sensor_name: human-readable name
      - setup(): one-time initialization
      - collect(): called every interval, returns list of events
      - teardown(): cleanup on stop
    """

    sensor_type: SensorType
    sensor_name: str

    def __init__(
        self,
        interval: float = 5.0,
        on_event: Callable[[AegisEvent], None] | None = None,
    ):
        self._interval = interval
        self._on_event = on_event
        self._running = False
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    @abc.abstractmethod
    def setup(self) -> None:
        """One-time initialization. Called before first collect()."""

    @abc.abstractmethod
    def collect(self) -> list[AegisEvent]:
        """Collect data and return events. Called every interval."""

    @abc.abstractmethod
    def teardown(self) -> None:
        """Cleanup resources. Called on stop."""

    def start(self) -> None:
        """Start the sensor collection loop in a background thread."""
        if self._running:
            return
        logger.info(f"Sensor '{self.sensor_name}' starting (interval={self._interval}s)")
        self._running = True
        self.setup()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self) -> None:
        while self._running:
            try:
                events = self.collect()
                for event in events:
                    if self._on_event:
                        self._on_event(event)
            except Exception as e:
                logger.error(f"Sensor '{self.sensor_name}' error in collect(): {e}")
            time.sleep(self._interval)

    def stop(self) -> None:
        """Stop the sensor."""
        logger.info(f"Sensor '{self.sensor_name}' stopping")
        self._running = False
        if self._thread:
            self._thread.join(timeout=self._interval + 2)
        self.teardown()
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_sensors/test_base.py -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add src/aegis/sensors/ tests/test_sensors/
git commit -m "feat: add abstract BaseSensor class with interval-based collection loop"
```

---

### Task 8: System Tray Application

**Files:**
- Create: `src/aegis/ui/__init__.py`
- Create: `src/aegis/ui/app.py`
- Create: `src/aegis/ui/tray.py`
- Create: `tests/test_ui/__init__.py`
- Create: `tests/test_ui/test_tray.py`

**Step 1: Write the failing tests**

```python
# tests/test_ui/test_tray.py
"""Tests for Aegis system tray and app (non-GUI unit tests)."""

import pytest
from aegis.ui.tray import TrayState, AegisTrayManager


class TestTrayState:
    def test_all_states_defined(self):
        assert TrayState.ALL_CLEAR is not None
        assert TrayState.WARNING is not None
        assert TrayState.CRITICAL is not None
        assert TrayState.LEARNING is not None

    def test_state_has_tooltip(self):
        assert "clear" in TrayState.ALL_CLEAR.tooltip.lower()
        assert "warning" in TrayState.WARNING.tooltip.lower() or "alert" in TrayState.WARNING.tooltip.lower()
        assert "critical" in TrayState.CRITICAL.tooltip.lower()
        assert "learning" in TrayState.LEARNING.tooltip.lower()

    def test_state_has_color(self):
        assert TrayState.ALL_CLEAR.color == "green"
        assert TrayState.WARNING.color == "yellow"
        assert TrayState.CRITICAL.color == "red"
        assert TrayState.LEARNING.color == "grey"


class TestTrayManager:
    def test_initial_state_is_learning(self):
        manager = AegisTrayManager(headless=True)
        assert manager.state == TrayState.LEARNING

    def test_set_state(self):
        manager = AegisTrayManager(headless=True)
        manager.set_state(TrayState.ALL_CLEAR)
        assert manager.state == TrayState.ALL_CLEAR

    def test_set_state_to_critical(self):
        manager = AegisTrayManager(headless=True)
        manager.set_state(TrayState.CRITICAL)
        assert manager.state == TrayState.CRITICAL

    def test_sensor_status_tracking(self):
        manager = AegisTrayManager(headless=True)
        manager.update_sensor_status("network", running=True)
        manager.update_sensor_status("process", running=True)
        manager.update_sensor_status("fim", running=False)
        statuses = manager.sensor_statuses
        assert statuses["network"] is True
        assert statuses["process"] is True
        assert statuses["fim"] is False
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_ui/test_tray.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write minimal implementation**

```python
# src/aegis/ui/__init__.py
"""Aegis desktop UI components."""
```

```python
# src/aegis/ui/tray.py
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
        """Initialize the Qt system tray icon. Only called in non-headless mode."""
        try:
            from PySide6.QtWidgets import QSystemTrayIcon, QMenu
            from PySide6.QtGui import QIcon, QPixmap, QColor, QPainter
            # Tray icon creation deferred to when QApplication exists
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
        # Will be implemented when we build the full UI
        pass
```

```python
# src/aegis/ui/app.py
"""Main Aegis desktop application.

Creates the QApplication, system tray, and dashboard window.
This is the entry point for the user-facing UI.
"""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)


def run_ui() -> int:
    """Launch the Aegis desktop application.

    Returns exit code.
    """
    try:
        from PySide6.QtWidgets import QApplication
        from aegis.ui.tray import AegisTrayManager

        app = QApplication(sys.argv)
        app.setApplicationName("Aegis")
        app.setQuitOnLastWindowClosed(False)  # keep running in tray

        tray = AegisTrayManager(headless=False)
        tray.set_state(tray.state)  # show initial state

        logger.info("Aegis UI started")
        return app.exec()

    except ImportError:
        logger.error("PySide6 is required for the GUI. Install with: pip install PySide6")
        return 1
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_ui/test_tray.py -v`
Expected: All 7 tests PASS

**Step 5: Commit**

```bash
git add src/aegis/ui/ tests/test_ui/
git commit -m "feat: add system tray manager with state tracking and headless test mode"
```

---

### Task 9: Wire Entry Point and Integration Test

**Files:**
- Modify: `src/aegis/__main__.py`
- Create: `tests/test_integration/__init__.py`
- Create: `tests/test_integration/test_phase1.py`

**Step 1: Write the integration test**

```python
# tests/test_integration/test_phase1.py
"""Integration test: verify Phase 1 components work together."""

import pytest
import time
from aegis.core.config import AegisConfig
from aegis.core.engine import EventEngine
from aegis.core.bus import EventPublisher
from aegis.core.models import AegisEvent, Alert, SensorType, Severity
from aegis.sensors.base import BaseSensor
from aegis.ui.tray import AegisTrayManager, TrayState


class StubSensor(BaseSensor):
    sensor_type = SensorType.PROCESS
    sensor_name = "stub"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.events_generated = 0

    def setup(self): pass

    def collect(self):
        self.events_generated += 1
        return [AegisEvent(
            sensor=self.sensor_type,
            event_type="stub_event",
            data={"count": self.events_generated},
        )]

    def teardown(self): pass


class TestPhase1Integration:
    def test_full_pipeline_sensor_to_database(self, tmp_data_dir):
        """Sensor → EventBus → EventEngine → Database."""
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "integration.db"))

        engine = EventEngine(config=config, pub_port=17771, sub_port=17772)
        engine.start()
        time.sleep(0.3)

        # Create a publisher that mimics a sensor
        pub = EventPublisher(port=17771, topic="sensor.process")
        time.sleep(0.2)

        # Send events
        events_sent = []
        for i in range(3):
            event = AegisEvent(
                sensor=SensorType.PROCESS,
                event_type="test_integration",
                data={"iteration": i},
            )
            events_sent.append(event)
            pub.send(event)

        time.sleep(1.0)

        # Verify all events reached the database
        for event in events_sent:
            stored = engine.db.get_event(event.event_id)
            assert stored is not None, f"Event {event.event_id} not found in database"

        assert engine.events_processed >= 3

        pub.close()
        engine.stop()

    def test_alert_storage_and_retrieval(self, tmp_data_dir):
        """Alerts can be created, stored, queried, and status-updated."""
        config = AegisConfig()
        config.set("database.path", str(tmp_data_dir / "alerts.db"))
        engine = EventEngine(config=config, pub_port=17773, sub_port=17774)
        engine.start()
        time.sleep(0.2)

        alert = Alert(
            event_id="evt-integration",
            sensor=SensorType.NETWORK,
            alert_type="port_scan",
            severity=Severity.HIGH,
            title="Integration test alert",
            description="Testing end-to-end alert flow",
            confidence=0.9,
            data={"source_ip": "10.0.0.1"},
            mitre_ids=["T1046"],
            recommended_actions=["Block IP 10.0.0.1"],
        )
        engine.db.insert_alert(alert)

        retrieved = engine.db.get_alert(alert.alert_id)
        assert retrieved.title == "Integration test alert"
        assert retrieved.mitre_ids == ["T1046"]
        assert retrieved.priority_score > 0

        engine.stop()

    def test_tray_reflects_alert_state(self):
        """Tray manager state updates correctly."""
        tray = AegisTrayManager(headless=True)
        assert tray.state == TrayState.LEARNING

        # Simulate: baseline complete
        tray.set_state(TrayState.ALL_CLEAR)
        assert tray.state == TrayState.ALL_CLEAR

        # Simulate: critical alert arrives
        tray.set_state(TrayState.CRITICAL)
        assert tray.state == TrayState.CRITICAL

        # Simulate: alert resolved
        tray.set_state(TrayState.ALL_CLEAR)
        assert tray.state == TrayState.ALL_CLEAR

    def test_config_persists_across_restarts(self, tmp_data_dir):
        """Config changes survive save/load cycle."""
        config_path = tmp_data_dir / "config.yaml"
        config = AegisConfig()
        config.set("sensors.hardware.enabled", True)
        config.set("alerting.auto_suppress_after_dismissals", 5)
        config.save(config_path)

        loaded = AegisConfig.load(config_path)
        assert loaded.get("sensors.hardware.enabled") is True
        assert loaded.get("alerting.auto_suppress_after_dismissals") == 5
        # Defaults still intact
        assert loaded.get("sensors.network.enabled") is True
```

**Step 2: Run integration tests to verify they fail (module exists but test is new)**

Run: `pytest tests/test_integration/test_phase1.py -v`
Expected: All 4 tests PASS (these should pass if all prior tasks are done correctly)

**Step 3: Update the entry point**

```python
# src/aegis/__main__.py
"""Entry point for Aegis."""

import logging
import sys

from aegis import __version__


def main() -> int:
    """Launch Aegis."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logger = logging.getLogger("aegis")
    logger.info(f"Aegis v{__version__} starting...")

    # For now, just verify imports work
    from aegis.core.config import AegisConfig
    from aegis.core.engine import EventEngine
    from aegis.ui.tray import AegisTrayManager, TrayState

    config = AegisConfig()
    logger.info(f"Config loaded. Sensors enabled: network={config.get('sensors.network.enabled')}")
    logger.info("Phase 1 foundation ready. Sensors and detection coming in Phase 2+3.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

**Step 4: Run full test suite**

Run: `pytest -v`
Expected: All tests PASS (models: 8, config: 8, database: 12, bus: 3, engine: 4, sensor base: 4, tray: 7, integration: 4 = ~50 tests)

**Step 5: Run the application**

Run: `python -m aegis`
Expected: Prints startup log with version and config info, exits cleanly

**Step 6: Commit**

```bash
git add src/aegis/__main__.py tests/test_integration/
git commit -m "feat: wire entry point and add Phase 1 integration tests (50 tests passing)"
```

---

## Summary

Phase 1 creates 9 tasks that build the complete foundation:

| Task | Component | Tests | What It Builds |
|------|-----------|-------|----------------|
| 1 | Scaffolding | 0 | pyproject.toml, CLAUDE.md, entry point, test config |
| 2 | Data Models | 8 | AegisEvent, Alert, SensorType, Severity enums |
| 3 | Config | 8 | YAML config with dot-notation, defaults, merge |
| 4 | Database | 12 | SQLite WAL, events/alerts CRUD, audit log |
| 5 | Message Bus | 3 | ZeroMQ PUB/SUB proxy, publisher, subscriber |
| 6 | Event Engine | 4 | Central coordinator: bus + db + event routing |
| 7 | Sensor Base | 4 | Abstract BaseSensor with interval loop |
| 8 | System Tray | 7 | TrayState, AegisTrayManager with headless mode |
| 9 | Integration | 4 | End-to-end: sensor → bus → engine → db → tray |

**Total: ~50 tests, 9 commits, complete foundation for Phase 2.**

After Phase 1, the next step is Phase 2: First Sensors (Process Watchdog + Network Sensor wired to the Event Engine).
