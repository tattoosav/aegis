"""Windows Registry Monitor sensor — detects persistence and tampering.

Monitors critical Windows registry keys associated with autorun, services,
and security settings.  Detects new, modified, and deleted values using a
scan-based approach with value hashing.

MITRE coverage: T1547.001 (Registry Run Keys), T1547.004 (Winlogon),
T1546.001 (Change Default File Association), T1543.003 (Windows Service).

When winreg is not available (non-Windows), operates in stub mode.
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.base import BaseSensor

logger = logging.getLogger(__name__)

# Graceful import — winreg only available on Windows
try:
    import winreg  # type: ignore[import-not-found]

    _HAS_WINREG = True
except ImportError:
    _HAS_WINREG = False

# Hive constants (for cross-platform reference)
_HKLM = 0x80000002
_HKCU = 0x80000001

# Registry keys to monitor: (hive_const, key_path, category, mitre_id)
MONITORED_KEYS: list[tuple[int, str, str, str]] = [
    # Persistence — Run / RunOnce
    (_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "persistence", "T1547.001"),
    (_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
     "persistence", "T1547.001"),
    (_HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "persistence", "T1547.001"),
    (_HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
     "persistence", "T1547.001"),
    # Persistence — Winlogon
    (_HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
     "persistence", "T1547.004"),
    (_HKCU, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
     "persistence", "T1547.004"),
    # Persistence — Services
    (_HKLM, r"SYSTEM\CurrentControlSet\Services",
     "persistence", "T1543.003"),
    # Persistence — Startup approved
    (_HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
     r"\StartupApproved\Run", "persistence", "T1547.001"),
    # Defense evasion — IFEO (debugger hijack)
    (_HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
     r"\Image File Execution Options", "defense_evasion", "T1546.012"),
    # Credential access — LSA
    (_HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa",
     "credential_access", "T1547.001"),
    # Execution — Shell open commands
    (_HKLM, r"SOFTWARE\Classes\exefile\shell\open\command",
     "execution", "T1546.001"),
]


def _hive_name(hive: int) -> str:
    """Return human-readable hive name."""
    return "HKLM" if hive == _HKLM else "HKCU"


@dataclass
class RegistryValue:
    """A single registry value with its data."""

    hive: str
    key_path: str
    value_name: str
    value_data: Any
    value_type: int
    data_hash: str
    category: str
    mitre_id: str


def _hash_value(data: Any) -> str:
    """SHA-256 hash of serialised registry value data."""
    raw = str(data).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]


def _value_entropy(data: Any) -> float:
    """Shannon entropy of registry value data bytes."""
    raw = str(data).encode("utf-8", errors="replace")
    if not raw:
        return 0.0
    freq = Counter(raw)
    total = len(raw)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class RegistrySensor(BaseSensor):
    """Registry Monitor — tracks changes to security-critical registry keys.

    Emits:
    - registry_snapshot: summary with value counts and change stats
    - registry_change: individual key value creation / modification / deletion
    """

    sensor_type = SensorType.REGISTRY
    sensor_name = "registry_monitor"

    def __init__(
        self,
        interval: float = 10.0,
        monitored_keys: list[tuple[int, str, str, str]] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(interval=interval, **kwargs)
        self._monitored_keys = monitored_keys or MONITORED_KEYS
        self._baseline: dict[str, RegistryValue] = {}
        self._cycle = 0

    def setup(self) -> None:
        """Build initial registry value baseline."""
        self._baseline = self._build_baseline()
        logger.info(
            "Registry sensor baseline: %d values across %d keys",
            len(self._baseline),
            len(self._monitored_keys),
        )

    def collect(self) -> list[AegisEvent]:
        """Scan monitored keys and detect changes since last cycle."""
        self._cycle += 1
        current = self._build_baseline()
        events: list[AegisEvent] = []
        created = 0
        modified = 0
        deleted = 0

        # Check for new and modified values
        for key, val in current.items():
            if key not in self._baseline:
                created += 1
                events.append(self._make_change_event(val, "created"))
            elif val.data_hash != self._baseline[key].data_hash:
                modified += 1
                events.append(self._make_change_event(val, "modified"))

        # Check for deleted values
        for key, val in self._baseline.items():
            if key not in current:
                deleted += 1
                events.append(self._make_change_event(val, "deleted"))

        self._baseline = current

        # Summary snapshot
        events.append(AegisEvent(
            sensor=SensorType.REGISTRY,
            event_type="registry_snapshot",
            data={
                "cycle": self._cycle,
                "total_values": len(current),
                "created": created,
                "modified": modified,
                "deleted": deleted,
            },
            severity=Severity.INFO,
        ))

        return events

    def teardown(self) -> None:
        """Cleanup resources."""
        self._baseline.clear()

    def _build_baseline(self) -> dict[str, RegistryValue]:
        """Scan all monitored keys and return combined value map."""
        baseline: dict[str, RegistryValue] = {}
        for hive, key_path, category, mitre_id in self._monitored_keys:
            values = self._read_key_values(hive, key_path, category, mitre_id)
            for val in values:
                unique_key = f"{val.hive}\\{val.key_path}\\{val.value_name}"
                baseline[unique_key] = val
        return baseline

    def _read_key_values(
        self, hive: int, key_path: str, category: str, mitre_id: str,
    ) -> list[RegistryValue]:
        """Read all values from a single registry key."""
        if not _HAS_WINREG:
            return self._read_key_values_stub(hive, key_path, category, mitre_id)

        values: list[RegistryValue] = []
        hive_handle = winreg.HKEY_LOCAL_MACHINE if hive == _HKLM else winreg.HKEY_CURRENT_USER
        try:
            with winreg.OpenKey(hive_handle, key_path, 0, winreg.KEY_READ) as key:
                idx = 0
                while True:
                    try:
                        name, data, vtype = winreg.EnumValue(key, idx)
                        values.append(RegistryValue(
                            hive=_hive_name(hive),
                            key_path=key_path,
                            value_name=name,
                            value_data=data,
                            value_type=vtype,
                            data_hash=_hash_value(data),
                            category=category,
                            mitre_id=mitre_id,
                        ))
                        idx += 1
                    except OSError:
                        break
        except PermissionError:
            logger.debug("Permission denied reading %s\\%s", _hive_name(hive), key_path)
        except FileNotFoundError:
            logger.debug("Registry key not found: %s\\%s", _hive_name(hive), key_path)
        except Exception:
            logger.debug("Error reading %s\\%s", _hive_name(hive), key_path)
        return values

    def _read_key_values_stub(
        self, hive: int, key_path: str, category: str, mitre_id: str,
    ) -> list[RegistryValue]:
        """Stub data for non-Windows platforms (testing only)."""
        return []

    def _make_change_event(
        self, val: RegistryValue, change_type: str,
    ) -> AegisEvent:
        """Create a registry_change event."""
        entropy = _value_entropy(val.value_data)
        severity = Severity.HIGH if change_type == "created" else Severity.MEDIUM
        if change_type == "deleted":
            severity = Severity.MEDIUM

        return AegisEvent(
            sensor=SensorType.REGISTRY,
            event_type="registry_change",
            data={
                "hive": val.hive,
                "key_path": val.key_path,
                "value_name": val.value_name,
                "value_data": str(val.value_data),
                "value_type": val.value_type,
                "data_hash": val.data_hash,
                "category": val.category,
                "mitre_id": val.mitre_id,
                "change_type": change_type,
                "entropy": entropy,
            },
            severity=severity,
        )
