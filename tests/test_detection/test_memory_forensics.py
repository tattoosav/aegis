"""Tests for Memory Forensics Engine."""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

from aegis.detection.memory_forensics import (
    FindingType,
    MemoryFinding,
    MemoryForensicsEngine,
)
from aegis.detection.win_memory import MemoryRegion, ModuleInfo

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _make_pe_data(extra: bytes = b"", total: int = 4096) -> bytes:
    """Build minimal PE data with MZ + PE signature."""
    pe_offset = 0x80
    data = b"MZ" + b"\x00" * 0x3A + pe_offset.to_bytes(4, "little")
    data += b"\x00" * (pe_offset - len(data)) + b"PE\x00\x00"
    data += extra
    data += b"\x00" * (total - len(data))
    return data


def _private_exec_region(
    base: int = 0x1000000,
    size: int = 0x10000,
    protect: int = 0x20,
) -> MemoryRegion:
    """Create a committed, private, executable MemoryRegion."""
    return MemoryRegion(
        base_address=base,
        size=size,
        state=0x1000,       # MEM_COMMIT
        protect=protect,    # PAGE_EXECUTE_READ by default
        type=0x20000,       # MEM_PRIVATE
        allocation_base=base,
        allocation_protect=0x40,
    )


# ------------------------------------------------------------------ #
# MemoryFinding
# ------------------------------------------------------------------ #


class TestMemoryFinding:
    """Tests for the MemoryFinding dataclass."""

    def test_finding_creation(self) -> None:
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
        assert f.pid == 1234
        assert f.address == 0x7FF00000
        assert f.size == 0x10000
        assert f.confidence == 0.9
        assert f.details == {"has_pe_header": True}
        assert f.mitre_id == "T1620"

    def test_finding_defaults(self) -> None:
        f = MemoryFinding(
            finding_type=FindingType.SHELLCODE,
            pid=0,
            address=0,
            size=0,
            confidence=0.5,
        )
        assert f.details == {}
        assert f.mitre_id == ""


# ------------------------------------------------------------------ #
# FindingType enum
# ------------------------------------------------------------------ #


class TestFindingType:
    """Tests for the FindingType enum values."""

    def test_all_types_exist(self) -> None:
        expected = {
            "REFLECTIVE_DLL",
            "PROCESS_HOLLOWING",
            "SHELLCODE",
            "RWX_REGION",
            "DOTNET_INJECTION",
            "INLINE_HOOK",
            "SUSPICIOUS_THREAD",
        }
        actual = {member.name for member in FindingType}
        assert actual == expected


# ------------------------------------------------------------------ #
# Reflective DLL detection
# ------------------------------------------------------------------ #


class TestReflectiveDLLDetection:
    """Tests for _check_reflective_dll."""

    def test_detects_pe_in_private_executable_memory(self) -> None:
        engine = MemoryForensicsEngine()
        pe_data = _make_pe_data()
        region = _private_exec_region()
        module_bases: set[int] = {0x7FF00000}

        findings = engine._check_reflective_dll(
            region, pe_data, module_bases,
        )
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.REFLECTIVE_DLL
        assert findings[0].mitre_id == "T1620"
        assert findings[0].address == region.base_address
        assert findings[0].confidence > 0.0

    def test_ignores_pe_at_known_module_base(self) -> None:
        engine = MemoryForensicsEngine()
        pe_data = _make_pe_data()
        region = _private_exec_region(base=0x7FF00000)
        module_bases: set[int] = {0x7FF00000}

        findings = engine._check_reflective_dll(
            region, pe_data, module_bases,
        )
        assert len(findings) == 0

    def test_ignores_data_without_mz(self) -> None:
        engine = MemoryForensicsEngine()
        data = b"\x00" * 4096
        region = _private_exec_region()

        findings = engine._check_reflective_dll(region, data, set())
        assert len(findings) == 0

    def test_ignores_mz_with_bad_pe_offset(self) -> None:
        engine = MemoryForensicsEngine()
        # MZ header with PE offset pointing beyond data
        data = b"MZ" + b"\x00" * 0x3A + b"\xFF\xFF\x00\x00"
        data += b"\x00" * (4096 - len(data))
        region = _private_exec_region()

        findings = engine._check_reflective_dll(region, data, set())
        assert len(findings) == 0

    def test_ignores_short_data(self) -> None:
        engine = MemoryForensicsEngine()
        findings = engine._check_reflective_dll(
            _private_exec_region(), b"MZ", set(),
        )
        assert len(findings) == 0


# ------------------------------------------------------------------ #
# Shellcode detection
# ------------------------------------------------------------------ #


class TestShellcodeDetection:
    """Tests for _check_shellcode."""

    def test_detects_high_entropy_executable_private(self) -> None:
        engine = MemoryForensicsEngine()
        shellcode = os.urandom(4096)

        region = _private_exec_region(
            base=0x2000000, size=4096, protect=0x40,
        )

        findings = engine._check_shellcode(region, shellcode)
        assert len(findings) >= 1
        assert findings[0].finding_type == FindingType.SHELLCODE
        assert findings[0].mitre_id == "T1055"
        assert 0.0 <= findings[0].confidence <= 1.0

    def test_ignores_low_entropy_region(self) -> None:
        engine = MemoryForensicsEngine()
        low_entropy = b"\x00" * 4096

        region = _private_exec_region(
            base=0x2000000, size=4096, protect=0x40,
        )

        findings = engine._check_shellcode(region, low_entropy)
        assert len(findings) == 0

    def test_ignores_non_executable_region(self) -> None:
        engine = MemoryForensicsEngine()
        shellcode = os.urandom(4096)

        region = MemoryRegion(
            base_address=0x2000000, size=4096,
            state=0x1000, protect=0x04, type=0x20000,  # PAGE_READWRITE
            allocation_base=0x2000000, allocation_protect=0x04,
        )

        findings = engine._check_shellcode(region, shellcode)
        assert len(findings) == 0

    def test_ignores_non_private_region(self) -> None:
        engine = MemoryForensicsEngine()
        shellcode = os.urandom(4096)

        region = MemoryRegion(
            base_address=0x2000000, size=4096,
            state=0x1000, protect=0x40, type=0x1000000,  # MEM_IMAGE
            allocation_base=0x2000000, allocation_protect=0x40,
        )

        findings = engine._check_shellcode(region, shellcode)
        assert len(findings) == 0


# ------------------------------------------------------------------ #
# RWX detection
# ------------------------------------------------------------------ #


class TestRWXDetection:
    """Tests for _check_rwx."""

    def test_flags_rwx_private_regions(self) -> None:
        engine = MemoryForensicsEngine()
        region = _private_exec_region(
            base=0x3000000, size=0x1000, protect=0x40,
        )

        findings = engine._check_rwx(region)
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.RWX_REGION
        assert findings[0].mitre_id == "T1055.012"

    def test_ignores_non_rwx_region(self) -> None:
        engine = MemoryForensicsEngine()
        region = _private_exec_region(
            base=0x3000000, size=0x1000, protect=0x20,
        )

        findings = engine._check_rwx(region)
        assert len(findings) == 0

    def test_ignores_rwx_image_region(self) -> None:
        engine = MemoryForensicsEngine()
        region = MemoryRegion(
            base_address=0x3000000, size=0x1000,
            state=0x1000, protect=0x40, type=0x1000000,  # MEM_IMAGE
            allocation_base=0x3000000, allocation_protect=0x40,
        )

        findings = engine._check_rwx(region)
        assert len(findings) == 0


# ------------------------------------------------------------------ #
# .NET injection detection
# ------------------------------------------------------------------ #


class TestDotNetDetection:
    """Tests for _check_dotnet_injection."""

    def test_detects_dotnet_metadata_in_private_memory(self) -> None:
        engine = MemoryForensicsEngine()
        pe_data = _make_pe_data(extra=b"\x00" * 100 + b"BSJB")
        region = _private_exec_region(base=0x4000000, size=4096)

        findings = engine._check_dotnet_injection(
            region, pe_data, set(),
        )
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.DOTNET_INJECTION
        assert findings[0].mitre_id == "T1055"

    def test_ignores_dotnet_at_known_module(self) -> None:
        engine = MemoryForensicsEngine()
        pe_data = _make_pe_data(extra=b"\x00" * 100 + b"BSJB")
        region = _private_exec_region(base=0x4000000)
        module_bases: set[int] = {0x4000000}

        findings = engine._check_dotnet_injection(
            region, pe_data, module_bases,
        )
        assert len(findings) == 0

    def test_ignores_bsjb_without_pe_header(self) -> None:
        engine = MemoryForensicsEngine()
        data = b"\x00" * 200 + b"BSJB" + b"\x00" * 3892
        region = _private_exec_region(base=0x4000000)

        findings = engine._check_dotnet_injection(
            region, data, set(),
        )
        assert len(findings) == 0


# ------------------------------------------------------------------ #
# scan_process integration (mocked Windows APIs)
# ------------------------------------------------------------------ #


class TestScanProcess:
    """Tests for scan_process with mocked OS calls."""

    @patch("aegis.detection.memory_forensics.close_handle")
    @patch("aegis.detection.memory_forensics.read_memory")
    @patch("aegis.detection.memory_forensics.enumerate_regions")
    @patch("aegis.detection.memory_forensics.get_loaded_modules")
    @patch("aegis.detection.memory_forensics.open_process_readonly")
    def test_scan_returns_findings(
        self,
        mock_open: MagicMock,
        mock_modules: MagicMock,
        mock_regions: MagicMock,
        mock_read: MagicMock,
        mock_close: MagicMock,
    ) -> None:
        mock_open.return_value = 42
        mock_modules.return_value = [
            ModuleInfo(base=0x7FF00000, size=0x1000, name="a.dll", path=""),
        ]
        mock_regions.return_value = [
            _private_exec_region(base=0x1000000, protect=0x40),
        ]
        mock_read.return_value = _make_pe_data()

        engine = MemoryForensicsEngine()
        findings = engine.scan_process(1234)

        mock_open.assert_called_once_with(1234)
        mock_close.assert_called_once_with(42)
        assert len(findings) >= 1

    @patch("aegis.detection.memory_forensics.open_process_readonly")
    def test_scan_returns_empty_on_open_failure(
        self, mock_open: MagicMock,
    ) -> None:
        mock_open.return_value = None

        engine = MemoryForensicsEngine()
        findings = engine.scan_process(9999)
        assert findings == []

    @patch("aegis.detection.memory_forensics.close_handle")
    @patch("aegis.detection.memory_forensics.read_memory")
    @patch("aegis.detection.memory_forensics.enumerate_regions")
    @patch("aegis.detection.memory_forensics.get_loaded_modules")
    @patch("aegis.detection.memory_forensics.open_process_readonly")
    def test_scan_skips_unreadable_regions(
        self,
        mock_open: MagicMock,
        mock_modules: MagicMock,
        mock_regions: MagicMock,
        mock_read: MagicMock,
        mock_close: MagicMock,
    ) -> None:
        mock_open.return_value = 42
        mock_modules.return_value = []
        mock_regions.return_value = [
            _private_exec_region(base=0x1000000),
        ]
        mock_read.return_value = None  # read failed

        engine = MemoryForensicsEngine()
        findings = engine.scan_process(1234)
        assert findings == []
        mock_close.assert_called_once_with(42)


# ------------------------------------------------------------------ #
# analyze_event
# ------------------------------------------------------------------ #


class TestAnalyzeEvent:
    """Tests for analyze_event pipeline."""

    def test_analyze_event_returns_alerts(self) -> None:
        from aegis.core.models import AegisEvent, SensorType, Severity

        engine = MemoryForensicsEngine()
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.process_image_load",
            data={"pid": 1234},
            severity=Severity.INFO,
        )

        with patch.object(engine, "scan_process") as mock_scan:
            mock_scan.return_value = [
                MemoryFinding(
                    finding_type=FindingType.REFLECTIVE_DLL,
                    pid=1234,
                    address=0x1000000,
                    size=0x10000,
                    confidence=0.85,
                    details={"has_pe_header": True},
                    mitre_id="T1620",
                ),
            ]
            alerts = engine.analyze_event(event)

        assert len(alerts) == 1
        assert alerts[0].alert_type == "reflective_dll"
        assert alerts[0].mitre_ids == ["T1620"]
        assert alerts[0].confidence == 0.85

    def test_analyze_event_ignores_irrelevant_events(self) -> None:
        from aegis.core.models import AegisEvent, SensorType, Severity

        engine = MemoryForensicsEngine()
        event = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="network.connection",
            data={},
            severity=Severity.INFO,
        )

        alerts = engine.analyze_event(event)
        assert alerts == []
