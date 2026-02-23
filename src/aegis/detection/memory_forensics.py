"""Memory Forensics Engine — detect reflective DLLs, shellcode, and injections.

Scans process memory for indicators of code injection including reflective
DLL loading, shellcode (high-entropy executable regions), RWX memory,
and .NET assembly injection.  Each check maps to a MITRE ATT&CK technique.
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from enum import Enum

from aegis.core.models import AegisEvent, Alert, SensorType, Severity
from aegis.detection.win_memory import (
    MemoryRegion,
    calculate_entropy,
    close_handle,
    enumerate_regions,
    get_loaded_modules,
    open_process_readonly,
    read_memory,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Finding types
# ------------------------------------------------------------------ #


class FindingType(Enum):
    """Categories of suspicious memory findings."""

    REFLECTIVE_DLL = "reflective_dll"
    PROCESS_HOLLOWING = "process_hollowing"
    SHELLCODE = "shellcode"
    RWX_REGION = "rwx_region"
    DOTNET_INJECTION = "dotnet_injection"
    INLINE_HOOK = "inline_hook"
    SUSPICIOUS_THREAD = "suspicious_thread"


# ------------------------------------------------------------------ #
# Finding dataclass
# ------------------------------------------------------------------ #


@dataclass
class MemoryFinding:
    """A single suspicious finding from memory analysis."""

    finding_type: FindingType
    pid: int
    address: int
    size: int
    confidence: float
    details: dict = field(default_factory=dict)
    mitre_id: str = ""


# ------------------------------------------------------------------ #
# Severity mapping
# ------------------------------------------------------------------ #

_FINDING_SEVERITY: dict[FindingType, Severity] = {
    FindingType.REFLECTIVE_DLL: Severity.HIGH,
    FindingType.PROCESS_HOLLOWING: Severity.CRITICAL,
    FindingType.SHELLCODE: Severity.HIGH,
    FindingType.RWX_REGION: Severity.MEDIUM,
    FindingType.DOTNET_INJECTION: Severity.HIGH,
    FindingType.INLINE_HOOK: Severity.HIGH,
    FindingType.SUSPICIOUS_THREAD: Severity.MEDIUM,
}


# ------------------------------------------------------------------ #
# Engine
# ------------------------------------------------------------------ #


class MemoryForensicsEngine:
    """Scans process memory for injection and code-loading artefacts."""

    # ---- individual checks ---------------------------------------- #

    def _check_reflective_dll(
        self,
        region: MemoryRegion,
        data: bytes,
        module_bases: set[int],
    ) -> list[MemoryFinding]:
        """Detect PE headers in private memory not backed by a module.

        A PE image residing in a private, executable region whose base
        address does not match any legitimately loaded module strongly
        indicates reflective DLL injection (MITRE T1620).
        """
        findings: list[MemoryFinding] = []

        # Need at least 0x40 bytes to read the MZ header + PE offset
        if len(data) < 0x40:
            return findings

        # Check MZ signature
        if data[:2] != b"MZ":
            return findings

        # Parse the PE offset from the MZ header at 0x3C
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        except struct.error:
            return findings

        # Validate PE offset is within data bounds
        if pe_offset + 4 > len(data):
            return findings

        # Check PE signature
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return findings

        # Skip known module bases — these are legitimately loaded DLLs
        if region.base_address in module_bases:
            return findings

        findings.append(MemoryFinding(
            finding_type=FindingType.REFLECTIVE_DLL,
            pid=0,
            address=region.base_address,
            size=region.size,
            confidence=0.85,
            details={"has_pe_header": True, "pe_offset": pe_offset},
            mitre_id="T1620",
        ))

        return findings

    def _check_shellcode(
        self,
        region: MemoryRegion,
        data: bytes,
    ) -> list[MemoryFinding]:
        """Detect high-entropy executable private memory (shellcode).

        Shellcode typically has high Shannon entropy (> 6.0) because
        it is densely packed machine code or encrypted payload.
        Maps to MITRE T1055 (Process Injection).
        """
        findings: list[MemoryFinding] = []

        if not region.is_executable or not region.is_private:
            return findings

        entropy = calculate_entropy(data)
        if entropy <= 6.0:
            return findings

        confidence = min(1.0, max(0.0, (entropy - 6.0) / 2.0))

        findings.append(MemoryFinding(
            finding_type=FindingType.SHELLCODE,
            pid=0,
            address=region.base_address,
            size=region.size,
            confidence=confidence,
            details={"entropy": round(entropy, 4)},
            mitre_id="T1055",
        ))

        return findings

    def _check_rwx(
        self,
        region: MemoryRegion,
    ) -> list[MemoryFinding]:
        """Flag private regions with read-write-execute protection.

        RWX memory in private regions is unusual for legitimate code and
        is commonly used by packers and in-memory loaders.
        Maps to MITRE T1055.012 (Process Hollowing).
        """
        findings: list[MemoryFinding] = []

        if not region.is_rwx or not region.is_private:
            return findings

        findings.append(MemoryFinding(
            finding_type=FindingType.RWX_REGION,
            pid=0,
            address=region.base_address,
            size=region.size,
            confidence=0.6,
            details={"protect": hex(region.protect)},
            mitre_id="T1055.012",
        ))

        return findings

    def _check_dotnet_injection(
        self,
        region: MemoryRegion,
        data: bytes,
        module_bases: set[int],
    ) -> list[MemoryFinding]:
        """Detect .NET assemblies loaded into private memory.

        The CLI metadata header signature ``BSJB`` inside a PE image
        in private memory (not from a known module) indicates a .NET
        assembly was injected.  Maps to MITRE T1055.
        """
        findings: list[MemoryFinding] = []

        # Need at least a minimal MZ + PE header
        if len(data) < 0x40:
            return findings

        # Must have MZ header
        if data[:2] != b"MZ":
            return findings

        # Parse and validate PE signature
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        except struct.error:
            return findings

        if pe_offset + 4 > len(data):
            return findings

        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return findings

        # Check for BSJB (.NET CLI metadata signature)
        if b"BSJB" not in data:
            return findings

        # Skip known module bases
        if region.base_address in module_bases:
            return findings

        findings.append(MemoryFinding(
            finding_type=FindingType.DOTNET_INJECTION,
            pid=0,
            address=region.base_address,
            size=region.size,
            confidence=0.80,
            details={"has_bsjb": True},
            mitre_id="T1055",
        ))

        return findings

    # ---- process scanner ------------------------------------------ #

    def scan_process(self, pid: int) -> list[MemoryFinding]:
        """Scan a process for all supported memory injection indicators.

        Opens the target process read-only, enumerates memory regions,
        and runs each detection check on committed, executable, private
        regions.  Returns a list of all findings.
        """
        handle = open_process_readonly(pid)
        if handle is None:
            logger.debug("Cannot open process %d for scanning", pid)
            return []

        try:
            modules = get_loaded_modules(handle)
            module_bases: set[int] = {m.base for m in modules}

            regions = enumerate_regions(handle)
            all_findings: list[MemoryFinding] = []

            for region in regions:
                if not region.is_committed:
                    continue
                if not region.is_executable:
                    continue
                if not region.is_private:
                    continue

                data = read_memory(
                    handle, region.base_address, region.size,
                )
                if data is None:
                    continue

                # Run all detection checks
                findings = self._check_reflective_dll(
                    region, data, module_bases,
                )
                findings += self._check_shellcode(region, data)
                findings += self._check_rwx(region)
                findings += self._check_dotnet_injection(
                    region, data, module_bases,
                )

                # Tag each finding with the PID
                for f in findings:
                    # Dataclass is mutable; set pid
                    object.__setattr__(f, "pid", pid)

                all_findings.extend(findings)

            return all_findings
        finally:
            close_handle(handle)

    # ---- event pipeline interface --------------------------------- #

    def analyze_event(self, event: AegisEvent) -> list[Alert]:
        """Analyze an AegisEvent and return any generated alerts.

        Currently triggers a process scan on ``etw.process_image_load``
        events, converting each :class:`MemoryFinding` into an
        :class:`Alert`.
        """
        if event.event_type != "etw.process_image_load":
            return []

        pid = event.data.get("pid")
        if pid is None:
            return []

        findings = self.scan_process(pid)
        return [self._finding_to_alert(f, event) for f in findings]

    @staticmethod
    def _finding_to_alert(
        finding: MemoryFinding,
        event: AegisEvent,
    ) -> Alert:
        """Convert a MemoryFinding into an Alert."""
        severity = _FINDING_SEVERITY.get(
            finding.finding_type, Severity.MEDIUM,
        )

        return Alert(
            event_id=event.event_id,
            sensor=SensorType.ETW,
            alert_type=finding.finding_type.value,
            severity=severity,
            title=f"Memory forensics: {finding.finding_type.value}",
            description=(
                f"Suspicious memory at 0x{finding.address:X} "
                f"in PID {finding.pid} "
                f"({finding.finding_type.value})"
            ),
            confidence=finding.confidence,
            data={
                "pid": finding.pid,
                "address": hex(finding.address),
                "size": finding.size,
                **finding.details,
            },
            mitre_ids=[finding.mitre_id] if finding.mitre_id else [],
        )
