"""Tests for Windows memory API wrappers.

Verifies ctypes wrappers for VirtualQueryEx, ReadProcessMemory,
EnumProcessModulesEx, thread enumeration, Shannon entropy, and
critical-process classification.  All Windows API calls are mocked.
"""

from __future__ import annotations

import ctypes
from unittest.mock import MagicMock, patch

import pytest

from aegis.detection.win_memory import (
    MEM_COMMIT,
    MEM_PRIVATE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_READWRITE,
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
    THREAD_QUERY_LIMITED_INFORMATION,
    MemoryRegion,
    ModuleInfo,
    ThreadInfo,
    _get_thread_start_address,
    calculate_entropy,
    close_handle,
    enumerate_regions,
    enumerate_threads,
    get_loaded_modules,
    is_critical_process,
    open_process_readonly,
    read_memory,
)

# ------------------------------------------------------------------ #
# MemoryRegion dataclass
# ------------------------------------------------------------------ #


class TestMemoryRegion:
    """MemoryRegion dataclass creation and property access."""

    def test_creation_with_all_fields(self) -> None:
        region = MemoryRegion(
            base_address=0x10000,
            size=4096,
            state=MEM_COMMIT,
            protect=PAGE_READWRITE,
            type=MEM_PRIVATE,
            allocation_base=0x10000,
            allocation_protect=PAGE_READWRITE,
        )
        assert region.base_address == 0x10000
        assert region.size == 4096
        assert region.state == MEM_COMMIT
        assert region.protect == PAGE_READWRITE
        assert region.type == MEM_PRIVATE
        assert region.allocation_base == 0x10000
        assert region.allocation_protect == PAGE_READWRITE

    def test_is_committed_true(self) -> None:
        region = MemoryRegion(
            base_address=0, size=0, state=MEM_COMMIT,
            protect=0, type=0, allocation_base=0,
            allocation_protect=0,
        )
        assert region.is_committed is True

    def test_is_committed_false(self) -> None:
        region = MemoryRegion(
            base_address=0, size=0, state=0x2000,
            protect=0, type=0, allocation_base=0,
            allocation_protect=0,
        )
        assert region.is_committed is False

    def test_is_executable_page_execute_read(self) -> None:
        region = MemoryRegion(
            base_address=0, size=0, state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READ, type=0,
            allocation_base=0, allocation_protect=0,
        )
        assert region.is_executable is True

    def test_is_executable_page_readwrite(self) -> None:
        region = MemoryRegion(
            base_address=0, size=0, state=MEM_COMMIT,
            protect=PAGE_READWRITE, type=0,
            allocation_base=0, allocation_protect=0,
        )
        assert region.is_executable is False

    def test_is_private(self) -> None:
        region = MemoryRegion(
            base_address=0, size=0, state=0,
            protect=0, type=MEM_PRIVATE,
            allocation_base=0, allocation_protect=0,
        )
        assert region.is_private is True

    def test_is_rwx(self) -> None:
        region = MemoryRegion(
            base_address=0, size=0, state=0,
            protect=PAGE_EXECUTE_READWRITE, type=0,
            allocation_base=0, allocation_protect=0,
        )
        assert region.is_rwx is True

    def test_is_rwx_false_for_readonly(self) -> None:
        region = MemoryRegion(
            base_address=0, size=0, state=0,
            protect=PAGE_READONLY, type=0,
            allocation_base=0, allocation_protect=0,
        )
        assert region.is_rwx is False

    def test_frozen(self) -> None:
        region = MemoryRegion(
            base_address=0, size=0, state=0,
            protect=0, type=0, allocation_base=0,
            allocation_protect=0,
        )
        with pytest.raises(AttributeError):
            region.size = 999  # type: ignore[misc]


# ------------------------------------------------------------------ #
# ModuleInfo dataclass
# ------------------------------------------------------------------ #


class TestModuleInfo:
    """ModuleInfo dataclass creation and field access."""

    def test_creation(self) -> None:
        mod = ModuleInfo(
            base=0x7FF00000,
            size=0x1000,
            name="kernel32.dll",
            path="C:\\Windows\\System32\\kernel32.dll",
        )
        assert mod.base == 0x7FF00000
        assert mod.size == 0x1000
        assert mod.name == "kernel32.dll"
        assert mod.path == "C:\\Windows\\System32\\kernel32.dll"

    def test_frozen(self) -> None:
        mod = ModuleInfo(base=0, size=0, name="", path="")
        with pytest.raises(AttributeError):
            mod.name = "new"  # type: ignore[misc]


# ------------------------------------------------------------------ #
# ThreadInfo dataclass
# ------------------------------------------------------------------ #


class TestThreadInfo:
    """ThreadInfo dataclass creation and field access."""

    def test_creation(self) -> None:
        info = ThreadInfo(
            thread_id=1234,
            owner_pid=5678,
            start_address=0xDEADBEEF,
        )
        assert info.thread_id == 1234
        assert info.owner_pid == 5678
        assert info.start_address == 0xDEADBEEF

    def test_frozen(self) -> None:
        info = ThreadInfo(thread_id=0, owner_pid=0, start_address=0)
        with pytest.raises(AttributeError):
            info.thread_id = 99  # type: ignore[misc]


# ------------------------------------------------------------------ #
# Constants
# ------------------------------------------------------------------ #


class TestConstants:
    """Verify key constants are correct."""

    def test_mem_commit(self) -> None:
        assert MEM_COMMIT == 0x1000

    def test_mem_private(self) -> None:
        assert MEM_PRIVATE == 0x20000

    def test_page_execute_readwrite(self) -> None:
        assert PAGE_EXECUTE_READWRITE == 0x40

    def test_page_execute_read(self) -> None:
        assert PAGE_EXECUTE_READ == 0x20

    def test_page_noaccess(self) -> None:
        assert PAGE_NOACCESS == 0x01

    def test_process_query_information(self) -> None:
        assert PROCESS_QUERY_INFORMATION == 0x0400

    def test_process_vm_read(self) -> None:
        assert PROCESS_VM_READ == 0x0010


# ------------------------------------------------------------------ #
# calculate_entropy — pure Python, no platform dependence
# ------------------------------------------------------------------ #


class TestCalculateEntropy:
    """Shannon entropy calculation."""

    def test_empty_bytes_returns_zero(self) -> None:
        assert calculate_entropy(b"") == 0.0

    def test_all_zeros_returns_zero(self) -> None:
        assert calculate_entropy(b"\x00" * 1024) == 0.0

    def test_single_byte_value_returns_zero(self) -> None:
        assert calculate_entropy(b"\xff" * 256) == 0.0

    def test_uniform_random_near_eight(self) -> None:
        # All 256 byte values equally represented → entropy == 8.0
        data = bytes(range(256)) * 4
        result = calculate_entropy(data)
        assert abs(result - 8.0) < 0.01

    def test_low_entropy_string(self) -> None:
        data = b"aaaaaabbbb"
        result = calculate_entropy(data)
        assert result < 2.0

    def test_two_equal_values(self) -> None:
        # 50/50 split → entropy == 1.0
        data = b"\x00\x01" * 512
        result = calculate_entropy(data)
        assert abs(result - 1.0) < 0.01

    def test_returns_float(self) -> None:
        assert isinstance(calculate_entropy(b"\x42"), float)


# ------------------------------------------------------------------ #
# is_critical_process — pure Python, no platform dependence
# ------------------------------------------------------------------ #


class TestIsCriticalProcess:
    """Critical process name detection."""

    @pytest.mark.parametrize("name", [
        "csrss.exe", "lsass.exe", "smss.exe", "services.exe",
        "svchost.exe", "wininit.exe", "winlogon.exe", "system",
    ])
    def test_critical_processes(self, name: str) -> None:
        assert is_critical_process(name) is True

    def test_case_insensitive(self) -> None:
        assert is_critical_process("CSRSS.EXE") is True
        assert is_critical_process("Lsass.exe") is True

    def test_non_critical(self) -> None:
        assert is_critical_process("notepad.exe") is False
        assert is_critical_process("chrome.exe") is False

    def test_empty_string(self) -> None:
        assert is_critical_process("") is False


# ------------------------------------------------------------------ #
# enumerate_regions — mocked VirtualQueryEx
# ------------------------------------------------------------------ #


class TestEnumerateRegions:
    """Memory region enumeration via VirtualQueryEx."""

    @patch("aegis.detection.win_memory.platform")
    def test_non_windows_returns_empty(
        self, mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Linux"
        assert enumerate_regions(0) == []

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_walks_regions(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"

        # Build a fake MEMORY_BASIC_INFORMATION structure
        mbi = MagicMock()
        mbi.BaseAddress = 0x10000
        mbi.RegionSize = 4096
        mbi.State = MEM_COMMIT
        mbi.Protect = PAGE_READWRITE
        mbi.Type = MEM_PRIVATE
        mbi.AllocationBase = 0x10000
        mbi.AllocationProtect = PAGE_READWRITE

        # First call succeeds, second call fails (returns 0)
        mock_vqe = MagicMock()
        call_count = 0

        def vqe_side_effect(*args) -> int:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return ctypes.sizeof(ctypes.c_size_t)  # non-zero
            return 0

        mock_vqe.side_effect = vqe_side_effect
        mock_ctypes.windll.kernel32.VirtualQueryEx = mock_vqe
        mock_ctypes.sizeof.return_value = ctypes.sizeof(
            ctypes.c_size_t,
        )

        # Provide a mock constructor for MEMORY_BASIC_INFORMATION
        mock_mbi_class = MagicMock(return_value=mbi)
        mock_ctypes.Structure = ctypes.Structure

        with patch(
            "aegis.detection.win_memory._MemoryBasicInformation",
            mock_mbi_class,
        ):
            regions = enumerate_regions(123)

        assert len(regions) >= 1
        r = regions[0]
        assert r.base_address == 0x10000
        assert r.size == 4096
        assert r.state == MEM_COMMIT

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_empty_when_vqe_fails_immediately(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_ctypes.windll.kernel32.VirtualQueryEx.return_value = 0
        mock_ctypes.sizeof.return_value = 48

        mock_mbi_class = MagicMock()
        with patch(
            "aegis.detection.win_memory._MemoryBasicInformation",
            mock_mbi_class,
        ):
            regions = enumerate_regions(123)
        assert regions == []


# ------------------------------------------------------------------ #
# read_memory — mocked ReadProcessMemory
# ------------------------------------------------------------------ #


class TestReadMemory:
    """Process memory reading via ReadProcessMemory."""

    @patch("aegis.detection.win_memory.platform")
    def test_non_windows_returns_none(
        self, mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Linux"
        assert read_memory(0, 0x1000, 64) is None

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_success_returns_bytes(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"

        # ReadProcessMemory returns non-zero on success
        mock_rpm = MagicMock(return_value=1)
        mock_ctypes.windll.kernel32.ReadProcessMemory = mock_rpm
        mock_ctypes.c_size_t = ctypes.c_size_t
        mock_ctypes.c_void_p = ctypes.c_void_p
        mock_ctypes.byref = ctypes.byref
        real_buf = ctypes.create_string_buffer(64)
        mock_ctypes.create_string_buffer.return_value = real_buf

        result = read_memory(123, 0x10000, 64)
        assert result is not None
        assert isinstance(result, bytes)
        assert len(result) == 64

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_failure_returns_none(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"

        mock_rpm = MagicMock(return_value=0)
        mock_ctypes.windll.kernel32.ReadProcessMemory = mock_rpm
        mock_ctypes.c_size_t = ctypes.c_size_t
        mock_ctypes.c_void_p = ctypes.c_void_p
        mock_ctypes.byref = ctypes.byref
        mock_ctypes.create_string_buffer.return_value = (
            ctypes.create_string_buffer(64)
        )

        result = read_memory(123, 0x10000, 64)
        assert result is None


# ------------------------------------------------------------------ #
# get_loaded_modules — mocked EnumProcessModulesEx
# ------------------------------------------------------------------ #


class TestGetLoadedModules:
    """Module enumeration via EnumProcessModulesEx."""

    @patch("aegis.detection.win_memory.platform")
    def test_non_windows_returns_empty(
        self, mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Linux"
        assert get_loaded_modules(0) == []

    @patch("aegis.detection.win_memory.platform")
    def test_returns_modules(
        self,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"

        # Mock the psapi functions directly on the real ctypes.windll
        mock_enum = MagicMock()
        mock_get_name = MagicMock()
        mock_get_info = MagicMock(return_value=1)

        def enum_side(handle, array_ref, size, cb_needed_ref, flags):
            array_ref._obj[0] = 0x7FF00000
            cb_needed_ref._obj.value = ctypes.sizeof(
                ctypes.c_void_p,
            )
            return 1

        mock_enum.side_effect = enum_side

        def get_name_side(handle, hmod, buf, buf_size):
            path = "C:\\Windows\\System32\\kernel32.dll"
            for i, ch in enumerate(path):
                buf[i] = ch
            buf[len(path)] = "\0"
            return len(path)

        mock_get_name.side_effect = get_name_side

        # Use real ctypes structure for _MODULEINFO
        from aegis.detection.win_memory import _MODULEINFO
        real_modinfo = _MODULEINFO()
        real_modinfo.SizeOfImage = 0x1000

        with (
            patch.object(
                ctypes.windll.psapi,
                "EnumProcessModulesEx",
                mock_enum,
            ),
            patch.object(
                ctypes.windll.psapi,
                "GetModuleFileNameExW",
                mock_get_name,
            ),
            patch.object(
                ctypes.windll.psapi,
                "GetModuleInformation",
                mock_get_info,
            ),
            patch(
                "aegis.detection.win_memory._MODULEINFO",
                MagicMock(return_value=real_modinfo),
            ),
        ):
            modules = get_loaded_modules(123)

        assert mock_enum.called
        assert len(modules) == 1
        assert modules[0].name == "kernel32.dll"
        assert modules[0].base == 0x7FF00000


# ------------------------------------------------------------------ #
# enumerate_threads — mocked CreateToolhelp32Snapshot
# ------------------------------------------------------------------ #


class TestEnumerateThreads:
    """Thread enumeration via CreateToolhelp32Snapshot."""

    @patch("aegis.detection.win_memory.platform")
    def test_non_windows_returns_empty(
        self, mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Linux"
        assert enumerate_threads(1234) == []

    @patch("aegis.detection.win_memory._get_thread_start_address")
    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_returns_threads_for_pid(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
        mock_get_start: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_get_start.return_value = 0x7FF00000

        # Snapshot handle
        mock_ctypes.windll.kernel32.CreateToolhelp32Snapshot = (
            MagicMock(return_value=42)
        )

        # Build a fake THREADENTRY32
        te = MagicMock()
        te.th32OwnerProcessID = 1234
        te.th32ThreadID = 100

        # Thread32First succeeds, Thread32Next fails (one thread)
        mock_ctypes.windll.kernel32.Thread32First = MagicMock(
            return_value=1,
        )
        call_count = 0

        def next_side(*args):
            nonlocal call_count
            call_count += 1
            return 0  # No more threads

        mock_ctypes.windll.kernel32.Thread32Next = MagicMock(
            side_effect=next_side,
        )
        mock_ctypes.windll.kernel32.CloseHandle = MagicMock()

        with patch(
            "aegis.detection.win_memory._THREADENTRY32",
            MagicMock(return_value=te),
        ):
            threads = enumerate_threads(1234)

        assert len(threads) == 1
        assert threads[0].thread_id == 100
        assert threads[0].owner_pid == 1234
        assert threads[0].start_address == 0x7FF00000
        mock_get_start.assert_called_once_with(100)

    @patch("aegis.detection.win_memory._get_thread_start_address")
    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_filters_threads_by_pid(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
        mock_get_start: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_get_start.return_value = 0xABCD

        mock_ctypes.windll.kernel32.CreateToolhelp32Snapshot = (
            MagicMock(return_value=42)
        )

        te = MagicMock()
        first_call = True

        def first_side(*args):
            nonlocal first_call
            te.th32OwnerProcessID = 9999  # different PID
            te.th32ThreadID = 200
            first_call = False
            return 1

        def next_side(*args):
            return 0

        mock_ctypes.windll.kernel32.Thread32First = MagicMock(
            side_effect=first_side,
        )
        mock_ctypes.windll.kernel32.Thread32Next = MagicMock(
            side_effect=next_side,
        )
        mock_ctypes.windll.kernel32.CloseHandle = MagicMock()

        with patch(
            "aegis.detection.win_memory._THREADENTRY32",
            MagicMock(return_value=te),
        ):
            threads = enumerate_threads(1234)

        assert threads == []
        mock_get_start.assert_not_called()

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_invalid_snapshot_returns_empty(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_ctypes.c_void_p = ctypes.c_void_p
        # INVALID_HANDLE_VALUE (-1 as unsigned)
        mock_ctypes.windll.kernel32.CreateToolhelp32Snapshot = (
            MagicMock(return_value=ctypes.c_void_p(-1).value)
        )
        threads = enumerate_threads(1234)
        assert threads == []

    @patch("aegis.detection.win_memory._get_thread_start_address")
    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_snapshot_handle_always_closed(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
        mock_get_start: MagicMock,
    ) -> None:
        """Verify CloseHandle is called even when iteration raises."""
        mock_platform.system.return_value = "Windows"
        mock_get_start.return_value = 0

        mock_ctypes.windll.kernel32.CreateToolhelp32Snapshot = (
            MagicMock(return_value=42)
        )
        mock_close = MagicMock()
        mock_ctypes.windll.kernel32.CloseHandle = mock_close

        te = MagicMock()
        te.th32OwnerProcessID = 1234
        te.th32ThreadID = 100

        mock_ctypes.windll.kernel32.Thread32First = MagicMock(
            side_effect=RuntimeError("boom"),
        )

        with patch(
            "aegis.detection.win_memory._THREADENTRY32",
            MagicMock(return_value=te),
        ):
            threads = enumerate_threads(1234)

        # Snapshot handle must be closed despite the exception
        mock_close.assert_called_once_with(42)
        assert threads == []


# ------------------------------------------------------------------ #
# open_process_readonly
# ------------------------------------------------------------------ #


class TestOpenProcessReadonly:
    """open_process_readonly wrapper."""

    @patch("aegis.detection.win_memory.platform")
    def test_non_windows_returns_none(
        self, mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Linux"
        assert open_process_readonly(1234) is None

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_success_returns_handle(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_ctypes.windll.kernel32.OpenProcess = MagicMock(
            return_value=42,
        )
        handle = open_process_readonly(1234)
        assert handle == 42

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_failure_returns_none(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_ctypes.windll.kernel32.OpenProcess = MagicMock(
            return_value=0,
        )
        handle = open_process_readonly(1234)
        assert handle is None


# ------------------------------------------------------------------ #
# close_handle
# ------------------------------------------------------------------ #


class TestCloseHandle:
    """close_handle wrapper."""

    @patch("aegis.detection.win_memory.platform")
    def test_non_windows_noop(
        self, mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Linux"
        # Should not raise
        close_handle(42)

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_calls_closehandle(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_close = MagicMock()
        mock_ctypes.windll.kernel32.CloseHandle = mock_close
        close_handle(42)
        mock_close.assert_called_once_with(42)


# ------------------------------------------------------------------ #
# _get_thread_start_address — mocked OpenThread + NtQuery
# ------------------------------------------------------------------ #


class TestGetThreadStartAddress:
    """Thread start address retrieval via NtQueryInformationThread."""

    @patch("aegis.detection.win_memory.platform")
    def test_non_windows_returns_zero(
        self, mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Linux"
        assert _get_thread_start_address(100) == 0

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_open_thread_failure_returns_zero(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_ctypes.windll.kernel32.OpenThread = MagicMock(
            return_value=0,
        )
        assert _get_thread_start_address(100) == 0

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_open_thread_none_returns_zero(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_ctypes.windll.kernel32.OpenThread = MagicMock(
            return_value=None,
        )
        assert _get_thread_start_address(100) == 0

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_ntstatus_failure_returns_zero(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_ctypes.windll.kernel32.OpenThread = MagicMock(
            return_value=99,
        )
        mock_ctypes.windll.kernel32.CloseHandle = MagicMock()
        mock_ctypes.windll.ntdll.NtQueryInformationThread = (
            MagicMock(return_value=-1)  # non-zero NTSTATUS = failure
        )
        mock_ctypes.c_void_p = ctypes.c_void_p
        mock_ctypes.c_ulong = ctypes.c_ulong
        mock_ctypes.byref = ctypes.byref
        mock_ctypes.sizeof = ctypes.sizeof

        assert _get_thread_start_address(100) == 0
        mock_ctypes.windll.kernel32.CloseHandle.assert_called_with(99)

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_success_returns_address(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_ctypes.windll.kernel32.OpenThread = MagicMock(
            return_value=99,
        )
        mock_ctypes.windll.kernel32.CloseHandle = MagicMock()
        mock_ctypes.windll.ntdll.NtQueryInformationThread = (
            MagicMock(return_value=0)  # STATUS_SUCCESS
        )
        mock_ctypes.c_void_p = ctypes.c_void_p
        mock_ctypes.c_ulong = ctypes.c_ulong
        mock_ctypes.byref = ctypes.byref
        mock_ctypes.sizeof = ctypes.sizeof

        # The address is read from the c_void_p object, which
        # defaults to None when NtQuery doesn't actually write.
        # In real usage the kernel writes the address.
        result = _get_thread_start_address(100)
        assert isinstance(result, int)
        mock_ctypes.windll.kernel32.CloseHandle.assert_called_with(99)

    @patch("aegis.detection.win_memory.platform")
    @patch("aegis.detection.win_memory.ctypes")
    def test_exception_returns_zero(
        self,
        mock_ctypes: MagicMock,
        mock_platform: MagicMock,
    ) -> None:
        mock_platform.system.return_value = "Windows"
        mock_ctypes.windll.kernel32.OpenThread = MagicMock(
            side_effect=OSError("access denied"),
        )
        assert _get_thread_start_address(100) == 0

    def test_thread_query_limited_info_constant(self) -> None:
        """THREAD_QUERY_LIMITED_INFORMATION must be 0x1800."""
        assert THREAD_QUERY_LIMITED_INFORMATION == 0x1800
