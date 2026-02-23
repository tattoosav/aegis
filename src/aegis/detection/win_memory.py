"""Windows memory API wrappers — ctypes bindings for memory inspection.

Provides mockable wrappers for VirtualQueryEx, ReadProcessMemory,
EnumProcessModulesEx, and thread enumeration.  All functions accept a
handle parameter that tests can stub.

On non-Windows platforms every function returns empty results (graceful
degradation), so the rest of Aegis can import this module safely.
"""

from __future__ import annotations

import ctypes
import logging
import math
import platform
from collections import Counter
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Memory state constants
# ------------------------------------------------------------------ #

MEM_COMMIT: int = 0x1000
MEM_FREE: int = 0x10000
MEM_RESERVE: int = 0x2000

# ------------------------------------------------------------------ #
# Memory type constants
# ------------------------------------------------------------------ #

MEM_PRIVATE: int = 0x20000
MEM_IMAGE: int = 0x1000000
MEM_MAPPED: int = 0x40000

# ------------------------------------------------------------------ #
# Page protection constants
# ------------------------------------------------------------------ #

PAGE_EXECUTE: int = 0x10
PAGE_EXECUTE_READ: int = 0x20
PAGE_EXECUTE_READWRITE: int = 0x40
PAGE_EXECUTE_WRITECOPY: int = 0x80
PAGE_NOACCESS: int = 0x01
PAGE_READONLY: int = 0x02
PAGE_READWRITE: int = 0x04

# ------------------------------------------------------------------ #
# Process access constants
# ------------------------------------------------------------------ #

PROCESS_QUERY_INFORMATION: int = 0x0400
PROCESS_VM_READ: int = 0x0010
THREAD_QUERY_LIMITED_INFORMATION: int = 0x1800

# ------------------------------------------------------------------ #
# Toolhelp snapshot flags
# ------------------------------------------------------------------ #

TH32CS_SNAPTHREAD: int = 0x00000004

# ------------------------------------------------------------------ #
# Executable page protections (for property checks)
# ------------------------------------------------------------------ #

_EXECUTABLE_PROTECTIONS: set[int] = {
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
}

# ------------------------------------------------------------------ #
# Critical system processes
# ------------------------------------------------------------------ #

_CRITICAL_PROCESSES: set[str] = {
    "csrss.exe",
    "lsass.exe",
    "smss.exe",
    "services.exe",
    "svchost.exe",
    "wininit.exe",
    "winlogon.exe",
    "system",
}


# ------------------------------------------------------------------ #
# Dataclasses
# ------------------------------------------------------------------ #


@dataclass(frozen=True)
class MemoryRegion:
    """Describes a contiguous virtual memory region in a process."""

    base_address: int
    size: int
    state: int
    protect: int
    type: int
    allocation_base: int
    allocation_protect: int

    @property
    def is_committed(self) -> bool:
        """Return ``True`` if the region is committed."""
        return self.state == MEM_COMMIT

    @property
    def is_executable(self) -> bool:
        """Return ``True`` if the region has an executable protection."""
        return self.protect in _EXECUTABLE_PROTECTIONS

    @property
    def is_private(self) -> bool:
        """Return ``True`` if the region type is ``MEM_PRIVATE``."""
        return self.type == MEM_PRIVATE

    @property
    def is_rwx(self) -> bool:
        """Return ``True`` if the region is read-write-execute."""
        return self.protect == PAGE_EXECUTE_READWRITE


@dataclass(frozen=True)
class ModuleInfo:
    """Describes a loaded module (DLL) in a process."""

    base: int
    size: int
    name: str
    path: str


@dataclass(frozen=True)
class ThreadInfo:
    """Describes a thread belonging to a process."""

    thread_id: int
    owner_pid: int
    start_address: int


# ------------------------------------------------------------------ #
# Windows ctypes structures (defined only on Windows)
# ------------------------------------------------------------------ #

# We define these at module level so they can be patched in tests.
# On non-Windows the classes still exist but are never used at runtime.

if platform.system() == "Windows":
    class _MemoryBasicInformation(ctypes.Structure):
        """MEMORY_BASIC_INFORMATION structure."""

        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

    class _MODULEINFO(ctypes.Structure):
        """MODULEINFO structure."""

        _fields_ = [
            ("lpBaseOfDll", ctypes.c_void_p),
            ("SizeOfImage", ctypes.c_ulong),
            ("EntryPoint", ctypes.c_void_p),
        ]

    class _THREADENTRY32(ctypes.Structure):
        """THREADENTRY32 structure."""

        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ThreadID", ctypes.c_ulong),
            ("th32OwnerProcessID", ctypes.c_ulong),
            ("tpBasePri", ctypes.c_long),
            ("tpDeltaPri", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
        ]
else:
    # Stubs for non-Windows — never instantiated at runtime.
    class _MemoryBasicInformation:  # type: ignore[no-redef]
        """Stub for non-Windows platforms."""

    class _MODULEINFO:  # type: ignore[no-redef]
        """Stub for non-Windows platforms."""

    class _THREADENTRY32:  # type: ignore[no-redef]
        """Stub for non-Windows platforms."""


# ------------------------------------------------------------------ #
# ctypes configuration (Windows only)
# ------------------------------------------------------------------ #


def _configure_ctypes() -> None:
    """Set ``restype`` and ``argtypes`` for all kernel32/ntdll calls.

    This prevents 64-bit pointer truncation bugs that occur when ctypes
    defaults to ``c_int`` return types for function calls.
    """
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi  # noqa: F841

    # VirtualQueryEx
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_size_t,
    ]

    # ReadProcessMemory
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]

    # OpenProcess
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [
        wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
    ]

    # CloseHandle
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    # CreateToolhelp32Snapshot
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [
        wintypes.DWORD, wintypes.DWORD,
    ]

    # Thread32First / Thread32Next
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32First.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
    ]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
    ]

    # OpenThread
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.OpenThread.argtypes = [
        wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
    ]

    # NtQueryInformationThread (from ntdll)
    ntdll = ctypes.windll.ntdll
    ntdll.NtQueryInformationThread.restype = ctypes.c_long  # NTSTATUS
    ntdll.NtQueryInformationThread.argtypes = [
        wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p,
        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
    ]


if platform.system() == "Windows":
    _configure_ctypes()


# ------------------------------------------------------------------ #
# Thread start-address helper (Windows only)
# ------------------------------------------------------------------ #


def _get_thread_start_address(thread_id: int) -> int:
    """Query the Win32 start address of a thread via NtQueryInformationThread.

    Opens the thread with ``THREAD_QUERY_LIMITED_INFORMATION``, queries
    ``ThreadQuerySetWin32StartAddress`` (info class 9), and returns the
    address.  Returns ``0`` on any failure or on non-Windows.
    """
    if platform.system() != "Windows":
        return 0

    try:
        h_thread = ctypes.windll.kernel32.OpenThread(
            THREAD_QUERY_LIMITED_INFORMATION, False, thread_id,
        )
        if h_thread is None or h_thread == 0:
            return 0

        try:
            start_addr = ctypes.c_void_p(0)
            ret_len = ctypes.c_ulong(0)
            status = ctypes.windll.ntdll.NtQueryInformationThread(
                h_thread,
                9,  # ThreadQuerySetWin32StartAddress
                ctypes.byref(start_addr),
                ctypes.sizeof(start_addr),
                ctypes.byref(ret_len),
            )
            if status != 0:
                return 0
            return start_addr.value or 0
        finally:
            ctypes.windll.kernel32.CloseHandle(h_thread)
    except Exception:
        logger.debug(
            "Failed to get start address for thread %d",
            thread_id,
            exc_info=True,
        )
        return 0


# ------------------------------------------------------------------ #
# Public functions
# ------------------------------------------------------------------ #


def enumerate_regions(handle: int) -> list[MemoryRegion]:
    """Walk process virtual memory regions using VirtualQueryEx.

    Returns a list of :class:`MemoryRegion` objects describing each
    contiguous region.  On non-Windows returns an empty list.
    """
    if platform.system() != "Windows":
        return []

    regions: list[MemoryRegion] = []
    mbi = _MemoryBasicInformation()
    mbi_size = ctypes.sizeof(mbi)
    address = 0

    try:
        while True:
            result = ctypes.windll.kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                mbi_size,
            )
            if result == 0:
                break

            regions.append(MemoryRegion(
                base_address=mbi.BaseAddress or 0,
                size=mbi.RegionSize,
                state=mbi.State,
                protect=mbi.Protect,
                type=mbi.Type,
                allocation_base=mbi.AllocationBase or 0,
                allocation_protect=mbi.AllocationProtect,
            ))

            address = (mbi.BaseAddress or 0) + mbi.RegionSize
    except Exception:
        logger.debug(
            "VirtualQueryEx walk stopped at 0x%X",
            address,
            exc_info=True,
        )

    return regions


def read_memory(
    handle: int,
    address: int,
    size: int,
) -> bytes | None:
    """Read process memory using ReadProcessMemory.

    Returns *size* bytes on success, ``None`` on failure.
    On non-Windows returns ``None``.
    """
    if platform.system() != "Windows":
        return None

    try:
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        ok = ctypes.windll.kernel32.ReadProcessMemory(
            handle,
            ctypes.c_void_p(address),
            buf,
            size,
            ctypes.byref(bytes_read),
        )
        if ok:
            return buf.raw
        return None
    except Exception:
        logger.debug(
            "ReadProcessMemory failed at 0x%X",
            address,
            exc_info=True,
        )
        return None


def get_loaded_modules(handle: int) -> list[ModuleInfo]:
    """List loaded DLLs using EnumProcessModulesEx.

    Returns a list of :class:`ModuleInfo` objects.
    On non-Windows returns an empty list.
    """
    if platform.system() != "Windows":
        return []

    modules: list[ModuleInfo] = []
    try:
        hmod_array_type = (ctypes.c_void_p * 1024)
        hmod_array = hmod_array_type()
        cb_needed = ctypes.c_ulong(0)

        ok = ctypes.windll.psapi.EnumProcessModulesEx(
            handle,
            ctypes.byref(hmod_array),
            ctypes.sizeof(hmod_array),
            ctypes.byref(cb_needed),
            0x03,  # LIST_MODULES_ALL
        )
        if not ok:
            return []

        count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
        for i in range(count):
            hmod = hmod_array[i]
            if hmod is None:
                continue

            # Get module file name
            name_buf = ctypes.create_unicode_buffer(260)
            ctypes.windll.psapi.GetModuleFileNameExW(
                handle, hmod, name_buf, 260,
            )
            path = name_buf.value
            name = path.rsplit("\\", 1)[-1] if path else ""

            # Get module info (size)
            modinfo = _MODULEINFO()
            ctypes.windll.psapi.GetModuleInformation(
                handle,
                hmod,
                ctypes.byref(modinfo),
                ctypes.sizeof(modinfo),
            )

            modules.append(ModuleInfo(
                base=hmod,
                size=modinfo.SizeOfImage,
                name=name,
                path=path,
            ))
    except Exception:
        logger.debug(
            "EnumProcessModulesEx failed",
            exc_info=True,
        )

    return modules


def enumerate_threads(pid: int) -> list[ThreadInfo]:
    """Enumerate threads in a process using CreateToolhelp32Snapshot.

    Returns a list of :class:`ThreadInfo` for all threads owned by
    the given *pid*.  On non-Windows returns an empty list.
    """
    if platform.system() != "Windows":
        return []

    threads: list[ThreadInfo] = []
    try:
        snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPTHREAD, 0,
        )
        if snap is None or snap == ctypes.c_void_p(-1).value:
            return []

        try:
            te = _THREADENTRY32()
            te.dwSize = ctypes.sizeof(te)

            ok = ctypes.windll.kernel32.Thread32First(
                snap, ctypes.byref(te),
            )
            while ok:
                if te.th32OwnerProcessID == pid:
                    threads.append(ThreadInfo(
                        thread_id=te.th32ThreadID,
                        owner_pid=te.th32OwnerProcessID,
                        start_address=_get_thread_start_address(
                            te.th32ThreadID,
                        ),
                    ))
                ok = ctypes.windll.kernel32.Thread32Next(
                    snap, ctypes.byref(te),
                )
        finally:
            ctypes.windll.kernel32.CloseHandle(snap)
    except Exception:
        logger.debug(
            "Thread enumeration failed for pid %d",
            pid,
            exc_info=True,
        )

    return threads


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence.

    Returns ``0.0`` for empty data.  Maximum is ``8.0`` for
    perfectly random data (all 256 byte values equally likely).
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def is_critical_process(name: str) -> bool:
    """Check if *name* is a Windows critical system process.

    Comparison is case-insensitive.
    """
    return name.lower() in _CRITICAL_PROCESSES


def open_process_readonly(pid: int) -> int | None:
    """Open a process with ``QUERY_INFORMATION | VM_READ`` access.

    Returns the process handle on success, ``None`` on failure.
    On non-Windows returns ``None``.
    """
    if platform.system() != "Windows":
        return None

    try:
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid,
        )
        if handle is None or handle == 0:
            return None
        return handle
    except Exception:
        logger.debug(
            "OpenProcess failed for pid %d",
            pid,
            exc_info=True,
        )
        return None


def close_handle(handle: int) -> None:
    """Close a Windows handle.  On non-Windows this is a no-op."""
    if platform.system() != "Windows":
        return

    try:
        ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        logger.debug(
            "CloseHandle failed for handle %d",
            handle,
            exc_info=True,
        )
