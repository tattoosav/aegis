"""Process Watchdog sensor — monitors running processes.

Captures:
- Full process tree with parent-child relationships
- Command-line arguments, executable path, PID
- CPU/memory/thread usage per process
- Feature extraction: cmdline entropy, masquerade detection, lineage depth
- Detects new and terminated processes between collection cycles
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from typing import Any

import psutil

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.base import BaseSensor

logger = logging.getLogger(__name__)

# System binaries expected in specific locations (Windows)
SYSTEM_BINARY_PATHS: dict[str, set[str]] = {
    "svchost.exe": {
        r"c:\windows\system32\svchost.exe",
        r"c:\windows\syswow64\svchost.exe",
    },
    "csrss.exe": {r"c:\windows\system32\csrss.exe"},
    "lsass.exe": {r"c:\windows\system32\lsass.exe"},
    "services.exe": {r"c:\windows\system32\services.exe"},
    "smss.exe": {r"c:\windows\system32\smss.exe"},
    "wininit.exe": {r"c:\windows\system32\wininit.exe"},
    "winlogon.exe": {r"c:\windows\system32\winlogon.exe"},
    "explorer.exe": {r"c:\windows\explorer.exe"},
    "taskhostw.exe": {r"c:\windows\system32\taskhostw.exe"},
    "conhost.exe": {r"c:\windows\system32\conhost.exe"},
    "dllhost.exe": {r"c:\windows\system32\dllhost.exe"},
    "rundll32.exe": {
        r"c:\windows\system32\rundll32.exe",
        r"c:\windows\syswow64\rundll32.exe",
    },
    "cmd.exe": {
        r"c:\windows\system32\cmd.exe",
        r"c:\windows\syswow64\cmd.exe",
    },
    "powershell.exe": {
        r"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
        r"c:\windows\syswow64\windowspowershell\v1.0\powershell.exe",
    },
}

# Attributes we request from psutil.process_iter in a single batch
_PROC_ATTRS = [
    "pid", "ppid", "name", "exe", "cmdline",
    "status", "create_time", "num_threads",
    "username", "cpu_percent", "memory_info",
]


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (bits per character, 0-8 range)."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _is_masquerading(name: str, exe_path: str | None) -> bool:
    """Check if a process name matches a system binary but runs from wrong path."""
    if not exe_path:
        return False
    name_lower = name.lower()
    if name_lower in SYSTEM_BINARY_PATHS:
        expected = SYSTEM_BINARY_PATHS[name_lower]
        actual = exe_path.lower().replace("/", "\\")
        return actual not in expected
    return False


def _compute_lineage_depths(pid_to_ppid: dict[int, int]) -> dict[int, int]:
    """Compute lineage depth for all PIDs from a pid->ppid mapping.

    This avoids per-process psutil.Process() calls by using the already
    collected parent mapping. Depth 0 = root process (ppid=0 or self-parent).
    Handles cycles in the process tree gracefully.
    """
    cache: dict[int, int] = {}

    def _depth(pid: int, visiting: set[int]) -> int:
        if pid in cache:
            return cache[pid]
        ppid = pid_to_ppid.get(pid, 0)
        # Base cases: root, self-parent, unknown parent, or cycle
        if ppid == 0 or ppid == pid or ppid not in pid_to_ppid or ppid in visiting:
            cache[pid] = 0
            return 0
        visiting.add(pid)
        d = 1 + _depth(ppid, visiting)
        cache[pid] = d
        return d

    for pid in pid_to_ppid:
        if pid not in cache:
            _depth(pid, set())

    return cache


class ProcessSensor(BaseSensor):
    """Process Watchdog — monitors running processes and detects anomalies.

    Emits:
    - process_snapshot: per-process data with feature fields
    - process_new: newly appeared process since last collection
    - process_gone: process that disappeared since last collection
    """

    sensor_type = SensorType.PROCESS
    sensor_name = "process_watchdog"

    def __init__(self, interval: float = 5.0, **kwargs: Any):
        super().__init__(interval=interval, **kwargs)
        self._prev_pids: set[int] = set()

    def setup(self) -> None:
        """Initialize — prime psutil's CPU percent tracking."""
        # First cpu_percent() call always returns 0; prime it for all processes
        for proc in psutil.process_iter(attrs=["pid"]):
            try:
                proc.cpu_percent(interval=0)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def collect(self) -> list[AegisEvent]:
        """Collect process data and detect changes.

        Uses psutil.process_iter(attrs=...) for a fast single-pass collection,
        then computes features from the gathered data without extra syscalls.
        """
        events: list[AegisEvent] = []
        current_pids: set[int] = set()
        pid_to_ppid: dict[int, int] = {}
        proc_infos: list[dict[str, Any]] = []

        # --- Single fast pass: gather all process info ---
        for proc in psutil.process_iter(attrs=_PROC_ATTRS):
            info = proc.info
            if info is None:
                continue

            pid = info.get("pid")
            if pid is None:
                continue

            current_pids.add(pid)
            ppid = info.get("ppid") or 0
            pid_to_ppid[pid] = ppid

            # Extract memory in MB
            mem_info = info.get("memory_info")
            memory_mb = round(mem_info.rss / (1024 * 1024), 2) if mem_info else 0.0

            proc_infos.append({
                "pid": pid,
                "ppid": ppid,
                "name": info.get("name") or "",
                "exe": info.get("exe") or "",
                "cmdline_parts": info.get("cmdline") or [],
                "status": info.get("status") or "",
                "username": info.get("username") or "",
                "create_time": info.get("create_time") or 0,
                "cpu_percent": info.get("cpu_percent") or 0.0,
                "memory_mb": memory_mb,
                "num_threads": info.get("num_threads") or 0,
            })

        # --- Compute lineage depths from the pid->ppid map (no extra syscalls) ---
        lineage_depths = _compute_lineage_depths(pid_to_ppid)

        # --- Build events with feature extraction ---
        for pinfo in proc_infos:
            cmdline_str = " ".join(pinfo["cmdline_parts"])
            pid = pinfo["pid"]

            data = {
                "pid": pid,
                "ppid": pinfo["ppid"],
                "name": pinfo["name"],
                "exe": pinfo["exe"],
                "cmdline": cmdline_str,
                "status": pinfo["status"],
                "username": pinfo["username"],
                "create_time": pinfo["create_time"],
                "cpu_percent": pinfo["cpu_percent"],
                "memory_mb": pinfo["memory_mb"],
                "num_threads": pinfo["num_threads"],
                "num_open_files": 0,  # Disabled — proc.open_files() can segfault
                "num_connections": 0,  # Moved to network sensor correlation
                # Feature fields
                "cmdline_entropy": _shannon_entropy(cmdline_str),
                "is_masquerading": _is_masquerading(pinfo["name"], pinfo["exe"]),
                "lineage_depth": lineage_depths.get(pid, 0),
            }

            # Determine severity based on features
            severity = Severity.INFO
            if data["is_masquerading"]:
                severity = Severity.HIGH
            elif data["cmdline_entropy"] > 5.0:
                severity = Severity.MEDIUM

            events.append(AegisEvent(
                sensor=SensorType.PROCESS,
                event_type="process_snapshot",
                severity=severity,
                data=data,
            ))

        # --- Detect new and gone processes ---
        if self._prev_pids:
            new_pids = current_pids - self._prev_pids
            gone_pids = self._prev_pids - current_pids

            for pid in new_pids:
                # Find the info we already collected
                matching = [p for p in proc_infos if p["pid"] == pid]
                if matching:
                    name = matching[0]["name"]
                    exe = matching[0]["exe"]
                else:
                    name = f"pid-{pid}"
                    exe = ""

                events.append(AegisEvent(
                    sensor=SensorType.PROCESS,
                    event_type="process_new",
                    severity=Severity.LOW,
                    data={"pid": pid, "name": name, "exe": exe},
                ))

            for pid in gone_pids:
                events.append(AegisEvent(
                    sensor=SensorType.PROCESS,
                    event_type="process_gone",
                    severity=Severity.INFO,
                    data={"pid": pid},
                ))

        self._prev_pids = current_pids
        return events

    def teardown(self) -> None:
        """Cleanup."""
        self._prev_pids.clear()
