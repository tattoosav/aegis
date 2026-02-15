"""File Integrity Monitor (FIM) sensor — detects file system changes.

Monitors critical Windows directories for file creation, modification,
and deletion using a scan-based approach with SHA-256 hashing. Includes
a ransomware tripwire system that places canary files in watched directories
and raises CRITICAL alerts if they are tampered with.

Captures:
- File hash baselines and change detection (new, modified, deleted)
- Ransomware canary file integrity
- Shannon entropy of changed files (high entropy = possible encryption)
- Feature extraction: change rate, file type distribution, entropy trends
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.base import BaseSensor

logger = logging.getLogger(__name__)

# Maximum directory depth to scan (avoid deeply nested trees)
_MAX_SCAN_DEPTH = 2

# Maximum files per directory to avoid hanging on huge folders
_MAX_FILES_PER_DIR = 500

# Size threshold for reading file contents (skip very large files)
_MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

# Canary file name prefix and content signature
_CANARY_PREFIX = ".aegis_canary_"
_CANARY_CONTENT = (
    b"AEGIS SECURITY CANARY FILE -- DO NOT MODIFY OR DELETE.\n"
    b"This file is a ransomware tripwire placed by the Aegis security system.\n"
    b"If this file is altered, encrypted, or removed, it indicates a potential\n"
    b"ransomware attack in progress. Modification timestamp: {ts}\n"
)

# Shannon entropy threshold indicating likely encryption
_HIGH_ENTROPY_THRESHOLD = 7.0

# Default directories to watch on Windows
_DEFAULT_WATCHED_DIRS: list[str] = [
    r"C:\Windows\System32",
    r"C:\Windows\Startup",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]


def _get_user_dirs() -> list[str]:
    """Return user-specific directories to watch.

    Includes the user home directory and the user startup folder.
    """
    dirs: list[str] = []
    home = Path.home()
    dirs.append(str(home))
    # Windows user startup folder
    user_startup = home / "AppData" / "Roaming" / "Microsoft" / "Windows" / (
        "Start Menu"
    ) / "Programs" / "Startup"
    dirs.append(str(user_startup))
    return dirs


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of raw bytes (0.0 – 8.0 scale).

    Values near 8.0 indicate highly random / encrypted content.
    Values near 0.0 indicate uniform or empty content.
    """
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _sha256_file(path: Path) -> str | None:
    """Compute SHA-256 hex digest of a file.

    Returns None if the file cannot be read (permission error, locked, etc.).
    Skips files larger than the size threshold.
    """
    try:
        size = path.stat().st_size
        if size > _MAX_FILE_SIZE_BYTES:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _file_entropy(path: Path) -> float:
    """Calculate Shannon entropy of a file's contents.

    Reads up to the first 64 KB to keep performance reasonable.
    Returns 0.0 if the file cannot be read.
    """
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
        return _shannon_entropy(data)
    except (OSError, PermissionError):
        return 0.0


def _iter_directory(
    root: Path,
    max_depth: int = _MAX_SCAN_DEPTH,
    max_files: int = _MAX_FILES_PER_DIR,
) -> list[Path]:
    """Iterate files in a directory up to a limited depth and count.

    Skips directories and files that are inaccessible. Does not follow
    symlinks. Returns a list of Path objects for regular files only.
    """
    results: list[Path] = []
    if not root.is_dir():
        return results

    # BFS with depth tracking
    queue: list[tuple[Path, int]] = [(root, 0)]
    while queue and len(results) < max_files:
        current, depth = queue.pop(0)
        try:
            entries = list(current.iterdir())
        except (OSError, PermissionError):
            continue

        for entry in entries:
            if len(results) >= max_files:
                break
            try:
                if entry.is_symlink():
                    continue
                if entry.is_file():
                    results.append(entry)
                elif entry.is_dir() and depth < max_depth:
                    queue.append((entry, depth + 1))
            except (OSError, PermissionError):
                continue

    return results


class FileIntegritySensor(BaseSensor):
    """File Integrity Monitor — detects file changes and ransomware activity.

    Emits:
    - file_snapshot: periodic summary with aggregate statistics
    - file_change: individual file creation, modification, or deletion
    - canary_triggered: CRITICAL alert when a ransomware canary is tampered with
    """

    sensor_type = SensorType.FILE
    sensor_name = "file_integrity_monitor"

    def __init__(
        self,
        interval: float = 30.0,
        watched_dirs: list[str] | None = None,
        enable_canary: bool = True,
        **kwargs: Any,
    ):
        """Initialize the file integrity sensor.

        Args:
            interval: Seconds between collection cycles (default 30).
            watched_dirs: List of directory paths to monitor. If None, uses
                the default Windows directories plus user-specific paths.
            enable_canary: Whether to create ransomware canary files.
            **kwargs: Passed through to BaseSensor (e.g. on_event).
        """
        super().__init__(interval=interval, **kwargs)
        if watched_dirs is not None:
            self._watched_dirs = [Path(d) for d in watched_dirs]
        else:
            all_dirs = _DEFAULT_WATCHED_DIRS + _get_user_dirs()
            self._watched_dirs = [Path(d) for d in all_dirs]
        self._enable_canary = enable_canary

        # Hash baseline: path_str -> sha256_hex
        self._baseline: dict[str, str] = {}
        # Canary file paths
        self._canary_paths: list[Path] = []
        # Timing for rate calculations
        self._last_collect_time: float = 0.0

    def setup(self) -> None:
        """Build initial file hash baseline and deploy canary files."""
        logger.info(
            "FileIntegritySensor setup: scanning %d directories",
            len(self._watched_dirs),
        )
        self._baseline = self._build_baseline()
        logger.info(
            "FileIntegritySensor baseline: %d files indexed",
            len(self._baseline),
        )
        if self._enable_canary:
            self._deploy_canaries()
        self._last_collect_time = time.time()

    def collect(self) -> list[AegisEvent]:
        """Re-scan watched directories and detect changes.

        Compares current file hashes against the baseline, emits events
        for new, modified, and deleted files, checks canary integrity,
        and produces a summary snapshot with feature vectors.
        """
        events: list[AegisEvent] = []
        now = time.time()
        elapsed = now - self._last_collect_time if self._last_collect_time else 1.0
        elapsed = max(elapsed, 1.0)  # avoid division by zero

        # --- Check canary files first (highest priority) ---
        canary_events = self._check_canaries()
        events.extend(canary_events)

        # --- Scan current state ---
        current_hashes = self._build_baseline()

        prev_keys = set(self._baseline.keys())
        curr_keys = set(current_hashes.keys())

        new_files = curr_keys - prev_keys
        deleted_files = prev_keys - curr_keys
        common_files = prev_keys & curr_keys
        modified_files: set[str] = set()

        for fpath in common_files:
            if self._baseline[fpath] != current_hashes[fpath]:
                modified_files.add(fpath)

        total_changes = len(new_files) + len(modified_files) + len(deleted_files)

        # Feature extraction
        changed_extensions: set[str] = set()
        entropy_values: list[float] = []
        critical_dir_change_count = 0

        # --- Emit individual file_change events ---
        for fpath in new_files:
            ext = Path(fpath).suffix.lower()
            changed_extensions.add(ext)
            ent = _file_entropy(Path(fpath))
            entropy_values.append(ent)
            if self._is_critical_path(fpath):
                critical_dir_change_count += 1

            events.append(AegisEvent(
                sensor=SensorType.FILE,
                event_type="file_change",
                severity=Severity.LOW,
                data={
                    "change_type": "created",
                    "path": fpath,
                    "hash": current_hashes[fpath],
                    "entropy": ent,
                    "extension": ext,
                },
            ))

        for fpath in modified_files:
            ext = Path(fpath).suffix.lower()
            changed_extensions.add(ext)
            ent = _file_entropy(Path(fpath))
            entropy_values.append(ent)
            if self._is_critical_path(fpath):
                critical_dir_change_count += 1

            severity = Severity.MEDIUM
            if ent >= _HIGH_ENTROPY_THRESHOLD:
                severity = Severity.HIGH

            events.append(AegisEvent(
                sensor=SensorType.FILE,
                event_type="file_change",
                severity=severity,
                data={
                    "change_type": "modified",
                    "path": fpath,
                    "old_hash": self._baseline[fpath],
                    "new_hash": current_hashes[fpath],
                    "entropy": ent,
                    "extension": ext,
                },
            ))

        for fpath in deleted_files:
            # Skip canary deletions here — already handled by _check_canaries
            if self._is_canary_path(fpath):
                continue
            ext = Path(fpath).suffix.lower()
            changed_extensions.add(ext)
            if self._is_critical_path(fpath):
                critical_dir_change_count += 1

            events.append(AegisEvent(
                sensor=SensorType.FILE,
                event_type="file_change",
                severity=Severity.MEDIUM,
                data={
                    "change_type": "deleted",
                    "path": fpath,
                    "old_hash": self._baseline[fpath],
                    "extension": ext,
                },
            ))

        # --- Compute feature vector ---
        elapsed_minutes = elapsed / 60.0
        files_changed_per_minute = (
            total_changes / elapsed_minutes if elapsed_minutes > 0 else 0.0
        )
        avg_entropy = (
            sum(entropy_values) / len(entropy_values) if entropy_values else 0.0
        )

        # Entropy increase rate: compare current average to a neutral baseline (4.0)
        entropy_increase_rate = max(0.0, avg_entropy - 4.0)

        # --- Emit snapshot summary ---
        snapshot_severity = Severity.INFO
        if canary_events:
            snapshot_severity = Severity.CRITICAL
        elif critical_dir_change_count > 0:
            snapshot_severity = Severity.HIGH
        elif total_changes > 50:
            snapshot_severity = Severity.MEDIUM

        events.append(AegisEvent(
            sensor=SensorType.FILE,
            event_type="file_snapshot",
            severity=snapshot_severity,
            data={
                "total_files_tracked": len(current_hashes),
                "files_new": len(new_files),
                "files_modified": len(modified_files),
                "files_deleted": len(deleted_files),
                "total_changes": total_changes,
                "files_changed_per_minute": round(files_changed_per_minute, 2),
                "file_types_changed": sorted(changed_extensions),
                "entropy_increase_rate": round(entropy_increase_rate, 4),
                "critical_dir_changes": critical_dir_change_count,
                "canary_alerts": len(canary_events),
                "watched_dirs": [str(d) for d in self._watched_dirs],
            },
        ))

        # Update baseline and timestamp
        self._baseline = current_hashes
        self._last_collect_time = now
        return events

    def teardown(self) -> None:
        """Clean up canary files and release resources."""
        self._cleanup_canaries()
        self._baseline.clear()
        self._canary_paths.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_baseline(self) -> dict[str, str]:
        """Scan all watched directories and return a path->hash mapping.

        Skips inaccessible directories gracefully.
        """
        baseline: dict[str, str] = {}
        for directory in self._watched_dirs:
            if not directory.exists():
                logger.debug("Skipping non-existent directory: %s", directory)
                continue
            try:
                files = _iter_directory(directory)
            except (OSError, PermissionError) as e:
                logger.debug("Cannot scan %s: %s", directory, e)
                continue

            for fpath in files:
                # Skip our own canary files in the baseline
                if self._is_canary_path(str(fpath)):
                    continue
                file_hash = _sha256_file(fpath)
                if file_hash is not None:
                    baseline[str(fpath)] = file_hash
        return baseline

    def _deploy_canaries(self) -> None:
        """Create canary files in each watched directory.

        If a directory is not writable, the canary for that directory
        is silently skipped.
        """
        self._canary_paths.clear()
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        content = _CANARY_CONTENT.replace(b"{ts}", ts.encode("utf-8"))

        for directory in self._watched_dirs:
            if not directory.exists():
                continue
            canary_path = directory / f"{_CANARY_PREFIX}{os.getpid()}.txt"
            try:
                canary_path.write_bytes(content)
                self._canary_paths.append(canary_path)
                logger.debug("Canary deployed: %s", canary_path)
            except (OSError, PermissionError) as e:
                logger.debug(
                    "Cannot deploy canary in %s: %s", directory, e
                )

    def _check_canaries(self) -> list[AegisEvent]:
        """Verify all canary files are intact.

        Returns CRITICAL events for any canary that has been modified,
        deleted, or whose entropy suggests encryption.
        """
        events: list[AegisEvent] = []
        surviving: list[Path] = []

        for canary in self._canary_paths:
            if not canary.exists():
                events.append(AegisEvent(
                    sensor=SensorType.FILE,
                    event_type="canary_triggered",
                    severity=Severity.CRITICAL,
                    data={
                        "reason": "deleted",
                        "canary_path": str(canary),
                        "message": (
                            "Ransomware tripwire canary file was deleted. "
                            "Possible ransomware activity detected."
                        ),
                    },
                ))
                continue

            # Check if contents have been altered
            try:
                current_data = canary.read_bytes()
                entropy = _shannon_entropy(current_data)

                if b"AEGIS SECURITY CANARY" not in current_data:
                    events.append(AegisEvent(
                        sensor=SensorType.FILE,
                        event_type="canary_triggered",
                        severity=Severity.CRITICAL,
                        data={
                            "reason": "modified",
                            "canary_path": str(canary),
                            "entropy": entropy,
                            "message": (
                                "Ransomware tripwire canary file was modified. "
                                "Original signature not found."
                            ),
                        },
                    ))
                elif entropy >= _HIGH_ENTROPY_THRESHOLD:
                    events.append(AegisEvent(
                        sensor=SensorType.FILE,
                        event_type="canary_triggered",
                        severity=Severity.CRITICAL,
                        data={
                            "reason": "encrypted",
                            "canary_path": str(canary),
                            "entropy": entropy,
                            "message": (
                                "Ransomware tripwire canary shows high entropy "
                                f"({entropy:.2f}), indicating possible encryption."
                            ),
                        },
                    ))
                else:
                    surviving.append(canary)
            except (OSError, PermissionError):
                events.append(AegisEvent(
                    sensor=SensorType.FILE,
                    event_type="canary_triggered",
                    severity=Severity.CRITICAL,
                    data={
                        "reason": "inaccessible",
                        "canary_path": str(canary),
                        "message": (
                            "Ransomware tripwire canary file is no longer "
                            "accessible. Possible ransomware activity."
                        ),
                    },
                ))

        self._canary_paths = surviving
        return events

    def _cleanup_canaries(self) -> None:
        """Remove all canary files on shutdown."""
        for canary in self._canary_paths:
            try:
                if canary.exists():
                    canary.unlink()
                    logger.debug("Canary removed: %s", canary)
            except (OSError, PermissionError):
                logger.debug("Cannot remove canary: %s", canary)

    def _is_canary_path(self, path: str) -> bool:
        """Check whether a file path is one of our canary files."""
        return _CANARY_PREFIX in Path(path).name

    def _is_critical_path(self, path: str) -> bool:
        """Check whether a path is inside a critical system directory."""
        path_lower = path.lower()
        critical_prefixes = [
            r"c:\windows\system32",
            r"c:\windows\startup",
        ]
        return any(path_lower.startswith(p) for p in critical_prefixes)
