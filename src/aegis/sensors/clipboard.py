"""Clipboard & Screen Monitor sensor — monitors clipboard activity and screen capture.

Detects:
- Clipboard content changes (via SHA-256 hash, never storing actual content)
- Clipboard hijacking (rapid modifications, replace attacks)
- Sensitive data patterns in clipboard (credit cards, SSNs, API keys, crypto wallets)
- Screen capture processes using known capture tool signatures

Privacy: Actual clipboard content is NEVER stored or logged. Only metadata
(content length, content type, SHA-256 hash) is recorded for change detection.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from typing import Any

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.base import BaseSensor

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Optional win32clipboard import — graceful fallback for non-Windows / tests
# --------------------------------------------------------------------------- #
try:
    import win32clipboard  # type: ignore[import-untyped]
    _HAS_WIN32 = True
except ImportError:
    _HAS_WIN32 = False
    logger.info("win32clipboard not available — clipboard sensor runs in stub mode")

# --------------------------------------------------------------------------- #
# Optional psutil import for screen-capture process detection
# --------------------------------------------------------------------------- #
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

# --------------------------------------------------------------------------- #
# Sensitive data regex patterns
# --------------------------------------------------------------------------- #
_SENSITIVE_PATTERNS: dict[str, re.Pattern[str]] = {
    "credit_card": re.compile(
        r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
    ),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "api_key": re.compile(r"\b[A-Za-z0-9]{32,}\b"),
    "crypto_btc": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "crypto_eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
}

# --------------------------------------------------------------------------- #
# Screen-capture process name fragments (case-insensitive match)
# --------------------------------------------------------------------------- #
_SCREEN_CAPTURE_NAMES: list[str] = [
    "screenshot",
    "capture",
    "snip",
    "obs",
    "screenrec",
]

# Maximum clipboard changes per minute before flagging hijacking
_HIJACK_CHANGE_THRESHOLD = 5

# Sliding window length in seconds for hijack detection
_HIJACK_WINDOW_SECS = 60.0


def _sha256(text: str) -> str:
    """Return the hex SHA-256 digest of *text*."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _get_clipboard_text() -> str | None:
    """Read current clipboard text via win32clipboard.

    Returns ``None`` when win32clipboard is unavailable or the clipboard
    does not contain text data.
    """
    if not _HAS_WIN32:
        return None
    try:
        win32clipboard.OpenClipboard()
        try:
            if win32clipboard.IsClipboardFormatAvailable(
                win32clipboard.CF_UNICODETEXT
            ):
                data = win32clipboard.GetClipboardData(
                    win32clipboard.CF_UNICODETEXT
                )
                return str(data) if data else None
            return None
        finally:
            win32clipboard.CloseClipboard()
    except Exception as exc:
        logger.debug("Failed to read clipboard: %s", exc)
        return None


def _detect_sensitive_patterns(text: str) -> list[dict[str, Any]]:
    """Scan *text* for sensitive data patterns.

    Returns a list of dicts describing each match type found. Actual
    matched content is **never** included — only the pattern name and
    the number of occurrences.
    """
    findings: list[dict[str, Any]] = []
    for pattern_name, regex in _SENSITIVE_PATTERNS.items():
        matches = regex.findall(text)
        if matches:
            findings.append({
                "pattern": pattern_name,
                "count": len(matches),
            })
    return findings


def _find_screen_capture_processes() -> list[dict[str, Any]]:
    """Return metadata for running processes whose names suggest screen capture.

    Uses psutil when available; returns an empty list otherwise.
    """
    if not _HAS_PSUTIL:
        return []
    results: list[dict[str, Any]] = []
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            info = proc.info
            name: str = (info.get("name") or "").lower()
            for fragment in _SCREEN_CAPTURE_NAMES:
                if fragment in name:
                    results.append({
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "match_fragment": fragment,
                    })
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results


class ClipboardSensor(BaseSensor):
    """Clipboard & Screen Monitor — watches clipboard changes and capture tools.

    Emits:
    - clipboard_snapshot: periodic summary of clipboard state
    - clipboard_change: clipboard content changed (hash, type, length only)
    - clipboard_hijack: potential clipboard hijacking detected (HIGH)
    - sensitive_data: sensitive pattern found in clipboard (MEDIUM)
    - screen_capture: screen capture process detected (MEDIUM)
    """

    sensor_type = SensorType.CLIPBOARD
    sensor_name = "clipboard_monitor"

    def __init__(self, interval: float = 5.0, **kwargs: Any):
        super().__init__(interval=interval, **kwargs)
        # Clipboard state tracking
        self._prev_hash: str | None = None
        self._prev_content_length: int = 0
        self._prev_content_type: str = "unknown"

        # Hijacking detection — timestamps of recent clipboard changes
        self._change_timestamps: list[float] = []

        # Screen capture process tracking
        self._known_capture_pids: set[int] = set()

    # ------------------------------------------------------------------ #
    # BaseSensor interface
    # ------------------------------------------------------------------ #

    def setup(self) -> None:
        """Record the initial clipboard hash so the first collect() has a baseline."""
        text = _get_clipboard_text()
        if text is not None:
            self._prev_hash = _sha256(text)
            self._prev_content_length = len(text)
            self._prev_content_type = "text"
        else:
            self._prev_hash = None
            self._prev_content_length = 0
            self._prev_content_type = "empty"
        self._change_timestamps.clear()
        self._known_capture_pids.clear()
        logger.info(
            "ClipboardSensor initialised (win32=%s, psutil=%s)",
            _HAS_WIN32,
            _HAS_PSUTIL,
        )

    def collect(self) -> list[AegisEvent]:
        """Check clipboard state, detect changes, patterns, and capture tools."""
        events: list[AegisEvent] = []
        now = time.time()

        # ---- Clipboard analysis ---- #
        text = _get_clipboard_text()
        current_hash: str | None = None
        content_length = 0
        content_type = "empty"

        if text is not None:
            current_hash = _sha256(text)
            content_length = len(text)
            content_type = "text"

        changed = (current_hash != self._prev_hash)

        # -- clipboard_change event -- #
        if changed:
            self._change_timestamps.append(now)
            events.append(AegisEvent(
                sensor=SensorType.CLIPBOARD,
                event_type="clipboard_change",
                severity=Severity.LOW,
                data={
                    "content_hash": current_hash or "",
                    "content_type": content_type,
                    "content_length": content_length,
                    "previous_hash": self._prev_hash or "",
                    "previous_length": self._prev_content_length,
                },
            ))

        # -- clipboard hijacking detection -- #
        # Prune timestamps outside the sliding window
        self._change_timestamps = [
            ts for ts in self._change_timestamps
            if now - ts <= _HIJACK_WINDOW_SECS
        ]
        if len(self._change_timestamps) > _HIJACK_CHANGE_THRESHOLD:
            events.append(AegisEvent(
                sensor=SensorType.CLIPBOARD,
                event_type="clipboard_hijack",
                severity=Severity.HIGH,
                data={
                    "changes_in_window": len(self._change_timestamps),
                    "window_seconds": _HIJACK_WINDOW_SECS,
                    "threshold": _HIJACK_CHANGE_THRESHOLD,
                    "current_hash": current_hash or "",
                    "content_length": content_length,
                },
            ))

        # -- sensitive data pattern matching -- #
        if text is not None and changed:
            findings = _detect_sensitive_patterns(text)
            if findings:
                events.append(AegisEvent(
                    sensor=SensorType.CLIPBOARD,
                    event_type="sensitive_data",
                    severity=Severity.MEDIUM,
                    data={
                        "patterns_found": findings,
                        "content_hash": current_hash or "",
                        "content_length": content_length,
                    },
                ))

        # -- screen capture detection -- #
        capture_procs = _find_screen_capture_processes()
        capture_pids = {p["pid"] for p in capture_procs}
        new_capture = capture_pids - self._known_capture_pids
        if new_capture:
            new_procs = [p for p in capture_procs if p["pid"] in new_capture]
            events.append(AegisEvent(
                sensor=SensorType.CLIPBOARD,
                event_type="screen_capture",
                severity=Severity.MEDIUM,
                data={
                    "new_processes": new_procs,
                    "total_capture_processes": len(capture_procs),
                },
            ))
        self._known_capture_pids = capture_pids

        # -- periodic clipboard snapshot -- #
        events.append(AegisEvent(
            sensor=SensorType.CLIPBOARD,
            event_type="clipboard_snapshot",
            severity=Severity.INFO,
            data={
                "content_hash": current_hash or "",
                "content_type": content_type,
                "content_length": content_length,
                "changed_since_last": changed,
                "changes_in_last_minute": len(self._change_timestamps),
                "screen_capture_processes": len(capture_pids),
                "win32_available": _HAS_WIN32,
            },
        ))

        # Update state for next cycle
        self._prev_hash = current_hash
        self._prev_content_length = content_length
        self._prev_content_type = content_type

        return events

    def teardown(self) -> None:
        """Cleanup internal state."""
        self._change_timestamps.clear()
        self._known_capture_pids.clear()
        self._prev_hash = None
