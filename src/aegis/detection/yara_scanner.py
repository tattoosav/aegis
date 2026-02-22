"""YARA rule scanner — file-based malware signature detection.

Loads YARA rules from the rules/yara/ directory, compiles them on startup,
and scans files reported by the FIM sensor. Matches produce Alert objects
via the detection pipeline.

When yara-python is not available, the scanner operates in disabled mode
and scan_file() always returns an empty list.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Graceful import — yara-python requires C build tools
try:
    import yara  # type: ignore[import-untyped]

    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False

# Default rules directory (relative to project root)
_DEFAULT_RULES_DIR = Path(__file__).parent.parent.parent.parent / "rules" / "yara"

# Safety limits
_SCAN_TIMEOUT_SECONDS = 30
_MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB


@dataclass
class YaraMatch:
    """Result of a YARA rule match against a file or bytes."""

    rule_name: str
    tags: list[str]
    meta: dict[str, Any]
    strings_matched: list[str]
    file_path: str = ""
    file_hash: str = ""


class YaraScanner:
    """YARA rule scanning engine.

    Compiles rules from a directory of .yar/.yara files on init.
    Thread-safe: compiled rules object is immutable after loading.
    """

    def __init__(
        self,
        rules_dir: str | Path | None = None,
        scan_timeout: int = _SCAN_TIMEOUT_SECONDS,
        max_file_size: int = _MAX_FILE_SIZE_BYTES,
    ) -> None:
        self._rules_dir = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR
        self._scan_timeout = scan_timeout
        self._max_file_size = max_file_size
        self._compiled_rules: Any = None
        self._rule_count = 0

    @property
    def is_available(self) -> bool:
        """Whether yara-python is installed and rules are loaded."""
        return _HAS_YARA and self._compiled_rules is not None

    @property
    def rule_count(self) -> int:
        """Number of loaded rules."""
        return self._rule_count

    def load_rules(self) -> int:
        """Compile all .yar/.yara files in the rules directory.

        Returns count of rule files loaded.  Raises nothing — logs
        warnings on failure.
        """
        if not _HAS_YARA:
            logger.warning("yara-python not installed — YARA scanning disabled")
            return 0

        if not self._rules_dir.is_dir():
            logger.warning("YARA rules directory not found: %s", self._rules_dir)
            return 0

        filepaths: dict[str, str] = {}
        for ext in ("*.yar", "*.yara"):
            for path in self._rules_dir.glob(ext):
                filepaths[path.stem] = str(path)

        if not filepaths:
            logger.warning("No .yar/.yara files found in %s", self._rules_dir)
            return 0

        try:
            self._compiled_rules = yara.compile(filepaths=filepaths)
            self._rule_count = len(filepaths)
            logger.info(
                "YARA scanner loaded %d rule file(s) from %s",
                self._rule_count,
                self._rules_dir,
            )
            return self._rule_count
        except Exception:
            logger.exception("Failed to compile YARA rules from %s", self._rules_dir)
            self._compiled_rules = None
            self._rule_count = 0
            return 0

    def scan_file(self, file_path: str | Path) -> list[YaraMatch]:
        """Scan a single file against all loaded YARA rules.

        Returns list of matches.  Empty list if no match, scanner
        unavailable, or the file exceeds the size limit.
        """
        if not self.is_available:
            return []

        path = Path(file_path)
        if not path.is_file():
            logger.debug("YARA scan skipped — file not found: %s", path)
            return []

        try:
            if path.stat().st_size > self._max_file_size:
                logger.debug(
                    "YARA scan skipped — file too large: %s (%d bytes)",
                    path,
                    path.stat().st_size,
                )
                return []
        except OSError:
            return []

        try:
            raw_matches = self._compiled_rules.match(
                str(path), timeout=self._scan_timeout,
            )
            return [self._convert_match(m, str(path)) for m in raw_matches]
        except Exception:
            logger.exception("YARA scan failed for %s", path)
            return []

    def scan_bytes(self, data: bytes, identifier: str = "") -> list[YaraMatch]:
        """Scan raw bytes against all loaded YARA rules."""
        if not self.is_available:
            return []
        if not data:
            return []

        try:
            raw_matches = self._compiled_rules.match(
                data=data, timeout=self._scan_timeout,
            )
            return [self._convert_match(m, identifier) for m in raw_matches]
        except Exception:
            logger.exception("YARA scan_bytes failed for %s", identifier)
            return []

    @staticmethod
    def _convert_match(match: Any, source: str) -> YaraMatch:
        """Convert a yara.Match object to our YaraMatch dataclass."""
        strings_matched: list[str] = []
        if hasattr(match, "strings"):
            for s in match.strings:
                if hasattr(s, "identifier"):
                    strings_matched.append(s.identifier)
                else:
                    strings_matched.append(str(s))

        return YaraMatch(
            rule_name=match.rule,
            tags=list(match.tags) if match.tags else [],
            meta=dict(match.meta) if match.meta else {},
            strings_matched=strings_matched,
            file_path=source,
        )
