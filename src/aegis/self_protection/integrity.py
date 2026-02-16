"""Integrity checker for Aegis source and configuration files.

Provides SHA-256 hash verification of all Aegis Python source files and
individual config files.  Also exposes a lightweight debugger-detection
helper that calls kernel32.IsDebuggerPresent on Windows.

All imports are stdlib-only so this module can run even when third-party
packages are unavailable (e.g. during a tamper-recovery boot).
"""

from __future__ import annotations

import ctypes
import hashlib
import logging
import platform
from pathlib import Path

logger = logging.getLogger(__name__)

_HASH_ALGORITHM = "sha256"
_READ_CHUNK_SIZE = 8192  # bytes


class IntegrityChecker:
    """Verify the integrity of Aegis source files and configuration.

    Parameters
    ----------
    aegis_root:
        Root directory of the Aegis installation.  The checker scans
        ``<aegis_root>/src/aegis/`` for ``.py`` files.
    """

    def __init__(self, aegis_root: Path) -> None:
        self._root = Path(aegis_root)
        self._src_dir = self._root / "src" / "aegis"

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def root(self) -> Path:
        """Return the configured Aegis root directory."""
        return self._root

    @property
    def src_dir(self) -> Path:
        """Return the path to the ``src/aegis`` source tree."""
        return self._src_dir

    # ------------------------------------------------------------------
    # Hash computation
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_file(path: Path) -> str:
        """Return the hex-digest SHA-256 of *path*.

        Reads in fixed-size chunks so that very large files never blow
        up memory.
        """
        h = hashlib.new(_HASH_ALGORITHM)
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(_READ_CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def compute_file_hashes(self) -> dict[str, str]:
        """SHA-256 every ``.py`` file under ``src/aegis/``.

        Returns
        -------
        dict[str, str]
            Mapping of *relative* path (relative to ``aegis_root``,
            using forward slashes) to hex-digest string.
        """
        hashes: dict[str, str] = {}

        if not self._src_dir.is_dir():
            logger.warning(
                "Source directory does not exist: %s", self._src_dir
            )
            return hashes

        for py_file in sorted(self._src_dir.rglob("*.py")):
            rel = py_file.relative_to(self._root).as_posix()
            hashes[rel] = self._hash_file(py_file)

        logger.debug("Computed hashes for %d files.", len(hashes))
        return hashes

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_file_hashes(
        self, known_hashes: dict[str, str]
    ) -> list[str]:
        """Compare current file hashes against *known_hashes*.

        Returns
        -------
        list[str]
            Relative paths of files that are **missing on disk** or
            whose hash **does not match** the known value.
        """
        mismatches: list[str] = []
        current = self.compute_file_hashes()

        for rel_path, expected_hash in known_hashes.items():
            actual_hash = current.get(rel_path)
            if actual_hash is None:
                logger.warning("File missing: %s", rel_path)
                mismatches.append(rel_path)
            elif actual_hash != expected_hash:
                logger.warning(
                    "Hash mismatch for %s: expected=%s actual=%s",
                    rel_path,
                    expected_hash,
                    actual_hash,
                )
                mismatches.append(rel_path)

        return mismatches

    def verify_config_integrity(
        self, config_path: Path, known_hash: str
    ) -> bool:
        """Check whether a single configuration file matches *known_hash*.

        Parameters
        ----------
        config_path:
            Absolute or relative path to the configuration file.
        known_hash:
            Expected SHA-256 hex-digest.

        Returns
        -------
        bool
            ``True`` if the file exists and its hash matches.
        """
        config_path = Path(config_path)
        if not config_path.is_file():
            logger.warning(
                "Config file does not exist: %s", config_path
            )
            return False

        actual = self._hash_file(config_path)
        match = actual == known_hash
        if not match:
            logger.warning(
                "Config hash mismatch for %s: expected=%s actual=%s",
                config_path,
                known_hash,
                actual,
            )
        return match

    # ------------------------------------------------------------------
    # Debugger detection
    # ------------------------------------------------------------------

    @staticmethod
    def check_debugger_attached() -> bool:
        """Return ``True`` if a user-mode debugger is attached.

        Calls ``kernel32.IsDebuggerPresent`` on Windows via :mod:`ctypes`.
        Returns ``False`` on non-Windows platforms or if the ctypes call
        fails for any reason.
        """
        if platform.system() != "Windows":
            return False
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            return bool(kernel32.IsDebuggerPresent())
        except Exception:  # noqa: BLE001
            logger.debug(
                "Could not call IsDebuggerPresent.", exc_info=True
            )
            return False
