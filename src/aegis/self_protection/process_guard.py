"""Process guard for monitoring expected Aegis processes.

Uses :mod:`psutil` to enumerate running system processes and check
whether the expected Aegis service processes are alive.  This is a
lightweight watchdog that can be polled periodically by the Event
Engine or the self-protection subsystem.
"""

from __future__ import annotations

import logging

import psutil

logger = logging.getLogger(__name__)


class ProcessGuard:
    """Monitor a set of expected Aegis processes.

    Parameters
    ----------
    expected_processes:
        List of process names that should be running
        (e.g. ``["aegis_engine", "aegis_sensor"]``).
    """

    def __init__(self, expected_processes: list[str]) -> None:
        self._expected: list[str] = list(expected_processes)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def expected(self) -> list[str]:
        """Return a copy of the expected process name list."""
        return list(self._expected)

    # ------------------------------------------------------------------
    # Single-process check
    # ------------------------------------------------------------------

    def is_process_running(self, name: str) -> bool:
        """Return ``True`` if at least one process with *name* exists.

        The comparison is case-insensitive to account for Windows
        executable naming conventions.

        Parameters
        ----------
        name:
            The process name to look for (without ``.exe`` suffix).
        """
        target = name.lower()
        try:
            for proc in psutil.process_iter(["name"]):
                try:
                    proc_name: str | None = proc.info.get("name")  # type: ignore[union-attr]
                    if proc_name is None:
                        continue
                    # Strip common executable extensions for comparison
                    base = proc_name.lower().removesuffix(".exe")
                    if base == target:
                        return True
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue
        except Exception:  # noqa: BLE001
            logger.debug(
                "Error enumerating processes.", exc_info=True
            )
        return False

    # ------------------------------------------------------------------
    # Bulk checks
    # ------------------------------------------------------------------

    def check_all(self) -> list[str]:
        """Return expected process names that are **not** running.

        Returns
        -------
        list[str]
            Names of expected processes that could not be found among
            the currently running system processes.
        """
        missing: list[str] = []
        for name in self._expected:
            if not self.is_process_running(name):
                missing.append(name)
        if missing:
            logger.warning("Missing expected processes: %s", missing)
        return missing

    def get_running_processes(self) -> list[str]:
        """Return expected process names that **are** currently running.

        Returns
        -------
        list[str]
            Subset of ``expected_processes`` confirmed to be alive.
        """
        running: list[str] = []
        for name in self._expected:
            if self.is_process_running(name):
                running.append(name)
        return running

    def status_summary(self) -> dict[str, bool]:
        """Return a mapping of each expected process to its status.

        Returns
        -------
        dict[str, bool]
            ``{process_name: True}`` if the process is running,
            ``False`` otherwise.
        """
        return {
            name: self.is_process_running(name)
            for name in self._expected
        }
