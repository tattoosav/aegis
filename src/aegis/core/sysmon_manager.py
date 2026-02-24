"""Sysmon manager for Aegis -- install, uninstall, and status checks.

Provides a safe wrapper around Microsoft Sysmon (System Monitor).
The manager can check whether Sysmon is installed, install it with a
given configuration, uninstall it, and retrieve its version.

All subprocess calls are wrapped in try/except so that the manager
works safely even if Sysmon is not present on the system.
"""

from __future__ import annotations

import logging
import re
import subprocess

logger = logging.getLogger(__name__)

_VERSION_RE = re.compile(r"v(\d+\.\d+)")


class SysmonManager:
    """Manage Sysmon installation and status.

    Parameters
    ----------
    sysmon_path:
        Path to the Sysmon64.exe binary.  Defaults to
        ``tools/sysmon/Sysmon64.exe`` relative to the install directory.
    config_path:
        Path to the Sysmon XML config file.  Defaults to
        ``tools/sysmon/sysmonconfig.xml``.
    """

    def __init__(
        self,
        sysmon_path: str = "tools/sysmon/Sysmon64.exe",
        config_path: str = "tools/sysmon/sysmonconfig.xml",
    ) -> None:
        self.sysmon_path = sysmon_path
        self.config_path = config_path

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def is_installed(self) -> bool:
        """Check whether the Sysmon64 service is registered.

        Runs ``sc query Sysmon64`` and returns True if the service
        exists (returncode == 0).
        """
        try:
            result = subprocess.run(
                ["sc", "query", "Sysmon64"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception:
            logger.warning(
                "Failed to query Sysmon64 service status",
                exc_info=True,
            )
            return False

    def install(self) -> bool:
        """Install Sysmon with the configured XML policy.

        Runs ``Sysmon64.exe -accepteula -i <config_path>`` and returns
        True if the command succeeds.
        """
        try:
            result = subprocess.run(
                [
                    self.sysmon_path,
                    "-accepteula",
                    "-i",
                    self.config_path,
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                logger.error(
                    "Sysmon install failed (rc=%d): %s",
                    result.returncode,
                    result.stderr,
                )
                return False
            logger.info("Sysmon installed successfully")
            return True
        except Exception:
            logger.error(
                "Failed to run Sysmon installer",
                exc_info=True,
            )
            return False

    def uninstall(self) -> bool:
        """Uninstall Sysmon.

        Runs ``Sysmon64.exe -u`` and returns True if the command
        succeeds.
        """
        try:
            result = subprocess.run(
                [self.sysmon_path, "-u"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                logger.error(
                    "Sysmon uninstall failed (rc=%d): %s",
                    result.returncode,
                    result.stderr,
                )
                return False
            logger.info("Sysmon uninstalled successfully")
            return True
        except Exception:
            logger.error(
                "Failed to run Sysmon uninstaller",
                exc_info=True,
            )
            return False

    def get_version(self) -> str | None:
        """Return the installed Sysmon version string, or None.

        Parses the output of ``Sysmon64.exe`` looking for a version
        pattern like ``v15.14``.  If the pattern is not found but the
        command succeeded, returns the raw stdout (stripped).
        """
        try:
            result = subprocess.run(
                [self.sysmon_path],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            output = result.stdout.strip()
            match = _VERSION_RE.search(output)
            if match:
                return match.group(1)
            return output if output else None
        except Exception:
            logger.debug(
                "Failed to retrieve Sysmon version",
                exc_info=True,
            )
            return None
