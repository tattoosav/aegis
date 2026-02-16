"""Sysmon installation helper.

Downloads and installs Sysinternals Sysmon with the SwiftOnSecurity
configuration for enhanced Windows event logging.

Requires administrator privileges.

Run: ``python scripts/install_sysmon.py``
"""

from __future__ import annotations

import ctypes
import logging
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)

SYSMON_URL = (
    "https://download.sysinternals.com/files/Sysmon.zip"
)
SYSMON_CONFIG_URL = (
    "https://raw.githubusercontent.com/SwiftOnSecurity/"
    "sysmon-config/master/sysmonconfig-export.xml"
)


def is_admin() -> bool:
    """Check whether the current process has administrator privileges."""
    try:
        return ctypes.windll.kernel32.IsUserAnAdmin() != 0  # type: ignore[union-attr]
    except (AttributeError, OSError):
        return False


def download_file(url: str, dest: Path) -> bool:
    """Download a file from *url* to *dest*.  Returns True on success."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Aegis/1.0"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            dest.write_bytes(resp.read())
        return True
    except Exception:
        logger.exception("Failed to download %s", url)
        return False


def install_sysmon(install_dir: Path | None = None) -> bool:
    """Download, extract, and install Sysmon with config.

    Parameters
    ----------
    install_dir:
        Directory to store Sysmon files.  Defaults to
        ``C:\\ProgramData\\Aegis\\sysmon``.

    Returns
    -------
    bool
        True if installation succeeded.
    """
    if not is_admin():
        logger.error(
            "Administrator privileges required to install Sysmon."
        )
        return False

    if install_dir is None:
        install_dir = Path(r"C:\ProgramData\Aegis\sysmon")
    install_dir.mkdir(parents=True, exist_ok=True)

    # Download Sysmon zip
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "Sysmon.zip"
        print("Downloading Sysmon...")
        if not download_file(SYSMON_URL, zip_path):
            return False

        # Extract
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(install_dir)

        # Download config
        config_path = install_dir / "sysmonconfig.xml"
        print("Downloading Sysmon configuration...")
        if not download_file(SYSMON_CONFIG_URL, config_path):
            return False

    # Install Sysmon
    sysmon_exe = install_dir / "Sysmon64.exe"
    if not sysmon_exe.exists():
        sysmon_exe = install_dir / "Sysmon.exe"

    if not sysmon_exe.exists():
        logger.error("Sysmon executable not found after extraction")
        return False

    print(f"Installing Sysmon from {sysmon_exe}...")
    try:
        subprocess.run(
            [
                str(sysmon_exe), "-accepteula", "-i",
                str(install_dir / "sysmonconfig.xml"),
            ],
            check=True,
            capture_output=True,
        )
        print("Sysmon installed successfully.")
        return True
    except subprocess.CalledProcessError as exc:
        logger.error("Sysmon install failed: %s", exc.stderr)
        return False


def main() -> None:
    """Entry point."""
    logging.basicConfig(level=logging.INFO)
    if not is_admin():
        print("ERROR: Please run this script as Administrator.")
        sys.exit(1)
    success = install_sysmon()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
