"""Build script — bundle Aegis into a standalone Windows executable.

Uses PyInstaller to create a single-file distributable.
Run: ``python scripts/build.py``
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"

ENTRY_POINT = SRC_DIR / "aegis" / "__main__.py"
APP_NAME = "aegis"


def clean() -> None:
    """Remove previous build artifacts."""
    for d in (DIST_DIR, BUILD_DIR):
        if d.exists():
            shutil.rmtree(d)
            print(f"Removed {d}")


def build() -> None:
    """Run PyInstaller to create the single-file executable."""
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", APP_NAME,
        "--paths", str(SRC_DIR),
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR),
        "--add-data", f"{SRC_DIR / 'aegis'};aegis",
        str(ENTRY_POINT),
    ]
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    exe = DIST_DIR / f"{APP_NAME}.exe"
    if exe.exists():
        print(f"Build complete: {exe}")
    else:
        print("Build completed but executable not found.")


def main() -> None:
    """Entry point for build script."""
    clean()
    build()


if __name__ == "__main__":
    main()
