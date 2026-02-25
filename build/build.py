"""Aegis PyInstaller build script.

Reads version from pyproject.toml, invokes PyInstaller with the
aegis.spec file, copies non-Python asset directories to the dist
output, and prints a build summary.

Usage::

    python build/build.py          # standard build
    python build/build.py --clean  # wipe dist/ before building

The script does **not** require PyInstaller at import time so that it
remains syntactically valid in any Python 3.11+ environment.  If
PyInstaller is missing it exits with a helpful error at build time.
"""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

# ------------------------------------------------------------------
# Path constants
# ------------------------------------------------------------------

BUILD_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BUILD_DIR.parent
SPEC_FILE = BUILD_DIR / "aegis.spec"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
DIST_DIR = PROJECT_ROOT / "dist"
DIST_APP = DIST_DIR / "aegis"

# Non-Python asset directories that must be present in the distribution.
ASSET_DIRS: list[str] = ["rules", "tools", "data"]


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def read_version() -> str:
    """Parse the project version from *pyproject.toml*.

    Returns:
        The version string (e.g. ``"0.1.0"``).

    Raises:
        SystemExit: If the file is missing or lacks a version field.
    """
    if not PYPROJECT.exists():
        print(f"ERROR: {PYPROJECT} not found", file=sys.stderr)
        sys.exit(1)

    with open(PYPROJECT, "rb") as fh:
        data = tomllib.load(fh)

    try:
        return data["project"]["version"]
    except KeyError:
        print(
            "ERROR: [project].version not found in pyproject.toml",
            file=sys.stderr,
        )
        sys.exit(1)


def clean_dist() -> None:
    """Remove the *dist/* directory so the build starts fresh."""
    if DIST_DIR.exists():
        print(f"Cleaning {DIST_DIR} ...")
        shutil.rmtree(DIST_DIR)


def _check_pyinstaller() -> None:
    """Verify that PyInstaller is importable.

    Raises:
        SystemExit: With a helpful message when the package is absent.
    """
    if importlib.util.find_spec("PyInstaller") is None:
        print(
            "ERROR: PyInstaller is not installed.\n"
            "       Install it with:  pip install pyinstaller\n"
            "       Then re-run this script.",
            file=sys.stderr,
        )
        sys.exit(1)


def run_pyinstaller() -> None:
    """Invoke PyInstaller with the spec file.

    Raises:
        SystemExit: If PyInstaller is missing or exits non-zero.
    """
    _check_pyinstaller()
    cmd: list[str] = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR / "work"),
        str(SPEC_FILE),
    ]
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        print("ERROR: PyInstaller failed", file=sys.stderr)
        sys.exit(result.returncode)


def copy_assets() -> None:
    """Copy non-Python asset directories into the dist bundle.

    Each directory listed in :data:`ASSET_DIRS` is copied from the
    project root into ``dist/aegis/<name>``.  Directories that do not
    exist in the source tree are silently skipped.
    """
    for name in ASSET_DIRS:
        src = PROJECT_ROOT / name
        dst = DIST_APP / name
        if not src.exists():
            print(f"  SKIP {name}/ (not found at {src})")
            continue
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        print(f"  Copied {name}/ -> {dst}")


def report_summary(version: str) -> None:
    """Print a build summary with file count and total size.

    Args:
        version: The project version string for the banner.
    """
    if not DIST_APP.exists():
        print("WARNING: dist/aegis/ does not exist; nothing to report")
        return

    total_size = 0
    file_count = 0
    for path in DIST_APP.rglob("*"):
        if path.is_file():
            file_count += 1
            total_size += path.stat().st_size

    size_mb = total_size / (1024 * 1024)

    print()
    print("=" * 60)
    print(f"  Aegis v{version} build complete")
    print(f"  Output : {DIST_APP}")
    print(f"  Files  : {file_count}")
    print(f"  Size   : {size_mb:.1f} MB")
    print("=" * 60)


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed namespace with ``clean`` flag.
    """
    parser = argparse.ArgumentParser(
        description="Build Aegis with PyInstaller",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove dist/ before building",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point: orchestrate the full build pipeline."""
    args = parse_args()
    version = read_version()
    print(f"Building Aegis v{version} ...")

    if args.clean:
        clean_dist()

    run_pyinstaller()
    print("Copying non-Python assets ...")
    copy_assets()
    report_summary(version)


if __name__ == "__main__":
    main()
