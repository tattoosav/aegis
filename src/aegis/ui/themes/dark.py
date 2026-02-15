"""Aegis dark theme loader.

Provides the ``load_dark_stylesheet`` helper that reads the QSS file
bundled alongside this module and returns it as a string suitable for
``QApplication.setStyleSheet()``.
"""

from __future__ import annotations

from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_QSS_PATH = _THIS_DIR / "dark.qss"


def load_dark_stylesheet() -> str:
    """Read and return the dark-theme QSS stylesheet.

    Returns:
        The full contents of ``dark.qss`` as a string.

    Raises:
        FileNotFoundError: If the QSS file cannot be located next to this module.
    """
    return _QSS_PATH.read_text(encoding="utf-8")
