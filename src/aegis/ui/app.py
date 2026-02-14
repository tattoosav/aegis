"""Main Aegis desktop application.

Creates the QApplication, system tray, and dashboard window.
"""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)


def run_ui() -> int:
    """Launch the Aegis desktop application. Returns exit code."""
    try:
        from PySide6.QtWidgets import QApplication
        from aegis.ui.tray import AegisTrayManager

        app = QApplication(sys.argv)
        app.setApplicationName("Aegis")
        app.setQuitOnLastWindowClosed(False)

        tray = AegisTrayManager(headless=False)
        tray.set_state(tray.state)

        logger.info("Aegis UI started")
        return app.exec()

    except ImportError:
        logger.error("PySide6 is required for the GUI. Install with: pip install PySide6")
        return 1
