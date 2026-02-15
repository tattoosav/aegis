"""Main Aegis desktop application.

Creates the QApplication, applies the dark theme, and launches
the DashboardWindow as the primary interface.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PySide6.QtWidgets import QApplication

    from aegis.core.database import AegisDatabase
    from aegis.ui.dashboard import DashboardWindow

logger = logging.getLogger(__name__)


class AegisApp:
    """Wrapper around QApplication for the Aegis security dashboard.

    Handles application lifecycle: creation, theming, and event loop.
    """

    def __init__(self, db: AegisDatabase | None = None) -> None:
        from PySide6.QtWidgets import QApplication

        self._db = db
        self._qt_app = QApplication(sys.argv)
        self._qt_app.setApplicationName("Aegis")
        self._qt_app.setApplicationDisplayName("Aegis")
        self._qt_app.setQuitOnLastWindowClosed(True)

        self._apply_theme()
        self._apply_icon()

        from aegis.ui.dashboard import DashboardWindow

        self._window = DashboardWindow(db=self._db)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def window(self) -> DashboardWindow:
        """Return the main dashboard window."""

        return self._window  # type: ignore[return-value]

    @property
    def qt_app(self) -> QApplication:
        """Return the underlying QApplication."""

        return self._qt_app  # type: ignore[return-value]

    def run(self) -> int:
        """Show the dashboard and start the Qt event loop.

        Returns the application exit code.
        """
        self._window.show()
        logger.info("Aegis dashboard launched")
        return self._qt_app.exec()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _apply_theme(self) -> None:
        """Load and apply the dark stylesheet."""
        try:
            from aegis.ui.themes.dark import load_dark_stylesheet

            stylesheet = load_dark_stylesheet()
            self._qt_app.setStyleSheet(stylesheet)
            logger.debug("Dark theme applied")
        except Exception:
            logger.warning(
                "Could not load dark theme; falling back to default"
            )

    def _apply_icon(self) -> None:
        """Set the application window icon."""
        try:
            from PySide6.QtCore import Qt
            from PySide6.QtGui import QFont, QIcon, QPainter, QPixmap

            # Create a simple text-based icon with a shield character
            pixmap = QPixmap(64, 64)
            pixmap.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            font = QFont("Segoe UI Symbol", 40)
            painter.setFont(font)
            painter.setPen(Qt.GlobalColor.white)
            painter.drawText(
                pixmap.rect(),
                Qt.AlignmentFlag.AlignCenter,
                "\U0001f6e1",  # shield emoji
            )
            painter.end()

            icon = QIcon(pixmap)
            self._qt_app.setWindowIcon(icon)
        except Exception:
            logger.debug("Could not create app icon")


def create_app(db: AegisDatabase | None = None) -> AegisApp:
    """Factory function to create and configure an AegisApp instance.

    Parameters
    ----------
    db : AegisDatabase | None
        Optional database instance for the dashboard to use.

    Returns
    -------
    AegisApp
        Fully configured application ready to ``run()``.
    """
    return AegisApp(db=db)
