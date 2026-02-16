"""Main Aegis desktop application.

Creates the QApplication, applies the dark theme, and launches
the DashboardWindow as the primary interface.  Accepts an optional
EventEngine for live status updates and tray integration.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from PySide6.QtWidgets import QApplication

    from aegis.core.database import AegisDatabase
    from aegis.core.engine import EventEngine
    from aegis.ui.dashboard import DashboardWindow

logger = logging.getLogger(__name__)


class AegisApp:
    """Wrapper around QApplication for the Aegis security dashboard.

    Handles application lifecycle: creation, theming, and event loop.
    """

    def __init__(
        self,
        db: AegisDatabase | None = None,
        engine: EventEngine | None = None,
    ) -> None:
        from PySide6.QtWidgets import QApplication

        self._db = db
        self._engine = engine
        self._qt_app = QApplication(sys.argv)
        self._qt_app.setApplicationName("Aegis")
        self._qt_app.setApplicationDisplayName("Aegis")
        self._qt_app.setQuitOnLastWindowClosed(True)

        self._apply_theme()
        self._apply_icon()

        from aegis.ui.dashboard import DashboardWindow

        self._window = DashboardWindow(db=self._db)

        # System tray
        self._tray: Any = None
        self._init_tray()

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

    @property
    def tray(self) -> Any:
        """Return the tray icon (if available)."""
        return self._tray

    def run(self) -> int:
        """Show the dashboard and start the Qt event loop.

        Returns the application exit code.
        """
        self._window.show()
        if self._tray:
            self._tray.show()
        logger.info("Aegis dashboard launched")
        return self._qt_app.exec()

    # ------------------------------------------------------------------
    # Tray
    # ------------------------------------------------------------------

    def _init_tray(self) -> None:
        """Create the system tray icon if PySide6 supports it."""
        try:
            from aegis.ui.tray import AegisTray

            self._tray = AegisTray(parent=None)
            self._tray.dashboard_requested.connect(
                self._window.show
            )
            self._tray.dashboard_requested.connect(
                self._window.raise_
            )
            logger.info("System tray icon initialized")
        except Exception as exc:
            logger.warning("Could not create tray icon: %s", exc)

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


def create_app(
    db: AegisDatabase | None = None,
    engine: EventEngine | None = None,
) -> AegisApp:
    """Factory function to create and configure an AegisApp instance."""
    return AegisApp(db=db, engine=engine)
