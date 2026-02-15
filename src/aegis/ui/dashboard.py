"""Main dashboard window for the Aegis security application.

Provides sidebar navigation, a stacked page area, and a status bar
showing live sensor/event counts.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aegis.core.database import AegisDatabase

import aegis

logger = logging.getLogger(__name__)

# Sidebar button definitions: (label, icon text)
_NAV_ITEMS: list[tuple[str, str]] = [
    ("Home", "\u2302"),        # ⌂ house
    ("Alerts", "\u26a0"),      # ⚠ warning sign
    ("Network", "\U0001f310"), # globe with meridians
    ("Processes", "\u2699"),   # ⚙ gear
]


class DashboardWindow(QMainWindow):
    """Primary Aegis window with sidebar navigation and page stack.

    Parameters
    ----------
    db : AegisDatabase | None
        Optional database handle shared with every page.
    parent : QWidget | None
        Optional parent widget.
    """

    def __init__(
        self,
        db: AegisDatabase | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._db = db
        self._nav_buttons: list[QPushButton] = []

        self._setup_window()
        self._build_ui()
        self._build_status_bar()

        # Select the home page by default
        self.switch_page(0)

    # ------------------------------------------------------------------
    # Window configuration
    # ------------------------------------------------------------------

    def _setup_window(self) -> None:
        """Configure basic window properties."""
        self.setWindowTitle("Aegis \u2014 Security Dashboard")
        self.resize(1200, 800)
        self.setMinimumSize(900, 600)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Assemble sidebar + page stack into the central widget."""
        central = QWidget(self)
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # --- Sidebar ---
        sidebar = self._build_sidebar()
        root_layout.addWidget(sidebar)

        # --- Page stack ---
        self._stack = QStackedWidget(self)
        self._populate_pages()
        root_layout.addWidget(self._stack, stretch=1)

    def _build_sidebar(self) -> QFrame:
        """Create the left-hand navigation sidebar."""
        sidebar = QFrame(self)
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(200)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # --- Header ---
        header = self._build_sidebar_header()
        layout.addWidget(header)

        # --- Navigation buttons ---
        for index, (label, icon_text) in enumerate(_NAV_ITEMS):
            btn = QPushButton(f"  {icon_text}  {label}", sidebar)
            btn.setObjectName(f"nav_btn_{index}")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setFixedHeight(44)
            btn.setProperty("active", False)
            btn.clicked.connect(
                lambda checked=False, i=index: self.switch_page(i)
            )
            layout.addWidget(btn)
            self._nav_buttons.append(btn)

        layout.addStretch(1)
        return sidebar

    @staticmethod
    def _build_sidebar_header() -> QFrame:
        """Create the branded header at the top of the sidebar."""
        header = QFrame()
        header.setObjectName("sidebar_header")
        header.setFixedHeight(64)

        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(16, 0, 16, 0)

        shield_label = QLabel("\U0001f6e1")  # shield emoji
        shield_label.setObjectName("sidebar_shield")
        shield_label.setStyleSheet("font-size: 24px;")

        title_label = QLabel("AEGIS")
        title_label.setObjectName("sidebar_title")
        title_label.setStyleSheet(
            "font-weight: bold; font-size: 18px; letter-spacing: 2px;"
        )

        h_layout.addWidget(shield_label)
        h_layout.addWidget(title_label)
        h_layout.addStretch(1)
        return header

    def _populate_pages(self) -> None:
        """Import and add each page widget to the stack."""
        from aegis.ui.pages.alerts import AlertsPage
        from aegis.ui.pages.home import HomePage
        from aegis.ui.pages.network import NetworkPage
        from aegis.ui.pages.processes import ProcessesPage

        page_classes = [HomePage, AlertsPage, NetworkPage, ProcessesPage]
        for cls in page_classes:
            page = cls(parent=self, db=self._db)
            self._stack.addWidget(page)

    # ------------------------------------------------------------------
    # Status bar
    # ------------------------------------------------------------------

    def _build_status_bar(self) -> None:
        """Create the bottom status bar with sensor/event info."""
        self._status_bar = QStatusBar(self)
        self.setStatusBar(self._status_bar)

        version = getattr(aegis, "__version__", "0.1.0")
        self._status_label = QLabel(
            f"Aegis v{version} | Sensors: 0 active | Events: 0"
        )
        self._status_bar.addPermanentWidget(self._status_label)

    def update_status(
        self, sensor_count: int, event_count: int
    ) -> None:
        """Update the status bar with current sensor and event counts.

        Parameters
        ----------
        sensor_count : int
            Number of currently active sensors.
        event_count : int
            Total number of recorded events.
        """
        version = getattr(aegis, "__version__", "0.1.0")
        self._status_label.setText(
            f"Aegis v{version} | Sensors: {sensor_count} active"
            f" | Events: {event_count}"
        )

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def switch_page(self, index: int) -> None:
        """Switch the visible page and highlight the active button.

        Parameters
        ----------
        index : int
            Zero-based index of the page to display.
        """
        if 0 <= index < self._stack.count():
            self._stack.setCurrentIndex(index)
            self.set_active_button(index)
            logger.debug("Switched to page %d", index)

    def set_active_button(self, index: int) -> None:
        """Mark the button at *index* as active; deactivate the rest.

        Uses the Qt dynamic property ``active`` so that stylesheets
        can target ``QPushButton[active="true"]``.

        Parameters
        ----------
        index : int
            Index of the button to activate.
        """
        for i, btn in enumerate(self._nav_buttons):
            is_active = i == index
            btn.setProperty("active", is_active)
            # Force a style re-evaluation after the property change
            btn.style().unpolish(btn)
            btn.style().polish(btn)
            btn.update()
