"""Tests for the dark theme loader."""

from aegis.ui.themes.dark import load_dark_stylesheet


class TestDarkTheme:
    def test_loads_stylesheet(self):
        css = load_dark_stylesheet()
        assert isinstance(css, str)
        assert len(css) > 1000

    def test_contains_main_window_styles(self):
        css = load_dark_stylesheet()
        assert "QMainWindow" in css

    def test_contains_table_styles(self):
        css = load_dark_stylesheet()
        assert "QTableWidget" in css

    def test_contains_scrollbar_styles(self):
        css = load_dark_stylesheet()
        assert "QScrollBar" in css

    def test_contains_sidebar_styles(self):
        css = load_dark_stylesheet()
        assert "sidebar" in css

    def test_contains_dark_background_colors(self):
        css = load_dark_stylesheet()
        assert "#1a1a2e" in css

    def test_contains_accent_color(self):
        css = load_dark_stylesheet()
        assert "#4e9af5" in css

    def test_contains_status_indicator_styles(self):
        css = load_dark_stylesheet()
        assert "indicatorOnline" in css or "indicator" in css

    def test_contains_menu_styles(self):
        css = load_dark_stylesheet()
        assert "QMenu" in css

    def test_contains_button_styles(self):
        css = load_dark_stylesheet()
        assert "QPushButton" in css

    def test_contains_label_styles(self):
        css = load_dark_stylesheet()
        assert "QLabel" in css
