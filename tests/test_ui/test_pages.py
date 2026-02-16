"""Tests for dashboard page modules — import and structure checks.

These tests verify that all page modules can be imported and their
classes instantiated (with a Qt app) without errors.
"""


# We need a QApplication for any QWidget creation
_app = None


def get_app():
    """Get or create a QApplication instance for testing."""
    global _app
    if _app is None:
        from PySide6.QtWidgets import QApplication
        _app = QApplication.instance() or QApplication([])
    return _app


class TestHomePageStructure:
    def test_import(self):
        from aegis.ui.pages.home import HomePage
        assert HomePage is not None

    def test_instantiate_without_db(self):
        get_app()
        from aegis.ui.pages.home import HomePage
        page = HomePage(parent=None, db=None)
        assert page is not None

    def test_has_refresh_method(self):
        from aegis.ui.pages.home import HomePage
        assert callable(getattr(HomePage, "refresh", None))

    def test_has_update_sensor_status_method(self):
        from aegis.ui.pages.home import HomePage
        assert callable(getattr(HomePage, "update_sensor_status", None))

    def test_has_update_stats_method(self):
        from aegis.ui.pages.home import HomePage
        assert callable(getattr(HomePage, "update_stats", None))

    def test_update_sensor_status(self):
        get_app()
        from aegis.ui.pages.home import HomePage
        page = HomePage(parent=None, db=None)
        # Should not raise
        page.update_sensor_status("Network", "Active", 42)

    def test_update_stats(self):
        get_app()
        from aegis.ui.pages.home import HomePage
        page = HomePage(parent=None, db=None)
        page.update_stats(events_24h=100, alerts_24h=5, threats=2)


class TestAlertsPageStructure:
    def test_import(self):
        from aegis.ui.pages.alerts import AlertsPage
        assert AlertsPage is not None

    def test_instantiate_without_db(self):
        get_app()
        from aegis.ui.pages.alerts import AlertsPage
        page = AlertsPage(parent=None, db=None)
        assert page is not None

    def test_has_refresh_method(self):
        from aegis.ui.pages.alerts import AlertsPage
        assert callable(getattr(AlertsPage, "refresh", None))

    def test_empty_table_message(self):
        get_app()
        from aegis.ui.pages.alerts import AlertsPage
        page = AlertsPage(parent=None, db=None)
        # Should show "No database connected" in first cell
        item = page._table.item(0, 0)
        assert item is not None
        assert "No database" in item.text()


class TestNetworkPageStructure:
    def test_import(self):
        from aegis.ui.pages.network import NetworkPage
        assert NetworkPage is not None

    def test_instantiate_without_db(self):
        get_app()
        from aegis.ui.pages.network import NetworkPage
        page = NetworkPage(parent=None, db=None)
        assert page is not None

    def test_has_refresh_method(self):
        from aegis.ui.pages.network import NetworkPage
        assert callable(getattr(NetworkPage, "refresh", None))

    def test_has_update_connections_method(self):
        from aegis.ui.pages.network import NetworkPage
        assert callable(getattr(NetworkPage, "update_connections", None))

    def test_has_update_stats_method(self):
        from aegis.ui.pages.network import NetworkPage
        assert callable(getattr(NetworkPage, "update_stats", None))

    def test_update_connections(self):
        get_app()
        from aegis.ui.pages.network import NetworkPage
        page = NetworkPage(parent=None, db=None)
        connections = [
            {
                "status": "ESTABLISHED",
                "local_addr": "127.0.0.1:8080",
                "remote_addr": "93.184.216.34",
                "remote_port": 443,
                "protocol": "TCP",
                "pid": 1234,
                "process": "chrome.exe",
            }
        ]
        page.update_connections(connections)
        assert page._table.rowCount() == 1

    def test_update_stats(self):
        get_app()
        from aegis.ui.pages.network import NetworkPage
        page = NetworkPage(parent=None, db=None)
        page.update_stats(active=10, unique_ips=5, dns=20, flagged=1)


class TestProcessesPageStructure:
    def test_import(self):
        from aegis.ui.pages.processes import ProcessesPage
        assert ProcessesPage is not None

    def test_instantiate_without_db(self):
        get_app()
        from aegis.ui.pages.processes import ProcessesPage
        page = ProcessesPage(parent=None, db=None)
        assert page is not None

    def test_has_refresh_method(self):
        from aegis.ui.pages.processes import ProcessesPage
        assert callable(getattr(ProcessesPage, "refresh", None))

    def test_has_update_processes_method(self):
        from aegis.ui.pages.processes import ProcessesPage
        assert callable(getattr(ProcessesPage, "update_processes", None))

    def test_update_processes(self):
        get_app()
        from aegis.ui.pages.processes import ProcessesPage
        page = ProcessesPage(parent=None, db=None)
        processes = [
            {
                "pid": 1234,
                "name": "python.exe",
                "status": "running",
                "cpu_percent": 5.2,
                "memory_mb": 128.5,
                "num_threads": 12,
                "username": "test_user",
                "exe": "C:\\Python311\\python.exe",
                "risk_level": "none",
            },
            {
                "pid": 5678,
                "name": "suspicious.exe",
                "status": "running",
                "cpu_percent": 95.0,
                "memory_mb": 512.0,
                "num_threads": 50,
                "username": "SYSTEM",
                "exe": "C:\\Temp\\suspicious.exe",
                "risk_level": "high",
            },
        ]
        page.update_processes(processes)
        assert page._table.rowCount() == 2

    def test_search_filter(self):
        get_app()
        from aegis.ui.pages.processes import ProcessesPage
        page = ProcessesPage(parent=None, db=None)
        processes = [
            {
                "pid": 1,
                "name": "python.exe",
                "status": "running",
                "cpu_percent": 1.0,
                "memory_mb": 50.0,
                "num_threads": 4,
                "username": "user",
                "exe": "C:\\Python\\python.exe",
                "risk_level": "none",
            },
            {
                "pid": 2,
                "name": "chrome.exe",
                "status": "running",
                "cpu_percent": 2.0,
                "memory_mb": 200.0,
                "num_threads": 20,
                "username": "user",
                "exe": "C:\\Chrome\\chrome.exe",
                "risk_level": "none",
            },
        ]
        page.update_processes(processes)
        # Filter for "python"
        page._on_search_changed("python")
        # Exactly one row visible (python.exe), one hidden (chrome.exe).
        # Row order may vary due to Qt auto-sorting.
        visible = [
            r for r in range(page._table.rowCount())
            if not page._table.isRowHidden(r)
        ]
        hidden = [
            r for r in range(page._table.rowCount())
            if page._table.isRowHidden(r)
        ]
        assert len(visible) == 1
        assert len(hidden) == 1
        # The visible row must contain "python"
        visible_name = page._table.item(visible[0], 1).text()
        assert "python" in visible_name.lower()


class TestDashboardWindow:
    def test_import(self):
        from aegis.ui.dashboard import DashboardWindow
        assert DashboardWindow is not None

    def test_instantiate_without_db(self):
        get_app()
        from aegis.ui.dashboard import DashboardWindow
        window = DashboardWindow(db=None)
        assert window is not None
        assert window.windowTitle() == "Aegis \u2014 Security Dashboard"

    def test_switch_page(self):
        get_app()
        from aegis.ui.dashboard import DashboardWindow
        window = DashboardWindow(db=None)
        window.switch_page(1)  # Alerts
        assert window._stack.currentIndex() == 1
        window.switch_page(0)  # Home
        assert window._stack.currentIndex() == 0

    def test_page_count(self):
        get_app()
        from aegis.ui.dashboard import DashboardWindow
        window = DashboardWindow(db=None)
        assert window._stack.count() == 8

    def test_update_status(self):
        get_app()
        from aegis.ui.dashboard import DashboardWindow
        window = DashboardWindow(db=None)
        window.update_status(sensor_count=3, event_count=500)
        text = window._status_label.text()
        assert "3 active" in text
        assert "500" in text
