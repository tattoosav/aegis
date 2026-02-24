"""Tests for aegis.core.baseline_scanner — system baseline scanner.

Validates that BaselineScanner captures running processes, network
connections, and Windows services into a BaselineSnapshot dataclass,
handling errors gracefully even without admin privileges.
"""

from __future__ import annotations

import time
from dataclasses import FrozenInstanceError
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.baseline_scanner import BaselineScanner, BaselineSnapshot

# ------------------------------------------------------------------ #
# TestBaselineSnapshot
# ------------------------------------------------------------------ #


class TestBaselineSnapshot:
    """Verify the BaselineSnapshot dataclass."""

    def test_snapshot_has_processes(self):
        snap = BaselineSnapshot(
            processes=["explorer.exe", "svchost.exe"],
            connections=[("192.168.1.1", 443)],
            services=["Spooler", "BITS"],
            timestamp=1000.0,
        )
        assert len(snap.processes) == 2
        assert snap.timestamp == 1000.0

    def test_snapshot_has_connections(self):
        snap = BaselineSnapshot(
            processes=[],
            connections=[("10.0.0.1", 80), ("10.0.0.2", 443)],
            services=[],
            timestamp=2000.0,
        )
        assert len(snap.connections) == 2
        assert ("10.0.0.1", 80) in snap.connections

    def test_snapshot_has_services(self):
        snap = BaselineSnapshot(
            processes=[],
            connections=[],
            services=["Spooler", "BITS", "wuauserv"],
            timestamp=3000.0,
        )
        assert len(snap.services) == 3
        assert "wuauserv" in snap.services

    def test_snapshot_empty_lists(self):
        snap = BaselineSnapshot(
            processes=[],
            connections=[],
            services=[],
            timestamp=0.0,
        )
        assert snap.processes == []
        assert snap.connections == []
        assert snap.services == []

    def test_snapshot_is_frozen(self):
        """BaselineSnapshot should be immutable (frozen dataclass)."""
        snap = BaselineSnapshot(
            processes=["a.exe"],
            connections=[],
            services=[],
            timestamp=1.0,
        )
        with pytest.raises(FrozenInstanceError):
            snap.timestamp = 999.0


# ------------------------------------------------------------------ #
# TestBaselineScanner
# ------------------------------------------------------------------ #


class TestBaselineScanner:
    """Unit tests for BaselineScanner.scan()."""

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_returns_snapshot(self, mock_psutil):
        mock_psutil.process_iter.return_value = []
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert isinstance(snap, BaselineSnapshot)

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_captures_processes(self, mock_psutil):
        proc = type("P", (), {"info": {"name": "test.exe", "pid": 1}})()
        mock_psutil.process_iter.return_value = [proc]
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert "test.exe" in snap.processes

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_captures_multiple_processes(self, mock_psutil):
        procs = [
            type("P", (), {"info": {"name": "a.exe", "pid": 1}})(),
            type("P", (), {"info": {"name": "b.exe", "pid": 2}})(),
            type("P", (), {"info": {"name": "c.exe", "pid": 3}})(),
        ]
        mock_psutil.process_iter.return_value = procs
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert len(snap.processes) == 3
        assert "b.exe" in snap.processes

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_captures_connections(self, mock_psutil):
        conn = MagicMock()
        conn.raddr = MagicMock(ip="93.184.216.34", port=443)
        conn.status = "ESTABLISHED"
        mock_psutil.process_iter.return_value = []
        mock_psutil.net_connections.return_value = [conn]
        mock_psutil.win_service_iter.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert ("93.184.216.34", 443) in snap.connections

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_skips_connections_without_raddr(self, mock_psutil):
        """Listening sockets have no remote address."""
        conn = MagicMock()
        conn.raddr = None
        conn.status = "LISTEN"
        mock_psutil.process_iter.return_value = []
        mock_psutil.net_connections.return_value = [conn]
        mock_psutil.win_service_iter.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert len(snap.connections) == 0

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_captures_services(self, mock_psutil):
        svc = MagicMock()
        svc.name.return_value = "Spooler"
        svc.status.return_value = "running"
        mock_psutil.process_iter.return_value = []
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.return_value = [svc]
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert "Spooler" in snap.services

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_sets_timestamp(self, mock_psutil):
        mock_psutil.process_iter.return_value = []
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.return_value = []
        before = time.time()
        scanner = BaselineScanner()
        snap = scanner.scan()
        after = time.time()
        assert before <= snap.timestamp <= after

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_handles_process_access_denied(self, mock_psutil):
        """AccessDenied on a single process should not crash scan."""
        import psutil as real_psutil

        mock_psutil.AccessDenied = real_psutil.AccessDenied
        mock_psutil.NoSuchProcess = real_psutil.NoSuchProcess

        def bad_iter(*args, **kwargs):
            raise real_psutil.AccessDenied(pid=4)

        mock_psutil.process_iter.side_effect = bad_iter
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert isinstance(snap, BaselineSnapshot)
        assert snap.processes == []

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_handles_net_connections_access_denied(self, mock_psutil):
        """AccessDenied on net_connections should not crash scan."""
        import psutil as real_psutil

        mock_psutil.AccessDenied = real_psutil.AccessDenied
        mock_psutil.NoSuchProcess = real_psutil.NoSuchProcess
        mock_psutil.process_iter.return_value = []
        mock_psutil.net_connections.side_effect = (
            real_psutil.AccessDenied(pid=0)
        )
        mock_psutil.win_service_iter.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert isinstance(snap, BaselineSnapshot)
        assert snap.connections == []

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_handles_services_not_available(self, mock_psutil):
        """On non-Windows, win_service_iter may raise AttributeError."""
        mock_psutil.process_iter.return_value = []
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.side_effect = AttributeError(
            "win_service_iter not available"
        )
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert isinstance(snap, BaselineSnapshot)
        assert snap.services == []

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_deduplicates_processes(self, mock_psutil):
        """Multiple instances of the same process name kept as-is."""
        procs = [
            type("P", (), {"info": {"name": "svchost.exe", "pid": 1}})(),
            type("P", (), {"info": {"name": "svchost.exe", "pid": 2}})(),
        ]
        mock_psutil.process_iter.return_value = procs
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        # Each instance is listed separately
        assert snap.processes.count("svchost.exe") == 2

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_handles_process_with_none_name(self, mock_psutil):
        """A process whose name is None should be skipped."""
        proc = type("P", (), {"info": {"name": None, "pid": 99}})()
        mock_psutil.process_iter.return_value = [proc]
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert len(snap.processes) == 0

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_connection_dedup(self, mock_psutil):
        """Duplicate connections are kept (same remote can have many)."""
        c1 = MagicMock()
        c1.raddr = MagicMock(ip="1.2.3.4", port=443)
        c1.status = "ESTABLISHED"
        c2 = MagicMock()
        c2.raddr = MagicMock(ip="1.2.3.4", port=443)
        c2.status = "ESTABLISHED"
        mock_psutil.process_iter.return_value = []
        mock_psutil.net_connections.return_value = [c1, c2]
        mock_psutil.win_service_iter.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert len(snap.connections) == 2
