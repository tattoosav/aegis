"""Tests for ConnectionTable widget."""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from aegis.ui.widgets.connection_table import ConnectionTable  # noqa: E402

_app = QApplication.instance() or QApplication([])

_SAMPLE_CONNS = [
    {"process": "chrome.exe", "remote_ip": "142.250.80.46",
     "port": 443, "protocol": "TCP", "reputation": 95},
    {"process": "svchost.exe", "remote_ip": "10.0.0.1",
     "port": 53, "protocol": "UDP", "reputation": 80},
    {"process": "malware.exe", "remote_ip": "45.33.32.1",
     "port": 8080, "protocol": "TCP", "reputation": 15},
]


class TestConnectionTableInit:
    """Basic construction tests."""

    def test_creates(self) -> None:
        table = ConnectionTable()
        assert table is not None

    def test_has_protocol_filter(self) -> None:
        table = ConnectionTable()
        assert hasattr(table, "_protocol_filter")


class TestLoadConnections:
    """Tests for load_connections."""

    def test_loads_all(self) -> None:
        table = ConnectionTable()
        table.load_connections(_SAMPLE_CONNS)
        assert table._table.rowCount() == 3

    def test_empty_list(self) -> None:
        table = ConnectionTable()
        table.load_connections([])
        assert table._table.rowCount() == 0


class TestProtocolFilter:
    """Tests for protocol filtering."""

    def test_filter_tcp(self) -> None:
        table = ConnectionTable()
        table.load_connections(_SAMPLE_CONNS)
        table._protocol_filter.setCurrentText("TCP")
        assert table._table.rowCount() == 2

    def test_filter_udp(self) -> None:
        table = ConnectionTable()
        table.load_connections(_SAMPLE_CONNS)
        table._protocol_filter.setCurrentText("UDP")
        assert table._table.rowCount() == 1

    def test_filter_all(self) -> None:
        table = ConnectionTable()
        table.load_connections(_SAMPLE_CONNS)
        table._protocol_filter.setCurrentText("All")
        assert table._table.rowCount() == 3


class TestConnectionTableSignals:
    """Signal tests."""

    def test_block_ip_requested(self) -> None:
        table = ConnectionTable()
        received = []
        table.block_ip_requested.connect(received.append)
        table.block_ip_requested.emit("10.0.0.1")
        assert received == ["10.0.0.1"]
