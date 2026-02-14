"""Network Sensor — monitors network connections and traffic flow.

For Phase 2 we use psutil for connection monitoring (no raw packet capture yet).
Scapy-based deep packet inspection will be added in a later phase.

Captures:
- All active TCP/UDP connections with local/remote addresses
- Process owning each connection
- Flow statistics: unique IPs, ports, protocol distribution, entropy
- New/closed connection detection between collection cycles
- DNS query tracking (stub for future scapy integration)
"""

from __future__ import annotations

import logging
import math
import socket
from collections import Counter
from typing import Any

import psutil

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.base import BaseSensor

logger = logging.getLogger(__name__)

# Protocol family mapping
_PROTO_MAP = {
    socket.SOCK_STREAM: "TCP",
    socket.SOCK_DGRAM: "UDP",
}


def _port_entropy(ports: list[int]) -> float:
    """Calculate Shannon entropy of destination port distribution.

    High entropy (>3.5) may indicate port scanning.
    """
    if not ports:
        return 0.0
    freq = Counter(ports)
    total = len(ports)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _resolve_process(pid: int) -> str:
    """Get process name from PID, safely."""
    if pid is None or pid == 0:
        return "system"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"pid-{pid}"


def _conn_key(conn: Any) -> str:
    """Create a unique key for a connection to track new/closed."""
    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "none"
    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "none"
    pid = conn.pid or 0
    return f"{pid}|{laddr}|{raddr}|{conn.type}"


class NetworkSensor(BaseSensor):
    """Network Monitor — tracks connections and generates flow statistics.

    Emits:
    - connection_snapshot: per-connection data
    - connection_new: newly appeared connection
    - connection_closed: connection that disappeared
    - network_flow_stats: aggregated network statistics per collection cycle
    """

    sensor_type = SensorType.NETWORK
    sensor_name = "network_monitor"

    def __init__(self, interval: float = 5.0, **kwargs: Any):
        super().__init__(interval=interval, **kwargs)
        self._prev_conns: dict[str, dict[str, Any]] = {}
        self._known_remote_ips: set[str] = set()
        self._dns_query_count: int = 0  # Stub — will be populated by scapy layer

    def setup(self) -> None:
        """Initialize network monitoring."""
        self._prev_conns.clear()
        self._known_remote_ips.clear()
        self._dns_query_count = 0

    def collect(self) -> list[AegisEvent]:
        """Collect network connection data and flow statistics."""
        events: list[AegisEvent] = []
        current_conns: dict[str, dict[str, Any]] = {}

        remote_ips: list[str] = []
        remote_ports: list[int] = []
        status_counts: Counter[str] = Counter()
        protocol_counts: Counter[str] = Counter()

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as e:
            logger.warning(f"Cannot read network connections: {e}")
            connections = []

        for conn in connections:
            key = _conn_key(conn)
            proto = _PROTO_MAP.get(conn.type, "OTHER")
            status = conn.status if hasattr(conn, "status") else "NONE"
            pid = conn.pid or 0
            proc_name = _resolve_process(pid)

            local_addr = conn.laddr.ip if conn.laddr else ""
            local_port = conn.laddr.port if conn.laddr else 0
            remote_addr = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0

            data = {
                "pid": pid,
                "process_name": proc_name,
                "protocol": proto,
                "local_addr": local_addr,
                "local_port": local_port,
                "remote_addr": remote_addr,
                "remote_port": remote_port,
                "status": status,
                "family": str(conn.family.name) if hasattr(conn.family, "name") else str(conn.family),
            }

            current_conns[key] = data

            # Collect stats
            if remote_addr:
                remote_ips.append(remote_addr)
            if remote_port:
                remote_ports.append(remote_port)
            status_counts[status] += 1
            protocol_counts[proto] += 1

            events.append(AegisEvent(
                sensor=SensorType.NETWORK,
                event_type="connection_snapshot",
                severity=Severity.INFO,
                data=data,
            ))

        # Detect new and closed connections
        if self._prev_conns:
            prev_keys = set(self._prev_conns.keys())
            curr_keys = set(current_conns.keys())

            for key in curr_keys - prev_keys:
                conn_data = current_conns[key]
                events.append(AegisEvent(
                    sensor=SensorType.NETWORK,
                    event_type="connection_new",
                    severity=Severity.LOW,
                    data=conn_data,
                ))

            for key in prev_keys - curr_keys:
                conn_data = self._prev_conns[key]
                events.append(AegisEvent(
                    sensor=SensorType.NETWORK,
                    event_type="connection_closed",
                    severity=Severity.INFO,
                    data=conn_data,
                ))

        # Calculate new destination rate
        unique_remote = set(remote_ips)
        new_destinations = unique_remote - self._known_remote_ips
        new_dest_rate = len(new_destinations)
        self._known_remote_ips.update(unique_remote)

        # Generate flow statistics summary
        flow_stats: dict[str, Any] = {
            "total_connections": len(current_conns),
            "unique_remote_ips": len(unique_remote),
            "unique_remote_ports": len(set(remote_ports)),
            "port_entropy": _port_entropy(remote_ports),
            "connections_by_status": dict(status_counts),
            "connections_by_protocol": dict(protocol_counts),
            "new_destination_rate": new_dest_rate,
            "dns_query_count": self._dns_query_count,
        }

        events.append(AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="network_flow_stats",
            severity=Severity.INFO,
            data=flow_stats,
        ))

        self._prev_conns = current_conns
        return events

    def teardown(self) -> None:
        """Cleanup."""
        self._prev_conns.clear()
        self._known_remote_ips.clear()
