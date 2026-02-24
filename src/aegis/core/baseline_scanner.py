"""System baseline scanner for Aegis first-run wizard.

Captures a snapshot of the machine's current state — running processes,
active network connections, and Windows services — to establish what is
"normal" before threat detection begins.

The scanner is designed to be robust: it handles psutil AccessDenied
errors gracefully and works even without admin privileges (just with
reduced data).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import psutil

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BaselineSnapshot:
    """Immutable point-in-time snapshot of system state.

    Attributes
    ----------
    processes:
        Names of all running processes at scan time.
    connections:
        Active remote network connections as (ip, port) tuples.
    services:
        Names of Windows services discovered at scan time.
    timestamp:
        Unix epoch timestamp when the scan was taken.
    """

    processes: list[str]
    connections: list[tuple[str, int]]
    services: list[str]
    timestamp: float


class BaselineScanner:
    """Scans the local system and produces a :class:`BaselineSnapshot`.

    Intended for the first-run wizard so that Aegis knows what the
    machine looks like under normal operation.  All collection methods
    catch and log exceptions so a single subsystem failure never
    crashes the entire scan.
    """

    def scan(self) -> BaselineSnapshot:
        """Enumerate processes, connections, and services.

        Returns a frozen :class:`BaselineSnapshot`.  Each subsystem
        collector is wrapped in try/except so that AccessDenied or
        missing-API errors degrade gracefully.
        """
        processes = self._collect_processes()
        connections = self._collect_connections()
        services = self._collect_services()
        return BaselineSnapshot(
            processes=processes,
            connections=connections,
            services=services,
            timestamp=time.time(),
        )

    # ------------------------------------------------------------------ #
    # Private collectors
    # ------------------------------------------------------------------ #

    def _collect_processes(self) -> list[str]:
        """Return names of all running processes."""
        names: list[str] = []
        try:
            for proc in psutil.process_iter(["name", "pid"]):
                try:
                    name = proc.info["name"]
                    if name is not None:
                        names.append(name)
                except (
                    psutil.AccessDenied,
                    psutil.NoSuchProcess,
                ):
                    continue
        except psutil.AccessDenied:
            logger.warning(
                "Access denied enumerating processes — "
                "running without admin privileges"
            )
        except Exception:
            logger.error(
                "Unexpected error collecting processes",
                exc_info=True,
            )
        return names

    def _collect_connections(self) -> list[tuple[str, int]]:
        """Return active remote network connections as (ip, port)."""
        conns: list[tuple[str, int]] = []
        try:
            for conn in psutil.net_connections():
                if conn.raddr:
                    conns.append((conn.raddr.ip, conn.raddr.port))
        except psutil.AccessDenied:
            logger.warning(
                "Access denied enumerating connections — "
                "running without admin privileges"
            )
        except Exception:
            logger.error(
                "Unexpected error collecting connections",
                exc_info=True,
            )
        return conns

    def _collect_services(self) -> list[str]:
        """Return names of all Windows services.

        On non-Windows platforms ``psutil.win_service_iter`` does not
        exist, so we catch :class:`AttributeError` and return an empty
        list.
        """
        names: list[str] = []
        try:
            for svc in psutil.win_service_iter():
                try:
                    names.append(svc.name())
                except Exception:
                    continue
        except AttributeError:
            logger.info(
                "win_service_iter not available — "
                "not running on Windows"
            )
        except psutil.AccessDenied:
            logger.warning(
                "Access denied enumerating services — "
                "running without admin privileges"
            )
        except Exception:
            logger.error(
                "Unexpected error collecting services",
                exc_info=True,
            )
        return names
