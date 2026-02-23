"""WMI persistence scanner — detect malicious WMI event subscriptions.

Scans WMI namespaces for CommandLineEventConsumer and
ActiveScriptEventConsumer objects commonly used by adversaries for
persistence.  Maps to MITRE ATT&CK T1546.003 (Event Triggered
Execution: Windows Management Instrumentation Event Subscription).

When the ``wmi`` package is not installed the scanner degrades
gracefully and returns empty results.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# MITRE ATT&CK technique ID for WMI event subscription persistence
_MITRE_ID = "T1546.003"

# Consumer types and their associated risk levels
_CONSUMER_QUERIES: list[tuple[str, str, str]] = [
    (
        "SELECT * FROM CommandLineEventConsumer",
        "CommandLineEventConsumer",
        "high",
    ),
    (
        "SELECT * FROM ActiveScriptEventConsumer",
        "ActiveScriptEventConsumer",
        "critical",
    ),
]


def _connect_wmi(namespace: str) -> Any:
    """Connect to a WMI namespace.

    Raises ImportError if the ``wmi`` package is unavailable,
    or any WMI-related exception on connection failure.
    """
    import wmi as wmi_mod  # type: ignore[import-untyped]

    return wmi_mod.WMI(namespace=namespace)


@dataclass
class WMIFinding:
    """A single suspicious WMI consumer discovered during scanning."""

    namespace: str
    consumer_type: str
    consumer_name: str
    command_or_script: str
    risk: str  # "low", "medium", "high", or "critical"
    mitre_id: str


class WMIPersistenceScanner:
    """Scan WMI namespaces for persistence mechanisms.

    Looks for ``CommandLineEventConsumer`` (risk=high) and
    ``ActiveScriptEventConsumer`` (risk=critical) objects that
    adversaries plant for code execution at boot/login.
    """

    def scan_namespace(self, namespace: str) -> list[WMIFinding]:
        """Scan a single WMI namespace for suspicious consumers.

        Returns a list of findings.  Returns an empty list when
        the ``wmi`` package is missing, access is denied, or any
        other error occurs.
        """
        try:
            conn = _connect_wmi(namespace)
        except ImportError:
            logger.warning(
                "wmi package not installed — WMI scanning disabled",
            )
            return []
        except PermissionError:
            logger.warning(
                "Access denied to WMI namespace: %s", namespace,
            )
            return []
        except Exception:
            logger.exception(
                "Failed to connect to WMI namespace: %s", namespace,
            )
            return []

        return self._scan_namespace_with_conn(conn, namespace)

    def _scan_namespace_with_conn(
        self,
        conn: Any,
        namespace: str,
    ) -> list[WMIFinding]:
        """Query a WMI connection for suspicious event consumers.

        Args:
            conn: An active WMI connection object.
            namespace: The WMI namespace string being scanned.

        Returns:
            List of WMIFinding objects for each consumer found.
        """
        findings: list[WMIFinding] = []

        for wql, consumer_type, risk in _CONSUMER_QUERIES:
            try:
                consumers = conn.query(wql)
            except Exception:
                logger.debug(
                    "WMI query failed for %s in %s",
                    consumer_type,
                    namespace,
                    exc_info=True,
                )
                continue

            for consumer in consumers:
                command_or_script = self._extract_payload(
                    consumer, consumer_type,
                )
                findings.append(
                    WMIFinding(
                        namespace=namespace,
                        consumer_type=consumer_type,
                        consumer_name=getattr(
                            consumer, "Name", "<unknown>",
                        ),
                        command_or_script=command_or_script,
                        risk=risk,
                        mitre_id=_MITRE_ID,
                    ),
                )

        return findings

    def scan_all_namespaces(self) -> list[WMIFinding]:
        """Scan all known WMI namespaces for persistence.

        Always scans ``root\\subscription`` (the primary persistence
        namespace).  Additionally attempts to enumerate and scan
        other namespaces if accessible.

        Returns:
            Combined list of findings across all namespaces.
        """
        findings: list[WMIFinding] = []

        # Always scan the main persistence namespace
        findings.extend(self.scan_namespace("root\\subscription"))

        # Attempt to discover and scan additional namespaces
        extra_namespaces = self._enumerate_namespaces("root")
        for ns in extra_namespaces:
            if ns == "root\\subscription":
                continue  # already scanned
            findings.extend(self.scan_namespace(ns))

        return findings

    def _enumerate_namespaces(
        self,
        root: str = "root",
    ) -> list[str]:
        """List WMI namespaces under the given root.

        Returns an empty list on any failure (missing package,
        access denied, etc.).
        """
        try:
            conn = _connect_wmi(root)
            children = conn.query(
                "SELECT Name FROM __NAMESPACE",
            )
            return [
                f"{root}\\{getattr(ns, 'Name', '')}"
                for ns in children
                if getattr(ns, "Name", "")
            ]
        except Exception:
            logger.debug(
                "Could not enumerate WMI namespaces under %s",
                root,
                exc_info=True,
            )
            return []

    @staticmethod
    def _extract_payload(
        consumer: Any,
        consumer_type: str,
    ) -> str:
        """Pull the executable payload from a WMI consumer object.

        For CommandLineEventConsumer returns CommandLineTemplate;
        for ActiveScriptEventConsumer returns ScriptText.
        Falls back to ``"<unavailable>"`` when the attribute is
        missing.
        """
        if consumer_type == "CommandLineEventConsumer":
            return str(
                getattr(consumer, "CommandLineTemplate", "<unavailable>"),
            )
        if consumer_type == "ActiveScriptEventConsumer":
            return str(
                getattr(consumer, "ScriptText", "<unavailable>"),
            )
        return "<unavailable>"
