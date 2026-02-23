"""Fileless Attack Detection Engine.

Orchestrates multiple detection sub-engines to identify fileless attack
patterns across ETW telemetry and process creation events.  Covers:

* **PowerShell obfuscation** — delegates to
  :class:`~aegis.detection.powershell_analyzer.PowerShellAnalyzer`.
* **.NET in-memory assembly loads** — flags dynamic assemblies with no
  backing IL path as potential reflective injection.
* **WMI persistence** — detects activity in the ``root\\subscription``
  namespace, a common persistence mechanism.
* **LOLBins abuse** — delegates parent-child and command-line checks
  to :class:`~aegis.detection.lolbins_analyzer.LOLBinsAnalyzer`.

MITRE ATT&CK coverage:
    T1027 (Obfuscated Files), T1055 (.NET Injection),
    T1059.001 (PowerShell), T1546.003 (WMI Event Subscription),
    T1105/T1218.* (LOLBins).
"""

from __future__ import annotations

import logging
from typing import Any

from aegis.core.models import AegisEvent, Alert, Severity
from aegis.detection.lolbins_analyzer import LOLBinsAnalyzer
from aegis.detection.powershell_analyzer import PowerShellAnalyzer

logger = logging.getLogger(__name__)


class FilelessDetector:
    """Detect fileless attack patterns across multiple event types.

    Dispatches incoming :class:`AegisEvent` instances to specialised
    analysis methods based on ``event_type``:

    * ``etw.powershell_scriptblock`` -- PowerShell obfuscation analysis.
    * ``etw.dotnet_assembly_load`` -- in-memory .NET injection detection.
    * ``etw.wmi_activity`` -- WMI persistence namespace detection.
    * ``process_new`` -- LOLBins parent-child and command-line checks.

    All other event types are silently ignored (empty alert list).
    """

    def __init__(self) -> None:
        """Initialise sub-analyzers."""
        self._ps_analyzer = PowerShellAnalyzer()
        self._lolbins = LOLBinsAnalyzer()

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def analyze_event(self, event: AegisEvent) -> list[Alert]:
        """Analyse an event for fileless attack indicators.

        Parameters
        ----------
        event : AegisEvent
            The event to analyse.

        Returns
        -------
        list[Alert]
            Zero or more alerts produced by the relevant sub-engine.
        """
        dispatch: dict[
            str,
            Any,
        ] = {
            "etw.powershell_scriptblock": self._analyze_powershell,
            "etw.dotnet_assembly_load": self._analyze_dotnet,
            "etw.wmi_activity": self._analyze_wmi,
            "process_new": self._analyze_process,
        }
        handler = dispatch.get(event.event_type)
        if handler is None:
            return []
        return handler(event)

    # ------------------------------------------------------------------ #
    #  PowerShell obfuscation
    # ------------------------------------------------------------------ #

    def _analyze_powershell(self, event: AegisEvent) -> list[Alert]:
        """Check a PowerShell script-block event for obfuscation.

        Delegates to :class:`PowerShellAnalyzer` and wraps a positive
        result in an :class:`Alert`.
        """
        script_text = event.data.get("script_text", "")
        if not script_text:
            return []

        result = self._ps_analyzer.analyze(script_text)
        if not result.is_obfuscated:
            return []

        return [
            Alert(
                event_id=event.event_id,
                sensor=event.sensor,
                alert_type="fileless_powershell_obfuscation",
                severity=Severity.HIGH,
                title="Obfuscated PowerShell script detected",
                description=(
                    f"PowerShell script block with entropy "
                    f"{result.entropy:.2f} matched patterns: "
                    f"{', '.join(result.matched_patterns)}"
                ),
                confidence=max(result.confidence, 0.5),
                data={
                    "pid": event.data.get("pid"),
                    "script_block_id": event.data.get(
                        "script_block_id",
                    ),
                    "entropy": result.entropy,
                    "matched_patterns": result.matched_patterns,
                },
                mitre_ids=["T1027", "T1059.001"],
                recommended_actions=[
                    "Review the PowerShell script content",
                    "Check parent process tree for "
                    "suspicious launchers",
                    "Consider blocking obfuscated scripts "
                    "via policy",
                ],
            ),
        ]

    # ------------------------------------------------------------------ #
    #  .NET in-memory assembly injection
    # ------------------------------------------------------------------ #

    def _analyze_dotnet(self, event: AegisEvent) -> list[Alert]:
        """Detect in-memory .NET assembly loads (reflective injection).

        Flags assemblies that are dynamic (no backing file) and have
        an empty ``module_il_path``.
        """
        module_il_path = event.data.get("module_il_path", "")
        is_dynamic = event.data.get("is_dynamic", False)

        if module_il_path or not is_dynamic:
            return []

        assembly_name = event.data.get("assembly_name", "<unknown>")
        return [
            Alert(
                event_id=event.event_id,
                sensor=event.sensor,
                alert_type="fileless_dotnet_injection",
                severity=Severity.HIGH,
                title=(
                    "In-memory .NET assembly load detected"
                ),
                description=(
                    f"Dynamic assembly '{assembly_name}' loaded "
                    f"with no backing IL path — possible "
                    f"reflective injection"
                ),
                confidence=0.7,
                data={
                    "pid": event.data.get("pid"),
                    "assembly_name": assembly_name,
                    "is_dynamic": is_dynamic,
                },
                mitre_ids=["T1055"],
                recommended_actions=[
                    "Investigate the process loading the "
                    "assembly",
                    "Check for suspicious parent processes",
                    "Dump and analyse the in-memory assembly",
                ],
            ),
        ]

    # ------------------------------------------------------------------ #
    #  WMI persistence
    # ------------------------------------------------------------------ #

    def _analyze_wmi(self, event: AegisEvent) -> list[Alert]:
        """Detect WMI activity targeting persistence namespaces.

        Flags any WMI activity in the ``root\\subscription`` namespace,
        which is the primary mechanism for WMI event subscription
        persistence.
        """
        namespace = event.data.get("namespace", "")
        if "subscription" not in namespace.lower():
            return []

        return [
            Alert(
                event_id=event.event_id,
                sensor=event.sensor,
                alert_type="fileless_wmi_persistence",
                severity=Severity.HIGH,
                title="WMI persistence namespace activity",
                description=(
                    f"WMI operation '{event.data.get('operation')}'"
                    f" in namespace '{namespace}' — "
                    f"possible event subscription persistence"
                ),
                confidence=0.75,
                data={
                    "pid": event.data.get("pid"),
                    "namespace": namespace,
                    "operation": event.data.get("operation"),
                    "query": event.data.get("query"),
                },
                mitre_ids=["T1546.003"],
                recommended_actions=[
                    "Enumerate WMI event subscriptions",
                    "Check for CommandLineEventConsumer or "
                    "ActiveScriptEventConsumer objects",
                    "Remove any unauthorised subscriptions",
                ],
            ),
        ]

    # ------------------------------------------------------------------ #
    #  LOLBins abuse
    # ------------------------------------------------------------------ #

    def _analyze_process(self, event: AegisEvent) -> list[Alert]:
        """Check process creation for LOLBins abuse patterns.

        Runs both parent-child and command-line checks via
        :class:`LOLBinsAnalyzer` and converts any findings to alerts.
        """
        alerts: list[Alert] = []
        data = event.data

        parent = data.get("parent_name", "")
        child = data.get("name", "")
        cmd = data.get("command_line", "")

        if parent and child:
            pc_finding = self._lolbins.check_parent_child(
                parent, child, cmd,
            )
            if pc_finding is not None:
                alerts.append(
                    Alert(
                        event_id=event.event_id,
                        sensor=event.sensor,
                        alert_type="fileless_lolbin_abuse",
                        severity=Severity.from_string(
                            pc_finding.severity,
                        ),
                        title=(
                            f"LOLBin abuse: {pc_finding.description}"
                        ),
                        description=(
                            f"{parent} spawned {child} — "
                            f"rule '{pc_finding.matched_rule}'"
                        ),
                        confidence=0.8,
                        data={
                            "pid": data.get("pid"),
                            "parent_name": parent,
                            "child_name": child,
                            "command_line": cmd,
                        },
                        mitre_ids=[pc_finding.mitre_id],
                        recommended_actions=[
                            "Investigate the parent process",
                            "Review the child command line",
                            "Check for macro-based delivery",
                        ],
                    ),
                )

        if child and cmd:
            cl_finding = self._lolbins.check_command_line(child, cmd)
            if cl_finding is not None:
                alerts.append(
                    Alert(
                        event_id=event.event_id,
                        sensor=event.sensor,
                        alert_type="fileless_lolbin_abuse",
                        severity=Severity.from_string(
                            cl_finding.severity,
                        ),
                        title=(
                            f"LOLBin abuse: "
                            f"{cl_finding.description}"
                        ),
                        description=(
                            f"Suspicious command line for "
                            f"{child}: {cmd}"
                        ),
                        confidence=0.85,
                        data={
                            "pid": data.get("pid"),
                            "binary": child,
                            "command_line": cmd,
                        },
                        mitre_ids=[cl_finding.mitre_id],
                        recommended_actions=[
                            "Review the full command line",
                            "Check for downloaded payloads",
                            "Block LOLBin abuse via AppLocker",
                        ],
                    ),
                )

        return alerts
