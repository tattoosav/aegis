"""ETW Sensor — monitors Windows Event Tracing for security events.

Captures events from seven ETW providers covering:
- PowerShell script block logging
- .NET assembly loading (fileless attack indicator)
- Kernel process image loads (DLL injection)
- AMSI scan results
- WMI activity (persistence / lateral movement)
- WinINet HTTP requests (C2 beaconing)
- Schannel TLS handshakes (encrypted traffic metadata)
"""

from __future__ import annotations

import collections
import logging
from collections.abc import Callable

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.base import BaseSensor
from aegis.sensors.etw_providers import (
    PROVIDER_CONFIGS,
    ETWEventRecord,
    ETWSession,
)

logger = logging.getLogger(__name__)


class ETWSensor(BaseSensor):
    """ETW monitor sensor — subscribes to Windows ETW providers.

    Parses incoming ETW records into AegisEvent objects for the
    detection engine. Each supported provider has a dedicated parser
    that extracts security-relevant fields.
    """

    sensor_type = SensorType.ETW
    sensor_name = "etw_monitor"

    def __init__(
        self,
        interval: float = 2.0,
        on_event: Callable[[AegisEvent], None] | None = None,
    ) -> None:
        super().__init__(interval=interval, on_event=on_event)
        self._session: ETWSession | None = None
        self._buffer: collections.deque[AegisEvent] = (
            collections.deque(maxlen=10_000)
        )
        self._provider_parsers: dict[
            str,
            collections.abc.Callable[
                [ETWEventRecord], list[AegisEvent]
            ],
        ] = {}

    def setup(self) -> None:
        """Create ETW session, register providers, wire callback."""
        self._provider_parsers = {
            "Microsoft-Windows-PowerShell": self._parse_powershell,
            "Microsoft-Windows-DotNETRuntime": self._parse_dotnet,
            "Microsoft-Windows-Kernel-Process": (
                self._parse_kernel_process
            ),
            "Microsoft-Windows-AMSI": self._parse_amsi,
            "Microsoft-Windows-WMI-Activity": self._parse_wmi,
            "Microsoft-Windows-WinINet": self._parse_wininet,
            "Microsoft-Windows-Schannel": self._parse_schannel,
        }
        self._session = ETWSession(session_name="AegisETWSensor")
        for provider_cfg in PROVIDER_CONFIGS:
            self._session.add_provider(provider_cfg)
        self._session.set_callback(self._on_etw_event)
        self._session.start()

    def collect(self) -> list[AegisEvent]:
        """Drain buffered events and return them.

        Events are pushed into the buffer asynchronously by the ETW
        callback thread; collect() drains whatever has accumulated.
        """
        events: list[AegisEvent] = []
        while self._buffer:
            try:
                events.append(self._buffer.popleft())
            except IndexError:
                break
        return events

    def teardown(self) -> None:
        """Stop the ETW session and clear buffers."""
        if self._session is not None:
            self._session.stop()
            self._session = None
        self._buffer.clear()

    # ------------------------------------------------------------------
    # ETW callback
    # ------------------------------------------------------------------

    def _on_etw_event(self, record: ETWEventRecord) -> None:
        """Handle an incoming ETW record from the session callback.

        Parses the record into AegisEvent(s) and appends them to the
        internal buffer for later collection.
        """
        parsed = self._parse_etw_record(record)
        for event in parsed:
            self._buffer.append(event)

    # ------------------------------------------------------------------
    # Record dispatch
    # ------------------------------------------------------------------

    def _parse_etw_record(
        self, record: ETWEventRecord,
    ) -> list[AegisEvent]:
        """Dispatch an ETW record to the correct provider parser.

        Returns an empty list if the provider is unrecognized or the
        event_id is not handled by the parser.
        """
        parser = self._provider_parsers.get(record.provider_name)
        if parser is None:
            return []
        return parser(record)

    # ------------------------------------------------------------------
    # Provider-specific parsers
    # ------------------------------------------------------------------

    def _parse_powershell(
        self, record: ETWEventRecord,
    ) -> list[AegisEvent]:
        """Parse PowerShell script block logging events.

        Handles event_id 4104 (ScriptBlockLogging).
        """
        if record.event_id != 4104:
            return []
        props = record.properties
        return [
            AegisEvent(
                sensor=SensorType.ETW,
                event_type="etw.powershell_scriptblock",
                severity=Severity.INFO,
                timestamp=record.timestamp,
                data={
                    "script_text": props.get(
                        "ScriptBlockText", ""
                    ),
                    "script_block_id": props.get(
                        "ScriptBlockId", ""
                    ),
                    "script_path": props.get("Path", ""),
                    "pid": record.process_id,
                },
            ),
        ]

    def _parse_dotnet(
        self, record: ETWEventRecord,
    ) -> list[AegisEvent]:
        """Parse .NET runtime assembly load events.

        Handles event_id 152 (AssemblyLoad).
        """
        if record.event_id != 152:
            return []
        props = record.properties
        return [
            AegisEvent(
                sensor=SensorType.ETW,
                event_type="etw.dotnet_assembly_load",
                severity=Severity.INFO,
                timestamp=record.timestamp,
                data={
                    "assembly_name": props.get(
                        "FullyQualifiedAssemblyName", ""
                    ),
                    "module_il_path": props.get(
                        "ModuleILPath", ""
                    ),
                    "is_dynamic": props.get(
                        "IsDynamic", False
                    ),
                    "pid": record.process_id,
                },
            ),
        ]

    def _parse_kernel_process(
        self, record: ETWEventRecord,
    ) -> list[AegisEvent]:
        """Parse kernel process image load events.

        Handles event_id 5 (ImageLoad).
        """
        if record.event_id != 5:
            return []
        props = record.properties
        return [
            AegisEvent(
                sensor=SensorType.ETW,
                event_type="etw.process_image_load",
                severity=Severity.INFO,
                timestamp=record.timestamp,
                data={
                    "image_path": props.get("ImageName", ""),
                    "image_base": props.get("ImageBase", 0),
                    "image_size": props.get("ImageSize", 0),
                    "pid": record.process_id,
                },
            ),
        ]

    def _parse_amsi(
        self, record: ETWEventRecord,
    ) -> list[AegisEvent]:
        """Parse AMSI scan result events.

        Handles event_id 1101 (AntimalwareScanResult).
        """
        if record.event_id != 1101:
            return []
        props = record.properties
        return [
            AegisEvent(
                sensor=SensorType.ETW,
                event_type="etw.amsi_scan",
                severity=Severity.INFO,
                timestamp=record.timestamp,
                data={
                    "content_name": props.get(
                        "contentName", ""
                    ),
                    "app_name": props.get("appName", ""),
                    "result": props.get("scanResult", 0),
                    "pid": record.process_id,
                },
            ),
        ]

    def _parse_wmi(
        self, record: ETWEventRecord,
    ) -> list[AegisEvent]:
        """Parse WMI activity events.

        Handles event_id 5861 (WMI operation).
        """
        if record.event_id != 5861:
            return []
        props = record.properties
        return [
            AegisEvent(
                sensor=SensorType.ETW,
                event_type="etw.wmi_activity",
                severity=Severity.INFO,
                timestamp=record.timestamp,
                data={
                    "operation": props.get("Operation", ""),
                    "namespace": props.get("Namespace", ""),
                    "query": props.get("Query", ""),
                    "pid": record.process_id,
                },
            ),
        ]

    def _parse_wininet(
        self, record: ETWEventRecord,
    ) -> list[AegisEvent]:
        """Parse WinINet HTTP request events.

        Handles event_id 1057 (HTTP request).
        """
        if record.event_id != 1057:
            return []
        props = record.properties
        return [
            AegisEvent(
                sensor=SensorType.ETW,
                event_type="etw.http_request",
                severity=Severity.INFO,
                timestamp=record.timestamp,
                data={
                    "url": props.get("URL", ""),
                    "method": props.get("RequestMethod", ""),
                    "headers": props.get(
                        "RequestHeaders", ""
                    ),
                    "pid": record.process_id,
                },
            ),
        ]

    def _parse_schannel(
        self, record: ETWEventRecord,
    ) -> list[AegisEvent]:
        """Parse Schannel TLS handshake events.

        Handles event_id 36880 (TLS handshake).
        """
        if record.event_id != 36880:
            return []
        props = record.properties
        return [
            AegisEvent(
                sensor=SensorType.ETW,
                event_type="etw.tls_handshake",
                severity=Severity.INFO,
                timestamp=record.timestamp,
                data={
                    "server_name": props.get(
                        "ServerName", ""
                    ),
                    "cipher_suite": props.get(
                        "CipherSuite", ""
                    ),
                    "protocol_version": props.get(
                        "ProtocolVersion", ""
                    ),
                    "pid": record.process_id,
                },
            ),
        ]
