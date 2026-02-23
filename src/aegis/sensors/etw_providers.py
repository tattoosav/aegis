"""ETW provider abstraction layer.

Provides a mockable interface over Windows ETW so the sensor can be
tested without real ETW sessions.  On non-Windows platforms or without
admin privileges the session degrades gracefully (no events emitted).
"""
from __future__ import annotations

import logging
import platform
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ETWProviderConfig:
    """Configuration for a single ETW provider.

    Attributes:
        name: Provider friendly name (e.g. Microsoft-Windows-PowerShell).
        guid: Provider GUID in registry format {xxxxxxxx-...}.
        keywords: Bitmask selecting which event categories to receive.
    """

    name: str
    guid: str
    keywords: int = 0xFFFFFFFFFFFFFFFF


@dataclass
class ETWEventRecord:
    """A single parsed ETW event.

    Attributes:
        provider_name: Name of the provider that emitted the event.
        event_id: Numeric event identifier.
        process_id: PID of the process that generated the event.
        thread_id: TID of the thread that generated the event.
        timestamp: Event timestamp (seconds since epoch or QPC).
        properties: Arbitrary key-value payload from the event.
    """

    provider_name: str
    event_id: int
    process_id: int
    thread_id: int
    timestamp: float
    properties: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pre-defined provider configurations from the Aegis design doc.
# These seven providers cover process, .NET, PowerShell, AMSI, WMI,
# network, and TLS activity on Windows.
# ---------------------------------------------------------------------------
PROVIDER_CONFIGS: list[ETWProviderConfig] = [
    ETWProviderConfig(
        name="Microsoft-Windows-Kernel-Process",
        guid="{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
        keywords=0x10,
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-DotNETRuntime",
        guid="{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}",
        keywords=0x1C,
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-PowerShell",
        guid="{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
        keywords=0xFFFF,
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-AMSI",
        guid="{2A576B87-09A7-520E-C21A-4942F0271D67}",
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-WMI-Activity",
        guid="{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}",
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-WinINet",
        guid="{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}",
    ),
    ETWProviderConfig(
        name="Microsoft-Windows-Schannel",
        guid="{1F678132-5938-4686-9FDC-C8FF68F15C85}",
    ),
]


class ETWSession:
    """Manages an ETW tracing session.

    Wraps pywintrace or ctypes ETW APIs.  Gracefully degrades on
    non-Windows or when admin privileges are unavailable.
    """

    def __init__(self, session_name: str = "AegisTrace") -> None:
        self.session_name = session_name
        self.providers: list[ETWProviderConfig] = []
        self.is_running = False
        self._callback: Callable[[ETWEventRecord], None] | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def add_provider(self, config: ETWProviderConfig) -> None:
        """Register an ETW provider to trace."""
        self.providers.append(config)

    def set_callback(
        self, callback: Callable[[ETWEventRecord], None]
    ) -> None:
        """Set the function called for each incoming ETW event."""
        self._callback = callback

    def start(self) -> None:
        """Start the ETW tracing session.

        On non-Windows or without admin rights the call logs a warning
        and returns without raising.
        """
        if platform.system() != "Windows":
            logger.warning(
                "ETW only available on Windows; session not started"
            )
            return
        try:
            self._start_native()
        except Exception:
            logger.warning(
                "ETW session start failed (need admin?)",
                exc_info=True,
            )

    def stop(self) -> None:
        """Stop the ETW tracing session."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        self.is_running = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _start_native(self) -> None:
        """Start real ETW tracing via pywintrace or ctypes."""
        try:
            self._start_pywintrace()
        except ImportError:
            logger.info(
                "pywintrace not available; trying ctypes ETW"
            )
            self._start_ctypes()

    def _start_pywintrace(self) -> None:
        """Start ETW session using pywintrace library."""
        import etw as pywintrace  # type: ignore[import-untyped]

        providers = []
        for cfg in self.providers:
            providers.append(
                pywintrace.ProviderInfo(
                    cfg.name,
                    pywintrace.GUID(cfg.guid),
                    any_keywords=cfg.keywords,
                )
            )

        def _on_event(event_tufo: tuple) -> None:  # type: ignore[type-arg]
            if self._callback is None:
                return
            event_id, props = event_tufo
            record = ETWEventRecord(
                provider_name=props.get("ProviderName", ""),
                event_id=event_id,
                process_id=props.get("ProcessId", 0),
                thread_id=props.get("ThreadId", 0),
                timestamp=props.get("TimeStamp", 0.0),
                properties=props,
            )
            self._callback(record)

        self._etw = pywintrace.ETW(
            providers=providers,
            event_callback=_on_event,
        )
        self._etw.start()
        self.is_running = True

    def _start_ctypes(self) -> None:
        """Fallback: start ETW session via raw ctypes Win32 API.

        Not yet implemented -- logs a warning and returns.
        """
        logger.warning("ctypes ETW fallback not yet implemented")
