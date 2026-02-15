"""USB & Hardware Monitor sensor — detects USB device changes and rogue adapters.

Monitors:
- USB device insertion and removal between collection cycles
- Device fingerprinting: VID, PID, serial, device class, manufacturer
- BadUSB / Rubber Ducky detection (composite HID + mass storage devices)
- USB whitelist enforcement (alert on unknown device serials)
- Network adapter monitoring (rogue adapter detection)

Uses the ``wmi`` module when available on Windows.  When WMI is not
installed the sensor operates in **stub mode** with a simulated device
list so that tests and non-Windows environments still work.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.base import BaseSensor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Graceful WMI import
# ---------------------------------------------------------------------------
try:
    import wmi as _wmi_mod  # type: ignore[import-untyped]
    _HAS_WMI = True
except ImportError:
    _wmi_mod = None  # type: ignore[assignment]
    _HAS_WMI = False

# ---------------------------------------------------------------------------
# Known-suspicious vendor IDs associated with BadUSB / Rubber Ducky devices
# ---------------------------------------------------------------------------
BADUSB_VENDOR_IDS: set[str] = {
    "03EB",  # Atmel (common in DIY HID attacks)
    "1B4F",  # SparkFun (Pro Micro clones used for BadUSB)
    "2341",  # Arduino (Leonardo / Micro — HID injection)
    "16C0",  # Teensy (PJRC — popular Rubber Ducky alternative)
    "1FC9",  # NXP LPC-based attack boards
    "0483",  # STMicroelectronics (some attack dongles)
    "CAFE",  # Common development placeholder VID
}

# Device classes that indicate HID capability
_HID_CLASSES: set[str] = {"Keyboard", "Mouse", "HIDClass", "HID"}

# Device classes that indicate mass-storage capability
_STORAGE_CLASSES: set[str] = {"DiskDrive", "CDROM", "USB", "USBDevice"}


# ---------------------------------------------------------------------------
# Helpers — VID/PID extraction from PnP device IDs
# ---------------------------------------------------------------------------
_VID_PID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", re.IGNORECASE)


def _extract_vid_pid(device_id: str) -> tuple[str, str]:
    """Extract vendor-ID and product-ID from a PnP device string.

    Returns (vid, pid) in uppercase hex, or ("", "") when not found.
    """
    match = _VID_PID_RE.search(device_id)
    if match:
        return match.group(1).upper(), match.group(2).upper()
    return "", ""


def _extract_serial(device_id: str) -> str:
    """Best-effort serial extraction from a PnP device ID string.

    The serial typically appears as the last segment after the second
    backslash, e.g. ``USB\\VID_1234&PID_5678\\SERIAL123``.
    """
    parts = device_id.replace("/", "\\").split("\\")
    if len(parts) >= 3:
        candidate = parts[-1]
        # Filter out generic Windows-generated IDs
        if candidate and not candidate.startswith("&"):
            return candidate
    return ""


# ---------------------------------------------------------------------------
# WMI-based device enumeration
# ---------------------------------------------------------------------------

def _query_usb_devices_wmi() -> list[dict[str, Any]]:
    """Query USB devices via WMI and return normalised device dicts."""
    devices: list[dict[str, Any]] = []
    try:
        conn = _wmi_mod.WMI()  # type: ignore[union-attr]
        for item in conn.query(
            "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'"
        ):
            device_id: str = getattr(item, "DeviceID", "") or ""
            vid, pid = _extract_vid_pid(device_id)
            serial = _extract_serial(device_id)
            pnp_class: str = getattr(item, "PNPClass", "") or ""
            description: str = getattr(item, "Description", "") or ""
            manufacturer: str = getattr(item, "Manufacturer", "") or ""

            devices.append({
                "device_id": device_id,
                "vendor_id": vid,
                "product_id": pid,
                "serial": serial,
                "device_class": pnp_class,
                "description": description,
                "manufacturer": manufacturer,
                "timestamp": time.time(),
            })
    except Exception as exc:
        logger.warning("WMI USB query failed: %s", exc)
    return devices


def _query_network_adapters_wmi() -> list[dict[str, Any]]:
    """Query network adapters via WMI and return normalised dicts."""
    adapters: list[dict[str, Any]] = []
    try:
        conn = _wmi_mod.WMI()  # type: ignore[union-attr]
        for item in conn.query(
            "SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter = TRUE"
        ):
            adapters.append({
                "name": getattr(item, "Name", "") or "",
                "adapter_type": getattr(item, "AdapterType", "") or "",
                "mac_address": getattr(item, "MACAddress", "") or "",
                "manufacturer": getattr(item, "Manufacturer", "") or "",
                "device_id": str(getattr(item, "DeviceID", "")),
                "net_enabled": bool(getattr(item, "NetEnabled", False)),
                "timestamp": time.time(),
            })
    except Exception as exc:
        logger.warning("WMI network-adapter query failed: %s", exc)
    return adapters


# ---------------------------------------------------------------------------
# Stub / mock device lists (used when WMI is not available)
# ---------------------------------------------------------------------------

_STUB_USB_DEVICES: list[dict[str, Any]] = [
    {
        "device_id": "USB\\VID_8087&PID_0026\\5&1234ABCD&0&14",
        "vendor_id": "8087",
        "product_id": "0026",
        "serial": "5&1234ABCD&0&14",
        "device_class": "USB",
        "description": "Intel Bluetooth Adapter",
        "manufacturer": "Intel Corporation",
        "timestamp": 0.0,
    },
    {
        "device_id": "USB\\VID_0BDA&PID_5411\\1234567890",
        "vendor_id": "0BDA",
        "product_id": "5411",
        "serial": "1234567890",
        "device_class": "USB",
        "description": "Realtek USB Hub",
        "manufacturer": "Realtek",
        "timestamp": 0.0,
    },
]

_STUB_NETWORK_ADAPTERS: list[dict[str, Any]] = [
    {
        "name": "Intel Wi-Fi 6 AX201",
        "adapter_type": "Ethernet 802.3",
        "mac_address": "AA:BB:CC:DD:EE:01",
        "manufacturer": "Intel Corporation",
        "device_id": "1",
        "net_enabled": True,
        "timestamp": 0.0,
    },
]


def _query_usb_devices_stub() -> list[dict[str, Any]]:
    """Return a copy of the stub USB device list with fresh timestamps."""
    now = time.time()
    return [{**d, "timestamp": now} for d in _STUB_USB_DEVICES]


def _query_network_adapters_stub() -> list[dict[str, Any]]:
    """Return a copy of the stub network adapter list with fresh timestamps."""
    now = time.time()
    return [{**a, "timestamp": now} for a in _STUB_NETWORK_ADAPTERS]


# ---------------------------------------------------------------------------
# BadUSB / Rubber Ducky heuristic detection
# ---------------------------------------------------------------------------

def is_badusb_suspect(device: dict[str, Any]) -> tuple[bool, list[str]]:
    """Evaluate whether a USB device looks like a BadUSB / Rubber Ducky.

    Returns ``(is_suspect, reasons)`` where *reasons* lists human-readable
    strings explaining why the device is flagged.
    """
    reasons: list[str] = []
    vid = device.get("vendor_id", "").upper()
    dev_class = device.get("device_class", "")
    description = (device.get("description", "") or "").lower()

    # 1. Known suspicious vendor ID
    if vid in BADUSB_VENDOR_IDS:
        reasons.append(f"Known suspicious vendor ID: {vid}")

    # 2. Composite device presenting both HID and storage interfaces
    is_hid = dev_class in _HID_CLASSES or "keyboard" in description
    is_storage = dev_class in _STORAGE_CLASSES or "mass storage" in description
    if is_hid and is_storage:
        reasons.append(
            "Composite device with both HID and mass-storage interfaces"
        )

    # 3. Keyboard class but description hints at storage or composite
    if dev_class in _HID_CLASSES:
        storage_hints = ["disk", "storage", "flash", "drive", "composite"]
        for hint in storage_hints:
            if hint in description:
                reasons.append(
                    f"HID device description contains storage hint: '{hint}'"
                )
                break

    # 4. Known attack-tool keywords in description
    attack_keywords = [
        "rubber ducky", "badusb", "usb armory", "bash bunny",
        "lan turtle", "hak5", "teensy", "digispark",
    ]
    for kw in attack_keywords:
        if kw in description:
            reasons.append(f"Description matches attack-tool keyword: '{kw}'")
            break

    return (len(reasons) > 0, reasons)


# ---------------------------------------------------------------------------
# HardwareSensor
# ---------------------------------------------------------------------------

class HardwareSensor(BaseSensor):
    """USB & Hardware Monitor — tracks USB devices and network adapters.

    Emits:
    - hardware_snapshot: periodic device-count summary
    - usb_inserted: new USB device detected
    - usb_removed: USB device removed
    - badusb_detected: potential BadUSB / Rubber Ducky device (CRITICAL)
    - rogue_adapter: new network adapter detected (HIGH)
    """

    sensor_type = SensorType.HARDWARE
    sensor_name = "hardware_monitor"

    def __init__(
        self,
        interval: float = 10.0,
        whitelist: set[str] | None = None,
        on_event: Any = None,
        **kwargs: Any,
    ):
        super().__init__(interval=interval, on_event=on_event, **kwargs)
        self._whitelist: set[str] = set(whitelist) if whitelist else set()
        self._baseline_usb: dict[str, dict[str, Any]] = {}
        self._baseline_adapters: dict[str, dict[str, Any]] = {}
        self._use_wmi: bool = _HAS_WMI

    # -- Public helpers for testing / runtime injection ---------------------

    def add_to_whitelist(self, serial: str) -> None:
        """Add a device serial number to the whitelist."""
        self._whitelist.add(serial)

    def remove_from_whitelist(self, serial: str) -> None:
        """Remove a device serial number from the whitelist."""
        self._whitelist.discard(serial)

    @property
    def whitelist(self) -> set[str]:
        """Return a copy of the current whitelist."""
        return set(self._whitelist)

    # -- Internal device query dispatchers ---------------------------------

    def _get_usb_devices(self) -> list[dict[str, Any]]:
        """Return the current list of USB device dicts."""
        if self._use_wmi:
            return _query_usb_devices_wmi()
        return _query_usb_devices_stub()

    def _get_network_adapters(self) -> list[dict[str, Any]]:
        """Return the current list of network adapter dicts."""
        if self._use_wmi:
            return _query_network_adapters_wmi()
        return _query_network_adapters_stub()

    # -- BaseSensor implementation -----------------------------------------

    def setup(self) -> None:
        """Capture baseline USB devices and network adapters."""
        usb_devices = self._get_usb_devices()
        self._baseline_usb = {d["device_id"]: d for d in usb_devices}

        adapters = self._get_network_adapters()
        self._baseline_adapters = {a["name"]: a for a in adapters}

        logger.info(
            "HardwareSensor baseline: %d USB devices, %d network adapters",
            len(self._baseline_usb),
            len(self._baseline_adapters),
        )

    def collect(self) -> list[AegisEvent]:
        """Compare current devices against baseline and emit events."""
        events: list[AegisEvent] = []

        # ----- USB devices ------------------------------------------------
        current_usb_list = self._get_usb_devices()
        current_usb = {d["device_id"]: d for d in current_usb_list}

        prev_ids = set(self._baseline_usb.keys())
        curr_ids = set(current_usb.keys())

        inserted_ids = curr_ids - prev_ids
        removed_ids = prev_ids - curr_ids

        for dev_id in inserted_ids:
            device = current_usb[dev_id]

            # --- BadUSB check first (highest priority) ---
            suspect, reasons = is_badusb_suspect(device)
            if suspect:
                events.append(AegisEvent(
                    sensor=SensorType.HARDWARE,
                    event_type="badusb_detected",
                    severity=Severity.CRITICAL,
                    data={
                        **device,
                        "reasons": reasons,
                    },
                ))

            # --- Whitelist check ---
            serial = device.get("serial", "")
            on_whitelist = serial != "" and serial in self._whitelist

            severity = Severity.INFO if on_whitelist else Severity.MEDIUM
            events.append(AegisEvent(
                sensor=SensorType.HARDWARE,
                event_type="usb_inserted",
                severity=severity,
                data={
                    **device,
                    "whitelisted": on_whitelist,
                },
            ))

        for dev_id in removed_ids:
            device = self._baseline_usb[dev_id]
            events.append(AegisEvent(
                sensor=SensorType.HARDWARE,
                event_type="usb_removed",
                severity=Severity.INFO,
                data=device,
            ))

        # ----- Network adapters -------------------------------------------
        current_adapter_list = self._get_network_adapters()
        current_adapters = {a["name"]: a for a in current_adapter_list}

        prev_adapter_names = set(self._baseline_adapters.keys())
        curr_adapter_names = set(current_adapters.keys())

        new_adapters = curr_adapter_names - prev_adapter_names
        for adapter_name in new_adapters:
            adapter = current_adapters[adapter_name]
            events.append(AegisEvent(
                sensor=SensorType.HARDWARE,
                event_type="rogue_adapter",
                severity=Severity.HIGH,
                data=adapter,
            ))

        # ----- Periodic snapshot ------------------------------------------
        events.append(AegisEvent(
            sensor=SensorType.HARDWARE,
            event_type="hardware_snapshot",
            severity=Severity.INFO,
            data={
                "usb_device_count": len(current_usb),
                "network_adapter_count": len(current_adapters),
                "usb_inserted_count": len(inserted_ids),
                "usb_removed_count": len(removed_ids),
                "new_adapter_count": len(new_adapters),
                "whitelist_size": len(self._whitelist),
                "using_wmi": self._use_wmi,
            },
        ))

        # Update baseline for next cycle
        self._baseline_usb = current_usb
        self._baseline_adapters = current_adapters

        return events

    def teardown(self) -> None:
        """Cleanup — nothing special required."""
        self._baseline_usb.clear()
        self._baseline_adapters.clear()
