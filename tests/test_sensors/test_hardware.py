"""Tests for the Hardware Monitor sensor (USB & network adapter tracking)."""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import patch

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.hardware import (
    _STUB_NETWORK_ADAPTERS,
    _STUB_USB_DEVICES,
    BADUSB_VENDOR_IDS,
    HardwareSensor,
    _extract_serial,
    _extract_vid_pid,
    is_badusb_suspect,
)

# ---------------------------------------------------------------------------
# Helpers — reusable device factory
# ---------------------------------------------------------------------------

def _make_device(
    device_id: str = "USB\\VID_1234&PID_5678\\SERIAL001",
    vendor_id: str = "1234",
    product_id: str = "5678",
    serial: str = "SERIAL001",
    device_class: str = "USB",
    description: str = "Generic USB Device",
    manufacturer: str = "Acme Corp",
) -> dict[str, Any]:
    """Create a minimal USB device dict for testing."""
    return {
        "device_id": device_id,
        "vendor_id": vendor_id,
        "product_id": product_id,
        "serial": serial,
        "device_class": device_class,
        "description": description,
        "manufacturer": manufacturer,
        "timestamp": time.time(),
    }


def _make_adapter(
    name: str = "Test Adapter",
    adapter_type: str = "Ethernet 802.3",
    mac_address: str = "AA:BB:CC:DD:EE:FF",
    manufacturer: str = "Test Inc",
    device_id: str = "99",
    net_enabled: bool = True,
) -> dict[str, Any]:
    """Create a minimal network adapter dict for testing."""
    return {
        "name": name,
        "adapter_type": adapter_type,
        "mac_address": mac_address,
        "manufacturer": manufacturer,
        "device_id": device_id,
        "net_enabled": net_enabled,
        "timestamp": time.time(),
    }


# ===================================================================
# VID / PID Extraction
# ===================================================================

class TestVidPidExtraction:
    """Tests for _extract_vid_pid helper."""

    def test_extracts_vid_pid(self):
        vid, pid = _extract_vid_pid("USB\\VID_8087&PID_0026\\serial")
        assert vid == "8087"
        assert pid == "0026"

    def test_no_match_returns_empty(self):
        vid, pid = _extract_vid_pid("SOME_OTHER_ID")
        assert vid == ""
        assert pid == ""

    def test_case_insensitive(self):
        vid, pid = _extract_vid_pid("usb\\vid_abcd&pid_1234\\x")
        assert vid == "ABCD"
        assert pid == "1234"

    def test_mixed_case(self):
        vid, pid = _extract_vid_pid("USB\\Vid_DeAd&Pid_BeEf\\serial123")
        assert vid == "DEAD"
        assert pid == "BEEF"

    def test_empty_string(self):
        vid, pid = _extract_vid_pid("")
        assert vid == ""
        assert pid == ""

    def test_vid_pid_in_longer_path(self):
        device_id = "USB\\VID_0BDA&PID_5411\\5&1234ABCD&0&14"
        vid, pid = _extract_vid_pid(device_id)
        assert vid == "0BDA"
        assert pid == "5411"


# ===================================================================
# Serial Extraction
# ===================================================================

class TestSerialExtraction:
    """Tests for _extract_serial helper."""

    def test_extracts_serial(self):
        serial = _extract_serial("USB\\VID_1234&PID_5678\\MYSERIAL")
        assert serial == "MYSERIAL"

    def test_no_serial_returns_empty(self):
        serial = _extract_serial("USB")
        assert serial == ""

    def test_empty_string(self):
        serial = _extract_serial("")
        assert serial == ""

    def test_serial_with_mixed_separators(self):
        serial = _extract_serial("USB/VID_1234&PID_5678/SER123")
        assert serial == "SER123"

    def test_serial_starting_with_ampersand_filtered(self):
        """Serials starting with '&' are Windows-generated and filtered out."""
        serial = _extract_serial("USB\\VID_1234&PID_5678\\&0")
        assert serial == ""

    def test_serial_with_numbers_and_letters(self):
        serial = _extract_serial("USB\\VID_1234&PID_5678\\5&1234ABCD&0&14")
        assert serial == "5&1234ABCD&0&14"


# ===================================================================
# BadUSB / Rubber Ducky Detection
# ===================================================================

class TestBadUsbDetection:
    """Tests for is_badusb_suspect heuristic."""

    def test_normal_device_not_suspect(self):
        device = _make_device(
            vendor_id="8087",
            device_class="USB",
            description="Intel Bluetooth Adapter",
        )
        suspect, reasons = is_badusb_suspect(device)
        assert suspect is False
        assert reasons == []

    def test_suspicious_vid_flagged(self):
        device = _make_device(vendor_id="03EB", device_class="USB")
        suspect, reasons = is_badusb_suspect(device)
        assert suspect is True
        assert any("03EB" in r for r in reasons)

    def test_all_known_suspicious_vids(self):
        """Every VID in BADUSB_VENDOR_IDS should trigger detection."""
        for vid in BADUSB_VENDOR_IDS:
            device = _make_device(vendor_id=vid, device_class="USB")
            suspect, reasons = is_badusb_suspect(device)
            assert suspect is True, f"VID {vid} should be flagged as suspect"
            assert any(vid in r for r in reasons)

    def test_composite_hid_storage_flagged(self):
        """Device that is HID class with 'mass storage' in description."""
        device = _make_device(
            vendor_id="1234",
            device_class="Keyboard",
            description="USB Keyboard with mass storage interface",
        )
        suspect, reasons = is_badusb_suspect(device)
        assert suspect is True
        assert any("HID and mass-storage" in r or "storage" in r.lower() for r in reasons)

    def test_attack_keyword_flagged(self):
        device = _make_device(
            vendor_id="1234",
            device_class="USB",
            description="rubber ducky device",
        )
        suspect, reasons = is_badusb_suspect(device)
        assert suspect is True
        assert any("rubber ducky" in r for r in reasons)

    def test_multiple_attack_keywords(self):
        """Check several known attack keywords trigger detection."""
        keywords = ["badusb", "bash bunny", "hak5", "teensy", "digispark"]
        for kw in keywords:
            device = _make_device(description=f"Test {kw} device")
            suspect, reasons = is_badusb_suspect(device)
            assert suspect is True, f"Keyword '{kw}' should trigger detection"

    def test_hid_class_with_storage_hint_in_description(self):
        """HID-class device with storage-related words in description."""
        device = _make_device(
            device_class="Keyboard",
            description="composite flash keyboard",
        )
        suspect, reasons = is_badusb_suspect(device)
        assert suspect is True
        assert any("flash" in r for r in reasons)

    def test_case_insensitive_description_matching(self):
        device = _make_device(description="RUBBER DUCKY ATTACK TOOL")
        suspect, reasons = is_badusb_suspect(device)
        assert suspect is True

    def test_empty_device_dict(self):
        """An empty dict should not crash and should return not suspect."""
        suspect, reasons = is_badusb_suspect({})
        assert suspect is False
        assert reasons == []

    def test_keyboard_description_with_mass_storage(self):
        """Keyboard in description (not class) plus mass storage triggers composite."""
        device = _make_device(
            device_class="USBDevice",
            description="keyboard with mass storage",
        )
        suspect, reasons = is_badusb_suspect(device)
        assert suspect is True


# ===================================================================
# Module Constants
# ===================================================================

class TestModuleConstants:
    """Tests for module-level constants and stubs."""

    def test_badusb_vendor_ids_is_set(self):
        assert isinstance(BADUSB_VENDOR_IDS, set)
        assert len(BADUSB_VENDOR_IDS) > 0

    def test_badusb_vendor_ids_contains_known_ids(self):
        expected = {"03EB", "1B4F", "2341", "16C0"}
        assert expected.issubset(BADUSB_VENDOR_IDS)

    def test_stub_usb_devices_count(self):
        assert isinstance(_STUB_USB_DEVICES, list)
        assert len(_STUB_USB_DEVICES) == 2

    def test_stub_usb_devices_have_required_keys(self):
        required_keys = {
            "device_id", "vendor_id", "product_id", "serial",
            "device_class", "description", "manufacturer", "timestamp",
        }
        for device in _STUB_USB_DEVICES:
            assert required_keys.issubset(device.keys())

    def test_stub_network_adapters_count(self):
        assert isinstance(_STUB_NETWORK_ADAPTERS, list)
        assert len(_STUB_NETWORK_ADAPTERS) == 1

    def test_stub_network_adapters_have_required_keys(self):
        required_keys = {
            "name", "adapter_type", "mac_address",
            "manufacturer", "device_id", "net_enabled", "timestamp",
        }
        for adapter in _STUB_NETWORK_ADAPTERS:
            assert required_keys.issubset(adapter.keys())


# ===================================================================
# HardwareSensor — Initialisation
# ===================================================================

class TestHardwareSensorInit:
    """Tests for HardwareSensor constructor and class attributes."""

    def test_sensor_type(self):
        sensor = HardwareSensor(interval=999)
        assert sensor.sensor_type == SensorType.HARDWARE

    def test_sensor_name(self):
        sensor = HardwareSensor(interval=999)
        assert sensor.sensor_name == "hardware_monitor"

    def test_default_interval_10(self):
        sensor = HardwareSensor()
        assert sensor._interval == 10.0

    def test_custom_interval(self):
        sensor = HardwareSensor(interval=30.0)
        assert sensor._interval == 30.0

    def test_custom_whitelist(self):
        wl = {"SER1", "SER2"}
        sensor = HardwareSensor(whitelist=wl)
        assert sensor.whitelist == wl

    def test_default_whitelist_empty(self):
        sensor = HardwareSensor()
        assert sensor.whitelist == set()

    def test_on_event_callback_stored(self):
        cb = lambda e: None  # noqa: E731
        sensor = HardwareSensor(on_event=cb)
        assert sensor._on_event is cb


# ===================================================================
# HardwareSensor — Whitelist management
# ===================================================================

class TestHardwareSensorWhitelist:
    """Tests for whitelist add / remove / property."""

    def test_add_to_whitelist(self):
        sensor = HardwareSensor()
        sensor.add_to_whitelist("SERIAL_ABC")
        assert "SERIAL_ABC" in sensor.whitelist

    def test_add_multiple_to_whitelist(self):
        sensor = HardwareSensor()
        sensor.add_to_whitelist("S1")
        sensor.add_to_whitelist("S2")
        assert sensor.whitelist == {"S1", "S2"}

    def test_remove_from_whitelist(self):
        sensor = HardwareSensor(whitelist={"A", "B", "C"})
        sensor.remove_from_whitelist("B")
        assert "B" not in sensor.whitelist
        assert sensor.whitelist == {"A", "C"}

    def test_remove_nonexistent_serial_is_noop(self):
        sensor = HardwareSensor(whitelist={"A"})
        sensor.remove_from_whitelist("NONEXISTENT")
        assert sensor.whitelist == {"A"}

    def test_whitelist_property_returns_copy(self):
        sensor = HardwareSensor(whitelist={"X"})
        wl = sensor.whitelist
        wl.add("Y")
        assert "Y" not in sensor.whitelist, "Modifying returned set must not affect sensor"


# ===================================================================
# HardwareSensor — Lifecycle (setup / collect / teardown)
# ===================================================================

class TestHardwareSensorLifecycle:
    """Tests for setup, collect, and teardown methods."""

    def test_setup_captures_baseline(self):
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()
        assert len(sensor._baseline_usb) == len(_STUB_USB_DEVICES)
        assert len(sensor._baseline_adapters) == len(_STUB_NETWORK_ADAPTERS)

    def test_collect_returns_snapshot(self):
        """collect() should always emit at least a hardware_snapshot event."""
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()
        events = sensor.collect()
        snapshot_events = [e for e in events if e.event_type == "hardware_snapshot"]
        assert len(snapshot_events) == 1
        snap = snapshot_events[0]
        assert snap.sensor == SensorType.HARDWARE
        assert snap.severity == Severity.INFO
        assert "usb_device_count" in snap.data
        assert "network_adapter_count" in snap.data

    def test_collect_no_changes(self):
        """When nothing changes between setup and collect, no inserted/removed events."""
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()
        events = sensor.collect()
        inserted = [e for e in events if e.event_type == "usb_inserted"]
        removed = [e for e in events if e.event_type == "usb_removed"]
        assert len(inserted) == 0
        assert len(removed) == 0
        # Snapshot should reflect zero changes
        snap = [e for e in events if e.event_type == "hardware_snapshot"][0]
        assert snap.data["usb_inserted_count"] == 0
        assert snap.data["usb_removed_count"] == 0

    def test_teardown_clears_baselines(self):
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()
        assert len(sensor._baseline_usb) > 0
        sensor.teardown()
        assert len(sensor._baseline_usb) == 0
        assert len(sensor._baseline_adapters) == 0

    def test_snapshot_data_fields(self):
        """Snapshot event should contain all expected summary fields."""
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()
        events = sensor.collect()
        snap = [e for e in events if e.event_type == "hardware_snapshot"][0]
        expected_fields = {
            "usb_device_count",
            "network_adapter_count",
            "usb_inserted_count",
            "usb_removed_count",
            "new_adapter_count",
            "whitelist_size",
            "using_wmi",
        }
        assert expected_fields.issubset(snap.data.keys())

    def test_collect_updates_baseline(self):
        """After collect(), baseline should match current devices."""
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()

        new_device = _make_device(
            device_id="USB\\VID_AAAA&PID_BBBB\\NEWSN",
            serial="NEWSN",
        )
        stub_plus_new = list(_STUB_USB_DEVICES) + [new_device]

        with patch.object(sensor, "_get_usb_devices", return_value=stub_plus_new):
            sensor.collect()

        # After collect the baseline should include the new device
        assert "USB\\VID_AAAA&PID_BBBB\\NEWSN" in sensor._baseline_usb


# ===================================================================
# HardwareSensor — Device insertion / removal detection
# ===================================================================

class TestHardwareSensorDeviceDetection:
    """Tests for USB insertion, removal, whitelist severity, and BadUSB."""

    def test_new_device_emits_usb_inserted(self):
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()

        new_device = _make_device(
            device_id="USB\\VID_AAAA&PID_BBBB\\NEWSERIAL",
            vendor_id="AAAA",
            product_id="BBBB",
            serial="NEWSERIAL",
        )
        current_devices = list(_STUB_USB_DEVICES) + [new_device]

        with patch.object(sensor, "_get_usb_devices", return_value=current_devices):
            events = sensor.collect()

        inserted = [e for e in events if e.event_type == "usb_inserted"]
        assert len(inserted) == 1
        assert inserted[0].data["serial"] == "NEWSERIAL"

    def test_removed_device_emits_usb_removed(self):
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()

        # Return only the first stub device (the second is "removed")
        fewer_devices = [_STUB_USB_DEVICES[0].copy()]
        fewer_devices[0]["timestamp"] = time.time()

        with patch.object(sensor, "_get_usb_devices", return_value=fewer_devices):
            events = sensor.collect()

        removed = [e for e in events if e.event_type == "usb_removed"]
        assert len(removed) == 1
        assert removed[0].data["device_id"] == _STUB_USB_DEVICES[1]["device_id"]
        assert removed[0].severity == Severity.INFO

    def test_whitelisted_device_is_info_severity(self):
        sensor = HardwareSensor(interval=999, whitelist={"TRUSTED_SN"})
        sensor._use_wmi = False
        sensor.setup()

        new_device = _make_device(
            device_id="USB\\VID_1234&PID_5678\\TRUSTED_SN",
            serial="TRUSTED_SN",
        )
        current_devices = list(_STUB_USB_DEVICES) + [new_device]

        with patch.object(sensor, "_get_usb_devices", return_value=current_devices):
            events = sensor.collect()

        inserted = [e for e in events if e.event_type == "usb_inserted"]
        assert len(inserted) == 1
        assert inserted[0].severity == Severity.INFO
        assert inserted[0].data["whitelisted"] is True

    def test_unknown_device_is_medium_severity(self):
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()

        new_device = _make_device(
            device_id="USB\\VID_1234&PID_5678\\UNKNOWN_SN",
            serial="UNKNOWN_SN",
        )
        current_devices = list(_STUB_USB_DEVICES) + [new_device]

        with patch.object(sensor, "_get_usb_devices", return_value=current_devices):
            events = sensor.collect()

        inserted = [e for e in events if e.event_type == "usb_inserted"]
        assert len(inserted) == 1
        assert inserted[0].severity == Severity.MEDIUM
        assert inserted[0].data["whitelisted"] is False

    def test_badusb_device_emits_critical(self):
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()

        bad_device = _make_device(
            device_id="USB\\VID_03EB&PID_2FF4\\EVIL",
            vendor_id="03EB",
            product_id="2FF4",
            serial="EVIL",
            description="Atmel DFU Device",
        )
        current_devices = list(_STUB_USB_DEVICES) + [bad_device]

        with patch.object(sensor, "_get_usb_devices", return_value=current_devices):
            events = sensor.collect()

        badusb_events = [e for e in events if e.event_type == "badusb_detected"]
        assert len(badusb_events) == 1
        assert badusb_events[0].severity == Severity.CRITICAL
        assert "reasons" in badusb_events[0].data
        assert len(badusb_events[0].data["reasons"]) > 0

    def test_badusb_also_emits_usb_inserted(self):
        """A BadUSB device should also generate a usb_inserted event."""
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()

        bad_device = _make_device(
            device_id="USB\\VID_03EB&PID_2FF4\\EVIL2",
            vendor_id="03EB",
            serial="EVIL2",
        )
        current_devices = list(_STUB_USB_DEVICES) + [bad_device]

        with patch.object(sensor, "_get_usb_devices", return_value=current_devices):
            events = sensor.collect()

        badusb_events = [e for e in events if e.event_type == "badusb_detected"]
        inserted_events = [e for e in events if e.event_type == "usb_inserted"]
        assert len(badusb_events) == 1
        assert len(inserted_events) == 1
        assert inserted_events[0].data["serial"] == "EVIL2"

    def test_multiple_devices_inserted_at_once(self):
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()

        dev_a = _make_device(device_id="USB\\VID_AAAA&PID_0001\\SNa", serial="SNa")
        dev_b = _make_device(device_id="USB\\VID_BBBB&PID_0002\\SNb", serial="SNb")
        current_devices = list(_STUB_USB_DEVICES) + [dev_a, dev_b]

        with patch.object(sensor, "_get_usb_devices", return_value=current_devices):
            events = sensor.collect()

        inserted = [e for e in events if e.event_type == "usb_inserted"]
        assert len(inserted) == 2
        inserted_serials = {e.data["serial"] for e in inserted}
        assert inserted_serials == {"SNa", "SNb"}

    def test_device_inserted_then_removed(self):
        """Full cycle: insert on first collect, remove on second collect."""
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()

        new_dev = _make_device(
            device_id="USB\\VID_CCCC&PID_DDDD\\TEMP",
            serial="TEMP",
        )
        with_new = list(_STUB_USB_DEVICES) + [new_dev]

        # First collect: device inserted
        with patch.object(sensor, "_get_usb_devices", return_value=with_new):
            events_1 = sensor.collect()
        inserted = [e for e in events_1 if e.event_type == "usb_inserted"]
        assert len(inserted) == 1

        # Second collect: device removed (back to stubs only)
        stub_copy = [{**d, "timestamp": time.time()} for d in _STUB_USB_DEVICES]
        with patch.object(sensor, "_get_usb_devices", return_value=stub_copy):
            events_2 = sensor.collect()
        removed = [e for e in events_2 if e.event_type == "usb_removed"]
        assert len(removed) == 1
        assert removed[0].data["serial"] == "TEMP"


# ===================================================================
# HardwareSensor — Network adapter detection
# ===================================================================

class TestHardwareSensorAdapterDetection:
    """Tests for rogue network adapter detection."""

    def test_new_adapter_emits_rogue_adapter(self):
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()

        new_adapter = _make_adapter(
            name="Suspicious USB Ethernet",
            mac_address="DE:AD:BE:EF:00:01",
        )
        current_adapters = list(_STUB_NETWORK_ADAPTERS) + [new_adapter]
        current_adapters = [{**a, "timestamp": time.time()} for a in current_adapters]

        with patch.object(sensor, "_get_network_adapters", return_value=current_adapters):
            events = sensor.collect()

        rogue = [e for e in events if e.event_type == "rogue_adapter"]
        assert len(rogue) == 1
        assert rogue[0].severity == Severity.HIGH
        assert rogue[0].data["name"] == "Suspicious USB Ethernet"

    def test_no_new_adapter_no_rogue_event(self):
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()
        events = sensor.collect()
        rogue = [e for e in events if e.event_type == "rogue_adapter"]
        assert len(rogue) == 0


# ===================================================================
# HardwareSensor — Event structure validation
# ===================================================================

class TestHardwareSensorEventStructure:
    """Verify all emitted events are well-formed AegisEvent objects."""

    def test_all_events_are_aegis_events(self):
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()
        events = sensor.collect()
        for event in events:
            assert isinstance(event, AegisEvent)

    def test_all_events_have_hardware_sensor(self):
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()

        bad = _make_device(device_id="USB\\VID_03EB&PID_0001\\X", vendor_id="03EB", serial="X")
        with patch.object(
            sensor, "_get_usb_devices",
            return_value=list(_STUB_USB_DEVICES) + [bad],
        ):
            events = sensor.collect()

        for event in events:
            assert event.sensor == SensorType.HARDWARE

    def test_events_serializable(self):
        """All events should round-trip through to_dict / from_dict."""
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()

        new_dev = _make_device(device_id="USB\\VID_FFFF&PID_0001\\SN_RT", serial="SN_RT")
        with patch.object(
            sensor, "_get_usb_devices",
            return_value=list(_STUB_USB_DEVICES) + [new_dev],
        ):
            events = sensor.collect()

        for event in events:
            d = event.to_dict()
            restored = AegisEvent.from_dict(d)
            assert restored.event_type == event.event_type
            assert restored.severity == event.severity
            assert restored.sensor == event.sensor

    def test_snapshot_using_wmi_field(self):
        """Snapshot data should report whether WMI is in use."""
        sensor = HardwareSensor(interval=999)
        sensor._use_wmi = False
        sensor.setup()
        events = sensor.collect()
        snap = [e for e in events if e.event_type == "hardware_snapshot"][0]
        assert snap.data["using_wmi"] is False
