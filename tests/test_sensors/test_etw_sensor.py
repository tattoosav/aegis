"""Tests for ETW Sensor."""
from __future__ import annotations

import time

from aegis.core.models import SensorType, Severity
from aegis.sensors.etw_providers import ETWEventRecord
from aegis.sensors.etw_sensor import ETWSensor


class TestETWSensorInit:
    """Test ETWSensor class attributes and initialization."""

    def test_sensor_type(self) -> None:
        sensor = ETWSensor()
        assert sensor.sensor_type == SensorType.ETW

    def test_sensor_name(self) -> None:
        sensor = ETWSensor()
        assert sensor.sensor_name == "etw_monitor"


class TestETWSensorEventParsing:
    """Test ETW record parsing for each provider."""

    def test_parse_powershell_scriptblock(self) -> None:
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-PowerShell",
            event_id=4104,
            process_id=1234,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "ScriptBlockText": "Get-Process | Select-Object Name",
                "ScriptBlockId": "abc-123",
                "Path": "C:\\test.ps1",
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.powershell_scriptblock"
        assert events[0].data["script_text"] == (
            "Get-Process | Select-Object Name"
        )
        assert events[0].data["pid"] == 1234

    def test_parse_dotnet_assembly_load(self) -> None:
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-DotNETRuntime",
            event_id=152,
            process_id=5678,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "FullyQualifiedAssemblyName": "Malicious.Assembly",
                "ModuleILPath": "",
                "IsDynamic": True,
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.dotnet_assembly_load"
        assert events[0].data["module_il_path"] == ""
        assert events[0].data["is_dynamic"] is True

    def test_parse_image_load(self) -> None:
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-Kernel-Process",
            event_id=5,
            process_id=9999,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "ImageName": "\\Device\\HarddiskVolume3\\evil.dll",
                "ImageBase": 0x7FF00000,
                "ImageSize": 0x10000,
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.process_image_load"
        assert events[0].data["image_path"] == (
            "\\Device\\HarddiskVolume3\\evil.dll"
        )

    def test_parse_amsi_scan(self) -> None:
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-AMSI",
            event_id=1101,
            process_id=2222,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "contentName": "test_script",
                "appName": "PowerShell",
                "scanResult": 32768,
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.amsi_scan"
        assert events[0].data["result"] == 32768

    def test_parse_wmi_activity(self) -> None:
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-WMI-Activity",
            event_id=5861,
            process_id=3333,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "Operation": "ExecMethod",
                "Namespace": "root\\subscription",
                "Query": "SELECT * FROM __EventFilter",
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.wmi_activity"

    def test_parse_http_request(self) -> None:
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-WinINet",
            event_id=1057,
            process_id=4444,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "URL": "https://evil.com/beacon",
                "RequestMethod": "GET",
                "RequestHeaders": "Host: evil.com",
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.http_request"
        assert events[0].data["url"] == "https://evil.com/beacon"

    def test_parse_tls_handshake(self) -> None:
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-Schannel",
            event_id=36880,
            process_id=5555,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "ServerName": "evil.com",
                "CipherSuite": "TLS_AES_256_GCM_SHA384",
                "ProtocolVersion": "TLS 1.3",
            },
        )
        events = sensor._parse_etw_record(record)
        assert len(events) == 1
        assert events[0].event_type == "etw.tls_handshake"

    def test_unknown_provider_returns_empty(self) -> None:
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Unknown-Provider",
            event_id=1,
            process_id=1,
            thread_id=1,
            timestamp=time.time(),
            properties={},
        )
        events = sensor._parse_etw_record(record)
        assert events == []


class TestETWSensorEventFields:
    """Test that parsed events carry correct sensor, severity, ts."""

    def test_event_sensor_type(self) -> None:
        sensor = ETWSensor()
        sensor.setup()
        ts = time.time()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-PowerShell",
            event_id=4104,
            process_id=100,
            thread_id=1,
            timestamp=ts,
            properties={
                "ScriptBlockText": "whoami",
                "ScriptBlockId": "x",
                "Path": "",
            },
        )
        events = sensor._parse_etw_record(record)
        assert events[0].sensor == SensorType.ETW
        assert events[0].severity == Severity.INFO
        assert events[0].timestamp == ts

    def test_unmatched_event_id_returns_empty(self) -> None:
        """Known provider but unrecognized event_id => []."""
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-PowerShell",
            event_id=9999,
            process_id=100,
            thread_id=1,
            timestamp=time.time(),
            properties={},
        )
        events = sensor._parse_etw_record(record)
        assert events == []


class TestETWSensorCollect:
    """Test the collect() drain mechanism."""

    def test_collect_drains_buffer(self) -> None:
        sensor = ETWSensor()
        sensor.setup()
        record = ETWEventRecord(
            provider_name="Microsoft-Windows-AMSI",
            event_id=1101,
            process_id=10,
            thread_id=1,
            timestamp=time.time(),
            properties={
                "contentName": "c",
                "appName": "a",
                "scanResult": 1,
            },
        )
        # Simulate the ETW callback pushing an event
        sensor._on_etw_event(record)
        events = sensor.collect()
        assert len(events) == 1
        # Second collect should be empty
        assert sensor.collect() == []

    def test_collect_empty_when_no_events(self) -> None:
        sensor = ETWSensor()
        sensor.setup()
        assert sensor.collect() == []
