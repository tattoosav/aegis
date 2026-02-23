"""Tests for Fileless Attack Detection Engine."""
from __future__ import annotations

from aegis.core.models import AegisEvent, SensorType
from aegis.detection.fileless_detector import FilelessDetector


class TestPowerShellDetection:
    def test_obfuscated_script_produces_alert(self) -> None:
        detector = FilelessDetector()
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.powershell_scriptblock",
            data={
                "script_text": (
                    "I`nv`oke-`Exp`ress`ion "
                    "[System.Convert]::FromBase64String('dGVzdA==')"
                ),
                "pid": 1234,
                "script_block_id": "abc",
            },
        )
        alerts = detector.analyze_event(event)
        assert len(alerts) >= 1
        assert any("powershell" in a.alert_type.lower() for a in alerts)

    def test_clean_script_no_alert(self) -> None:
        detector = FilelessDetector()
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.powershell_scriptblock",
            data={
                "script_text": "Get-Process | Format-Table",
                "pid": 1234,
            },
        )
        alerts = detector.analyze_event(event)
        ps_alerts = [
            a for a in alerts if "powershell" in a.alert_type.lower()
        ]
        assert len(ps_alerts) == 0


class TestDotNetDetection:
    def test_fileless_assembly_produces_alert(self) -> None:
        detector = FilelessDetector()
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.dotnet_assembly_load",
            data={
                "assembly_name": "Malicious.Payload",
                "module_il_path": "",
                "is_dynamic": True,
                "pid": 5678,
            },
        )
        alerts = detector.analyze_event(event)
        assert len(alerts) >= 1
        assert any("dotnet" in a.alert_type.lower() for a in alerts)

    def test_normal_assembly_no_alert(self) -> None:
        detector = FilelessDetector()
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.dotnet_assembly_load",
            data={
                "assembly_name": "System.Core",
                "module_il_path": (
                    "C:\\Windows\\assembly\\System.Core.dll"
                ),
                "is_dynamic": False,
                "pid": 5678,
            },
        )
        alerts = detector.analyze_event(event)
        assert len(alerts) == 0


class TestWMIDetection:
    def test_subscription_namespace_produces_alert(self) -> None:
        detector = FilelessDetector()
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.wmi_activity",
            data={
                "operation": "ExecMethod",
                "namespace": "root\\subscription",
                "query": "SELECT * FROM __EventFilter",
                "pid": 3333,
            },
        )
        alerts = detector.analyze_event(event)
        assert len(alerts) >= 1
        assert any("wmi" in a.alert_type.lower() for a in alerts)


class TestLOLBinsDetection:
    def test_suspicious_parent_child_produces_alert(self) -> None:
        detector = FilelessDetector()
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_new",
            data={
                "name": "powershell.exe",
                "parent_name": "winword.exe",
                "command_line": "powershell -enc ...",
                "pid": 4444,
            },
        )
        alerts = detector.analyze_event(event)
        assert len(alerts) >= 1

    def test_normal_process_no_alert(self) -> None:
        detector = FilelessDetector()
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_new",
            data={
                "name": "notepad.exe",
                "parent_name": "explorer.exe",
                "command_line": "notepad.exe",
                "pid": 5555,
            },
        )
        alerts = detector.analyze_event(event)
        assert len(alerts) == 0


class TestIrrelevantEvents:
    def test_irrelevant_event_type(self) -> None:
        detector = FilelessDetector()
        event = AegisEvent(
            sensor=SensorType.FILE,
            event_type="file_modified",
            data={"path": "C:\\test.txt"},
        )
        alerts = detector.analyze_event(event)
        assert len(alerts) == 0
