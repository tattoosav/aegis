"""Tests for ETW provider abstraction."""
from __future__ import annotations

import pytest

from aegis.sensors.etw_providers import (
    PROVIDER_CONFIGS,
    ETWEventRecord,
    ETWProviderConfig,
    ETWSession,
)


class TestETWProviderConfig:
    def test_provider_config_has_name_and_guid(self):
        cfg = ETWProviderConfig(
            name="Microsoft-Windows-PowerShell",
            guid="{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
            keywords=0xFFFF,
        )
        assert cfg.name == "Microsoft-Windows-PowerShell"
        assert cfg.guid == "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"
        assert cfg.keywords == 0xFFFF

    def test_provider_config_is_frozen(self):
        cfg = ETWProviderConfig(
            name="Test",
            guid="{00000000-0000-0000-0000-000000000000}",
        )
        with pytest.raises(AttributeError):
            cfg.name = "Changed"  # type: ignore[misc]

    def test_provider_config_default_keywords(self):
        cfg = ETWProviderConfig(
            name="Test",
            guid="{00000000-0000-0000-0000-000000000000}",
        )
        assert cfg.keywords == 0xFFFFFFFFFFFFFFFF

    def test_all_seven_providers_defined(self):
        assert len(PROVIDER_CONFIGS) == 7
        names = {p.name for p in PROVIDER_CONFIGS}
        assert "Microsoft-Windows-Kernel-Process" in names
        assert "Microsoft-Windows-DotNETRuntime" in names
        assert "Microsoft-Windows-PowerShell" in names
        assert "Microsoft-Windows-AMSI" in names
        assert "Microsoft-Windows-WMI-Activity" in names
        assert "Microsoft-Windows-WinINet" in names
        assert "Microsoft-Windows-Schannel" in names

    def test_all_providers_have_guids(self):
        for cfg in PROVIDER_CONFIGS:
            assert cfg.guid.startswith("{"), f"{cfg.name} guid missing brace"
            assert cfg.guid.endswith("}"), f"{cfg.name} guid missing brace"
            assert len(cfg.guid) == 38, f"{cfg.name} guid wrong length"

    def test_provider_names_are_unique(self):
        names = [p.name for p in PROVIDER_CONFIGS]
        assert len(names) == len(set(names))

    def test_provider_guids_are_unique(self):
        guids = [p.guid for p in PROVIDER_CONFIGS]
        assert len(guids) == len(set(guids))


class TestETWEventRecord:
    def test_event_record_creation(self):
        rec = ETWEventRecord(
            provider_name="Microsoft-Windows-PowerShell",
            event_id=4104,
            process_id=1234,
            thread_id=5678,
            timestamp=1000.0,
            properties={"ScriptBlockText": "Get-Process"},
        )
        assert rec.provider_name == "Microsoft-Windows-PowerShell"
        assert rec.event_id == 4104
        assert rec.process_id == 1234
        assert rec.thread_id == 5678
        assert rec.timestamp == 1000.0
        assert rec.properties["ScriptBlockText"] == "Get-Process"

    def test_event_record_default_properties(self):
        rec = ETWEventRecord(
            provider_name="Test",
            event_id=1,
            process_id=0,
            thread_id=0,
            timestamp=0.0,
        )
        assert rec.properties == {}

    def test_event_record_is_mutable(self):
        rec = ETWEventRecord(
            provider_name="Test",
            event_id=1,
            process_id=0,
            thread_id=0,
            timestamp=0.0,
        )
        rec.properties["key"] = "value"
        assert rec.properties["key"] == "value"


class TestETWSession:
    def test_session_creation(self):
        session = ETWSession(session_name="AegisTrace")
        assert session.session_name == "AegisTrace"
        assert not session.is_running

    def test_session_default_name(self):
        session = ETWSession()
        assert session.session_name == "AegisTrace"

    def test_add_provider(self):
        session = ETWSession(session_name="AegisTrace")
        cfg = PROVIDER_CONFIGS[0]
        session.add_provider(cfg)
        assert len(session.providers) == 1
        assert session.providers[0] is cfg

    def test_add_multiple_providers(self):
        session = ETWSession(session_name="AegisTrace")
        for cfg in PROVIDER_CONFIGS:
            session.add_provider(cfg)
        assert len(session.providers) == 7

    def test_set_callback(self):
        session = ETWSession(session_name="AegisTrace")
        events_received: list[ETWEventRecord] = []
        session.set_callback(events_received.append)
        # Callback should be stored internally
        assert session._callback is not None

    def test_start_stop_lifecycle(self):
        session = ETWSession(session_name="AegisTrace")
        # On non-admin or non-Windows, start should gracefully degrade
        session.start()
        session.stop()
        assert not session.is_running

    def test_stop_without_start(self):
        session = ETWSession(session_name="AegisTrace")
        # Should not raise
        session.stop()
        assert not session.is_running

    def test_providers_initially_empty(self):
        session = ETWSession(session_name="AegisTrace")
        assert session.providers == []
