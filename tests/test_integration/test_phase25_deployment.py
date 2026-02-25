"""Phase 25 integration tests — deployment readiness.

Validates that all Phase 25 components work together:
- AegisConfig with first-run keys
- WizardConfig + apply_wizard_config
- AegisServiceFramework lifecycle
- detect_run_mode dual-mode detection
- BaselineScanner system snapshot
- SysmonManager status checking
"""

from __future__ import annotations

import sys
from collections import namedtuple
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.baseline_scanner import BaselineScanner, BaselineSnapshot
from aegis.core.config import DEFAULT_CONFIG, AegisConfig
from aegis.core.service import AegisServiceFramework
from aegis.core.sysmon_manager import SysmonManager
from aegis.ui.first_run_wizard import (
    SENSITIVITY_THRESHOLDS,
    WizardConfig,
    apply_wizard_config,
)

# ------------------------------------------------------------------ #
# 1. Config defaults — verify all Phase 25 keys exist
# ------------------------------------------------------------------ #

class TestPhase25ConfigDefaults:
    """All Phase 25 config keys must have correct defaults."""

    def test_first_run_complete_default_false(self) -> None:
        cfg = AegisConfig()
        assert cfg.get("first_run_complete") is False

    def test_exclusions_defaults_empty(self) -> None:
        cfg = AegisConfig()
        assert cfg.get("exclusions.processes") == []
        assert cfg.get("exclusions.directories") == []
        assert cfg.get("exclusions.ips") == []

    def test_sysmon_defaults(self) -> None:
        cfg = AegisConfig()
        assert cfg.get("sysmon.installed") is False
        assert cfg.get("sysmon.config_path") == ""

    def test_detection_sensitivity_default(self) -> None:
        cfg = AegisConfig()
        assert cfg.get("detection.sensitivity") == "medium"

    def test_baseline_defaults(self) -> None:
        cfg = AegisConfig()
        assert cfg.get("baseline.learning_period_days") == 7
        assert cfg.get("baseline.status") == "not_started"

    def test_default_config_contains_all_phase25_keys(self) -> None:
        assert "first_run_complete" in DEFAULT_CONFIG
        assert "exclusions" in DEFAULT_CONFIG
        assert "sysmon" in DEFAULT_CONFIG


# ------------------------------------------------------------------ #
# 2. Full first-run wizard flow
# ------------------------------------------------------------------ #

class TestFirstRunWizardFlow:
    """End-to-end: config -> WizardConfig -> apply -> verify."""

    def test_full_wizard_apply_flow(self) -> None:
        cfg = AegisConfig()
        assert cfg.get("first_run_complete") is False

        wc = WizardConfig(
            sensors_enabled={
                "network": True,
                "process": True,
                "fim": False,
                "eventlog": True,
                "threat_intel": True,
                "hardware": False,
                "clipboard": False,
            },
            sensitivity="high",
            feeds_enabled={
                "virustotal": True,
                "abuseipdb": False,
                "phishtank": True,
            },
            api_keys={
                "virustotal": "VT_KEY_123",
                "abuseipdb": "",
                "phishtank": "",
            },
            excluded_processes=["chrome.exe", "vscode.exe"],
            excluded_dirs=["C:\\Temp"],
            excluded_ips=["192.168.1.1"],
            install_sysmon=True,
        )

        apply_wizard_config(cfg, wc)

        # Verify first_run_complete flipped
        assert cfg.get("first_run_complete") is True

        # Verify sensor toggles
        assert cfg.get("sensors.fim.enabled") is False
        assert cfg.get("sensors.network.enabled") is True
        assert cfg.get("sensors.hardware.enabled") is False
        assert cfg.get("sensors.clipboard.enabled") is False

        # Verify sensitivity
        assert cfg.get("detection.sensitivity") == "high"
        assert cfg.get(
            "detection.isolation_forest.anomaly_threshold"
        ) == 0.4

        # Verify feeds
        assert cfg.get(
            "sensors.threat_intel.feeds.virustotal.enabled"
        ) is True
        assert cfg.get(
            "sensors.threat_intel.feeds.virustotal.api_key"
        ) == "VT_KEY_123"
        assert cfg.get(
            "sensors.threat_intel.feeds.abuseipdb.enabled"
        ) is False

        # Verify exclusions
        assert cfg.get("exclusions.processes") == [
            "chrome.exe", "vscode.exe",
        ]
        assert cfg.get("exclusions.directories") == ["C:\\Temp"]
        assert cfg.get("exclusions.ips") == ["192.168.1.1"]

        # Verify sysmon
        assert cfg.get("sysmon.installed") is True

    def test_wizard_default_config_no_changes(self) -> None:
        """Applying default WizardConfig should still mark complete."""
        cfg = AegisConfig()
        wc = WizardConfig()
        apply_wizard_config(cfg, wc)
        assert cfg.get("first_run_complete") is True

    def test_sensitivity_threshold_mapping(self) -> None:
        for level, expected in SENSITIVITY_THRESHOLDS.items():
            wc = WizardConfig(sensitivity=level)
            assert wc.anomaly_threshold == expected

    def test_wizard_config_saves_to_yaml(self, tmp_path) -> None:
        """Config survives a save/load round-trip."""
        cfg = AegisConfig()
        wc = WizardConfig(
            sensitivity="low",
            excluded_processes=["test.exe"],
        )
        apply_wizard_config(cfg, wc)

        yaml_path = tmp_path / "config.yaml"
        cfg.save(yaml_path)

        loaded = AegisConfig.load(yaml_path)
        assert loaded.get("first_run_complete") is True
        assert loaded.get("detection.sensitivity") == "low"
        assert loaded.get("exclusions.processes") == ["test.exe"]


# ------------------------------------------------------------------ #
# 3. Service framework lifecycle
# ------------------------------------------------------------------ #

class TestServiceLifecycle:
    """AegisServiceFramework start/stop with mocked coordinator."""

    @patch("aegis.core.service.AegisConfig.load")
    @patch("aegis.core.service.AegisCoordinator")
    def test_start_creates_coordinator(
        self, mock_coord_cls, mock_load,
    ) -> None:
        mock_load.return_value = AegisConfig()
        mock_coord = MagicMock()
        mock_coord_cls.return_value = mock_coord

        svc = AegisServiceFramework()
        assert not svc.running
        assert svc.coordinator is None

        svc.start()

        mock_coord.setup.assert_called_once()
        mock_coord.start.assert_called_once()
        assert svc.running is True
        assert svc.coordinator is mock_coord

    @patch("aegis.core.service.AegisConfig.load")
    @patch("aegis.core.service.AegisCoordinator")
    def test_stop_calls_coordinator_stop(
        self, mock_coord_cls, mock_load,
    ) -> None:
        mock_load.return_value = AegisConfig()
        mock_coord = MagicMock()
        mock_coord_cls.return_value = mock_coord

        svc = AegisServiceFramework()
        svc.start()
        svc.stop()

        mock_coord.stop.assert_called_once()
        assert svc.running is False

    @patch("aegis.core.service.AegisConfig.load")
    @patch("aegis.core.service.AegisCoordinator")
    def test_full_start_stop_cycle(
        self, mock_coord_cls, mock_load,
    ) -> None:
        mock_load.return_value = AegisConfig()
        mock_coord = MagicMock()
        mock_coord_cls.return_value = mock_coord

        svc = AegisServiceFramework()
        svc.start()
        assert svc.running
        svc.stop()
        assert not svc.running

        # Verify correct call order
        mock_coord.setup.assert_called_once()
        mock_coord.start.assert_called_once()
        mock_coord.stop.assert_called_once()

    def test_stop_without_start_is_safe(self) -> None:
        svc = AegisServiceFramework()
        svc.stop()  # Should not raise
        assert not svc.running

    def test_service_metadata(self) -> None:
        assert AegisServiceFramework._svc_name_ == "AegisDefense"
        assert "Aegis" in AegisServiceFramework._svc_display_name_


# ------------------------------------------------------------------ #
# 4. Dual-mode detection
# ------------------------------------------------------------------ #

class TestDualModeDetection:
    """detect_run_mode returns the right value for each flag."""

    def test_service_mode(self) -> None:
        with patch.object(
            sys, "argv", ["aegis", "--service"],
        ):
            from aegis.__main__ import detect_run_mode
            assert detect_run_mode() == "service"

    def test_headless_mode(self) -> None:
        with patch.object(
            sys, "argv", ["aegis", "--headless"],
        ):
            from aegis.__main__ import detect_run_mode
            assert detect_run_mode() == "headless"

    def test_gui_mode_default(self) -> None:
        with patch.object(sys, "argv", ["aegis"]):
            from aegis.__main__ import detect_run_mode
            assert detect_run_mode() == "gui"

    def test_gui_mode_no_flags(self) -> None:
        with patch.object(sys, "argv", []):
            from aegis.__main__ import detect_run_mode
            assert detect_run_mode() == "gui"

    def test_service_flag_takes_priority(self) -> None:
        """--service checked before --headless."""
        with patch.object(
            sys, "argv", ["aegis", "--service", "--headless"],
        ):
            from aegis.__main__ import detect_run_mode
            assert detect_run_mode() == "service"


# ------------------------------------------------------------------ #
# 5. Baseline scanner with mocked psutil
# ------------------------------------------------------------------ #

_FakeProc = namedtuple("_FakeProc", ["info"])
_FakeConn = namedtuple("_FakeConn", ["raddr"])
_FakeAddr = namedtuple("_FakeAddr", ["ip", "port"])
_FakeSvc = namedtuple("_FakeSvc", ["name"])


class TestBaselineScanner:
    """BaselineScanner produces a valid snapshot with mocked psutil."""

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_produces_snapshot(self, mock_psutil) -> None:
        mock_psutil.process_iter.return_value = [
            _FakeProc(info={"name": "svchost.exe", "pid": 1}),
            _FakeProc(info={"name": "explorer.exe", "pid": 2}),
        ]
        mock_psutil.net_connections.return_value = [
            _FakeConn(raddr=_FakeAddr("10.0.0.1", 443)),
        ]
        fake_svc = MagicMock()
        fake_svc.name.return_value = "Spooler"
        mock_psutil.win_service_iter.return_value = [fake_svc]

        scanner = BaselineScanner()
        snap = scanner.scan()

        assert isinstance(snap, BaselineSnapshot)
        assert "svchost.exe" in snap.processes
        assert "explorer.exe" in snap.processes
        assert len(snap.connections) == 1
        assert snap.connections[0] == ("10.0.0.1", 443)
        assert "Spooler" in snap.services
        assert snap.timestamp > 0

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_handles_no_connections(
        self, mock_psutil,
    ) -> None:
        mock_psutil.process_iter.return_value = []
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.return_value = []

        scanner = BaselineScanner()
        snap = scanner.scan()

        assert snap.processes == []
        assert snap.connections == []
        assert snap.services == []

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_handles_access_denied(
        self, mock_psutil,
    ) -> None:
        import psutil as real_psutil

        mock_psutil.AccessDenied = real_psutil.AccessDenied
        mock_psutil.NoSuchProcess = real_psutil.NoSuchProcess
        mock_psutil.process_iter.side_effect = (
            real_psutil.AccessDenied(pid=0)
        )
        mock_psutil.net_connections.side_effect = (
            real_psutil.AccessDenied(pid=0)
        )
        mock_psutil.win_service_iter.side_effect = (
            real_psutil.AccessDenied(pid=0)
        )

        scanner = BaselineScanner()
        snap = scanner.scan()

        # Should degrade gracefully, not crash
        assert isinstance(snap, BaselineSnapshot)
        assert snap.processes == []
        assert snap.connections == []

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_skips_null_process_names(
        self, mock_psutil,
    ) -> None:
        mock_psutil.process_iter.return_value = [
            _FakeProc(info={"name": None, "pid": 1}),
            _FakeProc(info={"name": "real.exe", "pid": 2}),
        ]
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.return_value = []

        scanner = BaselineScanner()
        snap = scanner.scan()

        assert snap.processes == ["real.exe"]

    @patch("aegis.core.baseline_scanner.psutil")
    def test_snapshot_is_frozen(self, mock_psutil) -> None:
        mock_psutil.process_iter.return_value = []
        mock_psutil.net_connections.return_value = []
        mock_psutil.win_service_iter.return_value = []

        scanner = BaselineScanner()
        snap = scanner.scan()

        with pytest.raises(AttributeError):
            snap.timestamp = 0  # type: ignore[misc]


# ------------------------------------------------------------------ #
# 6. Sysmon manager with mocked subprocess
# ------------------------------------------------------------------ #

class TestSysmonManager:
    """SysmonManager checks status via mocked subprocess."""

    @patch("aegis.core.sysmon_manager.subprocess.run")
    def test_is_installed_true(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        mgr = SysmonManager()
        assert mgr.is_installed() is True
        mock_run.assert_called_once_with(
            ["sc", "query", "Sysmon64"],
            capture_output=True,
            text=True,
        )

    @patch("aegis.core.sysmon_manager.subprocess.run")
    def test_is_installed_false(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=1)
        mgr = SysmonManager()
        assert mgr.is_installed() is False

    @patch("aegis.core.sysmon_manager.subprocess.run")
    def test_is_installed_exception(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError("sc not found")
        mgr = SysmonManager()
        assert mgr.is_installed() is False

    @patch("aegis.core.sysmon_manager.subprocess.run")
    def test_install_success(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        mgr = SysmonManager()
        assert mgr.install() is True

    @patch("aegis.core.sysmon_manager.subprocess.run")
    def test_install_failure(self, mock_run) -> None:
        mock_run.return_value = MagicMock(
            returncode=1, stderr="access denied",
        )
        mgr = SysmonManager()
        assert mgr.install() is False

    @patch("aegis.core.sysmon_manager.subprocess.run")
    def test_uninstall_success(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        mgr = SysmonManager()
        assert mgr.uninstall() is True

    @patch("aegis.core.sysmon_manager.subprocess.run")
    def test_get_version_parses(self, mock_run) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="System Monitor v15.14 - ...",
        )
        mgr = SysmonManager()
        assert mgr.get_version() == "15.14"

    @patch("aegis.core.sysmon_manager.subprocess.run")
    def test_get_version_returns_none_on_failure(
        self, mock_run,
    ) -> None:
        mock_run.return_value = MagicMock(returncode=1)
        mgr = SysmonManager()
        assert mgr.get_version() is None

    def test_custom_paths(self) -> None:
        mgr = SysmonManager(
            sysmon_path="C:\\custom\\Sysmon64.exe",
            config_path="C:\\custom\\config.xml",
        )
        assert mgr.sysmon_path == "C:\\custom\\Sysmon64.exe"
        assert mgr.config_path == "C:\\custom\\config.xml"


# ------------------------------------------------------------------ #
# 7. End-to-end: wizard + config persistence round-trip
# ------------------------------------------------------------------ #

class TestEndToEndDeployment:
    """Full deployment flow: config -> wizard -> save -> reload."""

    def test_config_round_trip_preserves_wizard(
        self, tmp_path,
    ) -> None:
        cfg = AegisConfig()
        assert cfg.get("first_run_complete") is False

        wc = WizardConfig(
            sensitivity="high",
            excluded_processes=["steam.exe"],
            excluded_dirs=["D:\\Games"],
            excluded_ips=["10.0.0.99"],
            install_sysmon=True,
        )
        apply_wizard_config(cfg, wc)

        yaml_path = tmp_path / "aegis_config.yaml"
        cfg.save(yaml_path)

        reloaded = AegisConfig.load(yaml_path)
        assert reloaded.get("first_run_complete") is True
        assert reloaded.get("detection.sensitivity") == "high"
        assert reloaded.get(
            "detection.isolation_forest.anomaly_threshold",
        ) == 0.4
        assert reloaded.get("exclusions.processes") == [
            "steam.exe",
        ]
        assert reloaded.get("exclusions.directories") == [
            "D:\\Games",
        ]
        assert reloaded.get("exclusions.ips") == ["10.0.0.99"]
        assert reloaded.get("sysmon.installed") is True

    @patch("aegis.core.service.AegisConfig.load")
    @patch("aegis.core.service.AegisCoordinator")
    def test_wizard_then_service_start(
        self, mock_coord_cls, mock_load,
    ) -> None:
        """After wizard applies, service can start normally."""
        cfg = AegisConfig()
        wc = WizardConfig(sensitivity="low")
        apply_wizard_config(cfg, wc)
        assert cfg.get("first_run_complete") is True

        mock_load.return_value = cfg
        mock_coord = MagicMock()
        mock_coord_cls.return_value = mock_coord

        svc = AegisServiceFramework()
        svc.start()
        assert svc.running

        svc.stop()
        assert not svc.running
        mock_coord.stop.assert_called_once()
