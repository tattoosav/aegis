"""Tests for aegis.core.sysmon_manager -- Sysmon management.

Validates that SysmonManager can check installation status,
install, uninstall, and retrieve version information for Sysmon,
handling errors gracefully when Sysmon is not present.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from aegis.core.sysmon_manager import SysmonManager

# ------------------------------------------------------------------ #
# TestSysmonManager
# ------------------------------------------------------------------ #


class TestSysmonManager:
    """Unit tests for SysmonManager."""

    # ---- defaults ------------------------------------------------ #

    def test_default_config_path(self):
        """Default config path contains sysmonconfig."""
        mgr = SysmonManager()
        assert "sysmonconfig" in mgr.config_path

    def test_default_sysmon_path(self):
        """Default sysmon path contains Sysmon64.exe."""
        mgr = SysmonManager()
        assert "Sysmon64.exe" in mgr.sysmon_path

    def test_custom_paths(self):
        """Custom paths are stored correctly."""
        mgr = SysmonManager(
            sysmon_path="C:/custom/Sysmon64.exe",
            config_path="C:/custom/config.xml",
        )
        assert mgr.sysmon_path == "C:/custom/Sysmon64.exe"
        assert mgr.config_path == "C:/custom/config.xml"

    # ---- is_installed -------------------------------------------- #

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_is_installed_true(self, mock_sub):
        """is_installed returns True when sc query succeeds."""
        mock_sub.run.return_value = MagicMock(returncode=0)
        mgr = SysmonManager()
        assert mgr.is_installed() is True

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_is_installed_false(self, mock_sub):
        """is_installed returns False when sc query fails."""
        mock_sub.run.return_value = MagicMock(returncode=1)
        mgr = SysmonManager()
        assert mgr.is_installed() is False

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_is_installed_calls_sc_query(self, mock_sub):
        """is_installed runs 'sc query Sysmon64'."""
        mock_sub.run.return_value = MagicMock(returncode=0)
        mgr = SysmonManager()
        mgr.is_installed()
        args = mock_sub.run.call_args
        cmd = args[0][0]
        assert "sc" in cmd
        assert "query" in cmd
        assert "Sysmon64" in cmd

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_is_installed_handles_exception(self, mock_sub):
        """is_installed returns False if subprocess raises."""
        mock_sub.run.side_effect = FileNotFoundError("sc not found")
        mgr = SysmonManager()
        assert mgr.is_installed() is False

    # ---- install ------------------------------------------------- #

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_install_calls_sysmon_exe(self, mock_sub):
        """install invokes Sysmon64.exe with -accepteula -i."""
        mock_sub.run.return_value = MagicMock(returncode=0)
        mgr = SysmonManager(sysmon_path="tools/sysmon/Sysmon64.exe")
        result = mgr.install()
        assert result is True
        mock_sub.run.assert_called()

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_install_passes_config(self, mock_sub):
        """install passes -i config_path to Sysmon."""
        mock_sub.run.return_value = MagicMock(returncode=0)
        mgr = SysmonManager(
            sysmon_path="tools/sysmon/Sysmon64.exe",
            config_path="tools/sysmon/sysmonconfig.xml",
        )
        mgr.install()
        args = mock_sub.run.call_args
        cmd = args[0][0]
        assert "-accepteula" in cmd
        assert "-i" in cmd
        assert "tools/sysmon/sysmonconfig.xml" in cmd

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_install_returns_false_on_failure(self, mock_sub):
        """install returns False when returncode != 0."""
        mock_sub.run.return_value = MagicMock(returncode=1)
        mgr = SysmonManager()
        assert mgr.install() is False

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_install_handles_exception(self, mock_sub):
        """install returns False if subprocess raises."""
        mock_sub.run.side_effect = FileNotFoundError("exe not found")
        mgr = SysmonManager()
        assert mgr.install() is False

    # ---- uninstall ----------------------------------------------- #

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_uninstall_success(self, mock_sub):
        """uninstall returns True on success."""
        mock_sub.run.return_value = MagicMock(returncode=0)
        mgr = SysmonManager(sysmon_path="tools/sysmon/Sysmon64.exe")
        assert mgr.uninstall() is True

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_uninstall_calls_sysmon_u(self, mock_sub):
        """uninstall passes -u flag to Sysmon."""
        mock_sub.run.return_value = MagicMock(returncode=0)
        mgr = SysmonManager(sysmon_path="tools/sysmon/Sysmon64.exe")
        mgr.uninstall()
        args = mock_sub.run.call_args
        cmd = args[0][0]
        assert "-u" in cmd

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_uninstall_returns_false_on_failure(self, mock_sub):
        """uninstall returns False when returncode != 0."""
        mock_sub.run.return_value = MagicMock(returncode=1)
        mgr = SysmonManager()
        assert mgr.uninstall() is False

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_uninstall_handles_exception(self, mock_sub):
        """uninstall returns False if subprocess raises."""
        mock_sub.run.side_effect = OSError("access denied")
        mgr = SysmonManager()
        assert mgr.uninstall() is False

    # ---- get_version --------------------------------------------- #

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_get_version_returns_string(self, mock_sub):
        """get_version returns version string on success."""
        mock_sub.run.return_value = MagicMock(
            returncode=0,
            stdout="System Monitor v15.14 - System activity monitor\n",
        )
        mgr = SysmonManager()
        version = mgr.get_version()
        assert version is not None
        assert "15.14" in version

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_get_version_returns_none_on_failure(self, mock_sub):
        """get_version returns None when returncode != 0."""
        mock_sub.run.return_value = MagicMock(
            returncode=1,
            stdout="",
        )
        mgr = SysmonManager()
        assert mgr.get_version() is None

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_get_version_handles_exception(self, mock_sub):
        """get_version returns None if subprocess raises."""
        mock_sub.run.side_effect = FileNotFoundError("not found")
        mgr = SysmonManager()
        assert mgr.get_version() is None

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_get_version_parses_version_number(self, mock_sub):
        """get_version extracts version from Sysmon output."""
        mock_sub.run.return_value = MagicMock(
            returncode=0,
            stdout="System Monitor v14.0 - System activity monitor\n",
        )
        mgr = SysmonManager()
        version = mgr.get_version()
        assert version == "14.0"

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_get_version_no_match_returns_raw(self, mock_sub):
        """get_version returns raw stdout if no version pattern found."""
        mock_sub.run.return_value = MagicMock(
            returncode=0,
            stdout="Sysmon is running\n",
        )
        mgr = SysmonManager()
        version = mgr.get_version()
        assert version is not None
