"""Tests for install_sysmon helper script."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add scripts to path for import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from install_sysmon import download_file, is_admin  # noqa: E402


class TestIsAdmin:
    """Tests for is_admin()."""

    @patch("install_sysmon.ctypes")
    def test_returns_true_when_admin(
        self, mock_ctypes: MagicMock,
    ) -> None:
        mock_ctypes.windll.kernel32.IsUserAnAdmin.return_value = 1
        assert is_admin() is True

    @patch("install_sysmon.ctypes")
    def test_returns_false_when_not_admin(
        self, mock_ctypes: MagicMock,
    ) -> None:
        mock_ctypes.windll.kernel32.IsUserAnAdmin.return_value = 0
        assert is_admin() is False

    @patch("install_sysmon.ctypes")
    def test_returns_false_on_attribute_error(
        self, mock_ctypes: MagicMock,
    ) -> None:
        mock_ctypes.windll.kernel32.IsUserAnAdmin.side_effect = (
            AttributeError("no windll")
        )
        assert is_admin() is False


class TestDownloadFile:
    """Tests for download_file()."""

    @patch("install_sysmon.urllib.request.urlopen")
    def test_successful_download(
        self, mock_urlopen: MagicMock, tmp_path: Path,
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"test content"
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        dest = tmp_path / "file.txt"
        result = download_file("https://example.com/file", dest)
        assert result is True
        assert dest.read_bytes() == b"test content"

    @patch("install_sysmon.urllib.request.urlopen")
    def test_download_failure(
        self, mock_urlopen: MagicMock, tmp_path: Path,
    ) -> None:
        mock_urlopen.side_effect = OSError("connection refused")
        dest = tmp_path / "file.txt"
        result = download_file("https://example.com/bad", dest)
        assert result is False
