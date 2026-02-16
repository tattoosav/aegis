"""Tests for the ProcessGuard self-protection module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import psutil

from aegis.self_protection.process_guard import ProcessGuard

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

_FAKE_NAME = "aegis_fake_process_xyz"


def _mock_process(name: str) -> MagicMock:
    """Return a mock that mimics a ``psutil.Process`` info dict."""
    proc = MagicMock()
    proc.info = {"name": name}
    return proc


# ------------------------------------------------------------------ #
# check_all
# ------------------------------------------------------------------ #

class TestCheckAll:
    """Tests for ProcessGuard.check_all."""

    def test_empty_expected_returns_empty(self) -> None:
        guard = ProcessGuard([])
        assert guard.check_all() == []

    def test_detects_missing_process(self) -> None:
        guard = ProcessGuard([_FAKE_NAME])
        missing = guard.check_all()
        assert _FAKE_NAME in missing

    @patch("aegis.self_protection.process_guard.psutil.process_iter")
    def test_all_running_returns_empty(
        self, mock_iter: MagicMock
    ) -> None:
        mock_iter.return_value = [
            _mock_process("alpha"),
            _mock_process("beta"),
        ]
        guard = ProcessGuard(["alpha", "beta"])
        assert guard.check_all() == []

    @patch("aegis.self_protection.process_guard.psutil.process_iter")
    def test_partial_running_reports_missing(
        self, mock_iter: MagicMock
    ) -> None:
        mock_iter.return_value = [_mock_process("alpha")]
        guard = ProcessGuard(["alpha", "beta"])
        missing = guard.check_all()
        assert missing == ["beta"]


# ------------------------------------------------------------------ #
# is_process_running
# ------------------------------------------------------------------ #

class TestIsProcessRunning:
    """Tests for ProcessGuard.is_process_running."""

    def test_returns_bool(self) -> None:
        guard = ProcessGuard([])
        result = guard.is_process_running(_FAKE_NAME)
        assert isinstance(result, bool)

    def test_known_running_process(self) -> None:
        """``python`` (or ``pytest``) should be running in CI."""
        guard = ProcessGuard(["python"])
        assert guard.is_process_running("python") is True

    def test_fake_process_not_running(self) -> None:
        guard = ProcessGuard([])
        assert guard.is_process_running(_FAKE_NAME) is False

    @patch("aegis.self_protection.process_guard.psutil.process_iter")
    def test_handles_no_such_process(
        self, mock_iter: MagicMock
    ) -> None:
        """NoSuchProcess during iteration should not crash."""
        bad_proc = MagicMock()
        bad_proc.info.__getitem__ = MagicMock(
            side_effect=psutil.NoSuchProcess(pid=99999)
        )
        bad_proc.info.get = MagicMock(
            side_effect=psutil.NoSuchProcess(pid=99999)
        )
        mock_iter.return_value = [bad_proc]

        guard = ProcessGuard([])
        assert guard.is_process_running("anything") is False

    @patch("aegis.self_protection.process_guard.psutil.process_iter")
    def test_handles_access_denied(
        self, mock_iter: MagicMock
    ) -> None:
        """AccessDenied during iteration should not crash."""
        bad_proc = MagicMock()
        bad_proc.info.__getitem__ = MagicMock(
            side_effect=psutil.AccessDenied(pid=1)
        )
        bad_proc.info.get = MagicMock(
            side_effect=psutil.AccessDenied(pid=1)
        )
        mock_iter.return_value = [bad_proc]

        guard = ProcessGuard([])
        assert guard.is_process_running("anything") is False


# ------------------------------------------------------------------ #
# status_summary
# ------------------------------------------------------------------ #

class TestStatusSummary:
    """Tests for ProcessGuard.status_summary."""

    def test_returns_dict_with_all_expected_names(self) -> None:
        names = ["alpha", "beta", "gamma"]
        guard = ProcessGuard(names)
        summary = guard.status_summary()
        assert isinstance(summary, dict)
        assert set(summary.keys()) == set(names)
        for val in summary.values():
            assert isinstance(val, bool)

    @patch("aegis.self_protection.process_guard.psutil.process_iter")
    def test_correct_status_values(
        self, mock_iter: MagicMock
    ) -> None:
        mock_iter.return_value = [_mock_process("alpha")]
        guard = ProcessGuard(["alpha", "beta"])
        summary = guard.status_summary()
        assert summary["alpha"] is True
        assert summary["beta"] is False


# ------------------------------------------------------------------ #
# get_running_processes
# ------------------------------------------------------------------ #

class TestGetRunningProcesses:
    """Tests for ProcessGuard.get_running_processes."""

    def test_returns_list(self) -> None:
        guard = ProcessGuard([_FAKE_NAME])
        result = guard.get_running_processes()
        assert isinstance(result, list)

    @patch("aegis.self_protection.process_guard.psutil.process_iter")
    def test_only_running_included(
        self, mock_iter: MagicMock
    ) -> None:
        mock_iter.return_value = [_mock_process("alpha")]
        guard = ProcessGuard(["alpha", "beta"])
        running = guard.get_running_processes()
        assert running == ["alpha"]
