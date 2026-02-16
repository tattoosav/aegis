"""Tests for AegisServiceFramework — Windows service wrapper."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from aegis.core.service import (
    _CHILD_PROCESSES,
    AegisServiceFramework,
)

# ------------------------------------------------------------------ #
# Construction
# ------------------------------------------------------------------ #

class TestServiceInit:
    """Basic construction tests."""

    def test_creates(self) -> None:
        svc = AegisServiceFramework()
        assert svc is not None

    def test_not_running_initially(self) -> None:
        svc = AegisServiceFramework()
        assert svc.running is False

    def test_no_children_initially(self) -> None:
        svc = AegisServiceFramework()
        assert svc.children == {}

    def test_service_name(self) -> None:
        assert AegisServiceFramework._svc_name_ == "AegisSecurity"


# ------------------------------------------------------------------ #
# Launch children
# ------------------------------------------------------------------ #

class TestLaunchChild:
    """Tests for _launch_child."""

    @patch("aegis.core.service.subprocess.Popen")
    def test_launches_process(
        self, mock_popen: MagicMock,
    ) -> None:
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_popen.return_value = mock_proc

        svc = AegisServiceFramework()
        svc._launch_child("test", "aegis.test")
        mock_popen.assert_called_once()
        assert "test" in svc._children

    @patch("aegis.core.service.subprocess.Popen")
    def test_launch_failure_handled(
        self, mock_popen: MagicMock,
    ) -> None:
        mock_popen.side_effect = OSError("spawn failed")
        svc = AegisServiceFramework()
        svc._launch_child("test", "aegis.test")
        assert "test" not in svc._children


# ------------------------------------------------------------------ #
# Launch all
# ------------------------------------------------------------------ #

class TestLaunchAll:
    """Tests for _launch_all."""

    @patch("aegis.core.service.subprocess.Popen")
    def test_launches_all_children(
        self, mock_popen: MagicMock,
    ) -> None:
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        svc = AegisServiceFramework()
        svc._launch_all()
        assert len(svc._children) == len(_CHILD_PROCESSES)


# ------------------------------------------------------------------ #
# Terminate all
# ------------------------------------------------------------------ #

class TestTerminateAll:
    """Tests for _terminate_all."""

    def test_terminates_running_children(self) -> None:
        svc = AegisServiceFramework()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # still running
        svc._children["test"] = mock_proc

        svc._terminate_all()
        mock_proc.terminate.assert_called_once()
        assert svc._children == {}

    def test_kills_stubborn_child(self) -> None:
        svc = AegisServiceFramework()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.wait.side_effect = subprocess.TimeoutExpired(
            cmd="test", timeout=5
        )
        svc._children["test"] = mock_proc

        svc._terminate_all()
        mock_proc.kill.assert_called_once()

    def test_skip_already_exited(self) -> None:
        svc = AegisServiceFramework()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0  # already exited
        svc._children["test"] = mock_proc

        svc._terminate_all()
        mock_proc.terminate.assert_not_called()


# ------------------------------------------------------------------ #
# Stop
# ------------------------------------------------------------------ #

class TestStop:
    """Tests for stop()."""

    def test_stop_sets_running_false(self) -> None:
        svc = AegisServiceFramework()
        svc._running = True
        svc.stop()
        assert svc.running is False


# ------------------------------------------------------------------ #
# Monitor loop (quick cycle)
# ------------------------------------------------------------------ #

class TestMonitorLoop:
    """Test _monitor_loop restarts crashed children."""

    @patch("aegis.core.service.time.sleep")
    @patch("aegis.core.service.subprocess.Popen")
    def test_restarts_crashed_child(
        self, mock_popen: MagicMock, mock_sleep: MagicMock,
    ) -> None:
        mock_proc = MagicMock()
        mock_proc.pid = 200
        mock_popen.return_value = mock_proc

        # After one loop iteration, stop the service
        call_count = 0

        def stop_after_one(*args):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                svc._running = False

        mock_sleep.side_effect = stop_after_one

        svc = AegisServiceFramework()
        # Simulate a crashed child
        dead_proc = MagicMock()
        dead_proc.poll.return_value = 1  # exited
        svc._children["event_engine"] = dead_proc
        svc._running = True

        svc._monitor_loop()
        # Should have launched a new process for event_engine
        assert mock_popen.call_count >= 1
