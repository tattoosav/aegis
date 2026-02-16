"""Tests for ActionExecutor — two-phase user-approved response actions."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis.response.action_executor import (
    ActionExecutor,
)

# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #

@pytest.fixture()
def executor(tmp_path: Path) -> ActionExecutor:
    return ActionExecutor(quarantine_dir=tmp_path / "quarantine")


# ------------------------------------------------------------------ #
# ActionPreview invariants
# ------------------------------------------------------------------ #

class TestPreviewAlwaysRequiresApproval:
    """Every preview must have requires_approval=True."""

    @pytest.mark.parametrize("action_type", [
        "kill_process", "block_ip", "quarantine_file",
        "disconnect_network", "unknown_action",
    ])
    def test_requires_approval_is_always_true(
        self, executor: ActionExecutor, action_type: str,
    ) -> None:
        preview = executor.preview_action(action_type, "target")
        assert preview.requires_approval is True

    def test_preview_has_description(
        self, executor: ActionExecutor,
    ) -> None:
        preview = executor.preview_action("block_ip", "10.0.0.1")
        assert "10.0.0.1" in preview.description

    def test_unknown_action_preview(
        self, executor: ActionExecutor,
    ) -> None:
        preview = executor.preview_action("nuke_from_orbit", "target")
        assert "Unknown" in preview.description
        assert preview.requires_approval is True


# ------------------------------------------------------------------ #
# Kill process
# ------------------------------------------------------------------ #

class TestKillProcess:
    """Tests for kill_process action."""

    def test_preview_fields(self, executor: ActionExecutor) -> None:
        preview = executor.preview_action("kill_process", "1234")
        assert preview.action_type == "kill_process"
        assert preview.reversible is False
        assert preview.risk_level == "high"
        assert "1234" in preview.description

    @patch("aegis.response.action_executor.psutil")
    def test_execute_kills_process(
        self, mock_psutil: MagicMock, executor: ActionExecutor,
    ) -> None:
        mock_proc = MagicMock()
        mock_psutil.Process.return_value = mock_proc
        preview = executor.preview_action("kill_process", "5678")

        result = executor.execute_action(preview)
        assert result.success is True
        mock_psutil.Process.assert_called_once_with(5678)
        mock_proc.kill.assert_called_once()

    @patch("aegis.response.action_executor.psutil")
    def test_kill_failure_returns_error(
        self, mock_psutil: MagicMock, executor: ActionExecutor,
    ) -> None:
        mock_psutil.Process.side_effect = RuntimeError("no such process")
        preview = executor.preview_action("kill_process", "9999")

        result = executor.execute_action(preview)
        assert result.success is False
        assert "failed" in result.message.lower()


# ------------------------------------------------------------------ #
# Block IP
# ------------------------------------------------------------------ #

class TestBlockIP:
    """Tests for block_ip action."""

    def test_preview_fields(self, executor: ActionExecutor) -> None:
        preview = executor.preview_action("block_ip", "45.33.32.1")
        assert preview.action_type == "block_ip"
        assert preview.reversible is True
        assert preview.risk_level == "medium"

    @patch("aegis.response.action_executor.subprocess.run")
    def test_execute_creates_firewall_rule(
        self, mock_run: MagicMock, executor: ActionExecutor,
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        preview = executor.preview_action("block_ip", "45.33.32.1")

        result = executor.execute_action(preview)
        assert result.success is True
        assert result.reversible is True
        assert "rule" in result.message.lower()
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "netsh" in cmd
        assert "remoteip=45.33.32.1" in cmd

    @patch("aegis.response.action_executor.subprocess.run")
    def test_reverse_removes_firewall_rule(
        self, mock_run: MagicMock, executor: ActionExecutor,
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        preview = executor.preview_action("block_ip", "10.0.0.99")
        result = executor.execute_action(preview)
        assert result.success is True

        reverse = executor.reverse_action(result.action_id)
        assert reverse.success is True
        assert mock_run.call_count == 2
        delete_cmd = mock_run.call_args_list[1][0][0]
        assert "delete" in delete_cmd


# ------------------------------------------------------------------ #
# Quarantine file
# ------------------------------------------------------------------ #

class TestQuarantineFile:
    """Tests for quarantine_file action."""

    def test_preview_fields(self, executor: ActionExecutor) -> None:
        preview = executor.preview_action(
            "quarantine_file", r"C:\temp\malware.exe",
        )
        assert preview.action_type == "quarantine_file"
        assert preview.reversible is True
        assert preview.risk_level == "medium"

    def test_execute_moves_file_with_sidecar(
        self, executor: ActionExecutor, tmp_path: Path,
    ) -> None:
        target = tmp_path / "suspicious.exe"
        target.write_bytes(b"MZ fake binary content")
        preview = executor.preview_action(
            "quarantine_file", str(target),
        )

        result = executor.execute_action(preview)
        assert result.success is True
        assert result.reversible is True
        assert not target.exists()

        # Find sidecar JSON
        q_dir = tmp_path / "quarantine"
        sidecars = list(q_dir.glob("*.json"))
        assert len(sidecars) == 1
        meta = json.loads(sidecars[0].read_text(encoding="utf-8"))
        assert meta["original_path"] == str(target)
        assert len(meta["sha256"]) == 64

    def test_execute_missing_file_fails(
        self, executor: ActionExecutor,
    ) -> None:
        preview = executor.preview_action(
            "quarantine_file", "/nonexistent/file.exe",
        )
        result = executor.execute_action(preview)
        assert result.success is False
        assert "not found" in result.message.lower()

    def test_reverse_restores_file(
        self, executor: ActionExecutor, tmp_path: Path,
    ) -> None:
        target = tmp_path / "restore_me.txt"
        target.write_text("important data", encoding="utf-8")
        preview = executor.preview_action(
            "quarantine_file", str(target),
        )
        result = executor.execute_action(preview)
        assert result.success is True
        assert not target.exists()

        reverse = executor.reverse_action(result.action_id)
        assert reverse.success is True
        assert target.exists()
        assert target.read_text(encoding="utf-8") == "important data"


# ------------------------------------------------------------------ #
# Disconnect network
# ------------------------------------------------------------------ #

class TestDisconnectNetwork:
    """Tests for disconnect_network action."""

    def test_preview_fields(self, executor: ActionExecutor) -> None:
        preview = executor.preview_action(
            "disconnect_network", "Ethernet",
        )
        assert preview.action_type == "disconnect_network"
        assert preview.reversible is False
        assert preview.risk_level == "critical"

    @patch("aegis.response.action_executor.subprocess.run")
    def test_execute_disables_adapter(
        self, mock_run: MagicMock, executor: ActionExecutor,
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        preview = executor.preview_action(
            "disconnect_network", "Wi-Fi",
        )

        result = executor.execute_action(preview)
        assert result.success is True
        cmd = mock_run.call_args[0][0]
        assert "disable" in cmd


# ------------------------------------------------------------------ #
# Reverse action edge cases
# ------------------------------------------------------------------ #

class TestReverseEdgeCases:
    """Tests for reverse_action error handling."""

    def test_unknown_action_id(self, executor: ActionExecutor) -> None:
        result = executor.reverse_action("nonexistent-id")
        assert result.success is False
        assert "not found" in result.message.lower()

    def test_irreversible_action(
        self, executor: ActionExecutor,
    ) -> None:
        # Manually inject a non-reversible record
        executor._history["test-id"] = {
            "action_type": "kill_process",
            "target": "123",
            "reversible": False,
        }
        result = executor.reverse_action("test-id")
        assert result.success is False
        assert "not reversible" in result.message.lower()
