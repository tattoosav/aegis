"""Action Executor — response actions with mandatory user approval.

Every response action goes through a two-phase workflow:
  1. ``preview_action()`` — returns an ActionPreview describing what WILL happen.
  2. ``execute_action()`` — ONLY runs after the user clicks "Approve" in the UI.

No action is ever executed automatically.  The ``requires_approval`` flag on
ActionPreview is always ``True`` — there is no bypass path.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ActionPreview:
    """Describes a response action *before* it is executed.

    Shown in the UI so the user can review and approve or dismiss.
    ``requires_approval`` is always True — no action fires without consent.
    """

    action_type: str
    description: str
    target: str
    reversible: bool
    risk_level: str  # "low", "medium", "high", "critical"
    requires_approval: bool = True
    preview_id: str = field(
        default_factory=lambda: f"prv-{uuid.uuid4().hex[:12]}"
    )


@dataclass
class ActionResult:
    """Outcome of a successfully executed (user-approved) action."""

    success: bool
    action_id: str
    action_type: str
    message: str
    reversible: bool
    approved_by: str = "user"
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# ActionExecutor
# ---------------------------------------------------------------------------


class ActionExecutor:
    """Execute response actions after explicit user approval.

    Parameters
    ----------
    quarantine_dir:
        Directory where quarantined files are moved.  Defaults to
        ``./quarantine`` relative to CWD.
    """

    def __init__(
        self, quarantine_dir: str | Path | None = None,
    ) -> None:
        self._quarantine_dir = Path(
            quarantine_dir or "quarantine"
        )
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)
        # Completed actions keyed by action_id for reversal
        self._history: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    # Preview — always returns requires_approval=True
    # ------------------------------------------------------------------ #

    def preview_action(
        self, action_type: str, target: str, **kwargs: Any,
    ) -> ActionPreview:
        """Build a preview of the requested action.

        The caller (UI) must show this to the user and wait for approval
        before calling :meth:`execute_action`.
        """
        builders = {
            "kill_process": self._preview_kill_process,
            "block_ip": self._preview_block_ip,
            "quarantine_file": self._preview_quarantine_file,
            "disconnect_network": self._preview_disconnect_network,
        }
        builder = builders.get(action_type)
        if builder is None:
            return ActionPreview(
                action_type=action_type,
                description=f"Unknown action: {action_type}",
                target=target,
                reversible=False,
                risk_level="high",
                requires_approval=True,
            )
        return builder(target, **kwargs)

    # ------------------------------------------------------------------ #
    # Execute — requires prior user approval
    # ------------------------------------------------------------------ #

    def execute_action(
        self, preview: ActionPreview,
    ) -> ActionResult:
        """Execute a previously previewed and user-approved action.

        The UI must ensure the user clicked "Approve" before calling this.
        """
        action_id = f"act-{uuid.uuid4().hex[:12]}"

        executors = {
            "kill_process": self._exec_kill_process,
            "block_ip": self._exec_block_ip,
            "quarantine_file": self._exec_quarantine_file,
            "disconnect_network": self._exec_disconnect_network,
        }
        executor = executors.get(preview.action_type)
        if executor is None:
            return ActionResult(
                success=False,
                action_id=action_id,
                action_type=preview.action_type,
                message=f"Unknown action type: {preview.action_type}",
                reversible=False,
            )

        try:
            result = executor(preview, action_id)
            return result
        except Exception as exc:
            logger.exception(
                "Action %s failed for target %s",
                preview.action_type, preview.target,
            )
            return ActionResult(
                success=False,
                action_id=action_id,
                action_type=preview.action_type,
                message=f"Action failed: {exc}",
                reversible=False,
            )

    # ------------------------------------------------------------------ #
    # Reverse — undo a previously executed action
    # ------------------------------------------------------------------ #

    def reverse_action(self, action_id: str) -> ActionResult:
        """Attempt to reverse a previously executed action."""
        record = self._history.get(action_id)
        if record is None:
            return ActionResult(
                success=False,
                action_id=action_id,
                action_type="unknown",
                message="Action not found in history.",
                reversible=False,
            )
        if not record.get("reversible", False):
            return ActionResult(
                success=False,
                action_id=action_id,
                action_type=record["action_type"],
                message="Action is not reversible.",
                reversible=False,
            )

        reversers = {
            "block_ip": self._reverse_block_ip,
            "quarantine_file": self._reverse_quarantine_file,
        }
        reverser = reversers.get(record["action_type"])
        if reverser is None:
            return ActionResult(
                success=False,
                action_id=action_id,
                action_type=record["action_type"],
                message="No reversal handler for this action type.",
                reversible=False,
            )
        try:
            return reverser(action_id, record)
        except Exception as exc:
            logger.exception("Reversal failed for %s", action_id)
            return ActionResult(
                success=False,
                action_id=action_id,
                action_type=record["action_type"],
                message=f"Reversal failed: {exc}",
                reversible=False,
            )

    # ------------------------------------------------------------------ #
    # Kill Process
    # ------------------------------------------------------------------ #

    @staticmethod
    def _preview_kill_process(
        target: str, **kwargs: Any,
    ) -> ActionPreview:
        return ActionPreview(
            action_type="kill_process",
            description=f"Terminate process with PID {target}.",
            target=target,
            reversible=False,
            risk_level="high",
            requires_approval=True,
        )

    def _exec_kill_process(
        self, preview: ActionPreview, action_id: str,
    ) -> ActionResult:
        pid = int(preview.target)
        proc = psutil.Process(pid)
        proc.kill()
        self._history[action_id] = {
            "action_type": "kill_process",
            "target": preview.target,
            "reversible": False,
        }
        return ActionResult(
            success=True,
            action_id=action_id,
            action_type="kill_process",
            message=f"Process {pid} terminated.",
            reversible=False,
        )

    # ------------------------------------------------------------------ #
    # Block IP (netsh advfirewall)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _preview_block_ip(
        target: str, **kwargs: Any,
    ) -> ActionPreview:
        return ActionPreview(
            action_type="block_ip",
            description=(
                f"Add Windows Firewall rule to block all traffic "
                f"to/from {target}."
            ),
            target=target,
            reversible=True,
            risk_level="medium",
            requires_approval=True,
        )

    def _exec_block_ip(
        self, preview: ActionPreview, action_id: str,
    ) -> ActionResult:
        rule_name = f"Aegis_Block_{preview.target}_{action_id}"
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={preview.target}",
            ],
            check=True,
            capture_output=True,
        )
        self._history[action_id] = {
            "action_type": "block_ip",
            "target": preview.target,
            "rule_name": rule_name,
            "reversible": True,
        }
        return ActionResult(
            success=True,
            action_id=action_id,
            action_type="block_ip",
            message=f"Firewall rule '{rule_name}' created.",
            reversible=True,
        )

    def _reverse_block_ip(
        self, action_id: str, record: dict[str, Any],
    ) -> ActionResult:
        rule_name = record["rule_name"]
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ],
            check=True,
            capture_output=True,
        )
        return ActionResult(
            success=True,
            action_id=action_id,
            action_type="block_ip",
            message=f"Firewall rule '{rule_name}' removed.",
            reversible=False,
        )

    # ------------------------------------------------------------------ #
    # Quarantine File
    # ------------------------------------------------------------------ #

    @staticmethod
    def _preview_quarantine_file(
        target: str, **kwargs: Any,
    ) -> ActionPreview:
        return ActionPreview(
            action_type="quarantine_file",
            description=(
                f"Move '{target}' to quarantine directory with "
                f"JSON sidecar recording original path and SHA-256."
            ),
            target=target,
            reversible=True,
            risk_level="medium",
            requires_approval=True,
        )

    def _exec_quarantine_file(
        self, preview: ActionPreview, action_id: str,
    ) -> ActionResult:
        src = Path(preview.target)
        if not src.exists():
            return ActionResult(
                success=False,
                action_id=action_id,
                action_type="quarantine_file",
                message=f"File not found: {preview.target}",
                reversible=False,
            )

        file_hash = hashlib.sha256(src.read_bytes()).hexdigest()
        dest_name = f"{action_id}_{src.name}"
        dest = self._quarantine_dir / dest_name
        sidecar = self._quarantine_dir / f"{dest_name}.json"

        shutil.move(str(src), str(dest))
        sidecar.write_text(
            json.dumps({
                "action_id": action_id,
                "original_path": str(src),
                "sha256": file_hash,
                "quarantined_at": time.time(),
                "filename": src.name,
            }),
            encoding="utf-8",
        )

        self._history[action_id] = {
            "action_type": "quarantine_file",
            "target": str(src),
            "quarantine_path": str(dest),
            "sidecar_path": str(sidecar),
            "reversible": True,
        }
        return ActionResult(
            success=True,
            action_id=action_id,
            action_type="quarantine_file",
            message=f"File quarantined: {src.name} (SHA-256: {file_hash[:16]}...)",
            reversible=True,
        )

    def _reverse_quarantine_file(
        self, action_id: str, record: dict[str, Any],
    ) -> ActionResult:
        quarantine_path = Path(record["quarantine_path"])
        original_path = Path(record["target"])
        sidecar_path = Path(record["sidecar_path"])

        if not quarantine_path.exists():
            return ActionResult(
                success=False,
                action_id=action_id,
                action_type="quarantine_file",
                message="Quarantined file no longer exists.",
                reversible=False,
            )

        original_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quarantine_path), str(original_path))
        if sidecar_path.exists():
            sidecar_path.unlink()

        return ActionResult(
            success=True,
            action_id=action_id,
            action_type="quarantine_file",
            message=f"File restored to {original_path}.",
            reversible=False,
        )

    # ------------------------------------------------------------------ #
    # Disconnect Network
    # ------------------------------------------------------------------ #

    @staticmethod
    def _preview_disconnect_network(
        target: str, **kwargs: Any,
    ) -> ActionPreview:
        return ActionPreview(
            action_type="disconnect_network",
            description=(
                f"Disable network adapter '{target}' to isolate "
                f"this machine from the network."
            ),
            target=target,
            reversible=False,
            risk_level="critical",
            requires_approval=True,
        )

    def _exec_disconnect_network(
        self, preview: ActionPreview, action_id: str,
    ) -> ActionResult:
        subprocess.run(
            [
                "netsh", "interface", "set", "interface",
                preview.target, "disable",
            ],
            check=True,
            capture_output=True,
        )
        self._history[action_id] = {
            "action_type": "disconnect_network",
            "target": preview.target,
            "reversible": False,
        }
        return ActionResult(
            success=True,
            action_id=action_id,
            action_type="disconnect_network",
            message=f"Network adapter '{preview.target}' disabled.",
            reversible=False,
        )
