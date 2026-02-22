"""Canary File Deployment System for Aegis.

Deploys honeypot files in strategic locations to detect ransomware,
file encryption attacks, and lateral movement.  When a canary file
is modified or deleted, a CRITICAL severity event is generated.

Supports multiple file types (.txt, .docx, .xlsx, .pdf, .csv) with
realistic-looking content to maximise detection probability.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from aegis.core.models import AegisEvent, SensorType, Severity

logger = logging.getLogger(__name__)

# Default canary file prefix
_CANARY_PREFIX = ".aegis_canary_"

# Default directories for canary deployment
_DEFAULT_HIGH_VALUE_DIRS = [
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / "Downloads",
]


class CanaryStatus(Enum):
    """Status of a deployed canary file."""

    DEPLOYED = "deployed"
    TRIGGERED = "triggered"
    MISSING = "missing"
    ERROR = "error"


@dataclass
class CanaryFile:
    """Tracks a single deployed canary file."""

    canary_id: str
    path: Path
    file_type: str  # ".txt", ".docx", ".xlsx", ".pdf", ".csv"
    content_hash: str  # SHA-256 of deployed content
    deployed_at: float = field(default_factory=time.time)
    last_verified: float = 0.0
    status: str = "deployed"  # deployed, triggered, missing, error
    trigger_reason: str = ""


@dataclass
class CanaryConfig:
    """Configuration for canary file deployment."""

    directories: list[Path] = field(default_factory=list)
    file_types: list[str] = field(
        default_factory=lambda: [".txt", ".docx", ".xlsx", ".pdf"]
    )
    files_per_directory: int = 2
    verification_interval_seconds: float = 60.0


class CanaryDeploymentSystem:
    """Deploy and monitor canary files across the filesystem.

    Parameters
    ----------
    config:
        Canary deployment configuration. If None, uses defaults.
    """

    def __init__(self, config: CanaryConfig | None = None) -> None:
        self._config = config or CanaryConfig()
        self._canaries: dict[str, CanaryFile] = {}

    @property
    def canary_count(self) -> int:
        """Return the number of tracked canary files."""
        return len(self._canaries)

    @property
    def canaries(self) -> list[CanaryFile]:
        """Return a list of all tracked canary files."""
        return list(self._canaries.values())

    def deploy(
        self,
        directory: Path,
        file_type: str = ".txt",
    ) -> CanaryFile | None:
        """Deploy a single canary file to a directory.

        Returns the CanaryFile if successful, None on failure.
        """
        directory = Path(directory)
        if not directory.is_dir():
            logger.warning(
                "Cannot deploy canary: %s is not a directory",
                directory,
            )
            return None

        canary_id = f"canary-{uuid.uuid4().hex[:8]}"
        filename = f"{_CANARY_PREFIX}{canary_id}{file_type}"
        filepath = directory / filename

        try:
            content = self.generate_content(file_type)
            filepath.write_bytes(content)
            content_hash = hashlib.sha256(content).hexdigest()

            canary = CanaryFile(
                canary_id=canary_id,
                path=filepath,
                file_type=file_type,
                content_hash=content_hash,
            )
            self._canaries[canary_id] = canary
            logger.debug(
                "Deployed canary %s at %s", canary_id, filepath,
            )
            return canary
        except OSError:
            logger.warning(
                "Failed to deploy canary at %s",
                filepath,
                exc_info=True,
            )
            return None

    def deploy_all(self) -> list[CanaryFile]:
        """Deploy canaries to all configured directories.

        Returns list of successfully deployed canaries.
        """
        directories = (
            self._config.directories or _DEFAULT_HIGH_VALUE_DIRS
        )
        deployed: list[CanaryFile] = []

        for directory in directories:
            directory = Path(directory)
            if not directory.is_dir():
                continue
            for file_type in self._config.file_types[
                : self._config.files_per_directory
            ]:
                canary = self.deploy(directory, file_type)
                if canary:
                    deployed.append(canary)

        logger.info(
            "Deployed %d canary files across %d directories",
            len(deployed),
            len(directories),
        )
        return deployed

    def verify_all(self) -> list[CanaryFile]:
        """Verify all deployed canaries.

        Returns list of triggered canaries.
        """
        triggered: list[CanaryFile] = []
        now = time.time()

        for canary in self._canaries.values():
            if canary.status in ("triggered", "error"):
                continue  # Already known

            canary.last_verified = now
            filepath = canary.path

            if not filepath.exists():
                canary.status = "missing"
                canary.trigger_reason = "File deleted"
                triggered.append(canary)
                logger.warning(
                    "Canary TRIGGERED (deleted): %s", filepath,
                )
                continue

            try:
                current_content = filepath.read_bytes()
                current_hash = hashlib.sha256(
                    current_content
                ).hexdigest()

                if current_hash != canary.content_hash:
                    canary.status = "triggered"
                    canary.trigger_reason = "Content modified"
                    triggered.append(canary)
                    logger.warning(
                        "Canary TRIGGERED (modified): %s", filepath,
                    )
            except OSError:
                canary.status = "error"
                canary.trigger_reason = "File inaccessible"
                triggered.append(canary)
                logger.warning(
                    "Canary TRIGGERED (inaccessible): %s", filepath,
                )

        return triggered

    def verify_one(self, canary_id: str) -> CanaryFile | None:
        """Verify a single canary.

        Returns the canary if triggered, else None.
        """
        canary = self._canaries.get(canary_id)
        if canary is None:
            return None

        now = time.time()
        canary.last_verified = now
        filepath = canary.path

        if not filepath.exists():
            canary.status = "missing"
            canary.trigger_reason = "File deleted"
            return canary

        try:
            current_content = filepath.read_bytes()
            current_hash = hashlib.sha256(
                current_content
            ).hexdigest()
            if current_hash != canary.content_hash:
                canary.status = "triggered"
                canary.trigger_reason = "Content modified"
                return canary
        except OSError:
            canary.status = "error"
            canary.trigger_reason = "File inaccessible"
            return canary

        return None  # Still healthy

    def get_status(self) -> dict[str, Any]:
        """Return deployment status summary."""
        canaries = list(self._canaries.values())
        return {
            "total_deployed": len(canaries),
            "healthy": sum(
                1 for c in canaries if c.status == "deployed"
            ),
            "triggered": sum(
                1
                for c in canaries
                if c.status in ("triggered", "missing")
            ),
            "errors": sum(
                1 for c in canaries if c.status == "error"
            ),
        }

    def cleanup(self) -> int:
        """Remove all deployed canary files.

        Returns count of files successfully removed.
        """
        removed = 0
        for canary in list(self._canaries.values()):
            try:
                if canary.path.exists():
                    canary.path.unlink()
                    removed += 1
            except OSError:
                logger.warning(
                    "Failed to remove canary %s", canary.path,
                )
        self._canaries.clear()
        return removed

    def to_events(
        self,
        triggered: list[CanaryFile],
    ) -> list[AegisEvent]:
        """Convert triggered canaries to AegisEvent objects."""
        events: list[AegisEvent] = []
        for canary in triggered:
            events.append(
                AegisEvent(
                    sensor=SensorType.FILE,
                    event_type="canary_triggered",
                    severity=Severity.CRITICAL,
                    data={
                        "canary_id": canary.canary_id,
                        "path": str(canary.path),
                        "file_type": canary.file_type,
                        "trigger_reason": canary.trigger_reason,
                        "deployed_at": canary.deployed_at,
                        "change_type": "canary_alert",
                    },
                )
            )
        return events

    @staticmethod
    def generate_content(file_type: str) -> bytes:
        """Generate realistic-looking canary content for a file type.

        Parameters
        ----------
        file_type:
            File extension including the dot (e.g. ".txt").

        Returns
        -------
        bytes
            Content bytes appropriate for the file type.
        """
        marker = (
            "AEGIS SECURITY CANARY — DO NOT MODIFY OR DELETE"
        )

        if file_type == ".txt":
            return (
                f"{marker}\n\n"
                "Quarterly Financial Report — CONFIDENTIAL\n"
                "Department: Corporate Finance\n"
                "Period: Q4 2025\n\n"
                "Revenue Summary:\n"
                "  Product A: $1,247,500\n"
                "  Product B: $893,200\n"
                "  Services:  $2,105,800\n"
                "  Total:     $4,246,500\n"
            ).encode()

        if file_type == ".csv":
            return (
                f"# {marker}\n"
                "Date,Department,Category,Amount,Status\n"
                "2025-10-01,Finance,Revenue,125000,Approved\n"
                "2025-10-05,HR,Payroll,89500,Processed\n"
                "2025-10-12,IT,Infrastructure,45200,Pending\n"
                "2025-10-18,Sales,Commission,67800,Approved\n"
                "2025-10-25,Marketing,Campaign,23400,Processed\n"
            ).encode()

        if file_type == ".docx":
            # Minimal ZIP structure mimicking a DOCX file.
            # Real DOCX is a ZIP with XML — we create a simple
            # marker that looks like a valid file to ransomware.
            header = b"PK\x03\x04"  # ZIP local file header
            content = marker.encode()
            return header + b"\x00" * 26 + content

        if file_type == ".xlsx":
            # Minimal ZIP structure mimicking an XLSX file
            header = b"PK\x03\x04"
            content = marker.encode()
            return header + b"\x00" * 26 + content

        if file_type == ".pdf":
            # Minimal PDF structure with canary marker
            return (
                b"%PDF-1.4\n"
                b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
                b"2 0 obj\n<< /Type /Page >>\nendobj\n"
                + marker.encode()
                + b"\n%%EOF\n"
            )

        # Fallback: plain text
        return (
            f"{marker}\nCanary file — type: {file_type}\n"
        ).encode()
