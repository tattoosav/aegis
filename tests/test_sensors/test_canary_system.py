"""Tests for the Canary File Deployment System.

Covers:
- CanaryDeploymentSystem initialisation with default and custom config
- Single and batch canary file deployment
- Verification of healthy, deleted, modified, and inaccessible canaries
- Content generation for each supported file type and fallback
- Status summary after deploy and trigger cycles
- Cleanup of deployed canary files from disk
- Conversion of triggered canaries to AegisEvent objects
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.sensors.canary_system import (
    CanaryConfig,
    CanaryDeploymentSystem,
    CanaryFile,
    _CANARY_PREFIX,
)


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _deploy_one(
    system: CanaryDeploymentSystem,
    directory: Path,
    file_type: str = ".txt",
) -> CanaryFile:
    """Deploy a single canary and assert success."""
    canary = system.deploy(directory, file_type)
    assert canary is not None
    return canary


# ------------------------------------------------------------------ #
# TestCanaryDeploymentSystemInit
# ------------------------------------------------------------------ #


class TestCanaryDeploymentSystemInit:
    """Initialisation of the CanaryDeploymentSystem."""

    def test_default_config(self) -> None:
        """System created without arguments uses default config."""
        system = CanaryDeploymentSystem()
        assert system.canary_count == 0
        # Default file types should include the four main formats
        assert ".txt" in system._config.file_types
        assert ".docx" in system._config.file_types

    def test_custom_config(self, tmp_path: Path) -> None:
        """System accepts a custom CanaryConfig."""
        cfg = CanaryConfig(
            directories=[tmp_path],
            file_types=[".csv", ".pdf"],
            files_per_directory=3,
            verification_interval_seconds=120.0,
        )
        system = CanaryDeploymentSystem(config=cfg)
        assert system._config.files_per_directory == 3
        assert system._config.verification_interval_seconds == 120.0
        assert system._config.file_types == [".csv", ".pdf"]

    def test_empty_canary_list_on_init(self) -> None:
        """No canaries exist immediately after initialisation."""
        system = CanaryDeploymentSystem()
        assert system.canaries == []
        assert system.canary_count == 0


# ------------------------------------------------------------------ #
# TestCanaryDeploy
# ------------------------------------------------------------------ #


class TestCanaryDeploy:
    """Deployment of canary files to the filesystem."""

    def test_deploy_to_valid_directory(
        self, tmp_path: Path,
    ) -> None:
        """deploy() returns a CanaryFile for a valid directory."""
        system = CanaryDeploymentSystem()
        canary = system.deploy(tmp_path, ".txt")
        assert canary is not None
        assert isinstance(canary, CanaryFile)

    def test_deploy_returns_correct_fields(
        self, tmp_path: Path,
    ) -> None:
        """Returned CanaryFile has expected canary_id, path, type."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path, ".pdf")

        assert canary.canary_id.startswith("canary-")
        assert canary.file_type == ".pdf"
        assert canary.status == "deployed"
        assert canary.content_hash != ""
        assert canary.path.parent == tmp_path

    def test_file_created_on_disk(self, tmp_path: Path) -> None:
        """The canary file physically exists after deployment."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path)
        assert canary.path.exists()
        assert canary.path.is_file()

    def test_content_hash_matches(self, tmp_path: Path) -> None:
        """SHA-256 hash stored in CanaryFile matches file on disk."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path, ".txt")
        on_disk = canary.path.read_bytes()
        expected_hash = hashlib.sha256(on_disk).hexdigest()
        assert canary.content_hash == expected_hash

    def test_deploy_nonexistent_directory_returns_none(
        self, tmp_path: Path,
    ) -> None:
        """deploy() returns None when directory does not exist."""
        system = CanaryDeploymentSystem()
        bad_dir = tmp_path / "nonexistent"
        result = system.deploy(bad_dir, ".txt")
        assert result is None

    def test_deploy_multiple_types(self, tmp_path: Path) -> None:
        """Deploying different file types creates distinct files."""
        system = CanaryDeploymentSystem()
        types = [".txt", ".csv", ".docx", ".xlsx", ".pdf"]
        canaries = [
            _deploy_one(system, tmp_path, ft) for ft in types
        ]
        paths = {c.path for c in canaries}
        assert len(paths) == len(types)
        for canary, ft in zip(canaries, types):
            assert canary.file_type == ft
            assert canary.path.suffix == ft

    def test_canary_count_updates(self, tmp_path: Path) -> None:
        """canary_count increments after each deployment."""
        system = CanaryDeploymentSystem()
        assert system.canary_count == 0
        _deploy_one(system, tmp_path, ".txt")
        assert system.canary_count == 1
        _deploy_one(system, tmp_path, ".csv")
        assert system.canary_count == 2


# ------------------------------------------------------------------ #
# TestCanaryVerification
# ------------------------------------------------------------------ #


class TestCanaryVerification:
    """Verification of deployed canary files."""

    def test_healthy_file_returns_empty_list(
        self, tmp_path: Path,
    ) -> None:
        """verify_all() returns empty list when files are intact."""
        system = CanaryDeploymentSystem()
        _deploy_one(system, tmp_path)
        triggered = system.verify_all()
        assert triggered == []

    def test_deleted_file_triggers_missing(
        self, tmp_path: Path,
    ) -> None:
        """Deleting a canary file marks it as 'missing'."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path)
        canary.path.unlink()

        triggered = system.verify_all()
        assert len(triggered) == 1
        assert triggered[0].status == "missing"
        assert triggered[0].trigger_reason == "File deleted"

    def test_modified_file_triggers_triggered(
        self, tmp_path: Path,
    ) -> None:
        """Modifying canary content marks it as 'triggered'."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path)
        canary.path.write_bytes(b"ransomware-encrypted-data")

        triggered = system.verify_all()
        assert len(triggered) == 1
        assert triggered[0].status == "triggered"
        assert triggered[0].trigger_reason == "Content modified"

    def test_inaccessible_file_triggers_error(
        self, tmp_path: Path,
    ) -> None:
        """OSError during read marks canary as 'error'."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path)

        with patch.object(
            type(canary.path),
            "exists",
            return_value=True,
        ), patch.object(
            type(canary.path),
            "read_bytes",
            side_effect=OSError("Permission denied"),
        ):
            triggered = system.verify_all()

        assert len(triggered) == 1
        assert triggered[0].status == "error"
        assert triggered[0].trigger_reason == "File inaccessible"

    def test_already_triggered_skipped_on_reverify(
        self, tmp_path: Path,
    ) -> None:
        """Canaries with 'triggered' status are skipped on re-verify."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path)
        # Modify to get "triggered" status (not "missing")
        canary.path.write_bytes(b"tampered-content")

        first = system.verify_all()
        assert len(first) == 1
        assert first[0].status == "triggered"

        second = system.verify_all()
        assert second == []

    def test_verify_one_returns_none_for_healthy(
        self, tmp_path: Path,
    ) -> None:
        """verify_one() returns None when the file is untouched."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path)
        result = system.verify_one(canary.canary_id)
        assert result is None

    def test_verify_one_returns_triggered_for_deleted(
        self, tmp_path: Path,
    ) -> None:
        """verify_one() returns the canary when file is deleted."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path)
        canary.path.unlink()

        result = system.verify_one(canary.canary_id)
        assert result is not None
        assert result.status == "missing"
        assert result.trigger_reason == "File deleted"

    def test_verify_one_unknown_id_returns_none(self) -> None:
        """verify_one() returns None for a non-existent canary ID."""
        system = CanaryDeploymentSystem()
        result = system.verify_one("canary-does-not-exist")
        assert result is None


# ------------------------------------------------------------------ #
# TestCanaryContentGeneration
# ------------------------------------------------------------------ #


class TestCanaryContentGeneration:
    """Static content generation for each file type."""

    def test_txt_content_contains_marker(self) -> None:
        """TXT content includes the AEGIS marker and financial data."""
        content = CanaryDeploymentSystem.generate_content(".txt")
        text = content.decode("utf-8")
        assert "AEGIS" in text
        assert "CANARY" in text
        assert "Financial" in text or "Revenue" in text

    def test_csv_contains_comment_header(self) -> None:
        """CSV content starts with a comment containing the marker."""
        content = CanaryDeploymentSystem.generate_content(".csv")
        text = content.decode("utf-8")
        assert text.startswith("# ")
        assert "AEGIS" in text
        assert "Date,Department" in text

    def test_docx_starts_with_pk_header(self) -> None:
        """DOCX content starts with PK ZIP magic bytes."""
        content = CanaryDeploymentSystem.generate_content(".docx")
        assert content[:2] == b"PK"
        assert b"AEGIS" in content

    def test_xlsx_starts_with_pk_header(self) -> None:
        """XLSX content starts with PK ZIP magic bytes."""
        content = CanaryDeploymentSystem.generate_content(".xlsx")
        assert content[:2] == b"PK"
        assert b"AEGIS" in content

    def test_pdf_starts_with_pdf_header(self) -> None:
        """PDF content starts with the standard %PDF header."""
        content = CanaryDeploymentSystem.generate_content(".pdf")
        assert content[:5] == b"%PDF-"
        assert b"AEGIS" in content

    def test_unknown_type_has_fallback(self) -> None:
        """Unrecognised file type produces fallback plain text."""
        content = CanaryDeploymentSystem.generate_content(".xyz")
        text = content.decode("utf-8")
        assert "AEGIS" in text
        assert ".xyz" in text


# ------------------------------------------------------------------ #
# TestCanaryStatus
# ------------------------------------------------------------------ #


class TestCanaryStatus:
    """get_status() summary reporting."""

    def test_status_after_deploy(self, tmp_path: Path) -> None:
        """Status shows correct total and healthy counts."""
        system = CanaryDeploymentSystem()
        _deploy_one(system, tmp_path, ".txt")
        _deploy_one(system, tmp_path, ".csv")

        status = system.get_status()
        assert status["total_deployed"] == 2
        assert status["healthy"] == 2
        assert status["triggered"] == 0
        assert status["errors"] == 0

    def test_status_after_trigger(self, tmp_path: Path) -> None:
        """Status reflects triggered canary after file deletion."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path)
        canary.path.unlink()
        system.verify_all()

        status = system.get_status()
        assert status["triggered"] == 1
        assert status["healthy"] == 0

    def test_status_counts_correct(self, tmp_path: Path) -> None:
        """Mixed states reported accurately in status dict."""
        system = CanaryDeploymentSystem()
        c1 = _deploy_one(system, tmp_path, ".txt")
        _deploy_one(system, tmp_path, ".csv")
        c3 = _deploy_one(system, tmp_path, ".pdf")

        # Delete one, modify another
        c1.path.unlink()
        c3.path.write_bytes(b"corrupted")
        system.verify_all()

        status = system.get_status()
        assert status["total_deployed"] == 3
        assert status["healthy"] == 1
        assert status["triggered"] == 2
        assert status["errors"] == 0

    def test_empty_status(self) -> None:
        """Status on a fresh system with no deployments."""
        system = CanaryDeploymentSystem()
        status = system.get_status()
        assert status["total_deployed"] == 0
        assert status["healthy"] == 0
        assert status["triggered"] == 0
        assert status["errors"] == 0


# ------------------------------------------------------------------ #
# TestCanaryCleanup
# ------------------------------------------------------------------ #


class TestCanaryCleanup:
    """cleanup() removes canary files from disk and registry."""

    def test_cleanup_removes_files_from_disk(
        self, tmp_path: Path,
    ) -> None:
        """After cleanup, canary files no longer exist on disk."""
        system = CanaryDeploymentSystem()
        c1 = _deploy_one(system, tmp_path, ".txt")
        c2 = _deploy_one(system, tmp_path, ".csv")

        system.cleanup()
        assert not c1.path.exists()
        assert not c2.path.exists()

    def test_cleanup_returns_count(self, tmp_path: Path) -> None:
        """cleanup() returns the number of files removed."""
        system = CanaryDeploymentSystem()
        _deploy_one(system, tmp_path, ".txt")
        _deploy_one(system, tmp_path, ".csv")
        _deploy_one(system, tmp_path, ".pdf")

        removed = system.cleanup()
        assert removed == 3

    def test_cleanup_clears_internal_registry(
        self, tmp_path: Path,
    ) -> None:
        """Internal canary tracking is emptied after cleanup."""
        system = CanaryDeploymentSystem()
        _deploy_one(system, tmp_path, ".txt")
        _deploy_one(system, tmp_path, ".csv")
        assert system.canary_count == 2

        system.cleanup()
        assert system.canary_count == 0
        assert system.canaries == []


# ------------------------------------------------------------------ #
# TestCanaryToEvents
# ------------------------------------------------------------------ #


class TestCanaryToEvents:
    """Conversion of triggered canaries to AegisEvent objects."""

    def test_events_have_critical_severity(
        self, tmp_path: Path,
    ) -> None:
        """All canary-triggered events have CRITICAL severity."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path)
        canary.path.unlink()
        triggered = system.verify_all()

        events = system.to_events(triggered)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_event_type_is_canary_triggered(
        self, tmp_path: Path,
    ) -> None:
        """Event type string is 'canary_triggered'."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path)
        canary.path.unlink()
        triggered = system.verify_all()

        events = system.to_events(triggered)
        assert events[0].event_type == "canary_triggered"

    def test_data_contains_canary_info(
        self, tmp_path: Path,
    ) -> None:
        """Event data includes canary_id, path, file_type, reason."""
        system = CanaryDeploymentSystem()
        canary = _deploy_one(system, tmp_path, ".csv")
        canary.path.write_bytes(b"tampered")
        triggered = system.verify_all()

        events = system.to_events(triggered)
        data = events[0].data
        assert data["canary_id"] == canary.canary_id
        assert data["path"] == str(canary.path)
        assert data["file_type"] == ".csv"
        assert data["trigger_reason"] == "Content modified"
        assert data["change_type"] == "canary_alert"
        assert "deployed_at" in data

    def test_empty_triggered_list_returns_empty_events(
        self,
    ) -> None:
        """Passing an empty list produces no events."""
        system = CanaryDeploymentSystem()
        events = system.to_events([])
        assert events == []
