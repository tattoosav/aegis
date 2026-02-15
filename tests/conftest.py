"""Shared test fixtures for Aegis."""

import pytest
import yaml


@pytest.fixture
def tmp_data_dir(tmp_path):
    """Provide a temporary directory for test data (database, configs, etc.)."""
    data_dir = tmp_path / "aegis_data"
    data_dir.mkdir()
    return data_dir


@pytest.fixture
def sample_event():
    """Provide a sample event dict matching the Aegis event schema."""
    return {
        "timestamp": 1707900000.0,
        "sensor": "process",
        "event_type": "process_created",
        "severity": "info",
        "data": {
            "pid": 1234,
            "name": "notepad.exe",
            "path": "C:\\Windows\\System32\\notepad.exe",
            "cmdline": "notepad.exe test.txt",
            "parent_pid": 5678,
            "parent_name": "explorer.exe",
        },
    }
