"""Tests for aegis.core.health — SystemHealth aggregator.

Validates that SystemHealth.collect() gathers metrics from all
subsystems, handles failures gracefully, and returns well-typed
dictionaries for every section.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from aegis.core.config import AegisConfig
from aegis.core.coordinator import AegisCoordinator
from aegis.core.health import SystemHealth

# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture
def config(tmp_path):
    cfg = AegisConfig()
    cfg._data["database"]["path"] = str(tmp_path / "test.db")
    cfg._data["canary"]["directories"] = []
    return cfg


@pytest.fixture
def coordinator(config):
    c = AegisCoordinator(config)
    c.setup()
    return c


@pytest.fixture
def health(coordinator):
    return SystemHealth(coordinator)


EXPECTED_SECTIONS = [
    "engine",
    "enricher",
    "correlation",
    "scheduler",
    "canary",
    "whitelist",
    "database",
    "playbooks",
    "response_router",
]


# ------------------------------------------------------------------ #
# TestSystemHealthInit
# ------------------------------------------------------------------ #


class TestSystemHealthInit:
    """Verify SystemHealth construction."""

    def test_init_stores_coordinator(self, coordinator):
        h = SystemHealth(coordinator)
        assert h._coordinator is coordinator

    def test_init_with_none_coordinator(self):
        """Passing None should not crash on construction."""
        h = SystemHealth(None)
        assert h._coordinator is None


# ------------------------------------------------------------------ #
# TestCollect
# ------------------------------------------------------------------ #


class TestCollect:
    """Unit tests for SystemHealth.collect() sections."""

    def test_collect_returns_dict(self, health):
        result = health.collect()
        assert isinstance(result, dict)
        for key in EXPECTED_SECTIONS:
            assert key in result, f"Missing section: {key}"

    def test_engine_section(self, health):
        section = health.collect()["engine"]
        assert isinstance(section, dict)
        assert "events_processed" in section
        assert "alerts_generated" in section
        assert "is_running" in section

    def test_enricher_section(self, health):
        section = health.collect()["enricher"]
        assert isinstance(section, dict)
        assert "events_enriched" in section
        assert "ioc_matches_found" in section

    def test_correlation_section(self, health):
        section = health.collect()["correlation"]
        assert isinstance(section, dict)
        assert "total_incidents" in section
        assert "active_incidents" in section
        assert "db_incidents" in section

    def test_scheduler_section(self, health):
        section = health.collect()["scheduler"]
        assert isinstance(section, dict)
        assert "task_count" in section
        assert "total_runs" in section
        assert "total_errors" in section

    def test_canary_section(self, health):
        """Canary section returns a dict (may be empty with no dirs)."""
        section = health.collect()["canary"]
        assert isinstance(section, dict)

    def test_whitelist_section(self, health):
        section = health.collect()["whitelist"]
        assert isinstance(section, dict)
        assert "total_entries" in section
        assert "by_type" in section

    def test_database_section(self, health):
        section = health.collect()["database"]
        assert isinstance(section, dict)
        assert "event_count" in section
        assert "alert_count" in section
        assert "incident_count" in section

    def test_playbooks_section(self, health):
        section = health.collect()["playbooks"]
        assert isinstance(section, dict)
        assert "loaded" in section
        assert "active_executions" in section

    def test_response_router_section(self, health):
        section = health.collect()["response_router"]
        assert isinstance(section, dict)
        assert "playbooks_triggered" in section
        assert "reports_generated" in section
        assert "responses_total" in section

    def test_all_none_coordinator(self):
        """A bare coordinator with nothing set up returns empty dicts."""
        cfg = AegisConfig()
        coord = AegisCoordinator(cfg)
        # Do NOT call setup — everything stays None
        h = SystemHealth(coord)
        result = h.collect()
        for key in EXPECTED_SECTIONS:
            assert result[key] == {}, (
                f"Expected empty dict for {key}"
            )

    def test_section_failure_doesnt_crash(self, health):
        """If one collector raises, the rest still complete."""
        with patch.object(
            health,
            "_collect_engine",
            side_effect=RuntimeError("boom"),
        ):
            result = health.collect()
        # engine section should be empty dict due to exception
        assert result["engine"] == {}
        # other sections should still be populated
        assert "database" in result
        assert isinstance(result["database"], dict)

    def test_database_counts_match(self, coordinator, health):
        """DB section counts must match real database counts."""
        db = coordinator.db
        result = health.collect()
        db_section = result["database"]
        assert db_section["event_count"] == db.event_count()
        assert db_section["alert_count"] == db.alert_count()
        assert db_section["incident_count"] == db.incident_count()

    def test_scheduler_counts_match(self, coordinator, health):
        """Scheduler section must reflect real scheduler stats."""
        scheduler = coordinator.scheduler
        assert scheduler is not None
        result = health.collect()
        sched_section = result["scheduler"]
        real_stats = scheduler.get_stats()
        assert sched_section["task_count"] == real_stats["task_count"]
        assert sched_section["total_runs"] == real_stats["total_runs"]
        assert (
            sched_section["total_errors"]
            == real_stats["total_errors"]
        )

    def test_enricher_stats_zero_initially(self, health):
        """Before any events are enriched, all counters are zero."""
        section = health.collect()["enricher"]
        assert section["events_enriched"] == 0
        assert section["ioc_matches_found"] == 0

    def test_collect_multiple_times(self, health):
        """Calling collect() repeatedly must be safe and consistent."""
        r1 = health.collect()
        r2 = health.collect()
        r3 = health.collect()
        assert set(r1.keys()) == set(r2.keys()) == set(r3.keys())
        for key in EXPECTED_SECTIONS:
            assert isinstance(r3[key], dict)

    def test_engine_not_running_before_start(self, health):
        """Engine is_running should be False before start()."""
        section = health.collect()["engine"]
        assert section["is_running"] is False

    def test_whitelist_by_type_dict(self, health):
        """by_type inside whitelist section is always a dict."""
        section = health.collect()["whitelist"]
        assert isinstance(section["by_type"], dict)


# ------------------------------------------------------------------ #
# TestCollectIntegration
# ------------------------------------------------------------------ #


class TestCollectIntegration:
    """Integration-level tests for health collection."""

    def test_full_coordinator_health(self, coordinator, health):
        """After full setup, all sections are dicts.

        Canary may be empty when no directories are configured.
        """
        result = health.collect()
        for key in EXPECTED_SECTIONS:
            assert isinstance(result[key], dict), (
                f"{key} is not a dict"
            )
        # engine/database/scheduler should be non-empty
        assert result["engine"] != {}
        assert result["database"] != {}
        assert result["scheduler"] != {}

    def test_health_after_events(self, coordinator, health):
        """Mocked stats should appear in health output."""
        enricher = coordinator.enricher
        if enricher is not None:
            enricher._events_enriched = 42
            enricher._ioc_matches_found = 5
        result = health.collect()
        if enricher is not None:
            assert result["enricher"]["events_enriched"] == 42
            assert result["enricher"]["ioc_matches_found"] == 5

    def test_all_sections_present(self, health):
        """Verify all 9 expected keys exist."""
        result = health.collect()
        assert len(EXPECTED_SECTIONS) == 9
        for key in EXPECTED_SECTIONS:
            assert key in result

    def test_empty_sections_are_dicts(self, health):
        """Every section is a dict even when empty."""
        result = health.collect()
        for key in EXPECTED_SECTIONS:
            assert isinstance(result[key], dict)

    def test_health_stats_types(self, health):
        """Numeric values in every section are int or float."""
        result = health.collect()
        for section_name, section in result.items():
            for k, v in section.items():
                if isinstance(v, (dict, list, str, bool)):
                    continue
                assert isinstance(v, (int, float)), (
                    f"{section_name}.{k} = {v!r} is not numeric"
                )
