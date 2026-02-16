"""Tests for the MITRE ATT&CK technique mapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.intelligence.mitre_mapper import (
    _DEFAULT_DATA_PATH,
    _FALLBACK_TECHNIQUES,
    MITREMapper,
    MITRETechnique,
)

# The 14 technique IDs used in graph_analyzer.py ATTACK_CHAINS
GRAPH_ANALYZER_IDS: list[str] = [
    "T1189",
    "T1204.002",
    "T1555",
    "T1003",
    "T1486",
    "T1547.001",
    "T1053",
    "T1059.001",
    "T1027",
    "T1021",
    "T1110",
    "T1041",
    "T1567",
    "T1055.001",
]


# -------------------------------------------------------------------
# TestMITRETechnique
# -------------------------------------------------------------------

class TestMITRETechnique:
    """Tests for the MITRETechnique frozen dataclass."""

    def test_fields_correct(self) -> None:
        tech = MITRETechnique(
            technique_id="T1234",
            name="Test Technique",
            tactic="execution",
            description="A test technique.",
            platforms=("Windows", "Linux"),
        )
        assert tech.technique_id == "T1234"
        assert tech.name == "Test Technique"
        assert tech.tactic == "execution"
        assert tech.description == "A test technique."
        assert tech.platforms == ("Windows", "Linux")

    def test_default_platforms(self) -> None:
        tech = MITRETechnique(
            technique_id="T1000",
            name="Default",
            tactic="discovery",
            description="Defaults test.",
        )
        assert tech.platforms == ("Windows",)

    def test_frozen_immutable(self) -> None:
        tech = MITRETechnique(
            technique_id="T1000",
            name="Frozen",
            tactic="impact",
            description="Cannot mutate.",
        )
        with pytest.raises(AttributeError):
            tech.name = "Changed"  # type: ignore[misc]

    def test_equality(self) -> None:
        a = MITRETechnique("T1", "A", "tactic", "desc")
        b = MITRETechnique("T1", "A", "tactic", "desc")
        assert a == b

    def test_hash_usable_in_set(self) -> None:
        tech = MITRETechnique("T1", "A", "tactic", "desc")
        s = {tech}
        assert tech in s


# -------------------------------------------------------------------
# TestMITREMapper
# -------------------------------------------------------------------

class TestMITREMapper:
    """Tests for the MITREMapper lookup service."""

    def test_loads_from_data_file(self) -> None:
        """Loads techniques from the actual JSON data file."""
        mapper = MITREMapper(_DEFAULT_DATA_PATH)
        assert mapper.technique_count >= 40

    def test_fallback_when_file_missing(self, tmp_path: Path) -> None:
        """Falls back to built-in data when path does not exist."""
        fake = tmp_path / "nonexistent" / "missing.json"
        mapper = MITREMapper(fake)
        assert mapper.technique_count == len(_FALLBACK_TECHNIQUES)

    def test_fallback_on_invalid_json(self, tmp_path: Path) -> None:
        """Falls back to built-in data when file contains bad JSON."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("NOT VALID JSON {{{", encoding="utf-8")
        mapper = MITREMapper(bad_file)
        assert mapper.technique_count == len(_FALLBACK_TECHNIQUES)

    def test_technique_count_positive(self) -> None:
        mapper = MITREMapper()
        assert mapper.technique_count > 0

    def test_get_known_technique(self) -> None:
        mapper = MITREMapper()
        tech = mapper.get("T1486")
        assert tech is not None
        assert tech.technique_id == "T1486"
        assert tech.tactic == "impact"

    def test_get_unknown_returns_none(self) -> None:
        mapper = MITREMapper()
        assert mapper.get("T9999.999") is None

    def test_get_many_filters_unknown(self) -> None:
        mapper = MITREMapper()
        results = mapper.get_many(["T1486", "T9999", "T1189"])
        ids = [t.technique_id for t in results]
        assert "T1486" in ids
        assert "T1189" in ids
        assert len(results) == 2

    def test_get_many_empty_list(self) -> None:
        mapper = MITREMapper()
        assert mapper.get_many([]) == []

    def test_describe_known_technique(self) -> None:
        mapper = MITREMapper()
        lines = mapper.describe(["T1486"])
        assert len(lines) == 1
        assert lines[0].startswith("T1486:")
        assert "(impact)" in lines[0]

    def test_describe_unknown_shows_placeholder(self) -> None:
        mapper = MITREMapper()
        lines = mapper.describe(["T9999"])
        assert lines == ["T9999: Unknown technique"]

    def test_describe_mixed_known_unknown(self) -> None:
        mapper = MITREMapper()
        lines = mapper.describe(["T1189", "T0000", "T1486"])
        assert len(lines) == 3
        assert "Unknown technique" in lines[1]
        assert lines[0].startswith("T1189:")
        assert lines[2].startswith("T1486:")

    def test_describe_empty_list(self) -> None:
        mapper = MITREMapper()
        assert mapper.describe([]) == []

    def test_graph_analyzer_techniques_all_present(self) -> None:
        """Every technique ID referenced in ATTACK_CHAINS is loadable."""
        mapper = MITREMapper()
        for tid in GRAPH_ANALYZER_IDS:
            tech = mapper.get(tid)
            assert tech is not None, f"{tid} not found in mapper"
            assert tech.technique_id == tid

    def test_graph_analyzer_techniques_in_fallback(self) -> None:
        """All 14 graph_analyzer IDs exist in the fallback dict."""
        for tid in GRAPH_ANALYZER_IDS:
            assert tid in _FALLBACK_TECHNIQUES, (
                f"{tid} missing from _FALLBACK_TECHNIQUES"
            )

    def test_platforms_tuple_from_json(self) -> None:
        """Platforms loaded from JSON are stored as tuples."""
        mapper = MITREMapper(_DEFAULT_DATA_PATH)
        tech = mapper.get("T1486")
        assert tech is not None
        assert isinstance(tech.platforms, tuple)
        assert "Windows" in tech.platforms
