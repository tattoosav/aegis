"""Tests for the Process DNA profiler behavioral fingerprinting engine."""

from __future__ import annotations

import math

import pytest

from aegis.core.database import AegisDatabase
from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.intelligence.process_dna import (
    MAX_TYPICAL_ITEMS,
    MIN_OBSERVATIONS_FOR_COMPARISON,
    ProcessDNA,
    ProcessDNAProfiler,
    _sigmoid_confidence,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

SAMPLE_HASH = "abc123def456"


@pytest.fixture()
def db() -> AegisDatabase:
    """In-memory AegisDatabase for testing."""
    return AegisDatabase(":memory:")


@pytest.fixture()
def profiler(db: AegisDatabase) -> ProcessDNAProfiler:
    """ProcessDNAProfiler backed by in-memory database."""
    return ProcessDNAProfiler(db)


def _make_event(
    process_hash: str = SAMPLE_HASH,
    sensor: SensorType = SensorType.PROCESS,
    extra: dict | None = None,
) -> AegisEvent:
    """Build a minimal process event with optional extra data fields."""
    data: dict = {
        "process_hash": process_hash,
        "process_name": "test.exe",
        "process_path": r"C:\Windows\test.exe",
    }
    if extra:
        data.update(extra)
    return AegisEvent(
        sensor=sensor,
        event_type="process_start",
        data=data,
        severity=Severity.INFO,
    )


# ---------------------------------------------------------------------------
# TestProcessDNA dataclass
# ---------------------------------------------------------------------------

class TestProcessDNA:
    """Tests for the ProcessDNA dataclass."""

    def test_creation_with_required_fields(self) -> None:
        dna = ProcessDNA(
            process_hash="abc",
            process_name="test.exe",
            process_path=r"C:\test.exe",
        )
        assert dna.process_hash == "abc"
        assert dna.process_name == "test.exe"
        assert dna.process_path == r"C:\test.exe"

    def test_default_sets_are_empty(self) -> None:
        dna = ProcessDNA(
            process_hash="abc",
            process_name="test.exe",
            process_path=r"C:\test.exe",
        )
        assert dna.typical_files == set()
        assert dna.typical_endpoints == set()
        assert dna.typical_children == set()
        assert dna.typical_dlls == set()
        assert dna.typical_registry == set()

    def test_default_numeric_fields(self) -> None:
        dna = ProcessDNA(
            process_hash="abc",
            process_name="test.exe",
            process_path=r"C:\test.exe",
        )
        assert dna.first_seen == 0.0
        assert dna.last_seen == 0.0
        assert dna.observations_count == 0
        assert dna.confidence == 0.1

    def test_sets_are_independent_between_instances(self) -> None:
        dna1 = ProcessDNA(
            process_hash="a", process_name="a", process_path="a",
        )
        dna2 = ProcessDNA(
            process_hash="b", process_name="b", process_path="b",
        )
        dna1.typical_files.add("file.txt")
        assert "file.txt" not in dna2.typical_files


# ---------------------------------------------------------------------------
# TestSigmoidConfidence
# ---------------------------------------------------------------------------

class TestSigmoidConfidence:
    """Tests for the _sigmoid_confidence helper."""

    def test_at_zero_observations(self) -> None:
        conf = _sigmoid_confidence(0)
        # 1/(1+exp(-0.05*(0-50))) = 1/(1+exp(2.5)) ~ 0.076
        assert conf == pytest.approx(
            1.0 / (1.0 + math.exp(2.5)), rel=1e-6,
        )
        assert conf < 0.1

    def test_at_50_observations(self) -> None:
        conf = _sigmoid_confidence(50)
        assert conf == pytest.approx(0.5, rel=1e-6)

    def test_at_100_observations(self) -> None:
        conf = _sigmoid_confidence(100)
        expected = 1.0 / (1.0 + math.exp(-0.05 * 50))
        assert conf == pytest.approx(expected, rel=1e-6)
        assert conf > 0.9

    def test_at_150_observations(self) -> None:
        conf = _sigmoid_confidence(150)
        expected = 1.0 / (1.0 + math.exp(-0.05 * 100))
        assert conf == pytest.approx(expected, rel=1e-6)
        assert conf > 0.99

    def test_monotonically_increasing(self) -> None:
        values = [_sigmoid_confidence(n) for n in range(0, 200, 10)]
        for i in range(1, len(values)):
            assert values[i] > values[i - 1]


# ---------------------------------------------------------------------------
# TestJaccardDistance
# ---------------------------------------------------------------------------

class TestJaccardDistance:
    """Tests for the static _jaccard_distance method."""

    def test_identical_sets_return_zero(self) -> None:
        s = {"a", "b", "c"}
        assert ProcessDNAProfiler._jaccard_distance(s, s.copy()) == 0.0

    def test_disjoint_sets_return_one(self) -> None:
        a = {"a", "b"}
        b = {"c", "d"}
        assert ProcessDNAProfiler._jaccard_distance(a, b) == 1.0

    def test_partial_overlap(self) -> None:
        a = {"a", "b", "c"}
        b = {"b", "c", "d"}
        # union = {a,b,c,d} = 4, intersection = {b,c} = 2 -> 1-2/4=0.5
        assert ProcessDNAProfiler._jaccard_distance(a, b) == pytest.approx(
            0.5,
        )

    def test_both_empty_return_zero(self) -> None:
        assert ProcessDNAProfiler._jaccard_distance(set(), set()) == 0.0

    def test_one_empty_one_not_return_one(self) -> None:
        assert ProcessDNAProfiler._jaccard_distance(set(), {"a"}) == 1.0
        assert ProcessDNAProfiler._jaccard_distance({"a"}, set()) == 1.0

    def test_subset_returns_fraction(self) -> None:
        a = {"a", "b"}
        b = {"a", "b", "c", "d"}
        # union=4, intersection=2 -> 1-2/4=0.5
        assert ProcessDNAProfiler._jaccard_distance(a, b) == pytest.approx(
            0.5,
        )


# ---------------------------------------------------------------------------
# TestProcessDNAProfiler (integration with DB)
# ---------------------------------------------------------------------------

class TestProcessDNAProfiler:
    """Integration tests for the profiler with in-memory SQLite."""

    def test_table_created(self, db: AegisDatabase) -> None:
        profiler = ProcessDNAProfiler(db)  # noqa: F841
        tables = db.list_tables()
        assert "process_dna" in tables

    def test_learn_creates_new_dna(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        event = _make_event(extra={"file_path": r"C:\data\log.txt"})
        profiler.learn(event)
        dna = profiler.get_dna(SAMPLE_HASH)
        assert dna is not None
        assert dna.process_hash == SAMPLE_HASH
        assert r"C:\data\log.txt" in dna.typical_files
        assert dna.observations_count == 1

    def test_learn_updates_existing_dna(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        profiler.learn(_make_event(extra={"file_path": "a.txt"}))
        profiler.learn(_make_event(extra={"file_path": "b.txt"}))
        dna = profiler.get_dna(SAMPLE_HASH)
        assert dna is not None
        assert dna.observations_count == 2
        assert {"a.txt", "b.txt"} <= dna.typical_files

    def test_learn_ignores_non_process_events(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        event = _make_event(sensor=SensorType.NETWORK)
        profiler.learn(event)
        assert profiler.get_dna(SAMPLE_HASH) is None

    def test_learn_requires_process_hash(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_start",
            data={"process_name": "test.exe"},
            severity=Severity.INFO,
        )
        profiler.learn(event)
        # No hash => nothing stored
        assert profiler.get_dna("") is None

    def test_get_dna_returns_none_for_unknown(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        assert profiler.get_dna("nonexistent") is None

    def test_get_dna_after_learn(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        profiler.learn(_make_event(extra={
            "file_path": "f.txt",
            "remote_ip": "10.0.0.1",
            "remote_port": 443,
            "child_process": "cmd.exe",
            "dll_path": "kernel32.dll",
            "registry_key": r"HKLM\Software\Test",
        }))
        dna = profiler.get_dna(SAMPLE_HASH)
        assert dna is not None
        assert "f.txt" in dna.typical_files
        assert "10.0.0.1:443" in dna.typical_endpoints
        assert "cmd.exe" in dna.typical_children
        assert "kernel32.dll" in dna.typical_dlls
        assert r"HKLM\Software\Test" in dna.typical_registry

    def test_learn_extracts_alternate_keys(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        """Alternate data keys ('path', 'child_name', 'loaded_dll')."""
        profiler.learn(_make_event(extra={
            "path": "alt_file.log",
            "child_name": "powershell.exe",
            "loaded_dll": "ntdll.dll",
        }))
        dna = profiler.get_dna(SAMPLE_HASH)
        assert dna is not None
        assert "alt_file.log" in dna.typical_files
        assert "powershell.exe" in dna.typical_children
        assert "ntdll.dll" in dna.typical_dlls

    def test_compare_unknown_process_returns_1(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        score = profiler.compare("unknown_hash", {"files": {"x.txt"}})
        assert score == 1.0

    def test_compare_identical_behavior_returns_low_score(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        # Learn enough observations to pass the minimum threshold
        for i in range(MIN_OBSERVATIONS_FOR_COMPARISON + 1):
            profiler.learn(_make_event(extra={"file_path": "data.csv"}))

        score = profiler.compare(SAMPLE_HASH, {
            "files": {"data.csv"},
            "endpoints": set(),
            "children": set(),
            "dlls": set(),
            "registry": set(),
        })
        assert score == pytest.approx(0.0, abs=0.01)

    def test_compare_novel_behavior_returns_high_score(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        for i in range(MIN_OBSERVATIONS_FOR_COMPARISON + 1):
            profiler.learn(_make_event(extra={"file_path": "known.txt"}))

        score = profiler.compare(SAMPLE_HASH, {
            "files": {"totally_new.exe"},
            "endpoints": {"1.2.3.4:9999"},
            "children": {"evil.exe"},
            "dlls": {"hack.dll"},
            "registry": {r"HKLM\Evil"},
        })
        assert score > 0.8

    def test_compare_requires_min_observations(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        # Learn fewer than minimum required observations
        for _ in range(MIN_OBSERVATIONS_FOR_COMPARISON - 1):
            profiler.learn(_make_event(extra={"file_path": "f.txt"}))

        score = profiler.compare(SAMPLE_HASH, {"files": {"f.txt"}})
        assert score == 1.0

    def test_confidence_increases_with_observations(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        confidences: list[float] = []
        for i in range(60):
            profiler.learn(_make_event(extra={"file_path": f"f{i}.txt"}))
            dna = profiler.get_dna(SAMPLE_HASH)
            assert dna is not None
            confidences.append(dna.confidence)

        # Confidence should be strictly increasing
        for i in range(1, len(confidences)):
            assert confidences[i] > confidences[i - 1]

    def test_typical_items_capped(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        for i in range(MAX_TYPICAL_ITEMS + 50):
            profiler.learn(_make_event(extra={
                "file_path": f"file_{i}.txt",
            }))

        dna = profiler.get_dna(SAMPLE_HASH)
        assert dna is not None
        assert len(dna.typical_files) <= MAX_TYPICAL_ITEMS

    def test_compare_partial_overlap(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        """Partial overlap produces a score between 0 and 1."""
        for _ in range(MIN_OBSERVATIONS_FOR_COMPARISON + 1):
            profiler.learn(_make_event(extra={
                "file_path": "shared.txt",
                "remote_ip": "10.0.0.1",
                "remote_port": 80,
            }))
        # Also learn an extra file
        profiler.learn(_make_event(extra={"file_path": "old.txt"}))

        score = profiler.compare(SAMPLE_HASH, {
            "files": {"shared.txt", "new_file.txt"},
            "endpoints": {"10.0.0.1:80"},
            "children": set(),
            "dlls": set(),
            "registry": set(),
        })
        assert 0.0 < score < 1.0

    def test_persistence_across_profiler_instances(
        self, db: AegisDatabase,
    ) -> None:
        """DNA persists in DB across separate profiler instances."""
        profiler1 = ProcessDNAProfiler(db)
        profiler1.learn(_make_event(extra={"file_path": "keep.txt"}))

        profiler2 = ProcessDNAProfiler(db)
        dna = profiler2.get_dna(SAMPLE_HASH)
        assert dna is not None
        assert "keep.txt" in dna.typical_files

    def test_learn_endpoint_format(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        profiler.learn(_make_event(extra={
            "remote_ip": "192.168.1.1",
            "remote_port": 8080,
        }))
        dna = profiler.get_dna(SAMPLE_HASH)
        assert dna is not None
        assert "192.168.1.1:8080" in dna.typical_endpoints

    def test_learn_no_endpoint_without_both_fields(
        self, profiler: ProcessDNAProfiler,
    ) -> None:
        """Endpoint requires both remote_ip and remote_port."""
        profiler.learn(_make_event(extra={"remote_ip": "10.0.0.1"}))
        dna = profiler.get_dna(SAMPLE_HASH)
        assert dna is not None
        assert len(dna.typical_endpoints) == 0
