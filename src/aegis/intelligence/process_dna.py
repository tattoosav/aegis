"""Process DNA profiler — behavioral fingerprinting for processes.

Builds a behavioral baseline for each unique process (identified by
executable hash). Learns typical file accesses, network endpoints,
child processes, loaded DLLs, and registry keys over time.

Comparing current behavior to the learned baseline produces an anomaly
score (0.0 = matches perfectly, 1.0 = completely different).

Confidence grows with observations via sigmoid curve:
  confidence = 1 / (1 + exp(-0.05 * (observations - 50)))
  At 50 observations: confidence = 0.5
  At 100 observations: confidence ~= 0.92
  At 150 observations: confidence ~= 0.99
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any

from aegis.core.models import AegisEvent, SensorType

logger = logging.getLogger(__name__)

MIN_OBSERVATIONS_FOR_COMPARISON = 5
MAX_TYPICAL_ITEMS = 500  # Cap per category to prevent unbounded growth


@dataclass
class ProcessDNA:
    """Behavioral fingerprint for a process."""

    process_hash: str
    process_name: str
    process_path: str
    typical_files: set[str] = field(default_factory=set)
    typical_endpoints: set[str] = field(default_factory=set)
    typical_children: set[str] = field(default_factory=set)
    typical_dlls: set[str] = field(default_factory=set)
    typical_registry: set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    observations_count: int = 0
    confidence: float = 0.1


def _sigmoid_confidence(observations: int) -> float:
    """Compute confidence from observation count via sigmoid.

    Returns value in (0, 1).
    """
    return 1.0 / (1.0 + math.exp(-0.05 * (observations - 50)))


def _cap_set(s: set[str], max_size: int = MAX_TYPICAL_ITEMS) -> set[str]:
    """Return the set trimmed to *max_size* elements.

    When the set exceeds the limit the most recently added items are
    kept (we convert to list, take the tail, and rebuild the set).
    Because Python 3.7+ dicts/sets do not guarantee insertion order for
    sets we simply pop from the front until the cap is satisfied.
    """
    while len(s) > max_size:
        s.pop()
    return s


class ProcessDNAProfiler:
    """Builds and queries process behavioral fingerprints.

    Args:
        db: AegisDatabase instance for persistence.  The profiler will
            create a ``process_dna`` table if it doesn't exist.
    """

    def __init__(self, db: Any) -> None:
        self._db = db
        self._ensure_table()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _ensure_table(self) -> None:
        """Create the process_dna table if needed."""
        self._db._conn.execute("""
            CREATE TABLE IF NOT EXISTS process_dna (
                process_hash TEXT PRIMARY KEY,
                process_name TEXT NOT NULL,
                process_path TEXT NOT NULL,
                typical_files TEXT NOT NULL DEFAULT '[]',
                typical_endpoints TEXT NOT NULL DEFAULT '[]',
                typical_children TEXT NOT NULL DEFAULT '[]',
                typical_dlls TEXT NOT NULL DEFAULT '[]',
                typical_registry TEXT NOT NULL DEFAULT '[]',
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                observations_count INTEGER NOT NULL DEFAULT 1,
                confidence REAL NOT NULL DEFAULT 0.1
            )
        """)
        self._db._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def learn(self, event: AegisEvent) -> None:
        """Ingest a process event and update the DNA profile.

        Extracts behavioral data from the event and adds it to
        the process's known behavior sets.

        Only processes events from the PROCESS sensor type.
        Requires ``process_hash`` in ``event.data``.
        """
        if event.sensor is not SensorType.PROCESS:
            return

        data = event.data
        process_hash = data.get("process_hash")
        if not process_hash:
            return

        dna = self._load_dna(process_hash)
        now = time.time()

        if dna is None:
            dna = ProcessDNA(
                process_hash=process_hash,
                process_name=data.get("process_name", "unknown"),
                process_path=data.get("process_path", "unknown"),
                first_seen=now,
                last_seen=now,
                observations_count=0,
                confidence=_sigmoid_confidence(0),
            )

        # Extract behavioral signals from event data
        file_path = data.get("file_path") or data.get("path")
        if file_path:
            dna.typical_files.add(file_path)
            _cap_set(dna.typical_files)

        remote_ip = data.get("remote_ip")
        remote_port = data.get("remote_port")
        if remote_ip and remote_port is not None:
            dna.typical_endpoints.add(f"{remote_ip}:{remote_port}")
            _cap_set(dna.typical_endpoints)

        child = data.get("child_process") or data.get("child_name")
        if child:
            dna.typical_children.add(child)
            _cap_set(dna.typical_children)

        dll = data.get("dll_path") or data.get("loaded_dll")
        if dll:
            dna.typical_dlls.add(dll)
            _cap_set(dna.typical_dlls)

        registry_key = data.get("registry_key")
        if registry_key:
            dna.typical_registry.add(registry_key)
            _cap_set(dna.typical_registry)

        dna.observations_count += 1
        dna.last_seen = now
        dna.confidence = _sigmoid_confidence(dna.observations_count)

        self._save_dna(dna)

    def get_dna(self, process_hash: str) -> ProcessDNA | None:
        """Retrieve a learned DNA profile by process hash."""
        return self._load_dna(process_hash)

    def compare(
        self,
        process_hash: str,
        current_behavior: dict[str, set[str]],
    ) -> float:
        """Compare current behavior to learned baseline.

        Args:
            process_hash: Hash of the process executable.
            current_behavior: Dict with keys like ``files``,
                ``endpoints``, ``children``, ``dlls``, ``registry``
                mapping to sets of currently observed values.

        Returns:
            Anomaly score 0.0 (matches perfectly) to 1.0 (completely
            novel behavior).  Returns 1.0 if process is unknown or
            has fewer than *MIN_OBSERVATIONS_FOR_COMPARISON* observations.
        """
        dna = self._load_dna(process_hash)
        if dna is None:
            return 1.0
        if dna.observations_count < MIN_OBSERVATIONS_FOR_COMPARISON:
            return 1.0

        weights = {
            "files": 0.3,
            "endpoints": 0.3,
            "children": 0.2,
            "dlls": 0.1,
            "registry": 0.1,
        }

        baseline_map: dict[str, set[str]] = {
            "files": dna.typical_files,
            "endpoints": dna.typical_endpoints,
            "children": dna.typical_children,
            "dlls": dna.typical_dlls,
            "registry": dna.typical_registry,
        }

        total = 0.0
        for category, weight in weights.items():
            baseline_set = baseline_map[category]
            current_set = current_behavior.get(category, set())
            distance = self._jaccard_distance(baseline_set, current_set)
            total += weight * distance

        return total

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _load_dna(self, process_hash: str) -> ProcessDNA | None:
        """Load from database."""
        cursor = self._db._conn.execute(
            "SELECT * FROM process_dna WHERE process_hash = ?",
            (process_hash,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        return ProcessDNA(
            process_hash=row["process_hash"],
            process_name=row["process_name"],
            process_path=row["process_path"],
            typical_files=set(json.loads(row["typical_files"])),
            typical_endpoints=set(json.loads(row["typical_endpoints"])),
            typical_children=set(json.loads(row["typical_children"])),
            typical_dlls=set(json.loads(row["typical_dlls"])),
            typical_registry=set(json.loads(row["typical_registry"])),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            observations_count=row["observations_count"],
            confidence=row["confidence"],
        )

    def _save_dna(self, dna: ProcessDNA) -> None:
        """Upsert to database."""
        self._db._conn.execute(
            """
            INSERT INTO process_dna (
                process_hash, process_name, process_path,
                typical_files, typical_endpoints, typical_children,
                typical_dlls, typical_registry,
                first_seen, last_seen, observations_count, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(process_hash) DO UPDATE SET
                process_name = excluded.process_name,
                process_path = excluded.process_path,
                typical_files = excluded.typical_files,
                typical_endpoints = excluded.typical_endpoints,
                typical_children = excluded.typical_children,
                typical_dlls = excluded.typical_dlls,
                typical_registry = excluded.typical_registry,
                last_seen = excluded.last_seen,
                observations_count = excluded.observations_count,
                confidence = excluded.confidence
            """,
            (
                dna.process_hash,
                dna.process_name,
                dna.process_path,
                json.dumps(sorted(dna.typical_files)),
                json.dumps(sorted(dna.typical_endpoints)),
                json.dumps(sorted(dna.typical_children)),
                json.dumps(sorted(dna.typical_dlls)),
                json.dumps(sorted(dna.typical_registry)),
                dna.first_seen,
                dna.last_seen,
                dna.observations_count,
                dna.confidence,
            ),
        )
        self._db._conn.commit()

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _jaccard_distance(set_a: set[str], set_b: set[str]) -> float:
        """Compute Jaccard distance between two sets.

        Returns 0.0 if identical, 1.0 if completely disjoint.
        Returns 0.0 if both are empty.
        """
        if not set_a and not set_b:
            return 0.0
        union = set_a | set_b
        intersection = set_a & set_b
        return 1.0 - len(intersection) / len(union)
