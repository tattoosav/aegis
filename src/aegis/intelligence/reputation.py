"""Connection reputation scoring for IP addresses and domains.

Maintains rolling trust scores (0-100) for every network endpoint
contacted. Higher scores indicate MORE suspicious connections.
Initial unknown connections start at 50.

Score adjustments:
  +10  IOC match (known malicious indicator)
  -10  excessive connections (>100 total)
  -5   first contact (never seen before)
  -3   unusual port (not 80, 443, 53, 8080, 8443)
  -2   high-entropy domain name (>4.0 bits)
  +5   valid TLS certificate
  -5   invalid/self-signed TLS
  +2   long interaction history (>7 days)
  Clamped to [0, 100]

NOTE: In this system, score adjustments that make connections LESS
suspicious are negative (lower score), and MORE suspicious are positive
(higher score). A score of 0 = fully trusted, 100 = maximally suspicious.
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Standard/common ports that are NOT suspicious
STANDARD_PORTS: set[int] = {80, 443, 53, 8080, 8443, 22, 25, 587, 993, 995}
DEFAULT_SCORE = 50.0
ENTROPY_THRESHOLD = 4.0
HIGH_CONNECTION_THRESHOLD = 100
LONG_HISTORY_DAYS = 7


@dataclass
class ReputationFactors:
    """Input factors for a reputation score update."""

    ioc_match: bool = False
    total_connections: int = 0
    is_first_contact: bool = True
    port: int | None = None
    domain_entropy: float = 0.0
    tls_valid: bool | None = None  # None = no TLS info
    history_days: float = 0.0


@dataclass
class ReputationRecord:
    """A stored reputation entry."""

    address: str
    address_type: str  # "ip" or "domain"
    score: float = DEFAULT_SCORE
    first_seen: float = 0.0
    last_seen: float = 0.0
    total_connections: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class ReputationManager:
    """Manages connection reputation scores with SQLite persistence.

    Uses the ``connection_reputation`` table (already in DB schema).
    """

    def __init__(self, db: Any) -> None:
        """Initialize with an AegisDatabase instance.

        Args:
            db: AegisDatabase with connection_reputation table.
        """
        self._db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_score(self, address: str) -> float:
        """Get current reputation score for an address.

        Returns DEFAULT_SCORE (50.0) if address is not in database.
        """
        record = self._load_record(address)
        if record is None:
            return DEFAULT_SCORE
        return record.score

    def get_record(self, address: str) -> ReputationRecord | None:
        """Get full reputation record for an address."""
        return self._load_record(address)

    def update(
        self,
        address: str,
        address_type: str,
        factors: ReputationFactors,
    ) -> float:
        """Update reputation score based on new evidence.

        Creates a new record if address not seen before.
        Returns the updated score.
        """
        now = time.time()
        record = self._load_record(address)

        if record is None:
            record = ReputationRecord(
                address=address,
                address_type=address_type,
                score=DEFAULT_SCORE,
                first_seen=now,
                last_seen=now,
                total_connections=1,
            )
        else:
            record.last_seen = now
            record.total_connections += 1

        new_score = self.compute_score(record.score, factors)
        record.score = new_score

        self._save_record(record)
        logger.debug(
            "Reputation update: %s -> %.1f (was %.1f)",
            address,
            new_score,
            record.score,
        )
        return new_score

    # ------------------------------------------------------------------
    # Pure scoring logic (static, no DB)
    # ------------------------------------------------------------------

    @staticmethod
    def compute_score(
        base_score: float,
        factors: ReputationFactors,
    ) -> float:
        """Compute adjusted score from base + factors.

        This is a pure function for testability.
        Returns score clamped to [0, 100].
        """
        score = base_score

        # IOC match => more suspicious (+10)
        if factors.ioc_match:
            score += 10.0

        # Excessive connections => less suspicious (-10)
        if factors.total_connections > HIGH_CONNECTION_THRESHOLD:
            score -= 10.0

        # First contact => less suspicious (-5)
        if factors.is_first_contact:
            score -= 5.0

        # Unusual port => less suspicious (-3)
        if factors.port is not None and factors.port not in STANDARD_PORTS:
            score -= 3.0

        # High-entropy domain => less suspicious (-2)
        if factors.domain_entropy > ENTROPY_THRESHOLD:
            score -= 2.0

        # TLS status
        if factors.tls_valid is True:
            score += 5.0   # valid TLS => more trusted (+5)
        elif factors.tls_valid is False:
            score -= 5.0   # invalid TLS => less trusted (-5)

        # Long history => more trusted (+2)
        if factors.history_days > LONG_HISTORY_DAYS:
            score += 2.0

        return max(0.0, min(100.0, score))

    @staticmethod
    def _domain_entropy(domain: str) -> float:
        """Shannon entropy of a domain string.

        Returns 0.0 for empty strings.
        """
        if not domain:
            return 0.0
        length = len(domain)
        counts = Counter(domain)
        entropy = 0.0
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        return entropy

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    def _load_record(self, address: str) -> ReputationRecord | None:
        """Load a record from the database."""
        cursor = self._db._conn.execute(
            "SELECT * FROM connection_reputation WHERE address = ?",
            (address,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return ReputationRecord(
            address=row["address"],
            address_type=row["address_type"],
            score=row["score"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            total_connections=row["total_connections"],
            metadata=json.loads(row["metadata"]),
        )

    def _save_record(self, record: ReputationRecord) -> None:
        """Upsert a record to the database."""
        self._db._conn.execute(
            "INSERT INTO connection_reputation "
            "(address, address_type, score, first_seen, last_seen, "
            "total_connections, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(address) DO UPDATE SET "
            "score = excluded.score, "
            "last_seen = excluded.last_seen, "
            "total_connections = excluded.total_connections, "
            "metadata = excluded.metadata",
            (
                record.address,
                record.address_type,
                record.score,
                record.first_seen,
                record.last_seen,
                record.total_connections,
                json.dumps(record.metadata),
            ),
        )
        self._db._conn.commit()
