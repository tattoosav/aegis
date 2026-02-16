"""Tests for connection reputation scoring module."""

from __future__ import annotations

import pytest

from aegis.core.database import AegisDatabase
from aegis.intelligence.reputation import (
    DEFAULT_SCORE,
    ENTROPY_THRESHOLD,
    HIGH_CONNECTION_THRESHOLD,
    LONG_HISTORY_DAYS,
    ReputationFactors,
    ReputationManager,
    ReputationRecord,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db() -> AegisDatabase:
    """In-memory AegisDatabase for testing."""
    return AegisDatabase(":memory:")


@pytest.fixture()
def manager(db: AegisDatabase) -> ReputationManager:
    """ReputationManager backed by the in-memory database."""
    return ReputationManager(db)


# ---------------------------------------------------------------------------
# ReputationFactors dataclass defaults
# ---------------------------------------------------------------------------


class TestReputationFactors:
    """Verify dataclass defaults for ReputationFactors."""

    def test_defaults(self) -> None:
        f = ReputationFactors()
        assert f.ioc_match is False
        assert f.total_connections == 0
        assert f.is_first_contact is True
        assert f.port is None
        assert f.domain_entropy == 0.0
        assert f.tls_valid is None
        assert f.history_days == 0.0

    def test_custom_values(self) -> None:
        f = ReputationFactors(
            ioc_match=True,
            total_connections=50,
            is_first_contact=False,
            port=8443,
            domain_entropy=3.5,
            tls_valid=True,
            history_days=10.0,
        )
        assert f.ioc_match is True
        assert f.total_connections == 50
        assert f.is_first_contact is False
        assert f.port == 8443
        assert f.domain_entropy == 3.5
        assert f.tls_valid is True
        assert f.history_days == 10.0


# ---------------------------------------------------------------------------
# compute_score (static, no DB)
# ---------------------------------------------------------------------------


class TestComputeScore:
    """Tests for the pure scoring function ReputationManager.compute_score."""

    def test_default_score_unchanged(self) -> None:
        """No active factors => score stays at base."""
        factors = ReputationFactors(is_first_contact=False)
        result = ReputationManager.compute_score(DEFAULT_SCORE, factors)
        assert result == DEFAULT_SCORE

    def test_ioc_match_increases_score(self) -> None:
        """IOC match adds +10 (more suspicious)."""
        factors = ReputationFactors(
            ioc_match=True, is_first_contact=False,
        )
        result = ReputationManager.compute_score(DEFAULT_SCORE, factors)
        assert result == DEFAULT_SCORE + 10.0

    def test_first_contact_decreases_score(self) -> None:
        """First contact subtracts 5 (less suspicious)."""
        factors = ReputationFactors(is_first_contact=True)
        result = ReputationManager.compute_score(DEFAULT_SCORE, factors)
        assert result == DEFAULT_SCORE - 5.0

    def test_unusual_port_decreases_score(self) -> None:
        """Non-standard port subtracts 3."""
        factors = ReputationFactors(
            is_first_contact=False, port=12345,
        )
        result = ReputationManager.compute_score(DEFAULT_SCORE, factors)
        assert result == DEFAULT_SCORE - 3.0

    def test_standard_port_no_change(self) -> None:
        """Standard port causes no adjustment."""
        factors = ReputationFactors(
            is_first_contact=False, port=443,
        )
        result = ReputationManager.compute_score(DEFAULT_SCORE, factors)
        assert result == DEFAULT_SCORE

    def test_high_entropy_domain(self) -> None:
        """Domain entropy above threshold subtracts 2."""
        factors = ReputationFactors(
            is_first_contact=False,
            domain_entropy=ENTROPY_THRESHOLD + 0.5,
        )
        result = ReputationManager.compute_score(DEFAULT_SCORE, factors)
        assert result == DEFAULT_SCORE - 2.0

    def test_valid_tls_increases_score(self) -> None:
        """Valid TLS adds +5 (more trusted)."""
        factors = ReputationFactors(
            is_first_contact=False, tls_valid=True,
        )
        result = ReputationManager.compute_score(DEFAULT_SCORE, factors)
        assert result == DEFAULT_SCORE + 5.0

    def test_invalid_tls_decreases_score(self) -> None:
        """Invalid/self-signed TLS subtracts 5."""
        factors = ReputationFactors(
            is_first_contact=False, tls_valid=False,
        )
        result = ReputationManager.compute_score(DEFAULT_SCORE, factors)
        assert result == DEFAULT_SCORE - 5.0

    def test_long_history_increases_score(self) -> None:
        """History > 7 days adds +2 (more trusted)."""
        factors = ReputationFactors(
            is_first_contact=False,
            history_days=LONG_HISTORY_DAYS + 1,
        )
        result = ReputationManager.compute_score(DEFAULT_SCORE, factors)
        assert result == DEFAULT_SCORE + 2.0

    def test_score_clamped_to_0_min(self) -> None:
        """Score never goes below 0."""
        factors = ReputationFactors(
            is_first_contact=True,
            port=9999,
            domain_entropy=5.0,
            tls_valid=False,
            total_connections=HIGH_CONNECTION_THRESHOLD + 1,
        )
        result = ReputationManager.compute_score(0.0, factors)
        assert result == 0.0

    def test_score_clamped_to_100_max(self) -> None:
        """Score never goes above 100."""
        factors = ReputationFactors(
            ioc_match=True,
            is_first_contact=False,
            tls_valid=True,
            history_days=LONG_HISTORY_DAYS + 1,
        )
        result = ReputationManager.compute_score(100.0, factors)
        assert result == 100.0

    def test_combined_factors(self) -> None:
        """Multiple adjustments combine additively before clamping."""
        factors = ReputationFactors(
            ioc_match=True,            # +10
            is_first_contact=True,     # -5
            port=9999,                 # -3
            tls_valid=True,            # +5
        )
        expected = DEFAULT_SCORE + 10.0 - 5.0 - 3.0 + 5.0
        result = ReputationManager.compute_score(DEFAULT_SCORE, factors)
        assert result == expected


# ---------------------------------------------------------------------------
# _domain_entropy (static helper)
# ---------------------------------------------------------------------------


class TestDomainEntropy:
    """Tests for the Shannon entropy helper."""

    def test_empty_string(self) -> None:
        assert ReputationManager._domain_entropy("") == 0.0

    def test_single_char(self) -> None:
        assert ReputationManager._domain_entropy("a") == 0.0

    def test_repeated_chars(self) -> None:
        assert ReputationManager._domain_entropy("aaaa") == 0.0

    def test_two_distinct_chars(self) -> None:
        entropy = ReputationManager._domain_entropy("ab")
        assert entropy == pytest.approx(1.0)

    def test_high_entropy_string(self) -> None:
        """Random-looking domain should have higher entropy."""
        entropy = ReputationManager._domain_entropy(
            "x7k2m9q4z1w8r3p6b5j0"
        )
        assert entropy > ENTROPY_THRESHOLD


# ---------------------------------------------------------------------------
# ReputationManager with DB
# ---------------------------------------------------------------------------


class TestReputationManager:
    """Integration tests using the in-memory SQLite database."""

    def test_get_score_unknown_returns_default(
        self, manager: ReputationManager,
    ) -> None:
        assert manager.get_score("192.168.1.1") == DEFAULT_SCORE

    def test_update_creates_record(
        self, manager: ReputationManager,
    ) -> None:
        factors = ReputationFactors(is_first_contact=True)
        score = manager.update("10.0.0.1", "ip", factors)
        assert isinstance(score, float)
        assert score == DEFAULT_SCORE - 5.0  # first contact -5

    def test_update_existing_record(
        self, manager: ReputationManager,
    ) -> None:
        factors1 = ReputationFactors(is_first_contact=True)
        manager.update("10.0.0.1", "ip", factors1)

        factors2 = ReputationFactors(
            is_first_contact=False, tls_valid=True,
        )
        score = manager.update("10.0.0.1", "ip", factors2)
        # Second update starts from previous score (45.0) and adds +5
        assert score == pytest.approx(50.0)

    def test_get_record_returns_none_for_unknown(
        self, manager: ReputationManager,
    ) -> None:
        assert manager.get_record("unknown.example.com") is None

    def test_get_record_after_update(
        self, manager: ReputationManager,
    ) -> None:
        factors = ReputationFactors(is_first_contact=False)
        manager.update("example.com", "domain", factors)

        record = manager.get_record("example.com")
        assert record is not None
        assert isinstance(record, ReputationRecord)
        assert record.address == "example.com"
        assert record.address_type == "domain"
        assert record.score == DEFAULT_SCORE
        assert record.total_connections == 1
        assert record.first_seen > 0
        assert record.last_seen >= record.first_seen

    def test_multiple_updates_accumulate(
        self, manager: ReputationManager,
    ) -> None:
        """Repeated updates accumulate connection count and adjust score."""
        # First update: first_contact (-5) => 45
        factors_first = ReputationFactors(is_first_contact=True)
        manager.update("8.8.8.8", "ip", factors_first)

        # Second update: valid TLS (+5) => 50
        factors_tls = ReputationFactors(
            is_first_contact=False, tls_valid=True,
        )
        manager.update("8.8.8.8", "ip", factors_tls)

        # Third update: IOC match (+10) => 60
        factors_ioc = ReputationFactors(
            is_first_contact=False, ioc_match=True,
        )
        manager.update("8.8.8.8", "ip", factors_ioc)

        record = manager.get_record("8.8.8.8")
        assert record is not None
        assert record.total_connections == 3
        assert record.score == pytest.approx(60.0)
