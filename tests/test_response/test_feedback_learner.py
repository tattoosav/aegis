"""Tests for feedback-based alert suppression learner."""

from __future__ import annotations

import pytest

from aegis.core.database import AegisDatabase
from aegis.response.feedback_learner import (
    ACTION_DISMISS,
    ACTION_INVESTIGATE,
    FeedbackLearner,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db() -> AegisDatabase:
    """In-memory AegisDatabase for testing."""
    return AegisDatabase(":memory:")


@pytest.fixture()
def learner(db: AegisDatabase) -> FeedbackLearner:
    """FeedbackLearner backed by the in-memory database."""
    return FeedbackLearner(db)


# ---------------------------------------------------------------------------
# record_dismissal
# ---------------------------------------------------------------------------


class TestRecordDismissal:
    """Verify that dismissals are persisted correctly."""

    def test_stores_row(
        self, db: AegisDatabase, learner: FeedbackLearner,
    ) -> None:
        """A single dismissal should create one feedback row."""
        learner.record_dismissal("a-1", "port_scan", "network")
        cursor = db._conn.execute(
            "SELECT COUNT(*) FROM user_feedback WHERE action = ?",
            (ACTION_DISMISS,),
        )
        assert cursor.fetchone()[0] == 1

    def test_stores_correct_fields(
        self, db: AegisDatabase, learner: FeedbackLearner,
    ) -> None:
        """All fields should be written accurately."""
        learner.record_dismissal("a-2", "brute_force", "process")
        cursor = db._conn.execute(
            "SELECT alert_id, alert_type, sensor, action "
            "FROM user_feedback ORDER BY id DESC LIMIT 1",
        )
        row = cursor.fetchone()
        assert row[0] == "a-2"
        assert row[1] == "brute_force"
        assert row[2] == "process"
        assert row[3] == ACTION_DISMISS

    def test_timestamp_is_positive(
        self, db: AegisDatabase, learner: FeedbackLearner,
    ) -> None:
        """Timestamp should be a positive float (epoch seconds)."""
        learner.record_dismissal("a-3", "port_scan", "network")
        cursor = db._conn.execute(
            "SELECT timestamp FROM user_feedback ORDER BY id DESC LIMIT 1",
        )
        assert cursor.fetchone()[0] > 0


# ---------------------------------------------------------------------------
# record_investigation
# ---------------------------------------------------------------------------


class TestRecordInvestigation:
    """Verify that investigations are persisted correctly."""

    def test_stores_row(
        self, db: AegisDatabase, learner: FeedbackLearner,
    ) -> None:
        learner.record_investigation("a-10", "malware", "file_integrity")
        cursor = db._conn.execute(
            "SELECT COUNT(*) FROM user_feedback WHERE action = ?",
            (ACTION_INVESTIGATE,),
        )
        assert cursor.fetchone()[0] == 1

    def test_stores_correct_fields(
        self, db: AegisDatabase, learner: FeedbackLearner,
    ) -> None:
        learner.record_investigation("a-11", "exfil", "network")
        cursor = db._conn.execute(
            "SELECT alert_id, alert_type, sensor, action "
            "FROM user_feedback ORDER BY id DESC LIMIT 1",
        )
        row = cursor.fetchone()
        assert row[0] == "a-11"
        assert row[1] == "exfil"
        assert row[2] == "network"
        assert row[3] == ACTION_INVESTIGATE


# ---------------------------------------------------------------------------
# get_dismissal_count
# ---------------------------------------------------------------------------


class TestGetDismissalCount:
    """Verify dismissal counting logic."""

    def test_zero_initially(self, learner: FeedbackLearner) -> None:
        """No feedback recorded yet => count is 0."""
        assert learner.get_dismissal_count("port_scan", "network") == 0

    def test_increments(self, learner: FeedbackLearner) -> None:
        """Each dismissal increments the count."""
        learner.record_dismissal("a-1", "port_scan", "network")
        assert learner.get_dismissal_count("port_scan", "network") == 1
        learner.record_dismissal("a-2", "port_scan", "network")
        assert learner.get_dismissal_count("port_scan", "network") == 2

    def test_investigations_not_counted(
        self, learner: FeedbackLearner,
    ) -> None:
        """Investigations should NOT inflate the dismissal count."""
        learner.record_investigation("a-5", "port_scan", "network")
        assert learner.get_dismissal_count("port_scan", "network") == 0


# ---------------------------------------------------------------------------
# get_investigation_count
# ---------------------------------------------------------------------------


class TestGetInvestigationCount:
    """Verify investigation counting logic."""

    def test_zero_initially(self, learner: FeedbackLearner) -> None:
        assert learner.get_investigation_count("malware", "process") == 0

    def test_increments(self, learner: FeedbackLearner) -> None:
        learner.record_investigation("a-1", "malware", "process")
        assert learner.get_investigation_count("malware", "process") == 1

    def test_dismissals_not_counted(
        self, learner: FeedbackLearner,
    ) -> None:
        learner.record_dismissal("a-1", "malware", "process")
        assert learner.get_investigation_count("malware", "process") == 0


# ---------------------------------------------------------------------------
# get_suppression_multiplier
# ---------------------------------------------------------------------------


class TestGetSuppressionMultiplier:
    """Verify suppression multiplier tiers."""

    def test_no_feedback_returns_1(
        self, learner: FeedbackLearner,
    ) -> None:
        """No recorded feedback => no suppression (1.0)."""
        assert learner.get_suppression_multiplier(
            "port_scan", "network",
        ) == 1.0

    def test_one_dismissal_returns_1(
        self, learner: FeedbackLearner,
    ) -> None:
        """A single dismissal is not enough to suppress."""
        learner.record_dismissal("a-1", "port_scan", "network")
        assert learner.get_suppression_multiplier(
            "port_scan", "network",
        ) == 1.0

    def test_two_dismissals_returns_075(
        self, learner: FeedbackLearner,
    ) -> None:
        """Two dismissals trigger light suppression (0.75)."""
        learner.record_dismissal("a-1", "port_scan", "network")
        learner.record_dismissal("a-2", "port_scan", "network")
        assert learner.get_suppression_multiplier(
            "port_scan", "network",
        ) == 0.75

    def test_three_dismissals_no_investigations_returns_05(
        self, learner: FeedbackLearner,
    ) -> None:
        """3+ dismissals with zero investigations => heavy suppression."""
        for i in range(3):
            learner.record_dismissal(
                f"a-{i}", "port_scan", "network",
            )
        assert learner.get_suppression_multiplier(
            "port_scan", "network",
        ) == 0.5

    def test_five_dismissals_no_investigations_returns_05(
        self, learner: FeedbackLearner,
    ) -> None:
        """More than 3 dismissals still returns 0.5."""
        for i in range(5):
            learner.record_dismissal(
                f"a-{i}", "port_scan", "network",
            )
        assert learner.get_suppression_multiplier(
            "port_scan", "network",
        ) == 0.5

    def test_three_dismissals_with_investigation_returns_075(
        self, learner: FeedbackLearner,
    ) -> None:
        """3 dismissals but also an investigation => light suppression."""
        for i in range(3):
            learner.record_dismissal(
                f"a-{i}", "port_scan", "network",
            )
        learner.record_investigation("a-10", "port_scan", "network")
        assert learner.get_suppression_multiplier(
            "port_scan", "network",
        ) == 0.75

    def test_investigations_prevent_heavy_suppression(
        self, learner: FeedbackLearner,
    ) -> None:
        """Even one investigation blocks the 0.5 tier."""
        for i in range(4):
            learner.record_dismissal(
                f"a-{i}", "port_scan", "network",
            )
        learner.record_investigation("a-20", "port_scan", "network")
        mult = learner.get_suppression_multiplier("port_scan", "network")
        assert mult == 0.75


# ---------------------------------------------------------------------------
# Independence of alert_type and sensor
# ---------------------------------------------------------------------------


class TestIsolation:
    """Different alert types and sensors are tracked independently."""

    def test_different_alert_types_independent(
        self, learner: FeedbackLearner,
    ) -> None:
        """Dismissals for one alert type do not affect another."""
        learner.record_dismissal("a-1", "port_scan", "network")
        learner.record_dismissal("a-2", "port_scan", "network")
        assert learner.get_dismissal_count("port_scan", "network") == 2
        assert learner.get_dismissal_count("malware", "network") == 0
        assert learner.get_suppression_multiplier(
            "malware", "network",
        ) == 1.0

    def test_different_sensors_independent(
        self, learner: FeedbackLearner,
    ) -> None:
        """Dismissals for one sensor do not affect another."""
        learner.record_dismissal("a-1", "port_scan", "network")
        learner.record_dismissal("a-2", "port_scan", "network")
        assert learner.get_dismissal_count("port_scan", "network") == 2
        assert learner.get_dismissal_count("port_scan", "process") == 0
        assert learner.get_suppression_multiplier(
            "port_scan", "process",
        ) == 1.0

    def test_mixed_types_and_sensors(
        self, learner: FeedbackLearner,
    ) -> None:
        """Feedback for different (type, sensor) pairs stays separate."""
        # 3 dismissals on (port_scan, network) => 0.5
        for i in range(3):
            learner.record_dismissal(
                f"a-{i}", "port_scan", "network",
            )
        # 1 dismissal on (malware, process) => 1.0
        learner.record_dismissal("b-1", "malware", "process")

        assert learner.get_suppression_multiplier(
            "port_scan", "network",
        ) == 0.5
        assert learner.get_suppression_multiplier(
            "malware", "process",
        ) == 1.0
