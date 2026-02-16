"""Feedback-based alert suppression learner.

Tracks user feedback (dismissals vs. investigations) on security alerts
and computes per-type, per-sensor suppression multipliers.  When users
repeatedly dismiss a particular alert category without investigating,
the multiplier drops below 1.0 so downstream scoring can de-prioritise
those alerts automatically.

Suppression multiplier rules:
  0.50 — 3+ dismissals AND 0 investigations
  0.75 — 2+ dismissals (with any investigation count)
  1.00 — otherwise (default, no suppression)
"""

from __future__ import annotations

import time

from aegis.core.database import AegisDatabase

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ACTION_DISMISS: str = "dismiss"
ACTION_INVESTIGATE: str = "investigate"

# Thresholds for suppression tiers
_HEAVY_SUPPRESS_DISMISSALS: int = 3
_LIGHT_SUPPRESS_DISMISSALS: int = 2

# Multiplier values
_HEAVY_SUPPRESS_MULTIPLIER: float = 0.50
_LIGHT_SUPPRESS_MULTIPLIER: float = 0.75
_NO_SUPPRESS_MULTIPLIER: float = 1.0


class FeedbackLearner:
    """Learns from user feedback to adjust alert suppression.

    Each recorded feedback row captures whether the user *dismissed*
    (ignored) or *investigated* (took action on) a given alert.  The
    suppression multiplier is then derived from the ratio of dismissals
    to investigations for each ``(alert_type, sensor)`` pair.

    Parameters
    ----------
    db:
        An initialised :class:`AegisDatabase` instance whose schema
        already contains the ``user_feedback`` table.
    """

    def __init__(self, db: AegisDatabase) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Recording helpers
    # ------------------------------------------------------------------

    def record_dismissal(
        self,
        alert_id: str,
        alert_type: str,
        sensor: str,
    ) -> None:
        """Record that the user dismissed an alert.

        Parameters
        ----------
        alert_id:
            Unique identifier of the dismissed alert.
        alert_type:
            Category / rule name that produced the alert.
        sensor:
            Originating sensor name.
        """
        self._insert_feedback(alert_id, alert_type, sensor, ACTION_DISMISS)

    def record_investigation(
        self,
        alert_id: str,
        alert_type: str,
        sensor: str,
    ) -> None:
        """Record that the user investigated an alert.

        Parameters
        ----------
        alert_id:
            Unique identifier of the investigated alert.
        alert_type:
            Category / rule name that produced the alert.
        sensor:
            Originating sensor name.
        """
        self._insert_feedback(
            alert_id, alert_type, sensor, ACTION_INVESTIGATE,
        )

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_dismissal_count(
        self, alert_type: str, sensor: str,
    ) -> int:
        """Return the number of dismissals for a type/sensor pair."""
        return self._count_action(alert_type, sensor, ACTION_DISMISS)

    def get_investigation_count(
        self, alert_type: str, sensor: str,
    ) -> int:
        """Return the number of investigations for a type/sensor pair."""
        return self._count_action(alert_type, sensor, ACTION_INVESTIGATE)

    # ------------------------------------------------------------------
    # Suppression logic
    # ------------------------------------------------------------------

    def get_suppression_multiplier(
        self, alert_type: str, sensor: str,
    ) -> float:
        """Compute a suppression multiplier in ``[0.5, 1.0]``.

        Returns
        -------
        float
            * ``0.50`` when there are 3+ dismissals and **zero**
              investigations (heavy suppression).
            * ``0.75`` when there are 2+ dismissals (light suppression).
            * ``1.00`` otherwise (no suppression).
        """
        dismissals = self.get_dismissal_count(alert_type, sensor)
        investigations = self.get_investigation_count(alert_type, sensor)

        if (
            dismissals >= _HEAVY_SUPPRESS_DISMISSALS
            and investigations == 0
        ):
            return _HEAVY_SUPPRESS_MULTIPLIER

        if dismissals >= _LIGHT_SUPPRESS_DISMISSALS:
            return _LIGHT_SUPPRESS_MULTIPLIER

        return _NO_SUPPRESS_MULTIPLIER

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _insert_feedback(
        self,
        alert_id: str,
        alert_type: str,
        sensor: str,
        action: str,
    ) -> None:
        """Insert a single feedback row into the database."""
        self._db._conn.execute(
            "INSERT INTO user_feedback "
            "(alert_id, alert_type, sensor, action, timestamp, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (alert_id, alert_type, sensor, action, time.time(), "{}"),
        )
        self._db._conn.commit()

    def _count_action(
        self, alert_type: str, sensor: str, action: str,
    ) -> int:
        """Count feedback rows matching *alert_type*, *sensor*, *action*."""
        cursor = self._db._conn.execute(
            "SELECT COUNT(*) FROM user_feedback "
            "WHERE alert_type = ? AND sensor = ? AND action = ?",
            (alert_type, sensor, action),
        )
        return cursor.fetchone()[0]
