"""Tests for the LSTM Sequence Analyzer detection engine."""

from __future__ import annotations

import time

import numpy as np
import pytest

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.detection.lstm_analyzer import (
    BEACONING_CV_THRESHOLD,
    BRUTE_FORCE_THRESHOLD,
    MIN_TRAINING_SEQUENCES,
    SEQUENCE_FEATURES_PER_EVENT,
    LSTMSequenceAnalyzer,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    event_type: str = "test_event",
    sensor: SensorType = SensorType.NETWORK,
    severity: Severity = Severity.INFO,
    timestamp: float | None = None,
    data: dict | None = None,
) -> AegisEvent:
    """Create an AegisEvent with sensible defaults for testing."""
    return AegisEvent(
        sensor=sensor,
        event_type=event_type,
        severity=severity,
        data=data or {},
        timestamp=timestamp or time.time(),
    )


def _make_normal_sequence(
    length: int = 20,
    base_time: float | None = None,
    interval: float = 5.0,
    jitter: float = 2.0,
) -> list[AegisEvent]:
    """Generate a sequence of normal-looking events with randomised timing."""
    rng = np.random.default_rng()
    base = base_time if base_time is not None else time.time()
    events: list[AegisEvent] = []
    t = base
    event_types = ["dns_query", "http_request", "tcp_connect", "process_start"]
    severities = [Severity.INFO, Severity.LOW]
    for i in range(length):
        events.append(
            _make_event(
                event_type=rng.choice(event_types),
                severity=rng.choice(severities),
                timestamp=t,
                data={"index": i},
            )
        )
        t += interval + rng.uniform(-jitter, jitter)
    return events


def _make_training_sequences(
    count: int = 40,
    seq_length: int = 20,
) -> list[list[AegisEvent]]:
    """Generate multiple normal sequences suitable for training."""
    return [
        _make_normal_sequence(length=seq_length, base_time=1_700_000_000.0 + i * 200)
        for i in range(count)
    ]


def _trained_analyzer(
    sequence_length: int = 20,
    n_sequences: int = 40,
) -> LSTMSequenceAnalyzer:
    """Return a pre-trained analyzer for convenience."""
    analyzer = LSTMSequenceAnalyzer(sequence_length=sequence_length)
    sequences = _make_training_sequences(count=n_sequences, seq_length=sequence_length)
    analyzer.train(sequences)
    return analyzer


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestInitialization:
    """Tests for LSTMSequenceAnalyzer constructor and defaults."""

    def test_default_params(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        assert analyzer.sequence_length == 20
        assert analyzer.is_trained is False

    def test_custom_sequence_length(self) -> None:
        analyzer = LSTMSequenceAnalyzer(sequence_length=10)
        assert analyzer.sequence_length == 10

    def test_custom_n_estimators_and_contamination(self) -> None:
        analyzer = LSTMSequenceAnalyzer(
            n_estimators=50, contamination=0.05,
        )
        assert analyzer._n_estimators == 50
        assert analyzer._contamination == 0.05

    def test_is_trained_false_before_training(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        assert analyzer.is_trained is False


# ---------------------------------------------------------------------------
# Event encoding
# ---------------------------------------------------------------------------


class TestEncodeEvent:
    """Tests for single-event feature encoding."""

    def test_shape(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec = analyzer.encode_event(_make_event())
        assert vec.shape == (SEQUENCE_FEATURES_PER_EVENT,)
        assert vec.shape == (12,)

    def test_dtype_is_float64(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec = analyzer.encode_event(_make_event())
        assert vec.dtype == np.float64

    def test_type_hash_in_unit_interval(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec = analyzer.encode_event(_make_event(event_type="http_request"))
        assert 0.0 <= vec[0] < 1.0

    def test_type_hash_deterministic(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        v1 = analyzer.encode_event(_make_event(event_type="dns_query"))
        v2 = analyzer.encode_event(_make_event(event_type="dns_query"))
        assert v1[0] == v2[0]

    def test_different_event_types_get_different_hashes(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        v1 = analyzer.encode_event(_make_event(event_type="dns_query"))
        v2 = analyzer.encode_event(_make_event(event_type="http_request"))
        assert v1[0] != v2[0]

    def test_sensor_ordinal(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec = analyzer.encode_event(_make_event(sensor=SensorType.PROCESS))
        # SensorType.PROCESS is at index 1 in the enum ordering
        expected = float(
            [st.value for st in SensorType].index(SensorType.PROCESS.value)
        )
        assert vec[1] == expected

    def test_severity_ordinal_and_weight(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec = analyzer.encode_event(_make_event(severity=Severity.HIGH))
        severity_order = [sv.value for sv in Severity]
        expected_ordinal = float(severity_order.index("high"))
        assert vec[2] == expected_ordinal
        assert vec[3] == Severity.HIGH.weight  # 0.8

    def test_timestamp_encoded(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        ts = 1_700_000_000.0
        vec = analyzer.encode_event(_make_event(timestamp=ts))
        assert vec[4] == ts

    def test_data_field_count(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec = analyzer.encode_event(_make_event(data={"a": 1, "b": 2, "c": 3}))
        assert vec[5] == 3.0

    def test_data_string_length(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec = analyzer.encode_event(_make_event(data={"msg": "hello"}))
        assert vec[6] == float(len("hello"))

    def test_has_pid_flag(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec_with = analyzer.encode_event(_make_event(data={"pid": 1234}))
        vec_without = analyzer.encode_event(_make_event(data={"name": "test"}))
        assert vec_with[7] == 1.0
        assert vec_without[7] == 0.0

    def test_has_ip_flag(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec_ip = analyzer.encode_event(_make_event(data={"ip": "10.0.0.1"}))
        vec_remote = analyzer.encode_event(_make_event(data={"remote_ip": "10.0.0.2"}))
        vec_none = analyzer.encode_event(_make_event(data={"host": "foo"}))
        assert vec_ip[8] == 1.0
        assert vec_remote[8] == 1.0
        assert vec_none[8] == 0.0

    def test_has_port_flag(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec_port = analyzer.encode_event(_make_event(data={"port": 443}))
        vec_remote = analyzer.encode_event(_make_event(data={"remote_port": 80}))
        vec_none = analyzer.encode_event(_make_event(data={}))
        assert vec_port[9] == 1.0
        assert vec_remote[9] == 1.0
        assert vec_none[9] == 0.0

    def test_has_user_flag(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec_user = analyzer.encode_event(_make_event(data={"user": "admin"}))
        vec_uname = analyzer.encode_event(_make_event(data={"username": "root"}))
        vec_none = analyzer.encode_event(_make_event(data={}))
        assert vec_user[10] == 1.0
        assert vec_uname[10] == 1.0
        assert vec_none[10] == 0.0

    def test_has_path_flag(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        vec_path = analyzer.encode_event(_make_event(data={"path": "/etc/passwd"}))
        vec_fp = analyzer.encode_event(_make_event(data={"file_path": "/tmp/x"}))
        vec_none = analyzer.encode_event(_make_event(data={}))
        assert vec_path[11] == 1.0
        assert vec_fp[11] == 1.0
        assert vec_none[11] == 0.0


# ---------------------------------------------------------------------------
# Sequence encoding
# ---------------------------------------------------------------------------


class TestEncodeSequence:
    """Tests for sequence-level feature encoding."""

    def test_shape(self) -> None:
        analyzer = LSTMSequenceAnalyzer(sequence_length=5)
        events = _make_normal_sequence(length=5)
        vec = analyzer.encode_sequence(events)
        # 4 stats * 12 features + 6 timing stats = 54
        assert vec.shape == (54,)

    def test_padding_short_sequence(self) -> None:
        """Fewer events than sequence_length should be zero-padded."""
        analyzer = LSTMSequenceAnalyzer(sequence_length=10)
        events = _make_normal_sequence(length=3, base_time=1_000_000.0)
        vec = analyzer.encode_sequence(events)
        assert vec.shape == (54,)
        # With padding, min values (features 24-35) should contain zeros
        # from the padded rows, so they should be 0 for most features.
        feat_min = vec[24:36]
        # Timestamp min should be 0 because of zero-padded rows
        assert feat_min[4] == 0.0

    def test_truncation_long_sequence(self) -> None:
        """More events than sequence_length should be truncated."""
        analyzer = LSTMSequenceAnalyzer(sequence_length=5)
        events = _make_normal_sequence(length=15, base_time=1_000_000.0)
        vec = analyzer.encode_sequence(events)
        assert vec.shape == (54,)

    def test_single_event_sequence(self) -> None:
        """A single event should still produce a valid 54-dim vector."""
        analyzer = LSTMSequenceAnalyzer(sequence_length=5)
        events = [_make_event(timestamp=1_000_000.0)]
        vec = analyzer.encode_sequence(events)
        assert vec.shape == (54,)

    def test_timing_stats_with_regular_intervals(self) -> None:
        """Regular timing should produce low CV and high regularity."""
        analyzer = LSTMSequenceAnalyzer(sequence_length=10)
        base = 1_000_000.0
        events = [
            _make_event(timestamp=base + i * 60.0) for i in range(10)
        ]
        vec = analyzer.encode_sequence(events)
        # Timing stats are the last 6 elements
        timing = vec[-6:]
        delta_mean, delta_std, delta_min, delta_max, cv, regularity = timing
        assert delta_mean == pytest.approx(60.0, abs=0.1)
        assert delta_std == pytest.approx(0.0, abs=0.1)
        assert cv == pytest.approx(0.0, abs=0.01)
        assert regularity == pytest.approx(1.0, abs=0.01)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


class TestTraining:
    """Tests for the train method."""

    def test_train_sets_is_trained(self) -> None:
        analyzer = LSTMSequenceAnalyzer(sequence_length=20)
        sequences = _make_training_sequences(count=40, seq_length=20)
        analyzer.train(sequences)
        assert analyzer.is_trained is True

    def test_train_insufficient_sequences_raises(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        too_few = _make_training_sequences(count=MIN_TRAINING_SEQUENCES - 1)
        with pytest.raises(ValueError, match="Need at least"):
            analyzer.train(too_few)

    def test_train_exact_minimum_sequences(self) -> None:
        analyzer = LSTMSequenceAnalyzer(sequence_length=20)
        sequences = _make_training_sequences(
            count=MIN_TRAINING_SEQUENCES, seq_length=20,
        )
        analyzer.train(sequences)
        assert analyzer.is_trained is True


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


class TestScore:
    """Tests for the score method."""

    def test_score_returns_float_in_range(self) -> None:
        analyzer = _trained_analyzer()
        events = _make_normal_sequence(length=20)
        result = analyzer.score(events)
        assert isinstance(result, float)
        assert 0.0 <= result <= 1.0

    def test_score_raises_when_untrained(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        events = _make_normal_sequence(length=20)
        with pytest.raises(RuntimeError, match="has not been trained"):
            analyzer.score(events)

    def test_score_is_rounded_to_four_decimals(self) -> None:
        analyzer = _trained_analyzer()
        events = _make_normal_sequence(length=20)
        result = analyzer.score(events)
        # The score is rounded to 4 decimal places
        assert result == round(result, 4)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


class TestClassify:
    """Tests for the classify method."""

    def test_normal_threshold(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        assert analyzer.classify(0.0) == "normal"
        assert analyzer.classify(0.2) == "normal"
        assert analyzer.classify(0.39) == "normal"

    def test_suspicious_threshold(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        assert analyzer.classify(0.4) == "suspicious"
        assert analyzer.classify(0.5) == "suspicious"
        assert analyzer.classify(0.59) == "suspicious"

    def test_anomalous_threshold(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        assert analyzer.classify(0.6) == "anomalous"
        assert analyzer.classify(0.8) == "anomalous"
        assert analyzer.classify(1.0) == "anomalous"

    def test_boundary_values(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        assert analyzer.classify(0.399) == "normal"
        assert analyzer.classify(0.4) == "suspicious"
        assert analyzer.classify(0.599) == "suspicious"
        assert analyzer.classify(0.6) == "anomalous"


# ---------------------------------------------------------------------------
# Beaconing detection
# ---------------------------------------------------------------------------


class TestDetectBeaconing:
    """Tests for the detect_beaconing method."""

    def test_regular_timing_detected_as_beaconing(self) -> None:
        """Perfectly periodic events should trigger beaconing detection."""
        analyzer = LSTMSequenceAnalyzer()
        base = 1_000_000.0
        events = [_make_event(timestamp=base + i * 60.0) for i in range(10)]
        is_beaconing, details = analyzer.detect_beaconing(events)
        assert is_beaconing is True
        assert details["coefficient_of_variation"] < BEACONING_CV_THRESHOLD
        assert details["interval_mean"] > 0

    def test_nearly_regular_timing_detected(self) -> None:
        """Very low jitter should still trigger beaconing."""
        analyzer = LSTMSequenceAnalyzer()
        base = 1_000_000.0
        # Tiny jitter well within the CV threshold
        timestamps = [base + i * 60.0 + (i % 2) * 0.5 for i in range(10)]
        events = [_make_event(timestamp=t) for t in timestamps]
        is_beaconing, details = analyzer.detect_beaconing(events)
        assert is_beaconing is True

    def test_irregular_timing_not_beaconing(self) -> None:
        """Highly variable timing should not trigger beaconing."""
        analyzer = LSTMSequenceAnalyzer()
        rng = np.random.default_rng(42)
        base = 1_000_000.0
        timestamps = sorted(base + rng.uniform(0, 10_000, size=10))
        events = [_make_event(timestamp=t) for t in timestamps]
        is_beaconing, details = analyzer.detect_beaconing(events)
        assert is_beaconing is False
        assert details["coefficient_of_variation"] >= BEACONING_CV_THRESHOLD

    def test_fewer_than_three_events_not_beaconing(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        events = [_make_event(timestamp=1_000_000.0 + i * 60.0) for i in range(2)]
        is_beaconing, details = analyzer.detect_beaconing(events)
        assert is_beaconing is False
        assert details["interval_mean"] == 0.0

    def test_empty_events_not_beaconing(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        is_beaconing, details = analyzer.detect_beaconing([])
        assert is_beaconing is False

    def test_details_keys_present(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        events = [_make_event(timestamp=1_000_000.0 + i * 60.0) for i in range(5)]
        _, details = analyzer.detect_beaconing(events)
        assert "interval_mean" in details
        assert "interval_std" in details
        assert "coefficient_of_variation" in details


# ---------------------------------------------------------------------------
# Brute-force detection
# ---------------------------------------------------------------------------


class TestDetectBruteForce:
    """Tests for the detect_brute_force method."""

    def test_many_failed_logins_detected(self) -> None:
        """10+ failed_login events should trigger brute-force detection."""
        analyzer = LSTMSequenceAnalyzer()
        base = 1_000_000.0
        events = [
            _make_event(
                event_type="failed_login",
                timestamp=base + i * 2.0,
            )
            for i in range(BRUTE_FORCE_THRESHOLD)
        ]
        is_bf, details = analyzer.detect_brute_force(events)
        assert is_bf is True
        assert details["failed_count"] == BRUTE_FORCE_THRESHOLD

    def test_login_failure_event_type(self) -> None:
        """The event_type 'login_failure' should also be counted."""
        analyzer = LSTMSequenceAnalyzer()
        base = 1_000_000.0
        events = [
            _make_event(event_type="login_failure", timestamp=base + i)
            for i in range(12)
        ]
        is_bf, details = analyzer.detect_brute_force(events)
        assert is_bf is True
        assert details["failed_count"] == 12

    def test_auth_fail_event_type(self) -> None:
        """The event_type 'auth_fail' should also be counted."""
        analyzer = LSTMSequenceAnalyzer()
        base = 1_000_000.0
        events = [
            _make_event(event_type="auth_fail", timestamp=base + i)
            for i in range(11)
        ]
        is_bf, details = analyzer.detect_brute_force(events)
        assert is_bf is True

    def test_few_failures_not_brute_force(self) -> None:
        """Fewer than threshold failures should not trigger."""
        analyzer = LSTMSequenceAnalyzer()
        base = 1_000_000.0
        events = [
            _make_event(event_type="failed_login", timestamp=base + i * 2.0)
            for i in range(BRUTE_FORCE_THRESHOLD - 1)
        ]
        is_bf, details = analyzer.detect_brute_force(events)
        assert is_bf is False
        assert details["failed_count"] == BRUTE_FORCE_THRESHOLD - 1

    def test_data_status_field_counts_as_failure(self) -> None:
        """Events with data['status'] containing 'fail' should be counted."""
        analyzer = LSTMSequenceAnalyzer()
        base = 1_000_000.0
        events = [
            _make_event(
                event_type="login_attempt",
                timestamp=base + i,
                data={"status": "failed"},
            )
            for i in range(12)
        ]
        is_bf, details = analyzer.detect_brute_force(events)
        assert is_bf is True
        assert details["failed_count"] == 12

    def test_data_result_field_counts_as_failure(self) -> None:
        """Events with data['result'] containing 'fail' should be counted."""
        analyzer = LSTMSequenceAnalyzer()
        base = 1_000_000.0
        events = [
            _make_event(
                event_type="auth_check",
                timestamp=base + i,
                data={"result": "auth_failure"},
            )
            for i in range(11)
        ]
        is_bf, details = analyzer.detect_brute_force(events)
        assert is_bf is True
        assert details["failed_count"] == 11

    def test_mixed_event_types_and_data_fields(self) -> None:
        """Mix of failed_login event_type and data status fields."""
        analyzer = LSTMSequenceAnalyzer()
        base = 1_000_000.0
        events = []
        # 5 via event_type
        for i in range(5):
            events.append(
                _make_event(event_type="failed_login", timestamp=base + i)
            )
        # 5 via data.status
        for i in range(5, 10):
            events.append(
                _make_event(
                    event_type="login_attempt",
                    timestamp=base + i,
                    data={"status": "failed"},
                )
            )
        is_bf, details = analyzer.detect_brute_force(events)
        assert is_bf is True
        assert details["failed_count"] == 10

    def test_details_contain_expected_keys(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        events = [_make_event(timestamp=1_000_000.0)]
        _, details = analyzer.detect_brute_force(events)
        assert "failed_count" in details
        assert "window_seconds" in details
        assert "rate_per_minute" in details

    def test_window_seconds_calculated(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        base = 1_000_000.0
        events = [
            _make_event(event_type="failed_login", timestamp=base),
            _make_event(event_type="failed_login", timestamp=base + 120.0),
        ]
        _, details = analyzer.detect_brute_force(events)
        assert details["window_seconds"] == 120.0

    def test_rate_per_minute(self) -> None:
        analyzer = LSTMSequenceAnalyzer()
        base = 1_000_000.0
        # 10 failures over 60 seconds => rate = 10/min
        events = [
            _make_event(
                event_type="failed_login",
                timestamp=base + i * (60.0 / 9),
            )
            for i in range(10)
        ]
        is_bf, details = analyzer.detect_brute_force(events)
        assert is_bf is True
        assert details["rate_per_minute"] == pytest.approx(10.0, rel=0.1)
