"""Tests for the BloomFilterCache probabilistic IOC lookup."""

from __future__ import annotations

import pytest

from aegis.intelligence.bloom_filter import BloomFilterCache

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_filter() -> BloomFilterCache:
    """Return a BloomFilterCache with default parameters."""
    return BloomFilterCache()


@pytest.fixture()
def small_filter() -> BloomFilterCache:
    """Return a small BloomFilterCache for deterministic tests."""
    return BloomFilterCache(estimated_size=100, fp_rate=0.01)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestBloomFilterInit:
    """Tests for BloomFilterCache construction and default values."""

    def test_default_params(self) -> None:
        bf = BloomFilterCache()
        assert bf.size > 0
        assert bf.hash_count > 0
        assert bf.item_count == 0

    def test_custom_params(self) -> None:
        bf = BloomFilterCache(estimated_size=500, fp_rate=0.05)
        assert bf.size > 0
        assert bf.hash_count > 0

    def test_size_increases_with_lower_fp_rate(self) -> None:
        bf_loose = BloomFilterCache(estimated_size=1000, fp_rate=0.1)
        bf_tight = BloomFilterCache(estimated_size=1000, fp_rate=0.001)
        assert bf_tight.size > bf_loose.size

    def test_hash_count_property(self) -> None:
        bf = BloomFilterCache(estimated_size=1000, fp_rate=0.01)
        # k = (m/n) * ln(2), for p=0.01 => k ~ 7
        assert bf.hash_count >= 1

    def test_item_count_starts_at_zero(self, default_filter: BloomFilterCache) -> None:
        assert default_filter.item_count == 0

    def test_invalid_estimated_size_raises(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            BloomFilterCache(estimated_size=0)

    def test_invalid_fp_rate_raises(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 1"):
            BloomFilterCache(fp_rate=0.0)
        with pytest.raises(ValueError, match="between 0 and 1"):
            BloomFilterCache(fp_rate=1.0)


# ---------------------------------------------------------------------------
# Add
# ---------------------------------------------------------------------------


class TestBloomFilterAdd:
    """Tests for the add() method."""

    def test_add_single_value(self, small_filter: BloomFilterCache) -> None:
        small_filter.add("192.168.1.1")
        assert small_filter.item_count == 1

    def test_item_count_increments(self, small_filter: BloomFilterCache) -> None:
        small_filter.add("alpha")
        small_filter.add("beta")
        small_filter.add("gamma")
        assert small_filter.item_count == 3

    def test_add_duplicate_increments_count(
        self, small_filter: BloomFilterCache,
    ) -> None:
        """Bloom filters do not track uniqueness; item_count always increments."""
        small_filter.add("dup")
        small_filter.add("dup")
        assert small_filter.item_count == 2


# ---------------------------------------------------------------------------
# Contains
# ---------------------------------------------------------------------------


class TestBloomFilterContains:
    """Tests for the contains() method."""

    def test_added_value_returns_true(
        self, small_filter: BloomFilterCache,
    ) -> None:
        small_filter.add("malware.exe")
        assert small_filter.contains("malware.exe") is True

    def test_never_added_value_returns_false(
        self, small_filter: BloomFilterCache,
    ) -> None:
        small_filter.add("malware.exe")
        # Very high probability this returns False for a never-added value
        assert small_filter.contains("benign.txt") is False

    def test_empty_filter_returns_false(
        self, small_filter: BloomFilterCache,
    ) -> None:
        assert small_filter.contains("anything") is False

    def test_multiple_added_values_all_found(
        self, small_filter: BloomFilterCache,
    ) -> None:
        values = ["a.exe", "b.dll", "c.sys", "d.bat"]
        for v in values:
            small_filter.add(v)
        for v in values:
            assert small_filter.contains(v) is True


# ---------------------------------------------------------------------------
# False positive rate
# ---------------------------------------------------------------------------


class TestBloomFilterFalsePositiveRate:
    """Tests for the statistical false positive rate."""

    def test_fp_rate_within_tolerance(self) -> None:
        """Add 10 000 items, test 10 000 absent items; FP rate ~ configured."""
        target_fp = 0.01
        bf = BloomFilterCache(estimated_size=10_000, fp_rate=target_fp)

        for i in range(10_000):
            bf.add(f"present-{i}")

        false_positives = sum(
            bf.contains(f"absent-{i}") for i in range(10_000)
        )
        observed_rate = false_positives / 10_000

        # Allow up to 2x the target rate
        assert observed_rate < target_fp * 2, (
            f"Observed FP rate {observed_rate:.4f} exceeds "
            f"2x target {target_fp}"
        )


# ---------------------------------------------------------------------------
# Clear
# ---------------------------------------------------------------------------


class TestBloomFilterClear:
    """Tests for the clear() method."""

    def test_clear_resets_item_count(
        self, small_filter: BloomFilterCache,
    ) -> None:
        small_filter.add("x")
        small_filter.add("y")
        small_filter.clear()
        assert small_filter.item_count == 0

    def test_clear_makes_contains_return_false(
        self, small_filter: BloomFilterCache,
    ) -> None:
        small_filter.add("malicious.js")
        assert small_filter.contains("malicious.js") is True
        small_filter.clear()
        assert small_filter.contains("malicious.js") is False


# ---------------------------------------------------------------------------
# Rebuild
# ---------------------------------------------------------------------------


class TestBloomFilterRebuild:
    """Tests for the rebuild() method."""

    def test_rebuild_from_list(self, small_filter: BloomFilterCache) -> None:
        small_filter.add("old_ioc")
        small_filter.rebuild(["new_a", "new_b", "new_c"])
        assert small_filter.item_count == 3

    def test_rebuild_all_items_present(
        self, small_filter: BloomFilterCache,
    ) -> None:
        values = ["ioc1", "ioc2", "ioc3"]
        small_filter.rebuild(values)
        for v in values:
            assert small_filter.contains(v) is True

    def test_rebuild_clears_old_items(
        self, small_filter: BloomFilterCache,
    ) -> None:
        small_filter.add("old_value")
        small_filter.rebuild(["fresh"])
        # The old value should (very likely) no longer be found
        assert small_filter.contains("old_value") is False


# ---------------------------------------------------------------------------
# Bit positions
# ---------------------------------------------------------------------------


class TestBitPositions:
    """Tests for the _get_bit_positions() internal method."""

    def test_returns_correct_count(
        self, small_filter: BloomFilterCache,
    ) -> None:
        positions = small_filter._get_bit_positions("test")
        assert len(positions) == small_filter.hash_count

    def test_positions_within_range(
        self, small_filter: BloomFilterCache,
    ) -> None:
        positions = small_filter._get_bit_positions("test")
        for pos in positions:
            assert 0 <= pos < small_filter.size

    def test_deterministic_output(
        self, small_filter: BloomFilterCache,
    ) -> None:
        pos1 = small_filter._get_bit_positions("hello")
        pos2 = small_filter._get_bit_positions("hello")
        assert pos1 == pos2


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestBloomFilterEdgeCases:
    """Edge-case tests for robustness."""

    def test_empty_string(self, small_filter: BloomFilterCache) -> None:
        small_filter.add("")
        assert small_filter.contains("") is True
        assert small_filter.item_count == 1

    def test_very_long_string(self, small_filter: BloomFilterCache) -> None:
        long_val = "x" * 100_000
        small_filter.add(long_val)
        assert small_filter.contains(long_val) is True

    def test_unicode_string(self, small_filter: BloomFilterCache) -> None:
        unicode_val = "\u2603\u2764\U0001f525"
        small_filter.add(unicode_val)
        assert small_filter.contains(unicode_val) is True
