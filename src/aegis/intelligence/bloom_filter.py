"""Bloom filter for probabilistic IOC membership testing.

Provides fast negative lookups (<1 microsecond) before hitting the
full SQLite IOC database. No false negatives -- if contains() returns
False, the value is definitely not in the set.
"""

from __future__ import annotations

import hashlib
import logging
import math

logger = logging.getLogger(__name__)


class BloomFilterCache:
    """Probabilistic set for fast IOC membership testing.

    Uses dual hashing (SHA-256 + MD5) to generate k hash functions
    via double hashing technique: h_i(x) = h1(x) + i * h2(x).

    Args:
        estimated_size: Expected number of items.
        fp_rate: Target false positive rate (0.01 = 1%).
    """

    def __init__(
        self,
        estimated_size: int = 1_000_000,
        fp_rate: float = 0.01,
    ) -> None:
        if estimated_size <= 0:
            raise ValueError("estimated_size must be a positive integer")
        if not (0.0 < fp_rate < 1.0):
            raise ValueError("fp_rate must be between 0 and 1 exclusive")

        # Optimal bit array size: m = -(n * ln(p)) / (ln(2)^2)
        m = -estimated_size * math.log(fp_rate) / (math.log(2) ** 2)
        self._size = max(1, int(math.ceil(m)))

        # Optimal hash count: k = (m / n) * ln(2)
        k = (self._size / estimated_size) * math.log(2)
        self._hash_count = max(1, int(round(k)))

        # Bit array stored as a bytearray
        self._bits = bytearray(math.ceil(self._size / 8))
        self._item_count = 0

        logger.debug(
            "BloomFilterCache created: size=%d bits, hash_count=%d, "
            "estimated_size=%d, fp_rate=%.4f",
            self._size,
            self._hash_count,
            estimated_size,
            fp_rate,
        )

    @property
    def size(self) -> int:
        """Number of bits in the filter."""
        return self._size

    @property
    def hash_count(self) -> int:
        """Number of hash functions used."""
        return self._hash_count

    @property
    def item_count(self) -> int:
        """Number of items added to the filter."""
        return self._item_count

    def add(self, value: str) -> None:
        """Add a value to the filter."""
        for pos in self._get_bit_positions(value):
            self._bits[pos // 8] |= 1 << (pos % 8)
        self._item_count += 1

    def contains(self, value: str) -> bool:
        """Test if a value might be in the set.

        Returns True if the value MIGHT be present (possible false positive).
        Returns False if the value is DEFINITELY NOT present.
        """
        for pos in self._get_bit_positions(value):
            if not ((self._bits[pos // 8] >> (pos % 8)) & 1):
                return False
        return True

    def clear(self) -> None:
        """Reset the filter, removing all items."""
        self._bits = bytearray(len(self._bits))
        self._item_count = 0

    def rebuild(self, values: list[str]) -> None:
        """Clear and rebuild filter from a list of values."""
        self.clear()
        for v in values:
            self.add(v)
        logger.debug(
            "BloomFilterCache rebuilt with %d values", len(values),
        )

    def _get_bit_positions(self, value: str) -> list[int]:
        """Compute k bit positions for a value using double hashing.

        h1 = SHA-256 digest interpreted as an integer.
        h2 = MD5 digest interpreted as an integer.
        positions[i] = (h1 + i * h2) % self._size
        """
        encoded = value.encode("utf-8")
        h1 = int(hashlib.sha256(encoded).hexdigest(), 16)
        h2 = int(hashlib.md5(encoded).hexdigest(), 16)  # noqa: S324
        return [(h1 + i * h2) % self._size for i in range(self._hash_count)]
