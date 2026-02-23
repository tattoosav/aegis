"""PowerShell obfuscation detector — entropy and pattern-based analysis.

Detects obfuscated PowerShell scripts using Shannon entropy scoring
and a bank of regex patterns targeting common obfuscation techniques:
backtick insertion, string concatenation, char-array encoding,
Base64 inline decoding, encoded commands, IEX invocations,
replace chains, and compression streams.

MITRE coverage: T1059.001 (PowerShell), T1027 (Obfuscated Files).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class ObfuscationResult:
    """Result of analysing a PowerShell script for obfuscation."""

    entropy: float
    is_obfuscated: bool
    matched_patterns: list[str] = field(default_factory=list)
    confidence: float = 0.0


class PowerShellAnalyzer:
    """Detect obfuscated PowerShell scripts.

    Uses two complementary signals:

    1. **Shannon entropy** — high character-level entropy indicates
       encoded or randomised content.
    2. **Regex pattern bank** — eight patterns targeting known
       obfuscation techniques used in the wild.

    A script is flagged as obfuscated when *entropy > 5.0* **or**
    *two or more* patterns match.
    """

    # Entropy threshold above which a script is suspicious on its own.
    _ENTROPY_THRESHOLD: float = 5.0

    # Minimum number of pattern matches to flag without high entropy.
    _PATTERN_COUNT_THRESHOLD: int = 2

    def __init__(self) -> None:
        """Initialise regex pattern bank."""
        self._patterns: dict[str, re.Pattern[str]] = (
            self._build_patterns()
        )

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def analyze(self, script: str) -> ObfuscationResult:
        """Analyse a PowerShell script for obfuscation indicators.

        Parameters
        ----------
        script : str
            The raw PowerShell script text.

        Returns
        -------
        ObfuscationResult
            Entropy, matched patterns, obfuscation flag, and confidence.
        """
        entropy = self._shannon_entropy(script)
        matched = self._match_patterns(script)

        is_obfuscated = (
            entropy > self._ENTROPY_THRESHOLD
            or len(matched) >= self._PATTERN_COUNT_THRESHOLD
        )

        confidence = self._compute_confidence(entropy, matched)

        return ObfuscationResult(
            entropy=entropy,
            is_obfuscated=is_obfuscated,
            matched_patterns=matched,
            confidence=confidence,
        )

    # ------------------------------------------------------------------ #
    #  Entropy calculation
    # ------------------------------------------------------------------ #

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate character-level Shannon entropy of *text*.

        Returns 0.0 for empty or single-character strings.
        """
        if not text:
            return 0.0
        freq = Counter(text)
        total = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    # ------------------------------------------------------------------ #
    #  Pattern matching
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_patterns() -> dict[str, re.Pattern[str]]:
        """Build the regex pattern bank.

        Returns a mapping of pattern name to compiled regex.
        """
        return {
            # 1. Backtick obfuscation — 3+ backticks between word chars
            "backtick_obfuscation": re.compile(
                r"(?:.*`\w){3,}",
            ),
            # 2. String concatenation — multiple '+' between quoted strings
            "string_concat": re.compile(
                r"'\w+'?\s*\+\s*'\w+",
            ),
            # 3. Char-array join — [char[]] + -join, or @(nn,nn,...)
            "char_array_join": re.compile(
                r"\[char(?:\[\])?\].*-join|@\(\d+,\d+",
                re.IGNORECASE,
            ),
            # 4. Base64 inline decode
            "base64_inline": re.compile(
                r"FromBase64String|\[Convert\]::FromBase64",
                re.IGNORECASE,
            ),
            # 5. Encoded command flag (-enc / -encodedcommand)
            "encoded_command": re.compile(
                r"-[eE]nc\b|-[eE]ncodedcommand\b",
                re.IGNORECASE,
            ),
            # 6. IEX / Invoke-Expression
            "iex_invoke": re.compile(
                r"\biex\b|\bInvoke-Expression\b",
                re.IGNORECASE,
            ),
            # 7. Replace chains — two or more -replace operators
            "replace_deobfuscation": re.compile(
                r"-replace.*-replace",
                re.IGNORECASE,
            ),
            # 8. Compression / decompression streams
            "compress_decompress": re.compile(
                r"DeflateStream|GZipStream|IO\.Compression",
                re.IGNORECASE,
            ),
        }

    def _match_patterns(self, script: str) -> list[str]:
        """Run all patterns against *script* and return matched names."""
        matched: list[str] = []
        for name, pattern in self._patterns.items():
            if pattern.search(script):
                matched.append(name)
        return matched

    # ------------------------------------------------------------------ #
    #  Confidence scoring
    # ------------------------------------------------------------------ #

    def _compute_confidence(
        self,
        entropy: float,
        matched: list[str],
    ) -> float:
        """Compute a combined confidence score in [0.0, 1.0].

        Weights:
        - Entropy component: up to 0.5 (scaled from 0 at threshold
          to 0.5 at threshold + 2.0).
        - Pattern component: 0.15 per matched pattern, up to 0.5.

        The two are summed and capped at 1.0.
        """
        # Entropy contribution
        if entropy > self._ENTROPY_THRESHOLD:
            entropy_score = min(
                (entropy - self._ENTROPY_THRESHOLD) / 2.0, 1.0,
            ) * 0.5
        else:
            entropy_score = 0.0

        # Pattern contribution
        pattern_score = min(len(matched) * 0.15, 0.5)

        confidence = min(entropy_score + pattern_score, 1.0)
        return round(confidence, 4)
