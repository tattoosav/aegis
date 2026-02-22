"""Tests for the YARA rule scanner detection module."""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis.detection.yara_scanner import YaraMatch, YaraScanner


# ---------------------------------------------------------------------------
# YaraMatch dataclass
# ---------------------------------------------------------------------------


class TestYaraMatch:
    """YaraMatch dataclass construction and field access."""

    def test_required_fields(self) -> None:
        """YaraMatch can be constructed with all required fields."""
        m = YaraMatch(
            rule_name="TestRule",
            tags=["malware"],
            meta={"author": "test"},
            strings_matched=["$s1"],
        )
        assert m.rule_name == "TestRule"
        assert m.tags == ["malware"]
        assert m.meta == {"author": "test"}
        assert m.strings_matched == ["$s1"]

    def test_default_file_path(self) -> None:
        """file_path defaults to empty string."""
        m = YaraMatch(
            rule_name="R",
            tags=[],
            meta={},
            strings_matched=[],
        )
        assert m.file_path == ""

    def test_default_file_hash(self) -> None:
        """file_hash defaults to empty string."""
        m = YaraMatch(
            rule_name="R",
            tags=[],
            meta={},
            strings_matched=[],
        )
        assert m.file_hash == ""

    def test_custom_file_path_and_hash(self) -> None:
        """file_path and file_hash can be set explicitly."""
        m = YaraMatch(
            rule_name="R",
            tags=[],
            meta={},
            strings_matched=[],
            file_path="/tmp/evil.exe",
            file_hash="abc123",
        )
        assert m.file_path == "/tmp/evil.exe"
        assert m.file_hash == "abc123"

    def test_field_count(self) -> None:
        """YaraMatch has exactly 6 fields."""
        assert len(fields(YaraMatch)) == 6

    def test_field_names(self) -> None:
        """YaraMatch fields have the expected names."""
        names = {f.name for f in fields(YaraMatch)}
        expected = {
            "rule_name",
            "tags",
            "meta",
            "strings_matched",
            "file_path",
            "file_hash",
        }
        assert names == expected

    def test_tags_is_list(self) -> None:
        """tags field stores a list of strings."""
        m = YaraMatch(
            rule_name="R",
            tags=["tag1", "tag2"],
            meta={},
            strings_matched=[],
        )
        assert isinstance(m.tags, list)
        assert len(m.tags) == 2

    def test_meta_is_dict(self) -> None:
        """meta field stores a dictionary."""
        m = YaraMatch(
            rule_name="R",
            tags=[],
            meta={"author": "tester", "score": 75},
            strings_matched=[],
        )
        assert isinstance(m.meta, dict)
        assert m.meta["score"] == 75


# ---------------------------------------------------------------------------
# YaraScanner.__init__
# ---------------------------------------------------------------------------


class TestYaraScannerInit:
    """YaraScanner construction and default parameters."""

    def test_default_scan_timeout(self) -> None:
        """Default scan timeout is 30 seconds."""
        scanner = YaraScanner()
        assert scanner._scan_timeout == 30

    def test_default_max_file_size(self) -> None:
        """Default max file size is 50 MB."""
        scanner = YaraScanner()
        assert scanner._max_file_size == 50 * 1024 * 1024

    def test_custom_rules_dir(self, tmp_path: Path) -> None:
        """Custom rules_dir is stored as a Path."""
        scanner = YaraScanner(rules_dir=tmp_path)
        assert scanner._rules_dir == tmp_path

    def test_custom_scan_timeout(self) -> None:
        """Custom scan_timeout is stored."""
        scanner = YaraScanner(scan_timeout=10)
        assert scanner._scan_timeout == 10

    def test_custom_max_file_size(self) -> None:
        """Custom max_file_size is stored."""
        scanner = YaraScanner(max_file_size=1024)
        assert scanner._max_file_size == 1024

    def test_rules_dir_accepts_string(self, tmp_path: Path) -> None:
        """rules_dir accepts a string and converts to Path."""
        scanner = YaraScanner(rules_dir=str(tmp_path))
        assert isinstance(scanner._rules_dir, Path)
        assert scanner._rules_dir == tmp_path

    def test_compiled_rules_initially_none(self) -> None:
        """No rules compiled on init."""
        scanner = YaraScanner()
        assert scanner._compiled_rules is None

    def test_rule_count_initially_zero(self) -> None:
        """Rule count starts at zero."""
        scanner = YaraScanner()
        assert scanner._rule_count == 0


# ---------------------------------------------------------------------------
# is_available property
# ---------------------------------------------------------------------------


class TestYaraScannerIsAvailable:
    """is_available property logic."""

    @patch("aegis.detection.yara_scanner._HAS_YARA", False)
    def test_false_when_yara_not_installed(self) -> None:
        """is_available is False when yara-python is not installed."""
        scanner = YaraScanner()
        assert scanner.is_available is False

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_false_when_no_rules_loaded(self) -> None:
        """is_available is False when yara is installed but no rules."""
        scanner = YaraScanner()
        assert scanner.is_available is False

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_true_when_yara_installed_and_rules_loaded(self) -> None:
        """is_available is True when yara installed and rules compiled."""
        scanner = YaraScanner()
        scanner._compiled_rules = MagicMock()
        assert scanner.is_available is True

    @patch("aegis.detection.yara_scanner._HAS_YARA", False)
    def test_false_even_with_rules_when_no_yara(self) -> None:
        """is_available is False even if _compiled_rules is set
        but _HAS_YARA is False."""
        scanner = YaraScanner()
        scanner._compiled_rules = MagicMock()
        assert scanner.is_available is False


# ---------------------------------------------------------------------------
# rule_count property
# ---------------------------------------------------------------------------


class TestYaraScannerRuleCount:
    """rule_count property."""

    def test_initial_count_is_zero(self) -> None:
        """rule_count is 0 before loading."""
        scanner = YaraScanner()
        assert scanner.rule_count == 0

    def test_count_reflects_loaded_rules(self) -> None:
        """rule_count returns the stored count."""
        scanner = YaraScanner()
        scanner._rule_count = 5
        assert scanner.rule_count == 5


# ---------------------------------------------------------------------------
# load_rules
# ---------------------------------------------------------------------------


class TestYaraScannerLoadRules:
    """load_rules method."""

    @patch("aegis.detection.yara_scanner._HAS_YARA", False)
    def test_returns_zero_when_yara_not_installed(
        self, tmp_path: Path,
    ) -> None:
        """load_rules returns 0 when yara-python is missing."""
        scanner = YaraScanner(rules_dir=tmp_path)
        assert scanner.load_rules() == 0

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_returns_zero_when_dir_missing(self, tmp_path: Path) -> None:
        """load_rules returns 0 when rules directory doesn't exist."""
        missing = tmp_path / "nonexistent"
        scanner = YaraScanner(rules_dir=missing)
        assert scanner.load_rules() == 0

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_returns_zero_for_empty_directory(
        self, tmp_path: Path,
    ) -> None:
        """load_rules returns 0 when directory has no .yar/.yara files."""
        scanner = YaraScanner(rules_dir=tmp_path)
        assert scanner.load_rules() == 0

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    @patch("aegis.detection.yara_scanner.yara", create=True)
    def test_loads_yar_files(
        self, mock_yara: MagicMock, tmp_path: Path,
    ) -> None:
        """load_rules compiles .yar files and returns count."""
        (tmp_path / "rule1.yar").write_text(
            "rule dummy { condition: true }"
        )
        (tmp_path / "rule2.yar").write_text(
            "rule dummy2 { condition: true }"
        )
        mock_yara.compile.return_value = MagicMock()

        scanner = YaraScanner(rules_dir=tmp_path)
        count = scanner.load_rules()

        assert count == 2
        assert scanner.rule_count == 2
        assert scanner._compiled_rules is not None
        mock_yara.compile.assert_called_once()

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    @patch("aegis.detection.yara_scanner.yara", create=True)
    def test_loads_yara_files(
        self, mock_yara: MagicMock, tmp_path: Path,
    ) -> None:
        """load_rules compiles .yara files as well."""
        (tmp_path / "rule1.yara").write_text(
            "rule dummy { condition: true }"
        )
        mock_yara.compile.return_value = MagicMock()

        scanner = YaraScanner(rules_dir=tmp_path)
        count = scanner.load_rules()

        assert count == 1

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    @patch("aegis.detection.yara_scanner.yara", create=True)
    def test_loads_mixed_extensions(
        self, mock_yara: MagicMock, tmp_path: Path,
    ) -> None:
        """load_rules handles a mix of .yar and .yara files."""
        (tmp_path / "alpha.yar").write_text(
            "rule a { condition: true }"
        )
        (tmp_path / "beta.yara").write_text(
            "rule b { condition: true }"
        )
        (tmp_path / "ignore.txt").write_text("not a rule file")
        mock_yara.compile.return_value = MagicMock()

        scanner = YaraScanner(rules_dir=tmp_path)
        count = scanner.load_rules()

        assert count == 2

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    @patch("aegis.detection.yara_scanner.yara", create=True)
    def test_compile_failure_resets_state(
        self, mock_yara: MagicMock, tmp_path: Path,
    ) -> None:
        """Compilation failure sets _compiled_rules to None
        and count to 0."""
        (tmp_path / "bad.yar").write_text("invalid rule")
        mock_yara.compile.side_effect = Exception("compile error")

        scanner = YaraScanner(rules_dir=tmp_path)
        count = scanner.load_rules()

        assert count == 0
        assert scanner._compiled_rules is None
        assert scanner.rule_count == 0

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    @patch("aegis.detection.yara_scanner.yara", create=True)
    def test_passes_filepaths_dict_to_compile(
        self, mock_yara: MagicMock, tmp_path: Path,
    ) -> None:
        """load_rules passes {stem: path} dict to yara.compile."""
        rule_file = tmp_path / "detect_trojan.yar"
        rule_file.write_text("rule trojan { condition: true }")
        mock_yara.compile.return_value = MagicMock()

        scanner = YaraScanner(rules_dir=tmp_path)
        scanner.load_rules()

        call_kwargs = mock_yara.compile.call_args
        filepaths = call_kwargs.kwargs.get(
            "filepaths", call_kwargs[1].get("filepaths", {}),
        )
        assert "detect_trojan" in filepaths
        assert filepaths["detect_trojan"] == str(rule_file)


# ---------------------------------------------------------------------------
# scan_file
# ---------------------------------------------------------------------------


class TestYaraScanFile:
    """scan_file method."""

    def test_returns_empty_when_not_available(
        self, tmp_path: Path,
    ) -> None:
        """scan_file returns [] when scanner is not available."""
        scanner = YaraScanner(rules_dir=tmp_path)
        target = tmp_path / "test.exe"
        target.write_bytes(b"MZ\x00")
        result = scanner.scan_file(target)
        assert result == []

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_returns_empty_for_nonexistent_file(
        self, tmp_path: Path,
    ) -> None:
        """scan_file returns [] for a file that doesn't exist."""
        scanner = YaraScanner(rules_dir=tmp_path)
        scanner._compiled_rules = MagicMock()
        result = scanner.scan_file(tmp_path / "missing.exe")
        assert result == []

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_returns_empty_for_oversized_file(
        self, tmp_path: Path,
    ) -> None:
        """scan_file returns [] when file exceeds max_file_size."""
        scanner = YaraScanner(
            rules_dir=tmp_path, max_file_size=10,
        )
        scanner._compiled_rules = MagicMock()
        target = tmp_path / "large.bin"
        target.write_bytes(b"X" * 100)
        result = scanner.scan_file(target)
        assert result == []

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_returns_empty_when_no_matches(
        self, tmp_path: Path,
    ) -> None:
        """scan_file returns [] when rules match nothing."""
        scanner = YaraScanner(rules_dir=tmp_path)
        mock_rules = MagicMock()
        mock_rules.match.return_value = []
        scanner._compiled_rules = mock_rules

        target = tmp_path / "clean.txt"
        target.write_text("hello world")
        result = scanner.scan_file(target)
        assert result == []

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_returns_matches(self, tmp_path: Path) -> None:
        """scan_file returns YaraMatch objects for each raw match."""
        mock_match = MagicMock()
        mock_match.rule = "EvilTrojan"
        mock_match.tags = ["trojan", "malware"]
        mock_match.meta = {"author": "tester"}
        mock_string = MagicMock()
        mock_string.identifier = "$evil_string"
        mock_match.strings = [mock_string]

        mock_rules = MagicMock()
        mock_rules.match.return_value = [mock_match]

        scanner = YaraScanner(rules_dir=tmp_path)
        scanner._compiled_rules = mock_rules

        target = tmp_path / "malware.bin"
        target.write_bytes(b"\x00" * 50)
        result = scanner.scan_file(target)

        assert len(result) == 1
        assert isinstance(result[0], YaraMatch)
        assert result[0].rule_name == "EvilTrojan"
        assert result[0].tags == ["trojan", "malware"]
        assert result[0].meta == {"author": "tester"}
        assert "$evil_string" in result[0].strings_matched
        assert result[0].file_path == str(target)

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_multiple_matches(self, tmp_path: Path) -> None:
        """scan_file handles multiple rule matches."""
        match1 = MagicMock()
        match1.rule = "Rule1"
        match1.tags = []
        match1.meta = {}
        match1.strings = []

        match2 = MagicMock()
        match2.rule = "Rule2"
        match2.tags = ["apt"]
        match2.meta = {"severity": "high"}
        match2.strings = []

        mock_rules = MagicMock()
        mock_rules.match.return_value = [match1, match2]

        scanner = YaraScanner(rules_dir=tmp_path)
        scanner._compiled_rules = mock_rules

        target = tmp_path / "suspect.bin"
        target.write_bytes(b"\xDE\xAD")
        result = scanner.scan_file(target)

        assert len(result) == 2
        assert result[0].rule_name == "Rule1"
        assert result[1].rule_name == "Rule2"

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_handles_scan_exception_gracefully(
        self, tmp_path: Path,
    ) -> None:
        """scan_file returns [] when match() raises an exception."""
        mock_rules = MagicMock()
        mock_rules.match.side_effect = RuntimeError("timeout")

        scanner = YaraScanner(rules_dir=tmp_path)
        scanner._compiled_rules = mock_rules

        target = tmp_path / "problem.bin"
        target.write_bytes(b"data")
        result = scanner.scan_file(target)

        assert result == []

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_passes_timeout_to_match(self, tmp_path: Path) -> None:
        """scan_file passes scan_timeout to rules.match()."""
        mock_rules = MagicMock()
        mock_rules.match.return_value = []

        scanner = YaraScanner(rules_dir=tmp_path, scan_timeout=15)
        scanner._compiled_rules = mock_rules

        target = tmp_path / "file.bin"
        target.write_bytes(b"content")
        scanner.scan_file(target)

        mock_rules.match.assert_called_once_with(
            str(target), timeout=15,
        )

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_accepts_string_path(self, tmp_path: Path) -> None:
        """scan_file accepts a string file path."""
        mock_rules = MagicMock()
        mock_rules.match.return_value = []

        scanner = YaraScanner(rules_dir=tmp_path)
        scanner._compiled_rules = mock_rules

        target = tmp_path / "file.txt"
        target.write_text("hello")
        result = scanner.scan_file(str(target))

        assert result == []
        mock_rules.match.assert_called_once()

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_file_at_max_size_is_scanned(
        self, tmp_path: Path,
    ) -> None:
        """A file exactly at max_file_size is still scanned."""
        mock_rules = MagicMock()
        mock_rules.match.return_value = []

        scanner = YaraScanner(rules_dir=tmp_path, max_file_size=10)
        scanner._compiled_rules = mock_rules

        target = tmp_path / "exact.bin"
        target.write_bytes(b"X" * 10)
        result = scanner.scan_file(target)

        assert result == []
        mock_rules.match.assert_called_once()


# ---------------------------------------------------------------------------
# scan_bytes
# ---------------------------------------------------------------------------


class TestYaraScanBytes:
    """scan_bytes method."""

    def test_returns_empty_when_not_available(self) -> None:
        """scan_bytes returns [] when scanner is not available."""
        scanner = YaraScanner()
        result = scanner.scan_bytes(b"data", "test")
        assert result == []

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_returns_empty_for_empty_data(self) -> None:
        """scan_bytes returns [] for empty bytes."""
        scanner = YaraScanner()
        scanner._compiled_rules = MagicMock()
        result = scanner.scan_bytes(b"", "test")
        assert result == []

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_returns_empty_when_no_matches(self) -> None:
        """scan_bytes returns [] when rules match nothing."""
        mock_rules = MagicMock()
        mock_rules.match.return_value = []
        scanner = YaraScanner()
        scanner._compiled_rules = mock_rules
        result = scanner.scan_bytes(b"clean data", "buffer")
        assert result == []

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_returns_matches(self) -> None:
        """scan_bytes returns YaraMatch list for matched rules."""
        mock_match = MagicMock()
        mock_match.rule = "Shellcode"
        mock_match.tags = ["exploit"]
        mock_match.meta = {"description": "shellcode pattern"}
        mock_string = MagicMock()
        mock_string.identifier = "$nop_sled"
        mock_match.strings = [mock_string]

        mock_rules = MagicMock()
        mock_rules.match.return_value = [mock_match]

        scanner = YaraScanner()
        scanner._compiled_rules = mock_rules

        result = scanner.scan_bytes(
            b"\x90" * 100, "memory_dump",
        )

        assert len(result) == 1
        assert result[0].rule_name == "Shellcode"
        assert result[0].tags == ["exploit"]
        assert result[0].file_path == "memory_dump"

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_handles_exception_gracefully(self) -> None:
        """scan_bytes returns [] when match() raises."""
        mock_rules = MagicMock()
        mock_rules.match.side_effect = Exception("yara error")

        scanner = YaraScanner()
        scanner._compiled_rules = mock_rules

        result = scanner.scan_bytes(b"data", "ident")
        assert result == []

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_passes_timeout_to_match(self) -> None:
        """scan_bytes passes scan_timeout to rules.match()."""
        mock_rules = MagicMock()
        mock_rules.match.return_value = []

        scanner = YaraScanner(scan_timeout=5)
        scanner._compiled_rules = mock_rules

        scanner.scan_bytes(b"payload", "test_id")

        mock_rules.match.assert_called_once_with(
            data=b"payload", timeout=5,
        )

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_identifier_stored_as_file_path(self) -> None:
        """The identifier argument becomes file_path in YaraMatch."""
        mock_match = MagicMock()
        mock_match.rule = "TestRule"
        mock_match.tags = []
        mock_match.meta = {}
        mock_match.strings = []

        mock_rules = MagicMock()
        mock_rules.match.return_value = [mock_match]

        scanner = YaraScanner()
        scanner._compiled_rules = mock_rules

        result = scanner.scan_bytes(b"data", "my_identifier")
        assert result[0].file_path == "my_identifier"

    @patch("aegis.detection.yara_scanner._HAS_YARA", True)
    def test_default_identifier_is_empty(self) -> None:
        """scan_bytes uses empty string as default identifier."""
        mock_match = MagicMock()
        mock_match.rule = "R"
        mock_match.tags = []
        mock_match.meta = {}
        mock_match.strings = []

        mock_rules = MagicMock()
        mock_rules.match.return_value = [mock_match]

        scanner = YaraScanner()
        scanner._compiled_rules = mock_rules

        result = scanner.scan_bytes(b"data")
        assert result[0].file_path == ""


# ---------------------------------------------------------------------------
# _convert_match
# ---------------------------------------------------------------------------


class TestConvertMatch:
    """YaraScanner._convert_match static method."""

    def test_basic_conversion(self) -> None:
        """Converts a yara match object to YaraMatch dataclass."""
        mock = MagicMock()
        mock.rule = "Ransomware"
        mock.tags = ["ransom", "crypto"]
        mock.meta = {"author": "analyst", "score": 90}
        mock.strings = []

        result = YaraScanner._convert_match(mock, "/tmp/file.exe")

        assert isinstance(result, YaraMatch)
        assert result.rule_name == "Ransomware"
        assert result.tags == ["ransom", "crypto"]
        assert result.meta == {"author": "analyst", "score": 90}
        assert result.file_path == "/tmp/file.exe"
        assert result.strings_matched == []

    def test_strings_with_identifier_attribute(self) -> None:
        """Extracts string identifiers when .identifier exists."""
        s1 = MagicMock()
        s1.identifier = "$magic_bytes"
        s2 = MagicMock()
        s2.identifier = "$pe_header"

        mock = MagicMock()
        mock.rule = "PE_Detect"
        mock.tags = []
        mock.meta = {}
        mock.strings = [s1, s2]

        result = YaraScanner._convert_match(mock, "scan")
        assert result.strings_matched == [
            "$magic_bytes", "$pe_header",
        ]

    def test_strings_without_identifier_attribute(self) -> None:
        """Falls back to str() when string has no .identifier."""

        class FakeString:
            """A string match object without an identifier attr."""

            def __str__(self) -> str:
                return "(0, '$s1', b'\\x00')"

        mock = MagicMock()
        mock.rule = "Fallback"
        mock.tags = []
        mock.meta = {}
        mock.strings = [FakeString()]

        result = YaraScanner._convert_match(mock, "test")
        assert len(result.strings_matched) == 1
        assert "(0, '$s1', b'\\x00')" in result.strings_matched[0]

    def test_empty_tags_becomes_empty_list(self) -> None:
        """Empty/falsy tags results in an empty list."""
        mock = MagicMock()
        mock.rule = "R"
        mock.tags = []
        mock.meta = {}
        mock.strings = []

        result = YaraScanner._convert_match(mock, "")
        assert result.tags == []

    def test_none_tags_becomes_empty_list(self) -> None:
        """None tags results in an empty list."""
        mock = MagicMock()
        mock.rule = "R"
        mock.tags = None
        mock.meta = {}
        mock.strings = []

        result = YaraScanner._convert_match(mock, "")
        assert result.tags == []

    def test_none_meta_becomes_empty_dict(self) -> None:
        """None meta results in an empty dict."""
        mock = MagicMock()
        mock.rule = "R"
        mock.tags = []
        mock.meta = None
        mock.strings = []

        result = YaraScanner._convert_match(mock, "")
        assert result.meta == {}

    def test_source_stored_as_file_path(self) -> None:
        """The source argument is stored as file_path."""
        mock = MagicMock()
        mock.rule = "R"
        mock.tags = []
        mock.meta = {}
        mock.strings = []

        result = YaraScanner._convert_match(
            mock, "C:\\Users\\scan\\target.exe",
        )
        assert result.file_path == "C:\\Users\\scan\\target.exe"

    def test_no_strings_attribute(self) -> None:
        """Handles match objects that lack a 'strings' attribute."""
        mock = MagicMock(spec=[])
        mock.rule = "NoStrings"
        mock.tags = ["test"]
        mock.meta = {}
        # spec=[] means no attributes, but we set rule/tags/meta

        result = YaraScanner._convert_match(mock, "test")
        assert result.strings_matched == []
