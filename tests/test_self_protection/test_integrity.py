"""Tests for the IntegrityChecker self-protection module."""

from __future__ import annotations

import hashlib
from pathlib import Path

from aegis.self_protection.integrity import IntegrityChecker

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _make_source_tree(base: Path, files: dict[str, str]) -> Path:
    """Create a minimal ``src/aegis/`` tree under *base*.

    *files* maps relative paths (e.g. ``"core/engine.py"``) to file
    content.  Returns the *base* directory (the "aegis_root").
    """
    src_aegis = base / "src" / "aegis"
    for rel, content in files.items():
        fpath = src_aegis / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
    return base


def _sha256_str(text: str) -> str:
    """Return the SHA-256 hex-digest of a UTF-8 encoded string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ #
# compute_file_hashes
# ------------------------------------------------------------------ #

class TestComputeFileHashes:
    """Tests for IntegrityChecker.compute_file_hashes."""

    def test_returns_dict_with_string_keys_and_hex_values(
        self, tmp_path: Path
    ) -> None:
        root = _make_source_tree(tmp_path, {"__init__.py": ""})
        checker = IntegrityChecker(root)
        result = checker.compute_file_hashes()

        assert isinstance(result, dict)
        for key, val in result.items():
            assert isinstance(key, str)
            assert isinstance(val, str)
            # SHA-256 hex-digest is 64 hex chars
            assert len(val) == 64
            int(val, 16)  # must be valid hex

    def test_consistent_results_on_repeated_calls(
        self, tmp_path: Path
    ) -> None:
        root = _make_source_tree(
            tmp_path,
            {
                "__init__.py": "",
                "core/__init__.py": "",
                "core/engine.py": "print('hello')\n",
            },
        )
        checker = IntegrityChecker(root)
        first = checker.compute_file_hashes()
        second = checker.compute_file_hashes()
        assert first == second

    def test_includes_all_py_files(self, tmp_path: Path) -> None:
        files = {
            "__init__.py": "",
            "a.py": "a = 1\n",
            "sub/b.py": "b = 2\n",
        }
        root = _make_source_tree(tmp_path, files)
        checker = IntegrityChecker(root)
        result = checker.compute_file_hashes()
        assert len(result) == 3

    def test_empty_directory_returns_empty_dict(
        self, tmp_path: Path
    ) -> None:
        # src/aegis/ exists but has no .py files
        (tmp_path / "src" / "aegis").mkdir(parents=True)
        checker = IntegrityChecker(tmp_path)
        assert checker.compute_file_hashes() == {}

    def test_missing_src_dir_returns_empty_dict(
        self, tmp_path: Path
    ) -> None:
        checker = IntegrityChecker(tmp_path)
        assert checker.compute_file_hashes() == {}


# ------------------------------------------------------------------ #
# verify_file_hashes
# ------------------------------------------------------------------ #

class TestVerifyFileHashes:
    """Tests for IntegrityChecker.verify_file_hashes."""

    def test_returns_empty_when_hashes_match(
        self, tmp_path: Path
    ) -> None:
        root = _make_source_tree(
            tmp_path,
            {"__init__.py": "", "mod.py": "x = 1\n"},
        )
        checker = IntegrityChecker(root)
        known = checker.compute_file_hashes()
        assert checker.verify_file_hashes(known) == []

    def test_detects_modified_file(self, tmp_path: Path) -> None:
        root = _make_source_tree(
            tmp_path, {"__init__.py": "", "mod.py": "x = 1\n"}
        )
        checker = IntegrityChecker(root)
        known = checker.compute_file_hashes()

        # Tamper with the known hash for mod.py
        key = [k for k in known if k.endswith("mod.py")][0]
        known[key] = "0" * 64  # bogus hash

        mismatches = checker.verify_file_hashes(known)
        assert key in mismatches

    def test_detects_missing_file(self, tmp_path: Path) -> None:
        root = _make_source_tree(
            tmp_path, {"__init__.py": ""}
        )
        checker = IntegrityChecker(root)
        known = checker.compute_file_hashes()

        # Pretend we expect a file that does not exist on disk
        known["src/aegis/phantom.py"] = "a" * 64
        mismatches = checker.verify_file_hashes(known)
        assert "src/aegis/phantom.py" in mismatches


# ------------------------------------------------------------------ #
# verify_config_integrity
# ------------------------------------------------------------------ #

class TestVerifyConfigIntegrity:
    """Tests for IntegrityChecker.verify_config_integrity."""

    def test_matching_hash_returns_true(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.toml"
        content_bytes = b"[aegis]\nmode = 'active'\n"
        cfg.write_bytes(content_bytes)

        checker = IntegrityChecker(tmp_path)
        expected = hashlib.sha256(content_bytes).hexdigest()
        assert checker.verify_config_integrity(cfg, expected) is True

    def test_mismatching_hash_returns_false(
        self, tmp_path: Path
    ) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_text("key = 'value'\n", encoding="utf-8")

        checker = IntegrityChecker(tmp_path)
        assert checker.verify_config_integrity(cfg, "0" * 64) is False

    def test_missing_file_returns_false(self, tmp_path: Path) -> None:
        checker = IntegrityChecker(tmp_path)
        missing = tmp_path / "does_not_exist.toml"
        assert checker.verify_config_integrity(missing, "0" * 64) is False


# ------------------------------------------------------------------ #
# check_debugger_attached
# ------------------------------------------------------------------ #

class TestCheckDebuggerAttached:
    """Tests for IntegrityChecker.check_debugger_attached."""

    def test_returns_bool(self) -> None:
        result = IntegrityChecker.check_debugger_attached()
        assert isinstance(result, bool)

    def test_callable_without_instance(self) -> None:
        # Ensure it works as a static method
        assert IntegrityChecker.check_debugger_attached() is not None
