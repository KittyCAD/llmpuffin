"""Tests for ContainerBackend.grep pattern handling."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from llmpuffin.backend import ContainerBackend

FIXTURES = Path(__file__).parent / "fixtures"


def _make_backend(cwd: str) -> ContainerBackend:
    """Create a ContainerBackend whose _run shells out to the host for testing."""
    execution = MagicMock()
    backend = ContainerBackend(execution)

    # Patch _run to execute commands locally in `cwd` instead of inside a container.
    async def _local_run(cmd: list[str], timeout: int | None = None):
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        return result.returncode, result.stdout, result.stderr

    backend._run = _local_run
    return backend


@pytest.fixture
def backend(tmp_path):
    """Backend with the sample.js fixture copied to a temp dir."""
    import shutil

    shutil.copy(FIXTURES / "sample.js", tmp_path / "sample.js")
    return _make_backend(str(tmp_path))


class TestGrep:
    def test_dot_document_is_regex(self, backend):
        """grep treats `.` as regex — `.document` also matches `xdocument`."""
        result = backend.grep(".document", ".")
        texts = [m["text"].strip() for m in result.matches]

        # The unescaped dot matches any char before "document",
        # so `xdocument` should appear in results.
        assert any("xdocument" in t for t in texts), (
            f"Regex dot should match 'xdocument': {texts}"
        )

    def test_escaped_dot_document(self, backend):
        r"""Escaped `\.document` only matches literal dot + document."""
        result = backend.grep(r"\.document", ".")
        texts = [m["text"].strip() for m in result.matches]

        assert any(".document" in t for t in texts)
        assert not any("xdocument" in t for t in texts), (
            f"Escaped dot should NOT match 'xdocument': {texts}"
        )
        assert not any(t.startswith("let documentName") for t in texts)

    def test_line_numbers(self, backend):
        r"""Verify `\.document` returns the correct line numbers."""
        result = backend.grep(r"\.document", ".")
        lines = {m["line"] for m in result.matches}
        # sample.js lines: 5 (window.document.title), 11 (this.document.createElement)
        assert {5, 11} <= lines
        # Line 2 has `document.getElementById` — dot is after document, not before it
        assert 2 not in lines

    def test_no_match(self, backend):
        """Pattern with zero hits returns empty matches, no error."""
        result = backend.grep("ZZZZZ_NO_MATCH_ZZZZZ", ".")
        assert result.matches == []
        assert result.error is None

    def test_glob_filter(self, backend):
        """Glob filter restricts search to matching filenames."""
        result_js = backend.grep(r"\.document", ".", glob="*.js")
        assert len(result_js.matches) > 0

        result_py = backend.grep(r"\.document", ".", glob="*.py")
        assert len(result_py.matches) == 0

    def test_grep_single_file_with_document_dot(self, backend):
        """Grep for `document.` in a single file using glob."""
        result = backend.grep(r"document\.", ".", glob="sample.js")
        texts = [m["text"].strip() for m in result.matches]

        # Should match lines where `document.` appears (property access)
        assert any("document.getElementById" in t for t in texts)
        assert any("document.title" in t for t in texts)
        assert any("document.createElement" in t for t in texts)

        # Should NOT match `documentName` (no dot after document)
        assert not any("documentName" in t for t in texts), (
            f"Should not match 'documentName': {texts}"
        )

    def test_pattern_starting_with_dash(self, backend):
        """Patterns starting with '-' (e.g. '->foo') must not be parsed as grep options."""
        result = backend.grep("->getElementById", ".")
        # Should not error — grep should treat it as a literal pattern
        assert result.error is None or "invalid option" not in (result.error or "")
        # The fixture has no '->' patterns so matches will be empty, but no crash
        assert result.matches is not None

    def test_glob_without_wildcard_hints_on_no_match(self, backend):
        """When glob has no wildcard and yields no results, return a hint."""
        result = backend.grep("document", glob="/src/viewer/main.ts")
        assert result.error is not None
        assert "filename pattern" in result.error
        assert "path parameter" in result.error

    def test_grep_single_file_path(self, tmp_path):
        """Grep with path pointing to a single file returns matches with filename."""
        target = tmp_path / "app.js"
        target.write_text("const x = document.body;\nlet y = 42;\n")
        backend = _make_backend(str(tmp_path))
        result = backend.grep("document", path=str(target))
        assert len(result.matches) == 1
        assert "document" in result.matches[0]["text"]
        assert result.matches[0]["line"] == 1
        # -H flag ensures filename is present even for single file
        assert result.matches[0]["path"] == str(target)
