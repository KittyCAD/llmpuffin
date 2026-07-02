"""Tests for ContainerBackend — execute, edit, write, read, ls.

Uses the same local _run pattern as test_grep.py: commands execute on the
host in a temp directory instead of inside a container.
"""

from __future__ import annotations

import asyncio
import subprocess
from unittest.mock import MagicMock

import pytest

from llmpuffin.backend import ContainerBackend


def _make_backend(cwd: str, max_output_bytes: int = 100_000) -> ContainerBackend:
    execution = MagicMock()
    backend = ContainerBackend(execution, max_output_bytes=max_output_bytes)

    async def _local_run(cmd: list[str], timeout: int | None = None):
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        return result.returncode, result.stdout, result.stderr

    backend._run = _local_run
    return backend


def _run_sync(coro):
    """Run an async function synchronously for tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture
def backend(tmp_path):
    return _make_backend(str(tmp_path))


# -- execute --


class TestExecute:
    def test_captures_stdout(self, backend):
        resp = backend.execute("echo hello")
        assert "hello" in resp.output
        assert resp.exit_code == 0

    def test_captures_stderr(self, backend):
        resp = backend.execute("echo err >&2")
        assert "[stderr] err" in resp.output

    def test_nonzero_exit_code(self, backend):
        resp = backend.execute("exit 42")
        assert resp.exit_code == 42
        assert "Exit code: 42" in resp.output

    def test_truncation(self, tmp_path):
        backend = _make_backend(str(tmp_path), max_output_bytes=50)
        resp = backend.execute("python3 -c \"print('x' * 200)\"")
        assert resp.truncated is True
        assert "truncated" in resp.output.lower()

    def test_no_output(self, backend):
        resp = backend.execute("true")
        assert resp.output == "<no output>"
        assert resp.exit_code == 0


# -- read --


class TestRead:
    def test_read_file(self, tmp_path, backend):
        f = tmp_path / "test.txt"
        f.write_text("line1\nline2\nline3\nline4\nline5\n")
        result = backend.read(str(f))
        assert "line1" in result.file_data["content"]
        assert result.error is None

    def test_read_with_offset(self, tmp_path, backend):
        f = tmp_path / "test.txt"
        f.write_text("line1\nline2\nline3\nline4\nline5\n")
        result = backend.read(str(f), offset=2, limit=2)
        content = result.file_data["content"]
        assert "line3" in content
        assert "line4" in content
        assert "line1" not in content

    def test_read_missing_file(self, backend):
        result = backend.read("/nonexistent/file.txt")
        assert result.error is not None


# -- write --


class TestWrite:
    def test_write_new_file(self, tmp_path, backend):
        target = str(tmp_path / "new.txt")
        result = backend.write(target, "hello world")
        assert result.error is None
        assert result.path == target
        assert (tmp_path / "new.txt").read_text() == "hello world"

    def test_write_existing_file_errors(self, tmp_path, backend):
        existing = tmp_path / "exists.txt"
        existing.write_text("old")
        result = backend.write(str(existing), "new")
        assert result.error is not None
        assert "already exists" in result.error

    def test_write_creates_parent_dirs(self, tmp_path, backend):
        target = str(tmp_path / "a" / "b" / "file.txt")
        result = backend.write(target, "nested")
        assert result.error is None
        assert result.path == target


# -- edit --


class TestEdit:
    def test_single_replacement(self, tmp_path, backend):
        f = tmp_path / "edit.txt"
        f.write_text("hello world")
        result = backend.edit(str(f), "world", "there")
        assert result.error is None
        assert f.read_text() == "hello there"

    def test_replace_all(self, tmp_path, backend):
        f = tmp_path / "edit.txt"
        f.write_text("aaa bbb aaa")
        result = backend.edit(str(f), "aaa", "ccc", replace_all=True)
        assert result.error is None
        assert result.occurrences == 2
        assert f.read_text() == "ccc bbb ccc"

    def test_multiple_without_replace_all_errors(self, tmp_path, backend):
        f = tmp_path / "edit.txt"
        f.write_text("aaa bbb aaa")
        result = backend.edit(str(f), "aaa", "ccc")
        assert result.error is not None
        assert "2 times" in result.error

    def test_string_not_found(self, tmp_path, backend):
        f = tmp_path / "edit.txt"
        f.write_text("hello world")
        result = backend.edit(str(f), "zzz", "yyy")
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_file_not_found(self, backend):
        result = backend.edit("/nonexistent/file.txt", "a", "b")
        assert result.error is not None


# -- ls --


class TestLs:
    def test_lists_files(self, tmp_path, backend):
        (tmp_path / "a.txt").write_text("a")
        (tmp_path / "b.txt").write_text("b")
        result = backend.ls(str(tmp_path))
        assert result.error is None
        paths = [e["path"] for e in result.entries]
        assert any("a.txt" in p for p in paths)
        assert any("b.txt" in p for p in paths)

    def test_identifies_directory(self, tmp_path, backend):
        (tmp_path / "subdir").mkdir()
        (tmp_path / "file.txt").write_text("x")
        result = backend.ls(str(tmp_path))
        entries_by_name = {e["path"]: e for e in result.entries}
        dir_entries = [e for e in result.entries if "subdir" in e["path"]]
        file_entries = [e for e in result.entries if "file.txt" in e["path"]]
        assert len(dir_entries) == 1
        assert dir_entries[0]["is_dir"] is True
        assert len(file_entries) == 1
        assert file_entries[0]["is_dir"] is False
