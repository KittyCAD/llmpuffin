"""Tests for model logic — GitInfo.github_url() and AuditRun.status."""

from __future__ import annotations

from unittest.mock import MagicMock

from llmpuffin.models import AuditRun, GitInfo


class TestGitInfoGithubUrl:
    def test_valid_https_github(self):
        gi = GitInfo(origin_remote="https://github.com/org/repo.git", head="abc1234def")
        url = gi.github_url("src/main.py", line=42)
        assert url == "https://github.com/org/repo/blob/abc1234/src/main.py#L42"

    def test_strips_git_suffix(self):
        gi = GitInfo(origin_remote="https://github.com/org/repo.git", head="abc1234def")
        url = gi.github_url("file.py")
        assert "/repo/blob/" in url
        assert ".git" not in url

    def test_no_git_suffix(self):
        gi = GitInfo(origin_remote="https://github.com/org/repo", head="abc1234def")
        url = gi.github_url("file.py")
        assert url == "https://github.com/org/repo/blob/abc1234/file.py"

    def test_no_line_number(self):
        gi = GitInfo(origin_remote="https://github.com/org/repo", head="abc1234def")
        url = gi.github_url("file.py")
        assert "#L" not in url

    def test_line_zero_no_fragment(self):
        gi = GitInfo(origin_remote="https://github.com/org/repo", head="abc1234def")
        url = gi.github_url("file.py", line=0)
        assert "#L" not in url

    def test_missing_head_uses_main(self):
        gi = GitInfo(origin_remote="https://github.com/org/repo", head="")
        url = gi.github_url("file.py")
        assert "/blob/main/" in url

    def test_short_head(self):
        gi = GitInfo(origin_remote="https://github.com/org/repo", head="abc")
        url = gi.github_url("file.py")
        assert "/blob/abc/" in url

    def test_empty_remote_returns_none(self):
        gi = GitInfo(origin_remote="", head="abc1234def")
        assert gi.github_url("file.py") is None

    def test_non_github_remote_returns_none(self):
        gi = GitInfo(origin_remote="https://gitlab.com/org/repo", head="abc1234def")
        assert gi.github_url("file.py") is None

    def test_ssh_remote_returns_none(self):
        gi = GitInfo(origin_remote="git@github.com:org/repo.git", head="abc1234def")
        assert gi.github_url("file.py") is None

    def test_strips_leading_slash_from_path(self):
        gi = GitInfo(origin_remote="https://github.com/org/repo", head="abc1234def")
        url = gi.github_url("/src/main.py", line=10)
        assert "/blob/abc1234/src/main.py#L10" in url
        assert "//src" not in url


class TestAuditRunStatus:
    """Test AuditRun.status derivation logic.

    We mock the entire AuditRun and its threads property to avoid SQLAlchemy
    instrumentation, since there's no DB in these unit tests.
    """

    def _derive_status(self, statuses: list[str]) -> str:
        threads = []
        for s in statuses:
            t = MagicMock()
            t.status = s
            threads.append(t)
        run = MagicMock(spec=AuditRun)
        run.threads = threads
        # Call the real property implementation
        return AuditRun.status.fget(run)

    def test_no_threads_pending(self):
        assert self._derive_status([]) == "pending"

    def test_any_running(self):
        assert self._derive_status(["completed", "running"]) == "running"

    def test_all_completed(self):
        assert self._derive_status(["completed", "completed"]) == "completed"

    def test_error_without_running(self):
        assert self._derive_status(["completed", "error"]) == "error"

    def test_running_takes_precedence_over_error(self):
        assert self._derive_status(["error", "running"]) == "running"

    def test_recursion_limit(self):
        assert self._derive_status(["completed", "recursion_limit"]) == "recursion_limit"

    def test_error_takes_precedence_over_recursion_limit(self):
        assert self._derive_status(["recursion_limit", "error"]) == "error"
