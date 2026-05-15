"""Tests for location_link template tag and github_file_url."""

from django.utils.safestring import mark_safe

from llmpuffin_web.templatetags.finding_links import location_link


class FakeLocation:
    def __init__(self, file_path: str, start_line: int):
        self.file_path = file_path
        self.start_line = start_line


class FakeAuditRun:
    def __init__(self, github_repo_url="", git_commit=""):
        self.github_repo_url = github_repo_url
        self.git_commit = git_commit

    def github_file_url(
        self, file_path: str, line: int | None = None, end_line: int | None = None
    ) -> str | None:
        base = self.github_repo_url.rstrip("/")
        if not base:
            return None
        ref = self.git_commit or "main"
        clean_path = file_path.lstrip("/")
        if clean_path.startswith("src/"):
            clean_path = clean_path[4:]
        url = f"{base}/blob/{ref}/{clean_path}"
        if line and end_line:
            url += f"#L{line}-L{end_line}"
        elif line:
            url += f"#L{line}"
        return url


# -- github_file_url tests --


def test_github_url_strips_src_prefix():
    run = FakeAuditRun("https://github.com/org/repo", "abc123")
    assert run.github_file_url("src/main.py", 10) == (
        "https://github.com/org/repo/blob/abc123/main.py#L10"
    )


def test_github_url_strips_slash_src_prefix():
    run = FakeAuditRun("https://github.com/org/repo", "abc123")
    assert run.github_file_url("/src/main.py", 10) == (
        "https://github.com/org/repo/blob/abc123/main.py#L10"
    )


def test_github_url_no_line():
    run = FakeAuditRun("https://github.com/org/repo", "abc123")
    assert run.github_file_url("src/lib/foo.ts") == (
        "https://github.com/org/repo/blob/abc123/lib/foo.ts"
    )


def test_github_url_no_commit_uses_main():
    run = FakeAuditRun("https://github.com/org/repo", "")
    assert run.github_file_url("src/app.py", 1) == (
        "https://github.com/org/repo/blob/main/app.py#L1"
    )


def test_github_url_non_src_path():
    run = FakeAuditRun("https://github.com/org/repo", "abc123")
    assert run.github_file_url("lib/utils.py", 5) == (
        "https://github.com/org/repo/blob/abc123/lib/utils.py#L5"
    )


def test_github_url_empty_repo():
    run = FakeAuditRun("", "abc123")
    assert run.github_file_url("src/main.py") is None


def test_github_url_line_range():
    run = FakeAuditRun("https://github.com/org/repo", "abc123")
    assert run.github_file_url("src/main.py", 1, 5) == (
        "https://github.com/org/repo/blob/abc123/main.py#L1-L5"
    )


# -- location_link tests --


def test_location_link_with_github():
    run = FakeAuditRun("https://github.com/org/repo", "abc123")
    loc = FakeLocation("src/main.py", 42)
    result = location_link(loc, run)
    assert "https://github.com/org/repo/blob/abc123/main.py#L42" in result
    assert "src/main.py:42</a>" in result


def test_location_link_no_repo():
    loc = FakeLocation("src/main.py", 42)
    result = location_link(loc, None)
    assert result == "src/main.py:42"
    assert "<a" not in result


def test_location_link_empty_repo():
    run = FakeAuditRun("", "abc123")
    loc = FakeLocation("src/main.py", 10)
    result = location_link(loc, run)
    assert result == "src/main.py:10"
    assert "<a" not in result
