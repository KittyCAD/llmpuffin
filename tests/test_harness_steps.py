"""Tests for harness_steps helpers."""

from llmpuffin.harness_steps import _inject_token


class TestInjectToken:
    def test_https_url(self):
        url = "https://github.com/org/repo.git"
        result = _inject_token(url, "ghp_abc123")
        assert result == "https://x-access-token:ghp_abc123@github.com/org/repo.git"

    def test_non_https_unchanged(self):
        url = "git@github.com:org/repo.git"
        result = _inject_token(url, "ghp_abc123")
        assert result == url

    def test_ssh_unchanged(self):
        url = "ssh://git@github.com/org/repo.git"
        result = _inject_token(url, "ghp_abc123")
        assert result == url

    def test_token_with_special_chars(self):
        url = "https://github.com/org/repo.git"
        token = "ghs_abc+def/123"
        result = _inject_token(url, token)
        assert f"x-access-token:{token}@" in result

    def test_only_first_https_replaced(self):
        url = "https://github.com/org/repo.git"
        result = _inject_token(url, "tok")
        assert result.count("x-access-token") == 1
