"""Tests for harness_steps helpers."""

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock

from llmpuffin.agent.steps import (
    _GIT_CREDENTIALS_PATH,
    _resolve_repo_name,
    _setup_git_credentials,
    _teardown_git_credentials,
)


def _mock_execution():
    execution = MagicMock()
    result = MagicMock()
    result.ok = True
    result.stderr = ""
    execution.exec = AsyncMock(return_value=result)
    return execution


class TestResolveRepoName:
    def test_explicit_name(self):
        assert _resolve_repo_name("my-repo", "https://github.com/org/other.git") == "my-repo"

    def test_from_url(self):
        assert _resolve_repo_name(None, "https://github.com/org/repo.git") == "repo"

    def test_from_url_no_suffix(self):
        assert _resolve_repo_name(None, "https://github.com/org/repo") == "repo"

    def test_from_url_trailing_slash(self):
        assert _resolve_repo_name(None, "https://github.com/org/repo/") == "repo"


class TestGitCredentials:
    def test_setup_writes_file_and_includes(self):
        execution = _mock_execution()
        asyncio.run(_setup_git_credentials(execution, "ghp_abc123"))
        assert execution.exec.call_count == 5

        # First call: write credentials file
        write_cmd = execution.exec.call_args_list[0][0][0]
        assert write_cmd[:2] == ["git", "config"]
        assert "--file" in write_cmd
        assert _GIT_CREDENTIALS_PATH in write_cmd
        assert "http.https://github.com/.extraheader" in write_cmd
        header = write_cmd[-1]
        assert header.startswith("AUTHORIZATION: basic ")
        decoded = base64.b64decode(header.split(" ", 2)[2]).decode()
        assert decoded == "x-access-token:ghp_abc123"

        # Second call: set include.path
        include_cmd = execution.exec.call_args_list[1][0][0]
        assert include_cmd == [
            "git", "config", "--global", "include.path", _GIT_CREDENTIALS_PATH,
        ]

    def test_teardown_removes_file_and_include(self):
        execution = _mock_execution()
        asyncio.run(_teardown_git_credentials(execution))
        assert execution.exec.call_count == 4
        rm_cmd = execution.exec.call_args_list[0][0][0]
        assert rm_cmd == ["rm", "-f", _GIT_CREDENTIALS_PATH]
        unset_cmd = execution.exec.call_args_list[1][0][0]
        assert unset_cmd == [
            "git", "config", "--global", "--unset-all", "include.path",
        ]
