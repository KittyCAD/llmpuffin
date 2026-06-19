"""
AuditEnvironment — containerized execution for security audits.

An AuditEnvironment wraps a container image that has the target codebase
baked in.  When started, it produces an AuditExecution — a running
container where the agent can execute tool calls (grep, read files,
run static analysis, etc.).

This is the **tool integration layer** of the harness:
the model never touches the host; all side effects happen inside the
container.  This provides both security isolation and reproducibility.

Two runtimes are supported:
  - podman: local Podman/Docker daemon via docker-py
  - nexecutor: remote nexecutor service via nexecutor-client
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

log = logging.getLogger("llmpuffin")


# ─── Shared data classes ───


@dataclass
class ExecResult:
    """Result of a command execution inside the container."""

    command: list[str]
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass
class GitInfo:
    """Git repository information extracted from a container."""

    repo_path: str
    repo_url: str
    commit: str


# ─── Protocol ───


@runtime_checkable
class AuditExecution(Protocol):
    """Protocol for a running container/workload where the agent executes tool calls."""

    @property
    def container_id(self) -> str:
        """Unique identifier for the running container/workload."""
        ...

    @property
    def code_dir(self) -> str:
        """Working directory inside the container."""
        ...

    def exec(self, command: list[str], timeout: int = 300) -> ExecResult:
        """Execute a command inside the container."""
        ...

    def capture_git_info(self) -> GitInfo:
        """Extract git remote URL and HEAD commit from the container."""
        ...

    def stop(self, timeout: int = 30, remove: bool = False) -> None:
        """Stop the container."""
        ...

    def __enter__(self) -> AuditExecution: ...
    def __exit__(self, exc_type, exc_val, exc_tb) -> None: ...


def _capture_git_info(execution: AuditExecution) -> GitInfo:
    """Shared implementation: extract git info by running commands."""
    from urllib.parse import urlparse

    remote_result = execution.exec(["git", "remote", "get-url", "origin"], timeout=5)
    if not remote_result.ok:
        raise RuntimeError(
            f"Failed to get git remote: {remote_result.stderr.strip()}"
        )
    git_remote = remote_result.stdout.strip()

    parsed = urlparse(git_remote)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise RuntimeError(
            f"Git remote must be a https://github.com URL, got: {git_remote}"
        )

    repo_path = parsed.path.removesuffix(".git").strip("/")

    head_result = execution.exec(["git", "rev-parse", "HEAD"], timeout=5)
    if not head_result.ok:
        raise RuntimeError(f"Failed to get git HEAD: {head_result.stderr.strip()}")

    return GitInfo(
        repo_path=repo_path,
        repo_url=f"https://github.com/{repo_path}",
        commit=head_result.stdout.strip(),
    )