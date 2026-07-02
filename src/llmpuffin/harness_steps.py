"""
Audit pipeline steps.

Each function is one step of the pipeline, called sequentially
by ``_execute_pipeline`` in ``agent.py``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from langchain_core.stores import BaseStore
from langgraph.checkpoint.base import BaseCheckpointSaver
from sqlalchemy import update

from llmpuffin.agent import AuditStatus, _build_agent, _stream_agent
from llmpuffin.audit_environment import AuditExecution, GitInfo
from llmpuffin.coverage import CoverageTracker
from llmpuffin.db import DB
from llmpuffin.github import GitHubClient
from llmpuffin.harness import Harness, HarnessConfig
from llmpuffin.log import log
from llmpuffin.models import AuditRun, AuditThread
from llmpuffin.threat_model import ThreatModel


@dataclass
class ResolvedThread:
    tid: str
    audit_run_id: int


@dataclass
class EnvironmentContext:
    execution: AuditExecution
    repo_path: str
    coverage: CoverageTracker | None = None


@dataclass
class AgentRunResult:
    status: AuditStatus
    error: str | None


# ── Step 1: Resolve thread ID and create audit run ──


async def resolved_thread(
    config: HarnessConfig,
    thread_id: str | None,
    source_thread_id: str | None,
    is_fork: bool,
    db: DB,
    profile_id: int | None,
    audit_run_id: int | None,
) -> ResolvedThread:
    """Create or resume an AuditRun and register the thread."""
    tid = thread_id or uuid.uuid4().hex[:12]
    if is_fork and source_thread_id:
        log.info("Forking thread %s → %s", source_thread_id, tid)
    else:
        log.info("Session thread_id: %s", tid)

    if audit_run_id is None:
        from llmpuffin.agent import _create_audit_run

        resume_tid = source_thread_id if is_fork else thread_id
        audit_run_id = await _create_audit_run(
            config, tid, resume_tid, db=db, profile_id=profile_id
        )
    return ResolvedThread(tid=tid, audit_run_id=audit_run_id)


# ── Step 2: Start environment ──


async def environment_context(
    harness: Harness,
    resolved: ResolvedThread,
    existing_container_id: str | None,
    db: DB,
) -> EnvironmentContext:
    """Start the container."""
    await _set_pipeline_state(resolved.tid, "starting", db=db)

    execution = await harness.start_environment(container_id=existing_container_id)
    execution.__enter__()

    try:
        cwd = await execution.exec(["pwd"], timeout=120)
        code_dir = cwd.stdout.strip() or harness.config.profile.code_dir
        log.info("Container cwd: %s", code_dir)
        await _save_container_id(resolved.tid, execution.container_id, db=db)
        # Use /src as coverage root when multiple repos are configured,
        # so files in sibling repos (e.g. /src/api and /src/modeling-api)
        # are all tracked.
        coverage_root = "/src" if harness.config.profile.repos else code_dir
        coverage = CoverageTracker(
            audit_run_id=resolved.audit_run_id,
            code_dir=coverage_root,
            db=db,
        )
        return EnvironmentContext(execution=execution, repo_path="", coverage=coverage)
    except BaseException:
        execution.__exit__(None, None, None)
        raise


# ── Step 3: Clone repositories ──


async def clone_repos(
    config: HarnessConfig,
    env_ctx: EnvironmentContext,
    resolved: ResolvedThread,
    github_client: GitHubClient | None,
    db: DB,
) -> None:
    """Clone git repositories specified in the profile into the container."""
    repos = config.profile.repos
    if not repos:
        return

    await _set_pipeline_state(resolved.tid, "cloning", db=db)
    execution = env_ctx.execution

    # Generate a single token for all clones in this run
    token = _get_clone_token(github_client)

    for repo in repos:
        repo_name = repo.name or repo.url.rstrip("/").rsplit("/", 1)[-1].removesuffix(
            ".git"
        )
        clone_path = f"/src/{repo_name}"

        # Skip if already cloned (e.g. resuming with an existing container).
        check = await execution.exec(
            ["test", "-d", f"{clone_path}/.git"], timeout=5, workdir="/"
        )
        if check.ok:
            log.info("Repo already cloned at %s, skipping", clone_path)
            continue

        clone_url = _inject_token(repo.url, token) if token else repo.url

        log.info("Cloning %s → %s", repo.url, clone_path)
        result = await execution.exec(
            ["git", "clone", "--depth", "1", clone_url, clone_path],
            timeout=600,
            workdir="/",
        )
        if not result.ok:
            raise RuntimeError(f"Failed to clone {repo.url}: {result.stderr.strip()}")
        log.info("Cloned %s", repo.url)

        if repo.lfs:
            log.info("Setting up git LFS for %s", clone_path)
            lfs_install = await execution.exec(
                ["git", "-C", clone_path, "lfs", "install", "--local"],
                timeout=30,
            )
            if not lfs_install.ok:
                log.warning("git lfs install failed: %s", lfs_install.stderr.strip())
            else:
                lfs_pull = await execution.exec(
                    ["git", "-C", clone_path, "lfs", "pull"],
                    timeout=600,
                )
                if not lfs_pull.ok:
                    log.warning("git lfs pull failed: %s", lfs_pull.stderr.strip())
                else:
                    log.info("LFS pull complete for %s", clone_path)

    # Capture git info from the first repo.
    first_repo = repos[0]
    first_name = first_repo.name or first_repo.url.rstrip("/").rsplit("/", 1)[
        -1
    ].removesuffix(".git")
    first_path = f"/src/{first_name}"

    git_info = await _capture_git_info_at(execution, first_path)
    if git_info:
        await _save_git_info(resolved.audit_run_id, git_info, db=db)
        log.info("Git info: %s @ %s", git_info.repo_url, git_info.commit[:12])
        env_ctx.repo_path = git_info.repo_path
    else:
        log.info("No git info available, continuing without")


# ── Step 3b: Populate file tree for coverage ──


async def file_tree(
    env_ctx: EnvironmentContext,
    resolved: ResolvedThread,
    db: DB,
) -> None:
    """Populate the file tree in the DB for coverage tracking."""
    coverage = env_ctx.coverage
    if coverage is None:
        return

    from llmpuffin.coverage import populate_file_tree

    await populate_file_tree(
        env_ctx.execution,
        coverage.code_dir,
        audit_run_id=resolved.audit_run_id,
        db=db,
    )


# ── Step 4: Build the agent ──


async def agent(
    config: HarnessConfig,
    env_ctx: EnvironmentContext,
    threat_model: ThreatModel,
    resolved: ResolvedThread,
    checkpointer: BaseCheckpointSaver,
    store: BaseStore,
    db: DB,
    github_client: GitHubClient | None,
) -> Any:
    """Build the deep agent with all backends, tools, and middleware."""
    await _set_pipeline_state(resolved.tid, "building", db=db)
    return _build_agent(
        config,
        env_ctx.execution,
        threat_model,
        resolved.audit_run_id,
        env_ctx.repo_path,
        checkpointer,
        store,
        db=db,
        github_client=github_client,
        coverage=env_ctx.coverage,
    )


# ── Step 5: Prepare input messages ──


async def input_messages(
    agent: Any,
    config: HarnessConfig,
    resolved: ResolvedThread,
    source_thread_id: str | None,
    user_message: str | None,
    is_fork: bool,
    thread_id: str | None,
) -> list:
    """Build the input messages for the agent."""
    if is_fork and source_thread_id:
        source_config: dict[str, Any] = {
            "configurable": {"thread_id": source_thread_id},
        }
        state = await agent.aget_state(source_config)
        messages = state.values.get("messages", [])
        messages.append({"role": "user", "content": user_message or "Continue."})
        return messages
    else:
        if user_message:
            msg = user_message
        elif thread_id:
            msg = "Continue the security audit."
        else:
            msg = "Begin the security audit."
        return [{"role": "user", "content": msg}]


# ── Step 6: Run the agent ──


async def agent_run_result(
    agent: Any,
    messages: list,
    config: HarnessConfig,
    resolved: ResolvedThread,
    db: DB,
) -> AgentRunResult:
    """Stream the agent execution."""
    await _set_pipeline_state(resolved.tid, "running", db=db)
    p = config.profile
    run_config: dict = {
        "recursion_limit": p.agent.max_iterations,
        "configurable": {"thread_id": resolved.tid},
    }
    status, error = await _stream_agent(
        agent, messages, run_config, p.agent.max_iterations
    )
    return AgentRunResult(status=status, error=error)


# ── Helpers ──


async def _capture_git_info_at(execution: AuditExecution, repo_path: str) -> GitInfo | None:
    """Capture git info from a specific directory inside the container."""
    from urllib.parse import urlparse

    try:
        remote_result = await execution.exec(
            ["git", "-C", repo_path, "remote", "get-url", "origin"], timeout=5
        )
        if not remote_result.ok:
            log.info("No git remote at %s: %s", repo_path, remote_result.stderr.strip())
            return None
        git_remote = remote_result.stdout.strip()

        parsed = urlparse(git_remote)
        if parsed.scheme != "https" or parsed.hostname != "github.com":
            log.info("Non-GitHub remote, skipping git info: %s", git_remote)
            return None

        path = parsed.path.removesuffix(".git").strip("/")

        head_result = await execution.exec(
            ["git", "-C", repo_path, "rev-parse", "HEAD"], timeout=5
        )
        if not head_result.ok:
            log.info("Failed to get git HEAD: %s", head_result.stderr.strip())
            return None

        return GitInfo(
            repo_path=path,
            repo_url=f"https://github.com/{path}",
            commit=head_result.stdout.strip(),
        )
    except Exception as exc:
        log.info("Could not capture git info at %s: %s", repo_path, exc)
        return None


def _get_clone_token(github_client: GitHubClient | None) -> str | None:
    """Get a short-lived GitHub installation token for cloning, or None."""
    if github_client is None or not github_client.configured:
        return None
    try:
        token = github_client._install_token()
        log.info("Generated GitHub installation token for cloning")
        return token
    except Exception as exc:
        log.warning("Failed to get GitHub token for cloning: %s", exc)
        return None


def _inject_token(url: str, token: str) -> str:
    """Inject an access token into an HTTPS git URL."""
    if url.startswith("https://"):
        return url.replace("https://", f"https://x-access-token:{token}@", 1)
    return url


async def _set_pipeline_state(tid: str, state: str, *, db: DB) -> None:
    try:
        async with db.async_session() as s:
            await s.execute(
                update(AuditThread)
                .where(AuditThread.thread_id == tid)
                .values(pipeline_state=state)
            )
            await s.commit()
    except Exception as exc:
        log.warning("Failed to set pipeline_state: %s", exc)


async def _save_container_id(tid: str, container_id: str, *, db: DB) -> None:
    try:
        async with db.async_session() as s:
            await s.execute(
                update(AuditThread)
                .where(AuditThread.thread_id == tid)
                .values(container_id=container_id)
            )
            await s.commit()
    except Exception as exc:
        log.warning("Failed to save container_id: %s", exc)


async def _save_git_info(audit_run_id: int, git_info: GitInfo, *, db: DB) -> None:
    async with db.async_session() as s:
        await s.execute(
            update(AuditRun)
            .where(AuditRun.id == audit_run_id)
            .values(
                github_repo_url=git_info.repo_url,
                git_commit=git_info.commit,
            )
        )
        await s.commit()
