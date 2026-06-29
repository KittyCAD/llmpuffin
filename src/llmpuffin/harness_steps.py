"""
Hamilton DAG defining the audit pipeline as a graph of steps.

Each function is a node in the DAG. Dependencies between steps are expressed
via function parameter names matching other function names (or external inputs).

External inputs (provided at execution time):
    harness, config, threat_model, checkpointer, store, db,
    thread_id, github_client, source_thread_id, user_message,
    existing_container_id, is_fork
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
from llmpuffin.db import DB
from llmpuffin.github import GitHubClient
from llmpuffin.harness import Harness, HarnessConfig
from llmpuffin.log import log
from llmpuffin.models import AuditRun, AuditThread
from llmpuffin.threat_model import ThreatModel


# ── Inputs that Hamilton resolves from the `inputs` dict ──
# harness: Harness
# config: HarnessConfig
# threat_model: ThreatModel
# checkpointer: BaseCheckpointSaver
# store: BaseStore
# db: DB
# thread_id: str | None
# github_client: GitHubClient | None
# source_thread_id: str | None
# user_message: str | None
# existing_container_id: str | None
# is_fork: bool


@dataclass
class ResolvedThread:
    tid: str
    audit_run_id: int


@dataclass
class EnvironmentContext:
    execution: AuditExecution
    repo_path: str


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
) -> ResolvedThread:
    """Create or resume an AuditRun and register the thread."""
    from llmpuffin.agent import _create_audit_run

    tid = thread_id or uuid.uuid4().hex[:12]
    if is_fork and source_thread_id:
        log.info("Forking thread %s → %s", source_thread_id, tid)
    else:
        log.info("Session thread_id: %s", tid)

    resume_tid = source_thread_id if is_fork else thread_id
    audit_run_id = await _create_audit_run(config, tid, resume_tid, db=db)
    return ResolvedThread(tid=tid, audit_run_id=audit_run_id)


# ── Step 2: Start environment and capture git info ──


async def environment_context(
    harness: Harness,
    resolved_thread: ResolvedThread,
    existing_container_id: str | None,
    db: DB,
) -> EnvironmentContext:
    """Start the container and capture git info.

    Note: the container lifecycle (context manager) is managed by the caller
    that holds the Hamilton driver, not by Hamilton itself.  This function
    receives an already-started execution via the harness.

    Actually — since the container is a context manager that must stay alive
    for the duration of the agent run, we start it here but the caller must
    ensure stop is called.  We store the execution on the result so the
    caller can manage cleanup.
    """
    execution = harness.start_environment(container_id=existing_container_id)
    # Enter the context manager — caller must call execution.__exit__ later
    execution.__enter__()

    try:
        cwd = execution.exec(["pwd"], timeout=5)
        log.info("Container cwd: %s", cwd.stdout.strip())
        await _save_container_id(resolved_thread.tid, execution.container_id, db=db)

        git_info = execution.capture_git_info()
        repo_path = ""
        if git_info:
            await _save_git_info(resolved_thread.audit_run_id, git_info, db=db)
            log.info("Git info: %s @ %s", git_info.repo_url, git_info.commit[:12])
            repo_path = git_info.repo_path
        else:
            log.info("No git info available, continuing without")

        return EnvironmentContext(execution=execution, repo_path=repo_path)
    except BaseException:
        execution.__exit__(None, None, None)
        raise


# ── Step 3: Build the agent ──


async def agent(
    config: HarnessConfig,
    environment_context: EnvironmentContext,
    threat_model: ThreatModel,
    resolved_thread: ResolvedThread,
    checkpointer: BaseCheckpointSaver,
    store: BaseStore,
    db: DB,
    github_client: GitHubClient | None,
) -> Any:
    """Build the deep agent with all backends, tools, and middleware."""
    return _build_agent(
        config,
        environment_context.execution,
        threat_model,
        resolved_thread.audit_run_id,
        environment_context.repo_path,
        checkpointer,
        store,
        db=db,
        github_client=github_client,
    )


# ── Step 4: Prepare input messages ──


async def input_messages(
    agent: Any,
    config: HarnessConfig,
    resolved_thread: ResolvedThread,
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


# ── Step 5: Run the agent ──


async def agent_run_result(
    agent: Any,
    input_messages: list,
    config: HarnessConfig,
    resolved_thread: ResolvedThread,
) -> AgentRunResult:
    """Stream the agent execution."""
    p = config.profile
    run_config: dict = {
        "recursion_limit": p.agent.max_iterations,
        "configurable": {"thread_id": resolved_thread.tid},
    }
    status, error = await _stream_agent(
        agent, input_messages, run_config, p.agent.max_iterations
    )
    return AgentRunResult(status=status, error=error)


# ── Helpers (not Hamilton nodes) ──


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
