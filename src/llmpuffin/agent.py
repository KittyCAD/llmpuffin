"""
The agentic loop — LangGraph orchestrator for security audits.

# Architecture: Harness vs Orchestrator vs Framework
#
# - Framework (LangChain): provides tool abstractions, prompt templates, etc.
# - Orchestrator (LangGraph): controls *when* and *how* to invoke the model,
#   manages reasoning loops and decision flow — the "brain".
# - Harness (llmpuffin): provides *capabilities and side effects* — tools,
#   context management, verification, SARIF output — the "hands and
#   infrastructure".
#
# This module is the orchestrator.  It uses the framework (LangChain) and
# is driven by the harness (Harness + AuditEnvironment + ThreatModel).
#
# The agentic loop follows an incremental execution pattern:
#   1. Load threat model and derive prioritized threat scenarios
#   2. For each scenario, provide context to the agent
#   3. Agent uses containerized tools to investigate
#   4. Verification step: agent must justify findings with evidence
#   5. Findings are collected into SARIF output
#
# This is NOT a meta-harness: we don't optimize harness parameters
# across runs.  But the declarative threat model TOML is designed to be
# the specification layer that a meta-harness could optimize over in future.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StoreBackend
from deepagents.backends.utils import create_file_data
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.stores import BaseStore
from langchain_quickjs import CodeInterpreterMiddleware
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.errors import GraphRecursionError
from langgraph.store.memory import InMemoryStore
from langgraph.store.postgres.aio import AsyncPostgresStore
from sqlalchemy import func, select, update
from sqlalchemy.orm import selectinload

from anthropic.types.beta import (
    BetaWebFetchTool20250910Param,
    BetaWebSearchTool20250305Param,
)

from llmpuffin.backend import ContainerBackend
from llmpuffin.db import DB
from llmpuffin.github import GitHubClient
from llmpuffin.harness import Harness, HarnessConfig
from llmpuffin.log import log
from llmpuffin.models import AuditProfile, AuditRun, AuditThread
from llmpuffin.subagents import MAIN_AGENT_TOOLS, build_subagents
from llmpuffin.threat_model import ThreatModel
from llmpuffin.tools import make_tools


class AuditStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    RECURSION_LIMIT = "recursion_limit"
    ABORTED = "aborted"
    ERROR = "error"


@dataclass
class AuditResult:
    finding_count: int
    status: AuditStatus
    error: str | None = None
    thread_id: str | None = None
    audit_run_id: int | None = None


def _build_agent(
    config: HarnessConfig,
    execution,
    threat_model: ThreatModel,
    audit_run_id: int,
    repo_path: str,
    checkpointer: BaseCheckpointSaver,
    store: BaseStore,
    *,
    db: DB,
    github_client: GitHubClient | None = None,
):
    """Build the deep agent with all backends, tools, and middleware."""
    p = config.profile
    agent_cfg = p.agent
    container_backend = ContainerBackend(execution)
    routes: dict = {
        "/memories/": StoreBackend(
            store=store,
            namespace=lambda rt, _n=p.name: ("llmpuffin", _n, "memories"),
        )
    }

    # Load skills from disk into an in-memory store
    skills_list: list[str] = []
    if agent_cfg.skills_dir and agent_cfg.skills_dir.is_dir():
        skills_store = InMemoryStore()
        skills_backend = StoreBackend(
            store=skills_store, namespace=lambda rt: ("skills",)
        )
        for file_path in sorted(agent_cfg.skills_dir.rglob("*")):
            if not file_path.is_file():
                continue
            rel = file_path.relative_to(agent_cfg.skills_dir)
            store_key = f"/{rel}"
            try:
                content = file_path.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            skills_store.put(
                namespace=("skills",),
                key=store_key,
                value=dict(create_file_data(content)),
            )
        routes["/skills/"] = skills_backend
        skills_list = ["/skills/"]
        log.info("Loaded skills from %s", agent_cfg.skills_dir)

    backend = CompositeBackend(
        default=container_backend,
        routes=routes,
    )

    tools = make_tools(
        threat_model,
        audit_run_id=audit_run_id,
        repo_path=repo_path,
        github_client=github_client,
        container_backend=container_backend,
        db=db,
    )
    main_tools: list = [tools[name] for name in MAIN_AGENT_TOOLS]

    # Anthropic server-side tools — executed by Claude, no local handler needed.
    main_tools.append(
        BetaWebSearchTool20250305Param(
            name="web_search",
            type="web_search_20250305",
            max_uses=5,
        )
    )
    main_tools.append(
        BetaWebFetchTool20250910Param(
            name="web_fetch",
            type="web_fetch_20250910",
            max_uses=5,
        )
    )

    subagents = build_subagents(tools)

    middleware = [CodeInterpreterMiddleware()]

    interrupt_on_config = None
    if agent_cfg.interrupt_on:
        interrupt_on_config = {name: True for name in agent_cfg.interrupt_on}

    return create_deep_agent(
        model=f"{agent_cfg.model}",
        tools=main_tools,
        backend=backend,
        store=store,
        checkpointer=checkpointer,
        middleware=middleware,
        interrupt_on=interrupt_on_config,
        skills=skills_list or None,
        subagents=subagents,
        system_prompt=config.profile.agent.system_prompt,
    )


class _ToolLogHandler(BaseCallbackHandler):
    """Log tool calls from subagents that don't go through the main stream."""

    def on_tool_start(self, serialized, input_str, *, run_id, **kwargs):
        name = serialized.get("name", "?")
        log.info("  tool: %s(%s)", name, _truncate(str(input_str), 120))

    def on_tool_error(self, error, *, run_id, **kwargs):
        log.warning("  tool error: %s", _truncate(str(error), 200))


async def _stream_agent(agent, input_messages, run_config, max_iterations: int):
    """Stream agent execution and log progress. Returns (status, error)."""
    run_config.setdefault("callbacks", []).append(_ToolLogHandler())
    status = AuditStatus.COMPLETED
    error: str | None = None
    try:
        async for chunk in agent.astream(
            {"messages": input_messages},
            config=run_config,
            stream_mode="updates",
        ):
            for node, updates in chunk.items():
                if updates is None:
                    continue
                messages = updates.get("messages", [])
                # LangGraph may wrap messages in an Overwrite container
                if hasattr(messages, "value"):
                    messages = messages.value
                if not isinstance(messages, list):
                    continue
                for msg in messages:
                    if isinstance(msg, AIMessage):
                        if msg.tool_calls:
                            for tc in msg.tool_calls:
                                log.info(
                                    "  tool: %s(%s)",
                                    tc["name"],
                                    _truncate(str(tc["args"]), 120),
                                )
                        elif msg.content:
                            log.info("  agent: %s", _truncate(str(msg.content), 200))
                    elif isinstance(msg, ToolMessage):
                        log.debug("  result: %s", _truncate(str(msg.content), 200))
    except GraphRecursionError:
        status = AuditStatus.RECURSION_LIMIT
        error = f"Agent hit recursion limit ({max_iterations} iterations)"
        log.warning("  %s", error)
    except Exception as exc:
        status = AuditStatus.ERROR
        error = str(exc)
        log.error("  Agent error: %s", error)
    return status, error


async def fork_audit(
    config: HarnessConfig,
    source_thread_id: str,
    user_message: str,
    *,
    db: DB,
    thread_id: str | None = None,
    github_client: GitHubClient | None = None,
) -> AuditResult:
    """Fork from an existing thread and continue with a new message."""
    harness = Harness(config)
    threat_model = harness.load_threat_model()

    async with (
        AsyncPostgresSaver.from_conn_string(db.url) as checkpointer,
        AsyncPostgresStore.from_conn_string(db.url) as store,
    ):
        await checkpointer.setup()
        await store.setup()
        return await _fork_audit_inner(
            harness,
            config,
            threat_model,
            source_thread_id,
            user_message,
            checkpointer,
            store,
            db=db,
            thread_id=thread_id,
            github_client=github_client,
        )


async def _fork_audit_inner(
    harness: Harness,
    config: HarnessConfig,
    threat_model: ThreatModel,
    source_thread_id: str,
    user_message: str,
    checkpointer: BaseCheckpointSaver,
    store: BaseStore,
    *,
    db: DB,
    thread_id: str | None = None,
    github_client: GitHubClient | None = None,
) -> AuditResult:
    p = config.profile
    new_tid = thread_id or uuid.uuid4().hex[:12]
    log.info("Forking thread %s → %s", source_thread_id, new_tid)

    audit_run_id = await _create_audit_run(config, new_tid, source_thread_id, db=db)

    try:
        with harness.start_environment() as execution:
            cwd = execution.exec(["pwd"], timeout=5)
            log.info("Container cwd: %s", cwd.stdout.strip())
            await _save_container_id(new_tid, execution.container.id, db=db)
            git_info = execution.capture_git_info()
            async with db.async_session() as s:
                await s.execute(
                    update(AuditRun)
                    .where(AuditRun.id == audit_run_id)
                    .values(
                        github_repo_url=git_info.repo_url, git_commit=git_info.commit
                    )
                )
                await s.commit()
            log.info("Git info: %s @ %s", git_info.repo_url, git_info.commit[:12])
            repo_path = git_info.repo_path

            agent = _build_agent(
                config,
                execution,
                threat_model,
                audit_run_id,
                repo_path,
                checkpointer,
                store,
                db=db,
                github_client=github_client,
            )

            source_config: dict[str, Any] = {
                "configurable": {"thread_id": source_thread_id},
            }
            state = await agent.aget_state(source_config)

            messages = state.values.get("messages", [])
            messages.append({"role": "user", "content": user_message})

            run_config: dict = {
                "recursion_limit": p.agent.max_iterations,
                "configurable": {"thread_id": new_tid},
            }

            status, error = await _stream_agent(
                agent, messages, run_config, p.agent.max_iterations
            )
    except (KeyboardInterrupt, asyncio.CancelledError):
        status = AuditStatus.ABORTED
        error = "Aborted by user"
        log.warning("Aborted: %s", error)
        await _finalize_audit_run(new_tid, status, error, db=db)
        raise
    except Exception as exc:
        status = AuditStatus.ERROR
        error = str(exc)
        log.error("Container startup failed: %s", error)

    finding_count = await _count_findings(audit_run_id, db=db)
    log.info(
        "Fork complete. %d finding(s) recorded. Status: %s",
        finding_count,
        status,
    )

    await _finalize_audit_run(new_tid, status, error, db=db)

    return AuditResult(
        finding_count=finding_count,
        status=status,
        error=error,
        thread_id=new_tid,
        audit_run_id=audit_run_id,
    )


async def run_audit(
    config: HarnessConfig,
    *,
    db: DB,
    thread_id: str | None = None,
    user_message: str | None = None,
    github_client: GitHubClient | None = None,
) -> AuditResult:
    """Run a full security audit driven by the threat model."""
    harness = Harness(config)
    threat_model = harness.load_threat_model()

    log.info(
        "Loaded threat model: %d components, %d scenarios",
        len(threat_model.components),
        len(threat_model.threat_scenarios),
    )

    async with (
        AsyncPostgresSaver.from_conn_string(db.url) as checkpointer,
        AsyncPostgresStore.from_conn_string(db.url) as store,
    ):
        await checkpointer.setup()
        await store.setup()
        return await _run_audit_inner(
            harness,
            config,
            threat_model,
            thread_id,
            checkpointer,
            store,
            user_message,
            db=db,
            github_client=github_client,
        )


async def _run_audit_inner(
    harness: Harness,
    config: HarnessConfig,
    threat_model: ThreatModel,
    thread_id: str | None,
    checkpointer: BaseCheckpointSaver,
    store: BaseStore,
    user_message: str | None = None,
    *,
    db: DB,
    github_client: GitHubClient | None = None,
) -> AuditResult:
    p = config.profile
    tid = thread_id or uuid.uuid4().hex[:12]
    log.info("Session thread_id: %s", tid)

    audit_run_id = await _create_audit_run(config, tid, thread_id, db=db)

    # Look up existing container for resume
    existing_container_id = await _get_container_id(tid, db=db)
    log.info("Starting container: %s (code_dir: %s)", p.image, p.code_dir)

    try:
        with harness.start_environment(container_id=existing_container_id) as execution:
            cwd = execution.exec(["pwd"], timeout=5)
            log.info("Container cwd: %s", cwd.stdout.strip())
            # Store container ID for future resumes
            await _save_container_id(tid, execution.container.id, db=db)
            git_info = execution.capture_git_info()
            async with db.async_session() as s:
                await s.execute(
                    update(AuditRun)
                    .where(AuditRun.id == audit_run_id)
                    .values(
                        github_repo_url=git_info.repo_url, git_commit=git_info.commit
                    )
                )
                await s.commit()
            log.info("Git info: %s @ %s", git_info.repo_url, git_info.commit[:12])
            repo_path = git_info.repo_path

            agent = _build_agent(
                config,
                execution,
                threat_model,
                audit_run_id,
                repo_path,
                checkpointer,
                store,
                db=db,
                github_client=github_client,
            )

            run_config: dict = {"recursion_limit": p.agent.max_iterations}
            if tid:
                run_config["configurable"] = {"thread_id": tid}

            if user_message:
                msg = user_message
            elif thread_id:
                msg = "Continue the security audit."
            else:
                msg = "Begin the security audit."

            status, error = await _stream_agent(
                agent,
                [{"role": "user", "content": msg}],
                run_config,
                p.agent.max_iterations,
            )
    except (KeyboardInterrupt, asyncio.CancelledError):
        status = AuditStatus.ABORTED
        error = "Aborted by user"
        log.warning("Aborted: %s", error)
        await _finalize_audit_run(tid, status, error, db=db)
        raise
    except Exception as exc:
        status = AuditStatus.ERROR
        error = str(exc)
        log.error("Container startup failed: %s", error)

    finding_count = await _count_findings(audit_run_id, db=db)
    log.info(
        "Audit finished. %d finding(s) recorded. Status: %s",
        finding_count,
        status,
    )

    await _finalize_audit_run(tid, status, error, db=db)

    return AuditResult(
        finding_count=finding_count,
        status=status,
        error=error,
        thread_id=tid,
        audit_run_id=audit_run_id,
    )


async def _count_findings(audit_run_id: int, *, db: DB) -> int:
    """Count non-deleted findings for an audit run."""
    from llmpuffin.models import Finding

    async with db.async_session() as s:
        result = await s.execute(
            select(func.count())
            .select_from(Finding)
            .where(Finding.audit_run_id == audit_run_id, Finding.deleted.is_(False))
        )
        return result.scalar_one()


async def _get_container_id(tid: str, *, db: DB) -> str | None:
    """Look up the container ID for a thread from the DB."""
    try:
        async with db.async_session() as s:
            row = (
                await s.execute(
                    select(AuditThread.container_id).where(AuditThread.thread_id == tid)
                )
            ).scalar_one_or_none()
        return row or None
    except Exception:
        return None


async def _save_container_id(tid: str, container_id: str, *, db: DB) -> None:
    """Store the container ID on the thread."""
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


async def _create_audit_run(
    config: HarnessConfig,
    tid: str,
    resume_thread_id: str | None,
    *,
    db: DB,
) -> int:
    """Create or resume an AuditRun, register the thread. Returns audit_run.id."""
    async with db.async_session() as s:
        if resume_thread_id:
            old_thread = (
                await s.execute(
                    select(AuditThread)
                    .options(selectinload(AuditThread.audit_run))
                    .where(AuditThread.thread_id == resume_thread_id)
                )
            ).scalar_one_or_none()
            if old_thread:
                audit_run = old_thread.audit_run
            else:
                db_profile = await AuditProfile.get_or_create(
                    s, name=config.profile.name, profile_toml=config.profile_toml
                )
                audit_run = AuditRun(
                    profile_id=db_profile.id,
                    profile_toml=config.profile_toml,
                    container_image=config.profile.image,
                    model_name=config.profile.agent.model,
                )
                s.add(audit_run)
                await s.flush()
        else:
            db_profile = await AuditProfile.get_or_create(
                s, name=config.profile.name, profile_toml=config.profile_toml
            )
            audit_run = AuditRun(
                profile_id=db_profile.id,
                profile_toml=config.profile_toml,
                container_image=config.profile.image,
                model_name=config.profile.agent.model,
            )
            s.add(audit_run)
            await s.flush()

        thread_obj = (
            await s.execute(select(AuditThread).where(AuditThread.thread_id == tid))
        ).scalar_one_or_none()
        if thread_obj is None:
            thread_obj = AuditThread(
                thread_id=tid,
                audit_run_id=audit_run.id,
                status=AuditStatus.RUNNING.value,
                error="",
            )
            s.add(thread_obj)
        else:
            thread_obj.status = AuditStatus.RUNNING.value
            thread_obj.error = ""

        run_id = audit_run.id
        await s.commit()
        return run_id


async def _finalize_audit_run(
    tid: str | None, status: AuditStatus, error: str | None, *, db: DB
) -> None:
    """Update the thread status and the run's finished_at."""
    if not tid:
        return
    try:
        async with db.async_session() as s:
            row = (
                await s.execute(
                    select(AuditThread.audit_run_id).where(AuditThread.thread_id == tid)
                )
            ).scalar_one_or_none()
            if row is None:
                log.warning("AuditThread %s not found in DB", tid)
                return
            await s.execute(
                update(AuditThread)
                .where(AuditThread.thread_id == tid)
                .values(status=status.value, error=error or "")
            )
            await s.execute(
                update(AuditRun)
                .where(AuditRun.id == row)
                .values(finished_at=datetime.now(timezone.utc))
            )
            await s.commit()
    except Exception as exc:
        log.warning("Failed to finalize thread in DB: %s", exc)


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", " ")
    return s[:n] + "..." if len(s) > n else s
