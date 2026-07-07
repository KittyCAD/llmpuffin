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
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StoreBackend
from deepagents.backends.utils import create_file_data
from langchain_core.messages import AIMessage
from typing import Any
from langchain_quickjs import CodeInterpreterMiddleware
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.errors import GraphRecursionError
from langgraph.store.memory import InMemoryStore
from langgraph.store.postgres.aio import AsyncPostgresStore
from sqlalchemy import func, select, update
from sqlalchemy.orm import selectinload


from llmpuffin.backend import ContainerBackend
from llmpuffin.config import Config
from llmpuffin.coverage import CoverageTracker
from llmpuffin.db import DB
from llmpuffin.finding_service import FindingService
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
    store: Any,
    *,
    db: DB,
    github_client: GitHubClient | None = None,
    coverage: CoverageTracker | None = None,
    finding_service: FindingService | None = None,
):
    """Build the deep agent with all backends, tools, and middleware."""
    p = config.profile
    agent_cfg = p.agent
    container_backend = ContainerBackend(execution, coverage=coverage)
    routes: dict = {
        "/memories/": StoreBackend(
            store=store,
            namespace=lambda rt, _n=p.name: ("llmpuffin", _n, "memories"),
        )
    }

    # Load skills from DB into an in-memory store
    skills_list: list[str] = []
    if agent_cfg.skills:
        from llmpuffin.models import Skill, SkillFile

        skills_store = InMemoryStore()
        skills_backend = StoreBackend(
            store=skills_store, namespace=lambda rt: ("skills",)
        )
        with db.sync_session() as s:
            for skill_name in agent_cfg.skills:
                skill = s.query(Skill).filter(Skill.name == skill_name).first()
                if skill is None:
                    log.warning("Skill %r not found in DB, skipping", skill_name)
                    continue
                for sf in (
                    s.query(SkillFile).filter(SkillFile.skill_id == skill.id).all()
                ):
                    store_key = f"/{skill.name}/{sf.path}"
                    skills_store.put(
                        namespace=("skills",),
                        key=store_key,
                        value=dict(create_file_data(sf.content)),
                    )
                log.info("Loaded skill %r (%d files)", skill.name, len(skill.files))
        routes["/skills/"] = skills_backend
        skills_list = ["/skills/"]

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
        finding_service=finding_service,
    )
    main_tools: list = [tools[name] for name in MAIN_AGENT_TOOLS]

    provider = p.provider

    # Anthropic server-side tools — only available with Anthropic models.
    if provider == "anthropic":
        from anthropic.types.beta import (
            BetaWebFetchTool20250910Param,
            BetaWebSearchTool20250305Param,
        )

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

    # Build model — use provider-specific classes when provider config is set,
    # otherwise pass the model string and let deepagents/init_chat_model handle it.
    model: str | object = agent_cfg.model

    if provider == "anthropic" and p.anthropic.effort:
        from langchain_anthropic import ChatAnthropic

        anthropic_model_name = agent_cfg.model.removeprefix("anthropic:")
        model = ChatAnthropic(
            model_name=anthropic_model_name, effort=p.anthropic.effort
        )  # pyright: ignore[reportCallIssue]
    elif provider == "openai":
        openai_cfg = p.openai
        kwargs: dict = {}
        if openai_cfg.reasoning_effort:
            kwargs["reasoning_effort"] = openai_cfg.reasoning_effort
        if kwargs or not openai_cfg.use_responses_api:
            from langchain_openai import ChatOpenAI

            openai_model_name = agent_cfg.model.removeprefix("openai:")
            kwargs["use_responses_api"] = openai_cfg.use_responses_api
            model = ChatOpenAI(model=openai_model_name, **kwargs)

    return create_deep_agent(
        model=model,
        tools=main_tools,
        backend=backend,
        store=store,
        checkpointer=checkpointer,
        middleware=middleware,  # pyright: ignore[reportArgumentType]
        interrupt_on=interrupt_on_config,  # pyright: ignore[reportArgumentType]
        skills=skills_list or None,
        subagents=subagents,  # pyright: ignore[reportArgumentType]
        system_prompt=config.profile.agent.system_prompt,
    )


async def _stream_agent(agent, input_messages, run_config, max_iterations: int):
    """Stream agent execution via event streaming and log progress.

    Uses astream_events (v2) for granular visibility into tool calls,
    model output, and subagent activity — including events from nested
    subgraphs that the old stream_mode="updates" approach missed.

    Returns (status, error).
    """
    status = AuditStatus.COMPLETED
    error: str | None = None
    try:
        async for event in agent.astream_events(
            {"messages": input_messages},
            config=run_config,
            version="v2",
        ):
            # Explicit cancel point — allows asyncio.Task.cancel() to
            # take effect between events.
            await asyncio.sleep(0)

            kind = event["event"]

            if kind == "on_chat_model_end":
                msg = event["data"].get("output")
                if isinstance(msg, AIMessage):
                    if not msg.content and not msg.tool_calls:
                        status = AuditStatus.ERROR
                        error = "Model returned empty response"
                        log.error("%s: %s", error, repr(msg))
                        return status, error
                    if msg.content and not msg.tool_calls:
                        log.info("  agent: %s", _truncate(str(msg.content), 200))

            elif kind == "on_tool_start":
                name = event.get("name", "?")
                input_data = event["data"].get("input", "")
                log.info("  tool: %s(%s)", name, _truncate(str(input_data), 120))

            elif kind == "on_tool_end":
                output = event["data"].get("output", "")
                log.debug("  result: %s", _truncate(str(output), 200))

            elif kind == "on_tool_error":
                err_data = event["data"].get("error", "")
                log.warning("  tool error: %s", _truncate(str(err_data), 200))
    except GraphRecursionError:
        status = AuditStatus.RECURSION_LIMIT
        error = f"Agent hit recursion limit ({max_iterations} iterations)"
        log.warning("  %s", error)
    except Exception as exc:
        status = AuditStatus.ERROR
        error = str(exc)
        log.error("Agent error: %s", error)
    return status, error


async def fork_audit(
    config: HarnessConfig,
    source_thread_id: str,
    user_message: str,
    *,
    db: DB,
    global_config: Config,
    thread_id: str | None = None,
    github_client: GitHubClient | None = None,
) -> AuditResult:
    """Fork from an existing thread and continue with a new message."""
    harness = Harness(config, global_config=global_config)
    threat_model = harness.load_threat_model(db=db)

    async with (
        AsyncPostgresSaver.from_conn_string(db.url) as checkpointer,
        AsyncPostgresStore.from_conn_string(db.url) as store,
    ):
        await checkpointer.setup()
        await store.setup()
        return await _execute_pipeline(
            harness,
            config,
            threat_model,
            checkpointer,
            store,
            db=db,
            thread_id=thread_id,
            source_thread_id=source_thread_id,
            user_message=user_message,
            is_fork=True,
            github_client=github_client,
        )


async def _execute_pipeline(
    harness: Harness,
    config: HarnessConfig,
    threat_model: ThreatModel,
    checkpointer: BaseCheckpointSaver,
    store: Any,
    *,
    db: DB,
    thread_id: str | None = None,
    source_thread_id: str | None = None,
    user_message: str | None = None,
    existing_container_id: str | None = None,
    is_fork: bool = False,
    github_client: GitHubClient | None = None,
    profile_id: int | None = None,
    audit_run_id: int | None = None,
) -> AuditResult:
    """Execute the audit pipeline.

    Shared implementation for both fresh audits and forks.
    """
    from llmpuffin.harness_steps import (
        resolved_thread,
        environment_context,
        clone_repos,
        file_tree,
        agent as build_agent_step,
        input_messages,
        agent_run_result,
    )

    # Step 1: resolve thread
    resolved = await resolved_thread(
        config, thread_id, source_thread_id, is_fork, db, profile_id, audit_run_id
    )

    env_ctx = None
    try:
        # Step 2: start environment
        env_ctx = await environment_context(
            harness, resolved, existing_container_id, db
        )

        # Step 3: clone repos
        await clone_repos(config, env_ctx, resolved, github_client, db)

        # Step 3b: populate file tree for coverage
        await file_tree(env_ctx, resolved, db)

        # Step 4: build agent
        finding_svc = FindingService(db)
        agent = await build_agent_step(
            config,
            env_ctx,
            threat_model,
            resolved,
            checkpointer,
            store,
            db,
            github_client,
            finding_service=finding_svc,
        )

        # Step 5: prepare input messages
        messages = await input_messages(
            agent,
            config,
            resolved,
            source_thread_id,
            user_message,
            is_fork,
            thread_id,
        )

        # Step 6: run agent
        run_result = await agent_run_result(agent, messages, config, resolved, db)
        status = run_result.status
        error = run_result.error
    except (KeyboardInterrupt, asyncio.CancelledError):
        status = AuditStatus.ABORTED
        error = "Aborted by user"
        log.warning("Aborted: %s", error)
        await _finalize_audit_run(resolved.tid, status, error, db=db)
        raise
    except Exception as exc:
        status = AuditStatus.ERROR
        error = str(exc)
        log.exception("Audit failed: %s", error)
    finally:
        if env_ctx is not None:
            env_ctx.execution.__exit__(None, None, None)

    finding_count = await _count_findings(resolved.audit_run_id, db=db)
    label = "Fork" if is_fork else "Audit"
    log.info(
        "%s complete. %d finding(s) recorded. Status: %s",
        label,
        finding_count,
        status,
    )

    await _finalize_audit_run(resolved.tid, status, error, db=db)

    return AuditResult(
        finding_count=finding_count,
        status=status,
        error=error,
        thread_id=resolved.tid,
        audit_run_id=resolved.audit_run_id,
    )


async def create_audit_run(
    config: HarnessConfig,
    tid: str,
    *,
    db: DB,
    profile_id: int | None = None,
    resume_thread_id: str | None = None,
) -> int:
    """Pre-create an AuditRun + thread before spawning. Returns audit_run.id."""
    return await _create_audit_run(
        config, tid, resume_thread_id, db=db, profile_id=profile_id
    )


async def run_audit(
    config: HarnessConfig,
    *,
    db: DB,
    global_config: Config,
    thread_id: str | None = None,
    user_message: str | None = None,
    github_client: GitHubClient | None = None,
    profile_id: int | None = None,
    audit_run_id: int | None = None,
) -> AuditResult:
    """Run a full security audit driven by the threat model."""
    harness = Harness(config, global_config=global_config)
    threat_model = harness.load_threat_model(db=db)

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
            profile_id=profile_id,
            audit_run_id=audit_run_id,
        )


async def _run_audit_inner(
    harness: Harness,
    config: HarnessConfig,
    threat_model: ThreatModel,
    thread_id: str | None,
    checkpointer: BaseCheckpointSaver,
    store: Any,
    user_message: str | None = None,
    *,
    db: DB,
    github_client: GitHubClient | None = None,
    profile_id: int | None = None,
    audit_run_id: int | None = None,
) -> AuditResult:
    existing_container_id = (
        await _get_container_id(thread_id, db=db) if thread_id else None
    )
    log.info(
        "Starting container: %s (code_dir: %s)",
        config.profile.image,
        config.profile.code_dir,
    )

    return await _execute_pipeline(
        harness,
        config,
        threat_model,
        checkpointer,
        store,
        db=db,
        thread_id=thread_id,
        user_message=user_message,
        existing_container_id=existing_container_id,
        is_fork=False,
        github_client=github_client,
        profile_id=profile_id,
        audit_run_id=audit_run_id,
    )


async def _count_findings(audit_run_id: int, *, db: DB) -> int:
    """Count non-deleted findings for an audit run."""
    from llmpuffin.models import Finding

    async with db.async_session() as s:
        result = await s.execute(
            select(func.count())
            .select_from(Finding)
            .where(Finding.audit_run_id == audit_run_id, Finding.status != "deleted")
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
    profile_id: int | None = None,
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
                if profile_id is None:
                    db_profile = await AuditProfile.get_or_create(
                        s, name=config.profile.name, profile_toml=config.profile_toml
                    )
                    profile_id = db_profile.id
                audit_run = AuditRun(
                    profile_id=profile_id,
                    profile_toml=config.profile_toml,
                    container_image=config.profile.image,
                    model_name=config.profile.agent.model,
                )
                s.add(audit_run)
                await s.flush()
        else:
            if profile_id is None:
                db_profile = await AuditProfile.get_or_create(
                    s, name=config.profile.name, profile_toml=config.profile_toml
                )
                profile_id = db_profile.id
            audit_run = AuditRun(
                profile_id=profile_id,
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
