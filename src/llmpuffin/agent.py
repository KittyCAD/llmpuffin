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
from urllib.parse import urlparse

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
from langgraph.store.memory import InMemoryStore as _InMemoryStore
from langgraph.store.postgres.aio import AsyncPostgresStore
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from llmpuffin.backend import ContainerBackend
from llmpuffin.db import async_session, get_postgres_url
from llmpuffin.github import GitHubClient, client_from_config
from llmpuffin.harness import Harness, HarnessConfig
from llmpuffin.log import log
from llmpuffin.models import AuditProfile, AuditRun, AuditThread, Finding
from llmpuffin.sarif import SarifReport
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
    report: SarifReport
    status: AuditStatus
    error: str | None = None
    thread_id: str | None = None


SYSTEM_PROMPT = """\
You are a security auditor performing a code review.
The source code is in the current working directory of a container.
Do not use /src as starting point, use the `cwd`. You may lookup code in /src.

Start by invoking the skill audit-context-building.

## Subagents

You have specialized subagents — delegate to them instead of doing everything yourself:

- **threat-model-auditor**: Systematically investigates every threat scenario from the \
threat model. Delegate to this subagent for threat-model-driven analysis. Do NOT call \
get_threat_model or get_threat_scenario yourself — that is the threat-model-auditor's job.
- **finding-validator**: Validates a reported finding by constructing a full exploit chain \
or by actually running the target app and writing an exploit/test. A finding is only \
confirmed if the validator proves it. Pass the finding_id and description when delegating.
- **function-analyzer**: Performs ultra-granular per-function deep analysis. Use for dense \
functions, data-flow chains, cryptographic code, or state machines.

## Your workflow
1. Start with the audit-context-building skill to understand the codebase structure
2. Explore the codebase directly: read code, grep for patterns, understand the architecture
3. Report potential findings with report_finding as you discover them
4. Delegate to threat-model-auditor to ensure all threat scenarios are covered
5. For each reported finding, delegate to finding-validator to confirm or reject it
6. If /memories/ is available, read it for context from prior audits and write notes for future runs

## Findings
- report_finding returns a finding_id — use this ID for update_finding, delete_finding, validate_finding
- The finding ID is assigned automatically, do not invent IDs
- Report findings early — the finding-validator will confirm or reject them

## Guidelines
- Provide concrete evidence: file paths, line numbers, code snippets
- Do NOT call get_threat_model or get_threat_scenario directly — delegate to threat-model-auditor
- Focus your own analysis on codebase exploration and pattern recognition
"""


def _build_agent(
    config: HarnessConfig,
    execution,
    report: SarifReport,
    threat_model: ThreatModel,
    audit_run_id: int,
    thread_id: str,
    repo_path: str,
    checkpointer: BaseCheckpointSaver,
    store: BaseStore,
    github_client: GitHubClient | None = None,
):
    """Build the deep agent with all backends, tools, and middleware."""
    p = config.profile
    agent_cfg = p.agent
    container_backend = ContainerBackend(execution)
    routes: dict = {}

    memory_backend = StoreBackend(
        store=store,
        namespace=lambda rt, _n=p.name: ("llmpuffin", _n, "memories"),
    )
    routes["/memories/"] = memory_backend

    # Load skills from disk into an in-memory store
    skills_list: list[str] = []
    if agent_cfg.skills_dir and agent_cfg.skills_dir.is_dir():
        skills_store = _InMemoryStore()
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
        report,
        threat_model,
        audit_run_id=audit_run_id,
        thread_id=thread_id,
        repo_path=repo_path,
        github_client=github_client,
    )
    main_tools = [tools[name] for name in MAIN_AGENT_TOOLS]
    subagents = build_subagents(tools)

    middleware = [CodeInterpreterMiddleware()]

    interrupt_on_config = None
    if agent_cfg.interrupt_on:
        interrupt_on_config = {name: True for name in agent_cfg.interrupt_on}

    return create_deep_agent(
        model=f"anthropic:{agent_cfg.model}",
        tools=main_tools,
        backend=backend,
        store=store,
        checkpointer=checkpointer,
        middleware=middleware,
        interrupt_on=interrupt_on_config,
        skills=skills_list or None,
        subagents=subagents,
        system_prompt=SYSTEM_PROMPT,
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
    thread_id: str | None = None,
    github_client: GitHubClient | None = None,
) -> AuditResult:
    """Fork from an existing thread and continue with a new message."""
    harness = Harness(config)
    threat_model = harness.load_threat_model()
    report = SarifReport()

    postgres_url = get_postgres_url()
    async with (
        AsyncPostgresSaver.from_conn_string(postgres_url) as checkpointer,
        AsyncPostgresStore.from_conn_string(postgres_url) as store,
    ):
        await checkpointer.setup()
        await store.setup()
        return await _fork_audit_inner(
            harness,
            config,
            threat_model,
            report,
            source_thread_id,
            user_message,
            checkpointer,
            store,
            thread_id=thread_id,
            github_client=github_client,
        )


async def _fork_audit_inner(
    harness: Harness,
    config: HarnessConfig,
    threat_model: ThreatModel,
    report: SarifReport,
    source_thread_id: str,
    user_message: str,
    checkpointer: BaseCheckpointSaver,
    store: BaseStore,
    thread_id: str | None = None,
    github_client: GitHubClient | None = None,
) -> AuditResult:
    p = config.profile
    new_tid = thread_id or uuid.uuid4().hex[:12]
    log.info("Forking thread %s → %s", source_thread_id, new_tid)

    audit_run_id = await _create_audit_run(
        config,
        new_tid,
        source_thread_id,
    )

    try:
        with harness.start_environment() as execution:
            cwd = execution.exec(["pwd"], timeout=5)
            log.info("Container cwd: %s", cwd.stdout.strip())
            await _save_container_id(new_tid, execution.container.id)
            repo_path = await _capture_git_info(execution, audit_run_id)

            agent = _build_agent(
                config,
                execution,
                report,
                threat_model,
                audit_run_id,
                new_tid,
                repo_path,
                checkpointer,
                store,
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
        await _finalize_audit_run(new_tid, status, error)
        raise
    except Exception as exc:
        status = AuditStatus.ERROR
        error = str(exc)
        log.error("Container startup failed: %s", error)

    log.info(
        "Fork complete. %d finding(s) recorded. Status: %s",
        len(report.findings),
        status,
    )
    report.write(p.output)

    await _finalize_audit_run(new_tid, status, error)

    return AuditResult(report=report, status=status, error=error, thread_id=new_tid)


async def run_audit(
    config: HarnessConfig,
    thread_id: str | None = None,
    user_message: str | None = None,
    github_client: GitHubClient | None = None,
) -> AuditResult:
    """Run a full security audit driven by the threat model."""
    harness = Harness(config)
    threat_model = harness.load_threat_model()
    report = SarifReport()

    log.info(
        "Loaded threat model: %d components, %d scenarios",
        len(threat_model.components),
        len(threat_model.threat_scenarios),
    )

    postgres_url = get_postgres_url()
    async with (
        AsyncPostgresSaver.from_conn_string(postgres_url) as checkpointer,
        AsyncPostgresStore.from_conn_string(postgres_url) as store,
    ):
        await checkpointer.setup()
        await store.setup()
        return await _run_audit_inner(
            harness,
            config,
            threat_model,
            report,
            thread_id,
            checkpointer,
            store,
            user_message,
            github_client=github_client,
        )


async def _run_audit_inner(
    harness: Harness,
    config: HarnessConfig,
    threat_model: ThreatModel,
    report: SarifReport,
    thread_id: str | None,
    checkpointer: BaseCheckpointSaver,
    store: BaseStore,
    user_message: str | None = None,
    github_client: GitHubClient | None = None,
) -> AuditResult:
    p = config.profile
    tid = thread_id or uuid.uuid4().hex[:12]
    log.info("Session thread_id: %s", tid)

    audit_run_id = await _create_audit_run(config, tid, thread_id)

    # Look up existing container for resume
    existing_container_id = await _get_container_id(tid)
    log.info("Starting container: %s (code_dir: %s)", p.image, p.code_dir)

    try:
        with harness.start_environment(container_id=existing_container_id) as execution:
            cwd = execution.exec(["pwd"], timeout=5)
            log.info("Container cwd: %s", cwd.stdout.strip())
            # Store container ID for future resumes
            await _save_container_id(tid, execution.container.id)
            repo_path = await _capture_git_info(execution, audit_run_id)

            agent = _build_agent(
                config,
                execution,
                report,
                threat_model,
                audit_run_id,
                tid,
                repo_path,
                checkpointer,
                store,
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
        await _finalize_audit_run(tid, status, error)
        raise
    except Exception as exc:
        status = AuditStatus.ERROR
        error = str(exc)
        log.error("Container startup failed: %s", error)

    log.info(
        "Audit finished. %d finding(s) recorded. Status: %s",
        len(report.findings),
        status,
    )
    report.write(p.output)

    await _finalize_audit_run(tid, status, error)

    return AuditResult(report=report, status=status, error=error, thread_id=tid)


async def _get_container_id(tid: str) -> str | None:
    """Look up the container ID for a thread from the DB."""
    try:
        async with async_session() as s:
            row = (
                await s.execute(
                    select(AuditThread.container_id).where(AuditThread.thread_id == tid)
                )
            ).scalar_one_or_none()
        return row or None
    except Exception:
        return None


async def _save_container_id(tid: str, container_id: str) -> None:
    """Store the container ID on the thread."""
    try:
        async with async_session() as s:
            await s.execute(
                update(AuditThread)
                .where(AuditThread.thread_id == tid)
                .values(container_id=container_id)
            )
            await s.commit()
    except Exception as exc:
        log.warning("Failed to save container_id: %s", exc)


async def _capture_git_info(execution, audit_run_id: int) -> str:
    """Run git commands in the container and store repo URL + commit on the AuditRun.

    Returns the repo path (e.g. "KittyCAD/engine").
    Raises RuntimeError if git info cannot be retrieved or the remote
    is not a https://github.com URL.
    """
    remote_result = execution.exec(["git", "remote", "get-url", "origin"], timeout=5)
    if not remote_result.ok:
        raise RuntimeError(f"Failed to get git remote: {remote_result.stderr.strip()}")
    git_remote = remote_result.stdout.strip()

    parsed = urlparse(git_remote)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise RuntimeError(
            f"Git remote must be a https://github.com URL, got: {git_remote}"
        )

    repo_path = parsed.path.removesuffix(".git").strip("/")
    github_repo_url = f"https://github.com/{repo_path}"

    head_result = execution.exec(["git", "rev-parse", "HEAD"], timeout=5)
    if not head_result.ok:
        raise RuntimeError(f"Failed to get git HEAD: {head_result.stderr.strip()}")
    git_commit = head_result.stdout.strip()

    async with async_session() as s:
        await s.execute(
            update(AuditRun)
            .where(AuditRun.id == audit_run_id)
            .values(github_repo_url=github_repo_url, git_commit=git_commit)
        )
        await s.commit()
    log.info("Git info: %s @ %s", github_repo_url, git_commit[:12])
    return repo_path


async def _get_or_create_profile(session, config: HarnessConfig) -> AuditProfile:
    """Get or create an AuditProfile for this config. CLI runs get jit=True."""
    profile = (
        await session.execute(
            select(AuditProfile).where(AuditProfile.name == config.profile.name)
        )
    ).scalar_one_or_none()
    if profile is None:
        profile = AuditProfile(
            name=config.profile.name,
            profile_toml=config.profile_toml,
            jit=True,
        )
        session.add(profile)
        await session.flush()
    elif profile.profile_toml != config.profile_toml:
        profile.profile_toml = config.profile_toml
        await session.flush()
    return profile


async def _create_audit_run(
    config: HarnessConfig,
    tid: str,
    resume_thread_id: str | None,
) -> int:
    """Create or resume an AuditRun, register the thread. Returns audit_run.id."""
    async with async_session() as s:
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
                db_profile = await _get_or_create_profile(s, config)
                audit_run = AuditRun(
                    profile_id=db_profile.id,
                    profile_toml=config.profile_toml,
                    container_image=config.profile.image,
                    model_name=config.profile.agent.model,
                )
                s.add(audit_run)
                await s.flush()
        else:
            db_profile = await _get_or_create_profile(s, config)
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
    tid: str | None, status: AuditStatus, error: str | None
) -> None:
    """Update the thread status and the run's finished_at."""
    if not tid:
        return
    try:
        async with async_session() as s:
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
