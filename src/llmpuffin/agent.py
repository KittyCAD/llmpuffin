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

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StoreBackend
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.stores import BaseStore
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.errors import GraphRecursionError

from llmpuffin.backend import ContainerBackend
from llmpuffin.db import get_postgres_url
from llmpuffin.harness import Harness, HarnessConfig
from llmpuffin.sarif import SarifReport
from llmpuffin.threat_model import ThreatModel
from llmpuffin.log import log
from llmpuffin.subagents import ALL as SUBAGENTS
from llmpuffin.tools import make_tools


class AuditStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    RECURSION_LIMIT = "recursion_limit"
    ERROR = "error"


@dataclass
class AuditResult:
    report: SarifReport
    status: AuditStatus
    error: str | None = None
    thread_id: str | None = None


SYSTEM_PROMPT = """\
You are a security auditor performing a code review guided by a threat model.
The source code is in the current working directory of a container.

Start by invoking the skill audit-context-building.

Your workflow:
1. Call get_threat_model to understand the system architecture and threat scenarios
2. For each threat scenario, call get_threat_scenario to get full details
3. Use the codebase tools (read_file, grep_code, list_files, run_command) to investigate
4. Call report_finding for each confirmed vulnerability

Guidelines:
- Work through scenarios systematically, prioritizing high severity first
- Provide concrete evidence: file paths, line numbers, code snippets
- Distinguish between confirmed vulnerabilities and potential concerns
- Check whether existing mitigations are properly implemented
- Call report_finding as soon as you confirm a vulnerability — don't wait until the end
- If /memories/ is available, read it for context from prior audits and write notes for future runs
"""


def _build_agent(
    config: HarnessConfig,
    execution,
    report: SarifReport,
    threat_model: ThreatModel,
    audit_run_id: int | None,
    thread_id: str,
    checkpointer: BaseCheckpointSaver,
    store: BaseStore,
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
        from deepagents.backends.utils import create_file_data
        from langgraph.store.memory import InMemoryStore as _InMemoryStore

        skills_store = _InMemoryStore()
        skills_backend = StoreBackend(
            store=skills_store, namespace=lambda rt: ("skills",)
        )
        for file_path in sorted(agent_cfg.skills_dir.rglob("*")):
            if not file_path.is_file():
                continue
            rel = file_path.relative_to(agent_cfg.skills_dir)
            store_key = f"/skills/{rel}"
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
        report, threat_model, audit_run_id=audit_run_id, thread_id=thread_id
    )

    middleware = []
    if agent_cfg.interpreter:
        from langchain_quickjs import CodeInterpreterMiddleware

        middleware.append(CodeInterpreterMiddleware())

    interrupt_on_config = None
    if agent_cfg.interrupt_on:
        interrupt_on_config = {name: True for name in agent_cfg.interrupt_on}

    return create_deep_agent(
        model=f"anthropic:{agent_cfg.model}",
        tools=tools,
        backend=backend,
        store=store,
        checkpointer=checkpointer,
        middleware=middleware,
        interrupt_on=interrupt_on_config,
        skills=skills_list or None,
        subagents=SUBAGENTS,
        system_prompt=SYSTEM_PROMPT,
    )


async def _stream_agent(agent, input_messages, run_config, max_iterations: int):
    """Stream agent execution and log progress. Returns (status, error)."""
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
                for msg in updates.get("messages", []):
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
) -> AuditResult:
    """Fork from an existing thread and continue with a new message."""
    harness = Harness(config)
    threat_model = harness.load_threat_model()
    report = SarifReport()

    postgres_url = get_postgres_url()
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
    from langgraph.store.postgres.aio import AsyncPostgresStore

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
) -> AuditResult:
    p = config.profile
    new_tid = uuid.uuid4().hex[:12]
    log.info("Forking thread %s → %s", source_thread_id, new_tid)

    from asgiref.sync import sync_to_async

    audit_run_id = await sync_to_async(_create_audit_run)(
        config,
        new_tid,
        source_thread_id,
    )

    try:
        with harness.start_environment() as execution:
            agent = _build_agent(
                config,
                execution,
                report,
                threat_model,
                audit_run_id,
                new_tid,
                checkpointer,
                store,
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

    from asgiref.sync import sync_to_async

    await sync_to_async(_finalize_audit_run)(new_tid, status, error)

    return AuditResult(report=report, status=status, error=error, thread_id=new_tid)


async def run_audit(
    config: HarnessConfig,
    thread_id: str | None = None,
    user_message: str | None = None,
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
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
    from langgraph.store.postgres.aio import AsyncPostgresStore

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
) -> AuditResult:
    p = config.profile
    tid = thread_id or uuid.uuid4().hex[:12]
    log.info("Session thread_id: %s", tid)

    from asgiref.sync import sync_to_async

    audit_run_id = await sync_to_async(_create_audit_run)(config, tid, thread_id)

    log.info("Starting container: %s", p.image)

    try:
        with harness.start_environment() as execution:
            agent = _build_agent(
                config,
                execution,
                report,
                threat_model,
                audit_run_id,
                tid,
                checkpointer,
                store,
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

    from asgiref.sync import sync_to_async

    await sync_to_async(_finalize_audit_run)(tid, status, error)

    return AuditResult(report=report, status=status, error=error, thread_id=tid)


def _get_or_create_profile(config: HarnessConfig) -> object:
    """Get or create an AuditProfile for this config. CLI runs get jit=True."""
    from llmpuffin.models import AuditProfile

    profile, _ = AuditProfile.objects.get_or_create(
        name=config.profile.name,
        defaults={"profile_toml": config.profile_toml, "jit": True},
    )
    if profile.profile_toml != config.profile_toml:
        profile.profile_toml = config.profile_toml
        profile.save(update_fields=["profile_toml"])
    return profile


def _create_audit_run(
    config: HarnessConfig,
    tid: str,
    resume_thread_id: str | None,
) -> int | None:
    """Create or resume an AuditRun, register the thread. Returns audit_run.pk."""
    try:
        from llmpuffin.models import AuditRun, AuditThread

        if resume_thread_id:
            old_thread = AuditThread.objects.filter(thread_id=resume_thread_id).first()
            if old_thread:
                audit_run = old_thread.audit_run
                audit_run.status = AuditStatus.RUNNING.value
                audit_run.error = ""
                audit_run.save()
            else:
                db_profile = _get_or_create_profile(config)
                audit_run = AuditRun.objects.create(
                    profile=db_profile,
                    profile_toml=config.profile_toml,
                    container_image=config.profile.image,
                    model_name=config.profile.agent.model,
                    status=AuditStatus.RUNNING.value,
                )
        else:
            db_profile = _get_or_create_profile(config)
            audit_run = AuditRun.objects.create(
                profile=db_profile,
                profile_toml=config.profile_toml,
                container_image=config.profile.image,
                model_name=config.profile.agent.model,
                status=AuditStatus.RUNNING.value,
            )

        AuditThread.objects.get_or_create(
            thread_id=tid,
            defaults={"audit_run": audit_run},
        )
        return audit_run.pk
    except Exception as exc:
        log.warning("Failed to create audit run in DB: %s", exc)
        return None


def _finalize_audit_run(
    tid: str | None, status: AuditStatus, error: str | None
) -> None:
    """Update the AuditRun status at the end of a run. Findings are already persisted."""
    if not tid:
        return
    try:
        from django.utils import timezone
        from llmpuffin.models import AuditThread

        thread = (
            AuditThread.objects.filter(thread_id=tid)
            .select_related("audit_run")
            .first()
        )
        if not thread:
            log.warning("AuditThread %s not found in DB", tid)
            return

        audit_run = thread.audit_run
        audit_run.status = status.value
        audit_run.error = error or ""
        audit_run.finished_at = timezone.now()
        audit_run.save()
    except Exception as exc:
        log.warning("Failed to finalize audit run in DB: %s", exc)


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", " ")
    return s[:n] + "..." if len(s) > n else s
