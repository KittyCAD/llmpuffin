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

from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StoreBackend
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.errors import GraphRecursionError

from llmpuffin.backend import ContainerBackend
from llmpuffin.db import get_postgres_url, setup as setup_django
from llmpuffin.harness import Harness, HarnessConfig
from llmpuffin.sarif import SarifReport
from llmpuffin.threat_model import ThreatModel
from llmpuffin.log import log
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


async def fork_audit(
    config: HarnessConfig,
    source_thread_id: str,
    user_message: str,
    model_name: str = "claude-sonnet-4-20250514",
) -> AuditResult:
    """Fork from an existing thread and continue with a new message.

    Creates a new thread, copies the checkpoint state from source_thread_id
    via update_state, then continues the audit with user_message.
    """
    setup_django()

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
            harness, config, threat_model, report, model_name,
            source_thread_id, user_message, checkpointer, store,
        )


async def _fork_audit_inner(
    harness: Harness,
    config: HarnessConfig,
    threat_model: ThreatModel,
    report: SarifReport,
    model_name: str,
    source_thread_id: str,
    user_message: str,
    checkpointer: object,
    store: object,
) -> AuditResult:
    new_tid = uuid.uuid4().hex[:12]
    log.info("Forking thread %s → %s", source_thread_id, new_tid)

    from asgiref.sync import sync_to_async
    audit_run_id = await sync_to_async(_create_audit_run)(
        config, model_name, new_tid, source_thread_id,
    )

    status = AuditStatus.COMPLETED
    error: str | None = None

    with harness.start_environment() as execution:
        container_backend = ContainerBackend(execution)
        routes: dict = {}

        harness_name = config.name
        memory_backend = StoreBackend(
            store=store,
            namespace=lambda rt, _n=harness_name: ("llmpuffin", _n, "memories"),
        )
        routes["/memories/"] = memory_backend

        skills_list: list[str] = []
        if config.skills_dir and config.skills_dir.is_dir():
            from deepagents.backends.utils import create_file_data
            from langgraph.store.memory import InMemoryStore as _InMemoryStore
            skills_store = _InMemoryStore()
            skills_backend = StoreBackend(store=skills_store, namespace=lambda rt: ("skills",))
            for file_path in sorted(config.skills_dir.rglob("*")):
                if not file_path.is_file():
                    continue
                rel = file_path.relative_to(config.skills_dir)
                store_key = f"/skills/{rel}"
                try:
                    content = file_path.read_text()
                except (UnicodeDecodeError, OSError):
                    continue
                skills_store.put(
                    namespace=("skills",),
                    key=store_key,
                    value=create_file_data(content),
                )
            routes["/skills/"] = skills_backend
            skills_list = ["/skills/"]

        backend = CompositeBackend(
            default=container_backend,
            routes=routes,
        )

        tools = make_tools(report, threat_model, audit_run_id=audit_run_id)

        middleware = []
        if config.interpreter:
            from langchain_quickjs import CodeInterpreterMiddleware
            middleware.append(CodeInterpreterMiddleware())

        interrupt_on_config = None
        if config.interrupt_on:
            interrupt_on_config = {name: True for name in config.interrupt_on}

        agent = create_deep_agent(
            model=f"anthropic:{model_name}",
            tools=tools,
            backend=backend,
            store=store,
            checkpointer=checkpointer,
            middleware=middleware,
            interrupt_on=interrupt_on_config,
            skills=skills_list or None,
            subagents=[_FUNCTION_ANALYZER_SUBAGENT],
            system_prompt=SYSTEM_PROMPT,
        )

        # Read state from source thread and fork to new thread
        source_config = {"configurable": {"thread_id": source_thread_id}}
        state = await agent.aget_state(source_config)

        # Get existing messages from the source thread
        messages = state.values.get("messages", [])
        messages.append({"role": "user", "content": user_message})

        # Start the new thread with the forked messages
        new_config: dict = {
            "recursion_limit": config.max_iterations,
            "configurable": {"thread_id": new_tid},
        }

        try:
            async for chunk in agent.astream(
                {"messages": messages},
                config=new_config,
                stream_mode="updates",
            ):
                for node, updates in chunk.items():
                    if updates is None:
                        continue
                    for msg in updates.get("messages", []):
                        if isinstance(msg, AIMessage):
                            if msg.tool_calls:
                                for tc in msg.tool_calls:
                                    log.info("  tool: %s(%s)", tc["name"],
                                             _truncate(str(tc["args"]), 120))
                            elif msg.content:
                                log.info("  agent: %s", _truncate(str(msg.content), 200))
                        elif isinstance(msg, ToolMessage):
                            log.debug("  result: %s", _truncate(str(msg.content), 200))
        except GraphRecursionError:
            status = AuditStatus.RECURSION_LIMIT
            error = f"Agent hit recursion limit ({config.max_iterations} iterations)"
            log.warning("  %s", error)
        except Exception as exc:
            status = AuditStatus.ERROR
            error = str(exc)
            log.error("  Agent error: %s", error)

    log.info("Fork complete. %d finding(s) recorded. Status: %s",
             len(report.findings), status)
    report.write(config.output_path)

    from asgiref.sync import sync_to_async
    await sync_to_async(_finalize_audit_run)(new_tid, status, error)

    return AuditResult(report=report, status=status, error=error, thread_id=new_tid)


async def run_audit(
    config: HarnessConfig,
    model_name: str = "claude-sonnet-4-20250514",
    thread_id: str | None = None,
    user_message: str | None = None,
) -> AuditResult:
    """Run a full security audit driven by the threat model.

    The agent drives its own investigation: it fetches the threat model,
    chooses which scenarios to investigate, examines code, and records
    findings — all via tools.

    Args:
        config: Harness configuration.
        model_name: LLM model identifier.
        thread_id: Session ID for resumable checkpointing. If None and
                   postgres is configured, a new ID is generated.
    """
    setup_django()

    harness = Harness(config)
    threat_model = harness.load_threat_model()
    report = SarifReport()

    log.info("Loaded threat model: %d components, %d scenarios",
             len(threat_model.components), len(threat_model.threat_scenarios))

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
            harness, config, threat_model, report, model_name,
            thread_id, checkpointer, store, user_message,
        )


async def _run_audit_inner(
    harness: Harness,
    config: HarnessConfig,
    threat_model: ThreatModel,
    report: SarifReport,
    model_name: str,
    thread_id: str | None,
    checkpointer: object | None,
    store: object | None,
    user_message: str | None = None,
) -> AuditResult:
    tid = thread_id or uuid.uuid4().hex[:12]
    log.info("Session thread_id: %s", tid)

    # Create the AuditRun record immediately so it's visible as "running"
    from asgiref.sync import sync_to_async
    audit_run_id = await sync_to_async(_create_audit_run)(config, model_name, tid, thread_id)

    log.info("Starting container: %s", config.container_image)
    status = AuditStatus.COMPLETED
    error: str | None = None

    with harness.start_environment() as execution:
        container_backend = ContainerBackend(execution)
        routes: dict = {}

        # Memory backend via postgres store, scoped to this harness config name
        # TODO: should checkpoints also be scoped per harness name? Currently
        # thread_ids are globally unique so there's no collision, but scoping
        # would make it easier to list/clean up checkpoints per harness.
        harness_name = config.name
        memory_backend = StoreBackend(
            store=store,
            namespace=lambda rt, _n=harness_name: ("llmpuffin", _n, "memories"),
        )
        routes["/memories/"] = memory_backend

        # Load skills from disk into an in-memory store, mirroring the dir structure
        skills_list: list[str] = []
        if config.skills_dir and config.skills_dir.is_dir():
            from deepagents.backends.utils import create_file_data
            from langgraph.store.memory import InMemoryStore as _InMemoryStore
            skills_store = _InMemoryStore()
            skills_backend = StoreBackend(store=skills_store, namespace=lambda rt: ("skills",))
            for file_path in sorted(config.skills_dir.rglob("*")):
                if not file_path.is_file():
                    continue
                rel = file_path.relative_to(config.skills_dir)
                store_key = f"/skills/{rel}"
                try:
                    content = file_path.read_text()
                except (UnicodeDecodeError, OSError):
                    continue  # skip binary files
                skills_store.put(
                    namespace=("skills",),
                    key=store_key,
                    value=create_file_data(content),
                )
            routes["/skills/"] = skills_backend
            skills_list = ["/skills/"]
            log.info("Loaded skills from %s", config.skills_dir)

        backend = CompositeBackend(
            default=container_backend,
            routes=routes,
        )

        tools = make_tools(report, threat_model, audit_run_id=audit_run_id)

        middleware = []
        if config.interpreter:
            from langchain_quickjs import CodeInterpreterMiddleware
            middleware.append(CodeInterpreterMiddleware())

        # Build interrupt_on config from tool names
        interrupt_on_config = None
        if config.interrupt_on:
            interrupt_on_config = {name: True for name in config.interrupt_on}

        agent = create_deep_agent(
            model=f"anthropic:{model_name}",
            tools=tools,
            backend=backend,
            store=store,
            checkpointer=checkpointer,
            middleware=middleware,
            interrupt_on=interrupt_on_config,
            skills=skills_list or None,
            subagents=[_FUNCTION_ANALYZER_SUBAGENT],
            system_prompt=SYSTEM_PROMPT,
        )

        # Build run config
        run_config: dict = {"recursion_limit": config.max_iterations}
        if tid:
            run_config["configurable"] = {"thread_id": tid}

        # Determine the message to send
        if user_message:
            msg = user_message
        elif thread_id:
            msg = "Continue the security audit."
        else:
            msg = "Begin the security audit."

        try:
            async for chunk in agent.astream(
                {"messages": [{"role": "user", "content": msg}]},
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
                                    log.info("  tool: %s(%s)", tc["name"],
                                             _truncate(str(tc["args"]), 120))
                            elif msg.content:
                                log.info("  agent: %s", _truncate(str(msg.content), 200))
                        elif isinstance(msg, ToolMessage):
                            log.debug("  result: %s", _truncate(str(msg.content), 200))
        except GraphRecursionError:
            status = AuditStatus.RECURSION_LIMIT
            error = f"Agent hit recursion limit ({config.max_iterations} iterations)"
            log.warning("  %s", error)
        except Exception as exc:
            status = AuditStatus.ERROR
            error = str(exc)
            log.error("  Agent error: %s", error)

    # Store is persisted automatically via AsyncPostgresStore

    log.info("Container stopped. %d finding(s) recorded. Status: %s",
             len(report.findings), status)
    report.write(config.output_path)

    # Persist to Django DB
    from asgiref.sync import sync_to_async
    await sync_to_async(_finalize_audit_run)(tid, status, error)

    return AuditResult(report=report, status=status, error=error, thread_id=tid)


def _create_audit_run(
    config: HarnessConfig, model_name: str, tid: str, resume_thread_id: str | None,
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
                audit_run = AuditRun.objects.create(
                    config_toml=config.config_toml,
                    container_image=config.container_image,
                    model_name=model_name,
                    status=AuditStatus.RUNNING.value,
                )
        else:
            audit_run = AuditRun.objects.create(
                config_toml=config.config_toml,
                container_image=config.container_image,
                model_name=model_name,
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


def _finalize_audit_run(tid: str | None, status: AuditStatus, error: str | None) -> None:
    """Update the AuditRun status at the end of a run. Findings are already persisted."""
    if not tid:
        return
    try:
        from django.utils import timezone
        from llmpuffin.models import AuditThread

        thread = AuditThread.objects.filter(thread_id=tid).select_related("audit_run").first()
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


def _load_agent_md(path: str) -> str:
    """Load an agent .md file and strip YAML frontmatter."""
    from pathlib import Path
    text = Path(path).read_text()
    if text.startswith("---"):
        end = text.index("---", 3)
        return text[end + 3:].strip()
    return text


_FUNCTION_ANALYZER_SUBAGENT = {
    "name": "function-analyzer",
    "description": (
        "Performs ultra-granular per-function deep analysis for security audit "
        "context building. Use when analyzing dense functions, data-flow chains, "
        "cryptographic implementations, or state machines."
    ),
    "system_prompt": _load_agent_md(
        "vendor/trailofbits-skills/plugins/audit-context-building/agents/function-analyzer.md"
    ),
}
