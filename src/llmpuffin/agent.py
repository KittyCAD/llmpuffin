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
from llmpuffin.store import load_store, save_store
from llmpuffin.harness import Harness, HarnessConfig
from llmpuffin.sarif import SarifReport
from llmpuffin.threat_model import ThreatModel
from llmpuffin.log import log
from llmpuffin.tools import make_tools


class AuditStatus(StrEnum):
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


async def run_audit(
    config: HarnessConfig,
    model_name: str = "claude-sonnet-4-20250514",
    thread_id: str | None = None,
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
    harness = Harness(config)
    threat_model = harness.load_threat_model()
    report = SarifReport()

    log.info("Loaded threat model: %d components, %d scenarios",
             len(threat_model.components), len(threat_model.threat_scenarios))

    if config.postgres_connstring:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
        async with AsyncPostgresSaver.from_conn_string(config.postgres_connstring) as checkpointer:
            await checkpointer.setup()
            return await _run_audit_inner(
                harness, config, threat_model, report, model_name, thread_id, checkpointer,
            )
    else:
        return await _run_audit_inner(
            harness, config, threat_model, report, model_name, thread_id, None,
        )


async def _run_audit_inner(
    harness: Harness,
    config: HarnessConfig,
    threat_model: ThreatModel,
    report: SarifReport,
    model_name: str,
    thread_id: str | None,
    checkpointer: object | None,
) -> AuditResult:
    tid = thread_id or (uuid.uuid4().hex[:12] if checkpointer else None)
    if tid:
        log.info("Session thread_id: %s", tid)

    log.info("Starting container: %s", config.container_image)
    status = AuditStatus.COMPLETED
    error: str | None = None

    with harness.start_environment() as execution:
        container_backend = ContainerBackend(execution)

        store = None
        if config.store_dir:
            store = load_store(config.store_dir)
            memory_backend = StoreBackend(store=store)
            backend = CompositeBackend(
                default=container_backend,
                routes={"/memories/": memory_backend},
            )
        else:
            backend = container_backend

        tools = make_tools(report, threat_model)

        middleware = []
        if config.interpreter:
            from langchain_quickjs import CodeInterpreterMiddleware
            middleware.append(CodeInterpreterMiddleware())

        agent = create_deep_agent(
            model=f"anthropic:{model_name}",
            tools=tools,
            backend=backend,
            store=store,
            checkpointer=checkpointer,
            middleware=middleware,
            system_prompt=SYSTEM_PROMPT,
        )

        # Build run config
        run_config: dict = {"recursion_limit": config.max_iterations}
        if tid:
            run_config["configurable"] = {"thread_id": tid}

        # If resuming, send "Continue" instead of starting fresh
        if thread_id:
            user_message = "Continue the security audit."
        else:
            user_message = "Begin the security audit."

        try:
            async for chunk in agent.astream(
                {"messages": [{"role": "user", "content": user_message}]},
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

    if store and config.store_dir:
        save_store(store, config.store_dir)
        log.info("Store saved to %s", config.store_dir)

    log.info("Container stopped. %d finding(s) recorded. Status: %s",
             len(report.findings), status)
    report.write(config.output_path)

    # Persist to Django DB
    _save_to_db(config, model_name, tid, status, error, report)

    return AuditResult(report=report, status=status, error=error, thread_id=tid)


def _save_to_db(
    config: HarnessConfig,
    model_name: str,
    tid: str | None,
    status: AuditStatus,
    error: str | None,
    report: SarifReport,
) -> None:
    """Persist the audit run and findings to Django DB."""
    if not tid:
        return
    try:
        from llmpuffin.db import setup
        setup()

        from django.utils import timezone
        from llmpuffin.models import AuditRun, Finding, FindingLocation

        audit_run, _ = AuditRun.objects.update_or_create(
            thread_id=tid,
            defaults={
                "container_image": config.container_image,
                "model_name": model_name,
                "status": status.value,
                "error": error or "",
                "finished_at": timezone.now(),
            },
        )

        for f in report.findings:
            finding = Finding.objects.create(
                audit_run=audit_run,
                rule_id=f.rule_id,
                scenario_id=f.threat_scenario_ids[0] if f.threat_scenario_ids else "",
                severity=f.severity,
                difficulty=f.difficulty,
                level=f.level,
                description=f.description,
                impact=f.impact,
                recommendations=f.recommendations,
            )
            for loc in f.locations:
                FindingLocation.objects.create(
                    finding=finding,
                    file_path=loc.file_path,
                    start_line=loc.start_line,
                    end_line=loc.end_line,
                )

        log.info("Saved audit run %s with %d findings to DB", tid, len(report.findings))
    except Exception as exc:
        log.warning("Failed to save to DB: %s", exc)


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", " ")
    return s[:n] + "..." if len(s) > n else s
