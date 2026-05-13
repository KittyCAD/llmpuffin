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

from dataclasses import dataclass
from enum import StrEnum

from deepagents import create_deep_agent
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.errors import GraphRecursionError

from llmpuffin.backend import ContainerBackend
from llmpuffin.harness import Harness, HarnessConfig
from llmpuffin.sarif import SarifReport
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
"""


async def run_audit(
    config: HarnessConfig,
    model_name: str = "claude-sonnet-4-20250514",
) -> AuditResult:
    """Run a full security audit driven by the threat model.

    The agent drives its own investigation: it fetches the threat model,
    chooses which scenarios to investigate, examines code, and records
    findings — all via tools.
    """
    harness = Harness(config)
    threat_model = harness.load_threat_model()
    report = SarifReport()

    log.info("Loaded threat model: %d components, %d scenarios",
             len(threat_model.components), len(threat_model.threat_scenarios))

    log.info("Starting container: %s", config.container_image)
    status = AuditStatus.COMPLETED
    error: str | None = None

    with harness.start_environment() as execution:
        backend = ContainerBackend(execution)
        tools = make_tools(report, threat_model)
        agent = create_deep_agent(
            model=f"anthropic:{model_name}",
            tools=tools,
            backend=backend,
            system_prompt=SYSTEM_PROMPT,
        )

        try:
            async for chunk in agent.astream(
                {"messages": [{"role": "user", "content": "Begin the security audit."}]},
                config={"recursion_limit": config.max_iterations},
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

    log.info("Container stopped. %d finding(s) recorded. Status: %s",
             len(report.findings), status)
    report.write(config.output_path)
    return AuditResult(report=report, status=status, error=error)


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", " ")
    return s[:n] + "..." if len(s) > n else s
