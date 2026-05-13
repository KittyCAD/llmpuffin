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

from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain.agents import create_agent

from llmpuffin.harness import Harness, HarnessConfig
from llmpuffin.sarif import SarifReport
from llmpuffin.threat_model import Severity, ThreatModel, ThreatScenario
from llmpuffin.log import log
from llmpuffin.tools import make_tools

# System prompt grounding the agent in its role and the threat model.
# This is the **context engineering** layer of the harness: we dynamically
# curate what the model sees each turn.
SYSTEM_PROMPT = """\
You are a security auditor performing a code review guided by a threat model.
The source code is in the current working directory.

Your task is to investigate specific threat scenarios by examining the codebase
inside a container.  For each scenario you will:

1. Understand the threat scenario and which components/connections are involved
2. Use the provided tools to examine relevant code paths
3. Look for concrete vulnerabilities that match the scenario
4. Use the report_finding tool to record each finding you discover

Guidelines:
- Focus on the specific threat scenario — don't try to find everything at once
- Provide concrete evidence: file paths, line numbers, code snippets
- Distinguish between confirmed vulnerabilities and potential concerns
- Consider the existing mitigations listed in the scenario
- Call report_finding as soon as you confirm a vulnerability — don't wait until the end
- If you find no vulnerabilities for the scenario, explain why
"""


def build_scenario_prompt(
    threat_model: ThreatModel, scenario: ThreatScenario
) -> str:
    """Build a human message with context for investigating one scenario."""
    # Gather relevant components
    components = []
    for cid in scenario.affected_component_ids:
        comp = threat_model.get_component(cid)
        if comp:
            components.append(f"  - {comp.name} ({comp.id}): {comp.description}")

    # Gather relevant connections
    connections = []
    for conn_id in scenario.connection_ids:
        for conn in threat_model.connections:
            if conn.id == conn_id:
                connections.append(
                    f"  - {conn.id}: {conn.source_component_id} → "
                    f"{conn.destination_component_id} ({conn.protocol}): "
                    f"{conn.description}"
                )

    mitigations = "\n".join(f"  - {m}" for m in scenario.mitigations)

    return f"""\
Investigate the following threat scenario:

**{scenario.name}** ({scenario.id})
Category: {scenario.category}
Severity: {scenario.severity}

Description:
{scenario.description}

Affected components:
{chr(10).join(components)}

Relevant connections:
{chr(10).join(connections)}

Existing mitigations to verify:
{mitigations}

Examine the codebase to determine if this threat scenario represents a real
vulnerability. Look at the relevant code paths, check if mitigations are
properly implemented, and report any findings.
"""


async def run_audit(
    config: HarnessConfig,
    model_name: str = "claude-sonnet-4-20250514",
) -> SarifReport:
    """Run a full security audit driven by the threat model.

    This is the main entry point.  It:
      1. Loads the threat model
      2. Starts the audit environment (container)
      3. For each threat scenario, runs the agent
      4. Collects findings into a SARIF report
    """
    harness = Harness(config)
    threat_model = harness.load_threat_model()
    report = SarifReport()

    log.info("Loaded threat model: %d components, %d scenarios",
             len(threat_model.components), len(threat_model.threat_scenarios))

    log.info("Starting container: %s", config.container_image)
    with harness.start_environment() as execution:
        llm = ChatAnthropic(model=model_name)

        scenarios = sorted(
            threat_model.threat_scenarios,
            key=lambda s: _SEVERITY_ORDER.get(s.severity, 3),
        )

        for i, scenario in enumerate(scenarios, 1):
            log.info("[%d/%d] Scenario: %s (%s/%s)",
                     i, len(scenarios), scenario.name, scenario.severity, scenario.category)

            before = len(report.findings)
            tools = make_tools(execution, report, scenario.id)
            agent = create_agent(llm, tools)
            await _run_scenario(agent, threat_model, scenario, config.max_iterations)
            added = len(report.findings) - before
            log.info("  %d finding(s) for scenario %s", added, scenario.id)

    log.info("Container stopped")
    report.write(config.output_path)
    return report


_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.LOW: 1, Severity.INFORMATIONAL: 2}


async def run_single_scenario(
    config: HarnessConfig,
    scenario_id: str,
    model_name: str = "claude-sonnet-4-20250514",
) -> SarifReport:
    """Run the audit for a single threat scenario (useful for testing)."""
    harness = Harness(config)
    threat_model = harness.load_threat_model()
    report = SarifReport()

    scenario = next(
        (s for s in threat_model.threat_scenarios if s.id == scenario_id), None
    )
    if scenario is None:
        raise ValueError(f"Scenario '{scenario_id}' not found in threat model")

    log.info("Starting container: %s", config.container_image)
    with harness.start_environment() as execution:
        llm = ChatAnthropic(model=model_name)
        tools = make_tools(execution, report, scenario.id)
        agent = create_agent(llm, tools)
        await _run_scenario(agent, threat_model, scenario, config.max_iterations)

    log.info("Container stopped")
    report.write(config.output_path)
    return report


async def _run_scenario(
    agent: Any,
    threat_model: ThreatModel,
    scenario: ThreatScenario,
    max_iterations: int,
) -> None:
    """Run agent for one scenario. Findings are recorded via the report_finding tool."""
    scenario_prompt = build_scenario_prompt(threat_model, scenario)
    messages: list[Any] = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=scenario_prompt),
    ]

    async for chunk in agent.astream(
        {"messages": messages},
        config={"recursion_limit": max_iterations},
        stream_mode="updates",
    ):
        for node, updates in chunk.items():
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


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", " ")
    return s[:n] + "..." if len(s) > n else s
