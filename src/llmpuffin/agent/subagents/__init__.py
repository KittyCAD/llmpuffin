"""Subagent definitions for the audit agent.

Each subagent is built from the shared tools dict via a factory function, so
tools can be scoped per-subagent.
"""

from typing import Callable

from llmpuffin.agent.subagents._constants import MAIN_AGENT_TOOLS
from llmpuffin.agent.subagents.finding_validator import finding_validator
from llmpuffin.agent.subagents.function_analyzer import function_analyzer
from llmpuffin.agent.subagents.threat_model_auditor import threat_model_auditor

__all__ = ["MAIN_AGENT_TOOLS", "build_subagents"]


def build_subagents(tools: dict[str, Callable]) -> list[dict]:
    return [
        function_analyzer(tools),
        threat_model_auditor(tools),
        finding_validator(tools),
    ]
