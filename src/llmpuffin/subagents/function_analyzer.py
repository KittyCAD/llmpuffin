"""Function analyzer subagent — ultra-granular per-function security analysis."""

from typing import Callable

from llmpuffin.subagents._constants import MAIN_AGENT_TOOLS
from llmpuffin.subagents._utils import load_agent_md

TOOLS = MAIN_AGENT_TOOLS


def function_analyzer(tools: dict[str, Callable]) -> dict:
    return {
        "name": "function-analyzer",
        "description": (
            "Performs ultra-granular per-function deep analysis for security audit "
            "context building. Use when analyzing dense functions, data-flow chains, "
            "cryptographic implementations, or state machines."
        ),
        "system_prompt": load_agent_md(
            "vendor/trailofbits-skills/plugins/audit-context-building/agents/function-analyzer.md"
        ),
        "tools": [tools[name] for name in TOOLS],
    }
