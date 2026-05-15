"""Function analyzer subagent — ultra-granular per-function security analysis."""

from llmpuffin.subagents._utils import load_agent_md

FUNCTION_ANALYZER = {
    "name": "function-analyzer",
    "description": (
        "Performs ultra-granular per-function deep analysis for security audit "
        "context building. Use when analyzing dense functions, data-flow chains, "
        "cryptographic implementations, or state machines."
    ),
    "system_prompt": load_agent_md(
        "vendor/trailofbits-skills/plugins/audit-context-building/agents/function-analyzer.md"
    ),
}
