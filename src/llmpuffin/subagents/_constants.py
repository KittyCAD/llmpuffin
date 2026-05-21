"""Shared constants for subagent definitions.

Kept in a leaf module so subagents and the main agent can both import
without cycles.
"""

# Tools available to the main agent (which mostly delegates to subagents).
# Threat-model tools are scoped to threat-model-auditor only.
MAIN_AGENT_TOOLS = (
    "list_findings",
    "report_finding",
    "validate_finding",
    "update_finding",
    "delete_finding",
    "finding_attach_file",
    "finding_list_attached_files",
)
