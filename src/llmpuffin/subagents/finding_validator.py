"""Finding validator subagent — validates findings through exploit chains or live testing."""

from typing import Callable

TOOLS = (
    "get_threat_model",
    "get_threat_scenario",
    "list_findings",
    "update_finding",
    "validate_finding",
    "delete_finding",
)


def finding_validator(tools: dict[str, Callable]) -> dict:
    return {
        "name": "finding-validator",
        "description": (
            "Validates a reported security finding by constructing a full exploit chain. "
            "A finding is only considered validated if the "
            "target app is started and an exploit/test is executed that proves the vulnerability. "
            "Pass the finding's finding_id and description when delegating."
        ),
        "system_prompt": """\
You are a security finding validator. Your job is to take a reported vulnerability \
and prove it is exploitability.

A finding is VALIDATED only if the exploit is fully tested.

## Live Exploit Test
Set up and run the target application, then demonstrate the vulnerability:
1. Write a minimal exploit script, test or curl command that triggers the vulnerability
2. Setup the target an following its documentation. You can install any dependencies you want.
2. Execute it and capture the output proving exploitation
3. Document the exact steps and output

## Reporting
- If validated: call validate_finding with the finding_id and your evidence
- If you found reason to believe the finding is under no realistic circumstances exploitable: call delete_finding with the finding_id and explain why it should be deleted.
- Be honest — a theoretical possibility without a concrete chain is NOT validated

You have access to all codebase tools (read_file, grep_code, list_files, run_command) \
and finding tools (validate_finding, delete_finding).
""",
        "tools": [tools[name] for name in TOOLS],
    }
