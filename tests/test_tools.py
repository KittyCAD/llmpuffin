"""Tests for tool documentation and schema availability."""

from __future__ import annotations

from unittest.mock import MagicMock

from langchain_core.tools import StructuredTool

from llmpuffin.threat_model import ThreatModel
from llmpuffin.tools import make_tools


def _make_tools() -> dict:
    """Create tools with minimal mocks."""
    threat_model = MagicMock(spec=ThreatModel)
    threat_model.components = []
    threat_model.connections = []
    threat_model.threat_scenarios = []
    return make_tools(
        threat_model=threat_model,
        audit_run_id=1,
    )


class TestToolDocumentation:
    def test_all_tools_have_docstrings(self):
        """Every tool function must have a docstring (used as LLM description)."""
        tools = _make_tools()
        for name, fn in tools.items():
            doc = fn.__doc__
            assert doc, f"Tool '{name}' is missing a docstring"
            assert len(doc.strip()) > 20, (
                f"Tool '{name}' docstring is too short to be useful: {doc!r}"
            )

    def test_all_tools_have_names(self):
        """Tool names should match the dict keys."""
        tools = _make_tools()
        for name, fn in tools.items():
            assert fn.__name__ == name, (
                f"Tool key '{name}' doesn't match function name '{fn.__name__}'"
            )

    def test_tools_wrap_as_structured_tools(self):
        """All tools should be wrappable by LangChain and preserve docstrings."""
        tools = _make_tools()
        for name, fn in tools.items():
            tool = StructuredTool.from_function(fn)
            assert tool.name == name
            assert tool.description, f"Tool '{name}' has empty description after wrapping"
            # LangChain uses the first line of the docstring as description.
            first_line = fn.__doc__.strip().split("\n")[0]
            assert first_line in tool.description, (
                f"Tool '{name}': docstring not used by LangChain. "
                f"Expected '{first_line}' in '{tool.description}'"
            )

    def test_report_finding_has_typed_parameters(self):
        """report_finding should have type-annotated parameters."""
        import inspect

        tools = _make_tools()
        sig = inspect.signature(tools["report_finding"])
        params = set(sig.parameters.keys())

        expected = {"title", "severity", "difficulty",
                    "description", "exploit_scenario", "recommendations"}
        assert expected <= params, f"Missing params: {expected - params}"

        # All expected params should have type annotations
        for name in expected:
            p = sig.parameters[name]
            assert p.annotation != inspect.Parameter.empty, (
                f"Parameter '{name}' on report_finding has no type annotation"
            )

    def test_expected_tools_exist(self):
        """Verify the expected set of tools is created."""
        tools = _make_tools()
        expected = {
            "get_threat_model",
            "get_threat_scenario",
            "report_finding",
            "list_findings",
            "update_finding",
            "delete_finding",
            "validate_finding",
            "get_pull_request",
            "get_commit",
            "finding_attach_file",
            "finding_list_attached_files",
        }
        assert set(tools.keys()) == expected
