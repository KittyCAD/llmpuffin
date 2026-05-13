"""
LangChain tools that execute inside the AuditExecution container.

These tools form the **tool integration layer** of the harness.
The agent never touches the host — all side effects happen inside
the container.  Each tool wraps AuditExecution methods and returns
string results suitable for LLM consumption.
"""

from __future__ import annotations

from langchain_core.tools import StructuredTool

from llmpuffin.audit_environment import AuditExecution
from llmpuffin.sarif import SarifFinding, SarifLocation, SarifReport


def make_tools(execution: AuditExecution, report: SarifReport, scenario_id: str) -> list[StructuredTool]:
    """Create tool instances bound to a specific AuditExecution and SarifReport."""

    def report_finding(
        severity: str,
        difficulty: str,
        description: str,
        impact: str,
        recommendations: str,
        locations: list[dict] | None = None,
    ) -> str:
        """Record a security finding. Call this for each vulnerability you discover.

        Args:
            severity: How severe the issue is: "high", "medium", "low", or "informational"
            difficulty: How hard it is to exploit: "high", "medium", or "low"
            description: What the vulnerability is and where it occurs. Include code evidence.
            impact: What an attacker could achieve by exploiting this.
            recommendations: Concrete steps to fix or mitigate the issue.
            locations: Optional list of locations, each a dict with "file" (str) and "line" (int).
                       Example: [{"file": "src/main.py", "line": 42}]
        """
        level = {"high": "error", "medium": "warning", "low": "note", "informational": "note"}.get(
            severity, "warning"
        )
        sarif_locations = []
        if locations:
            for loc in locations:
                sarif_locations.append(SarifLocation(
                    file_path=loc["file"],
                    start_line=loc.get("line", 0),
                ))
        finding = SarifFinding(
            rule_id=f"{scenario_id}-{len(report.findings) + 1:03d}",
            description=description,
            impact=impact,
            recommendations=recommendations,
            severity=severity,
            difficulty=difficulty,
            level=level,
            locations=sarif_locations,
            threat_scenario_ids=[scenario_id],
        )
        report.add_finding(finding)
        return f"Finding recorded: {finding.rule_id}"

    def read_file(path: str) -> str:
        """Read the contents of a file in the codebase.

        Args:
            path: File path relative to the code directory (e.g. "src/main.py")
        """
        return execution.read_file(path)

    def grep_code(pattern: str, path: str = ".") -> str:
        """Search the codebase for a regex pattern. Returns matching lines with file:line prefixes.

        Args:
            pattern: Regex pattern to search for
            path: Directory or file to search in (default: entire codebase)
        """
        return execution.grep(pattern, path)

    def list_files(path: str = ".", pattern: str = "*") -> str:
        """List files in the codebase matching a glob pattern.

        Args:
            path: Directory to search in (default: root)
            pattern: Filename glob pattern (default: all files)
        """
        files = execution.list_files(path, pattern)
        return "\n".join(files) if files else "(no files found)"

    def run_command(command: str) -> str:
        """Run a shell command inside the container. Use for static analysis tools, dependency checks, etc.

        Args:
            command: Shell command to execute (e.g. "semgrep --config auto .")
        """
        result = execution.exec(["sh", "-c", command], timeout=60)
        output = result.stdout
        if result.stderr:
            output += f"\n[stderr]\n{result.stderr}"
        if not result.ok:
            output += f"\n[exit code: {result.exit_code}]"
        return output

    return [
        StructuredTool.from_function(read_file),
        StructuredTool.from_function(grep_code),
        StructuredTool.from_function(list_files),
        StructuredTool.from_function(run_command),
        StructuredTool.from_function(report_finding),
    ]
