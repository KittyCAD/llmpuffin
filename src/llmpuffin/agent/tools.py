"""
Custom tools for the security audit agent.

Threat model query and finding reporting tools. Codebase tools (read, grep,
ls, execute) are provided by the ContainerBackend via deepagents.
"""

from __future__ import annotations

import logging
from typing import Callable, Literal

from langchain_core.messages import ToolMessage
from langgraph.prebuilt.tool_node import ToolRuntime
from pydantic import BaseModel, Field

from llmpuffin.agent.backend import ContainerBackend
from llmpuffin.db import DB
from llmpuffin.features import FeatureFlags, Flag
from llmpuffin.services.finding import FindingService
from llmpuffin.github import GitHubClient
from llmpuffin.models import Finding, GitInfo
from llmpuffin.threat_model import ThreatModel, ThreatModelView

log = logging.getLogger("llmpuffin")


class LocationInput(BaseModel):
    """A source code location."""

    file: str = Field(
        description="File path relative to the repo root (e.g. 'src/main.py')"
    )
    line: int = Field(default=0, description="Line number (0 if unknown)")


class ReportFindingInput(BaseModel):
    """Input schema for report_finding."""

    title: str = Field(
        description="Short one-line summary (e.g. 'SQL injection in login endpoint')"
    )
    severity: Literal["high", "medium", "low", "informational"] = Field(
        description="How severe the issue is"
    )
    difficulty: Literal["high", "medium", "low"] = Field(
        description="How hard it is to exploit"
    )
    description: str = Field(
        description="What the vulnerability is and where it occurs. Include code evidence."
    )
    exploit_scenario: str = Field(
        description="Step-by-step exploit scenario showing how an attacker could exploit this"
    )
    recommendations: str = Field(
        description="Concrete steps to fix or mitigate the issue"
    )
    locations: list[LocationInput] | None = Field(
        default=None, description="Source code locations"
    )


class UpdateFindingInput(BaseModel):
    """Input schema for update_finding."""

    finding_id: int = Field(
        description="The finding_id returned by report_finding (0-indexed)"
    )
    title: str | None = Field(default=None, description="New title")
    severity: Literal["high", "medium", "low", "informational"] | None = Field(
        default=None, description="New severity"
    )
    difficulty: Literal["high", "medium", "low"] | None = Field(
        default=None, description="New difficulty"
    )
    description: str | None = Field(default=None, description="New description")
    exploit_scenario: str | None = Field(
        default=None, description="New exploit scenario"
    )
    recommendations: str | None = Field(default=None, description="New recommendations")


def _format_threat_model_view(view: ThreatModelView) -> str:
    """Format a ThreatModelView for the agent."""
    lines = ["# Local Components (in this repo — your audit target)"]
    for c in view.local_components:
        lines.append(f"  - {c.id}: {c.name} — {c.description}")

    if view.neighbor_components:
        lines.append("\n# Neighbor Components (connected, in other repos)")
        for c in view.neighbor_components:
            lines.append(f"  - {c.id}: {c.name} ({c.repo}) — {c.description}")

    lines.append("\n# Connections")
    for conn in view.connections:
        lines.append(
            f"  - {conn.id}: {conn.source_component_id} → {conn.destination_component_id} ({conn.protocol}) — {conn.description}"
        )

    lines.append("\n# Threat Scenarios")
    for s in view.threat_scenarios:
        lines.append(f"  - {s.id}: {s.name} [{s.severity}/{s.category}]")

    return "\n".join(lines)


async def _query_git_info(backend: ContainerBackend, file_path: str) -> GitInfo:
    """Query the container for git info (origin remote + HEAD) for a file path.

    Resolves the file to its git repo root, then gets the origin remote URL
    and HEAD commit. Returns an empty GitInfo on any failure.
    """
    try:
        # Resolve to absolute path.
        ec, abs_path, stderr = await backend._run(["sh", "-c", f"realpath {file_path}"])
        if ec != 0:
            log.debug("git_info: realpath failed for %s: %s", file_path, stderr.strip())
            return GitInfo()
        abs_path = abs_path.strip()
        parent = abs_path.rsplit("/", 1)[0]

        # Find git repo root.
        ec, repo_root, stderr = await backend._run(
            ["git", "-C", parent, "rev-parse", "--show-toplevel"]
        )
        if ec != 0:
            log.debug("git_info: no git root for %s: %s", parent, stderr.strip())
            return GitInfo()
        repo_root = repo_root.strip()

        # Origin remote URL.
        ec, remote, stderr = await backend._run(
            ["git", "-C", repo_root, "remote", "get-url", "origin"]
        )
        if ec != 0:
            log.debug("git_info: no origin remote in %s: %s", repo_root, stderr.strip())
            return GitInfo()

        # HEAD commit.
        ec, head, stderr = await backend._run(
            ["git", "-C", repo_root, "rev-parse", "HEAD"]
        )
        if ec != 0:
            log.debug("git_info: no HEAD in %s: %s", repo_root, stderr.strip())
            return GitInfo()

        result = GitInfo(origin_remote=remote.strip(), head=head.strip())
        log.debug(
            "git_info: %s → %s @ %s", file_path, result.origin_remote, result.head[:12]
        )
        return result
    except Exception as exc:
        log.debug("git_info: exception for %s: %s", file_path, exc)
        return GitInfo()


MAX_EXPORT_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


def make_tools(
    threat_model: ThreatModel,
    audit_run_id: int,
    repo_path: str = "",
    github_client: GitHubClient | None = None,
    container_backend: ContainerBackend | None = None,
    *,
    db: DB,
    finding_service: FindingService | None = None,
    features: FeatureFlags | None = None,
) -> dict[str, Callable]:
    """Create threat model and finding tools."""

    flags = features or FeatureFlags()
    svc = finding_service or FindingService(db)

    # Create a perspective view if we know the repo, otherwise show everything
    view = threat_model.view_for_repo(repo_path) if repo_path else None

    def get_threat_model() -> str:
        """Get the threat model from the perspective of the current audit.

        Shows local components (in this repo), neighbor components (connected
        but in other repos), relevant connections, and applicable threat scenarios.
        """
        if view:
            return _format_threat_model_view(view)

        # Fallback: show everything if no repo context
        lines = ["# Components"]
        for c in threat_model.components:
            lines.append(f"  - {c.id}: {c.name} ({c.repo}) — {c.description}")
        lines.append("\n# Connections")
        for conn in threat_model.connections:
            lines.append(
                f"  - {conn.id}: {conn.source_component_id} → {conn.destination_component_id} ({conn.protocol}) — {conn.description}"
            )
        lines.append("\n# Threat Scenarios")
        for s in threat_model.threat_scenarios:
            lines.append(f"  - {s.id}: {s.name} [{s.severity}/{s.category}]")
        return "\n".join(lines)

    def get_threat_scenario(scenario_id: str) -> str:
        """Get full details of a specific threat scenario by ID.

        Args:
            scenario_id: The scenario ID (e.g. "sqli", "auth_bypass")
        """
        scenarios = view.threat_scenarios if view else threat_model.threat_scenarios
        scenario = next((s for s in scenarios if s.id == scenario_id), None)
        if scenario is None:
            return f"Scenario '{scenario_id}' not found"

        components = []
        for cid in scenario.affected_component_ids:
            comp = threat_model.get_component(cid)
            if comp:
                components.append(f"  - {comp.name} ({comp.id}): {comp.description}")

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
{mitigations}"""

    async def report_finding(
        title: str,
        severity: Literal["high", "medium", "low", "informational"],
        difficulty: Literal["high", "medium", "low"],
        description: str,
        exploit_scenario: str,
        recommendations: str,
        locations: list[LocationInput] | None = None,
        runtime: ToolRuntime = None,  # pyright: ignore[reportArgumentType]  # injected by framework
    ) -> str | ToolMessage:
        """Record a security finding. Call this for each vulnerability you discover.

        Returns the finding_id (integer, starting from 0) which you must use
        to reference this finding in update_finding, delete_finding, and
        validate_finding.
        """
        if not runtime:
            raise RuntimeError("report_finding requires ToolRuntime")
        rt_tool_call_id = runtime.tool_call_id or ""
        rt_thread_id = runtime.config.get("configurable", {}).get("thread_id", "")

        # Check for duplicates before inserting.
        duplicates = (
            await svc.check_duplicate(
                audit_run_id,
                title=title,
                description=description,
                exploit_scenario=exploit_scenario,
            )
            if flags.enabled(Flag.DUPLICATE_DETECTION)
            else []
        )
        if duplicates:
            lines = [
                "This finding appears to be a duplicate of existing finding(s):"
            ]
            for dup, sim in duplicates:
                lines.append(
                    f"  - finding_id {dup.local_id}: \"{dup.title}\" "
                    f"(similarity: {sim:.0%})"
                )
            lines.append(
                "The finding was NOT recorded. If this is genuinely distinct, "
                "re-report with a more differentiated description."
            )
            return ToolMessage(
                content="\n".join(lines),
                tool_call_id=rt_tool_call_id,
                status="error",
            )

        # Convert LocationInput models to dicts for the DB layer,
        # enriching each with git info from the container.
        loc_dicts = None
        if locations:
            loc_dicts = []
            for loc in locations:
                d: dict = {"file": loc.file, "line": loc.line}
                if container_backend:
                    gi = await _query_git_info(container_backend, loc.file)
                    d["origin_remote"] = gi.origin_remote
                    d["head"] = gi.head
                log.debug("report_finding location: %s", d)
                loc_dicts.append(d)
        else:
            log.debug("report_finding: no locations provided")

        finding_pk, local_id = await svc.create(
            audit_run_id,
            thread_id=rt_thread_id,
            title=title,
            severity=severity,
            difficulty=difficulty,
            description=description,
            exploit_scenario=exploit_scenario,
            recommendations=recommendations,
            locations=loc_dicts,
            tool_call_id=rt_tool_call_id,
        )

        # Best-effort: generate embedding for deduplication.
        await svc._refresh_embedding(finding_pk)

        return f"Finding recorded. finding_id: {local_id}"

    async def update_finding(
        finding_id: int,
        title: str | None = None,
        severity: str | None = None,
        difficulty: str | None = None,
        description: str | None = None,
        exploit_scenario: str | None = None,
        recommendations: str | None = None,
    ) -> str:
        """Update an existing finding.

        Args:
            finding_id: The finding_id returned by report_finding (0-indexed)
            title: New title (optional)
            severity: New severity (optional)
            difficulty: New difficulty (optional)
            description: New description (optional)
            exploit_scenario: New exploit scenario (optional)
            recommendations: New recommendations (optional)
        """
        result = await svc.update(
            audit_run_id,
            finding_id,
            title=title,
            severity=severity,
            difficulty=difficulty,
            description=description,
            exploit_scenario=exploit_scenario,
            recommendations=recommendations,
        )
        if not result:
            return f"Finding {finding_id} not found"
        return f"Finding {finding_id} updated"

    async def delete_finding(finding_id: int) -> str:
        """Delete a finding. Use if a finding should never have been reported
        (e.g. reported in error, duplicate, or completely wrong).

        This is different from marking a finding as invalid — invalid means
        it was a legitimate reporting attempt that turned out to be wrong.

        Args:
            finding_id: The finding_id returned by report_finding (0-indexed)
        """
        if not await svc.delete(audit_run_id, finding_id):
            return f"Finding {finding_id} not found"
        return f"Finding {finding_id} deleted"

    async def validate_finding(
        finding_id: int,
        evidence: str,
        runtime: ToolRuntime = None,  # pyright: ignore[reportArgumentType]  # injected by framework
    ) -> str:
        """Mark a finding as validated with exploit evidence.

        Only call this after you have either (a) traced a complete exploit chain
        from attacker input to impact, or (b) run a live exploit/test that proves
        the vulnerability.

        Each call creates a new immutable validation note. You can call this
        multiple times to add additional evidence.

        Args:
            finding_id: The finding_id returned by report_finding (0-indexed)
            evidence: The validation evidence — exploit chain trace or test output
        """
        if not runtime:
            raise RuntimeError("validate_finding requires ToolRuntime")
        rt_tool_call_id = runtime.tool_call_id or ""
        rt_thread_id = runtime.config.get("configurable", {}).get("thread_id", "")

        if not await svc.validate(
            audit_run_id,
            finding_id,
            evidence=evidence,
            thread_id=rt_thread_id,
            tool_call_id=rt_tool_call_id,
        ):
            return f"Finding {finding_id} not found"
        return f"Finding {finding_id} validated"

    async def list_findings() -> str:
        """List all reported findings with their IDs, titles, severity, and status.

        Use this to see what has been reported so far and which findings
        need validation.
        """
        findings = await svc.list_all(audit_run_id)
        if not findings:
            return "No findings reported yet."
        lines = []
        for f in findings:
            if f.status == "deleted":
                lines.append(
                    f"- {f.local_id}: (deleted) {f.title or f.description[:60]}"
                )
                continue
            validated = "validated" if f.validated else "unvalidated"
            status_label = f" [{f.status}]" if f.status != "open" else ""
            lines.append(
                f"- {f.local_id}: {f.title or f.description[:60]} | "
                f"{f.severity}/{f.difficulty} | {validated}{status_label}"
            )
        return "\n".join(lines)

    def get_pull_request(repo: str, number: int) -> str:
        """Fetch a GitHub pull request or issue with its title, description, comments, and diff.

        Requires the GitHub App to be configured and installed on the target repo.

        Args:
            repo: The GitHub repo in "owner/name" format (e.g. "octocat/hello-world")
            number: The PR or issue number
        """
        if not github_client or not github_client.configured:
            return "Error: GitHub App is not configured"
        try:
            return github_client.fetch_pull_request(repo, number).format()
        except Exception as exc:
            log.warning("Failed to fetch PR %s#%d: %s", repo, number, exc)
            return f"Error fetching PR: {exc}"

    def get_commit(repo: str, sha: str) -> str:
        """Fetch a GitHub commit with its message, changed files, and diff.

        Requires the GitHub App to be configured and installed on the target repo.

        Args:
            repo: The GitHub repo in "owner/name" format (e.g. "octocat/hello-world")
            sha: The commit SHA (full or abbreviated)
        """
        if not github_client or not github_client.configured:
            return "Error: GitHub App is not configured"
        try:
            return github_client.fetch_commit(repo, sha).format()
        except Exception as exc:
            log.warning("Failed to fetch commit %s@%s: %s", repo, sha, exc)
            return f"Error fetching commit: {exc}"

    async def finding_attach_file(
        finding_id: int,
        file_path: str,
        description: str = "",
        runtime: ToolRuntime = None,  # pyright: ignore[reportArgumentType]  # injected by framework
    ) -> str:
        """Export a file from the container and attach it to a finding.

        Use this to save evidence files (exploit scripts, test output, screenshots,
        config files, etc.) that support a finding's validation.

        The file is read from the running container and stored in the database.
        Maximum file size is 2 MB.

        Args:
            finding_id: The finding_id returned by report_finding (0-indexed)
            file_path: Absolute path to the file inside the container
            description: Short description of what this file is (e.g. "exploit script", "test output")
        """
        if not container_backend:
            return "Error: no container available"

        # Read file raw via base64 to handle binary content safely.
        import base64

        exit_code, stdout, stderr = await container_backend._run(["base64", file_path])
        if exit_code != 0:
            return f"Error reading file: {stderr.strip() or 'file not found'}"

        try:
            raw = base64.b64decode(stdout)
        except Exception as exc:
            return f"Error decoding file: {exc}"

        if len(raw) > MAX_EXPORT_FILE_SIZE:
            return (
                f"Error: file too large (max {MAX_EXPORT_FILE_SIZE // 1024 // 1024} MB)"
            )

        rt_thread_id = (
            runtime.config.get("configurable", {}).get("thread_id", "")
            if runtime
            else ""
        )
        rt_tool_call_id = runtime.tool_call_id or "" if runtime else ""

        att = await svc.attach_file(
            audit_run_id,
            finding_id,
            filename=file_path,
            content=raw,
            description=description,
            thread_id=rt_thread_id,
            tool_call_id=rt_tool_call_id,
        )
        if not att:
            return f"Finding {finding_id} not found"

        return (
            f"Exported {file_path} ({len(raw)} bytes) attached to finding {finding_id}"
        )

    async def finding_list_attached_files(finding_id: int) -> str:
        """List files that have been exported and attached to a finding.

        Args:
            finding_id: The finding_id returned by report_finding (0-indexed)
        """
        attachments = await svc.list_attachments(audit_run_id, finding_id)
        if attachments is None:
            return f"Finding {finding_id} not found"
        if not attachments:
            return "No files exported for this finding."
        lines = []
        for a in attachments:
            desc = f" — {a.description}" if a.description else ""
            lines.append(f"- {a.filename} ({a.size} bytes){desc}")
        return "\n".join(lines)

    def get_coverage() -> str:
        """Get file coverage summary for this audit run.

        Shows which directories and files have been reached during the audit,
        with coverage percentages. Use this to identify areas of the codebase
        that have not been examined yet.
        """
        from llmpuffin.services.coverage import (
            load_coverage_for_run,
            build_coverage_tree,
        )

        all_files, accessed = load_coverage_for_run(audit_run_id, db=db)
        if not all_files:
            return "No coverage data available."

        tree = build_coverage_tree(all_files, accessed)
        lines = [
            f"Overall: {tree.accessed_files}/{tree.total_files} files ({tree.coverage_pct:.0f}%)",
            "",
        ]

        def _fmt(node, prefix: str = "", depth: int = 0) -> None:
            dirs = sorted(
                [(k, v) for k, v in node.children.items() if v.is_dir],
                key=lambda x: x[0],
            )
            for name, child in dirs:
                pct = child.coverage_pct
                indent = "  " * depth
                lines.append(
                    f"{indent}{name}/ — {child.accessed_files}/{child.total_files} ({pct:.0f}%)"
                )
                _fmt(child, f"{prefix}{name}/", depth + 1)

        _fmt(tree)
        return "\n".join(lines)

    async def get_similar_findings(finding_id: int, threshold: float = 0.8) -> str:
        """Find findings from other audit runs that are similar to the given finding.

        Uses vector similarity on finding embeddings to find duplicates or
        related findings across all audit runs. Useful for checking if a
        vulnerability has already been reported in a previous audit.

        Args:
            finding_id: The finding_id returned by report_finding (0-indexed)
            threshold: Minimum similarity score (0-1, default 0.8)
        """
        db_finding = await svc.resolve(audit_run_id, finding_id)
        if not db_finding:
            return f"Finding {finding_id} not found"

        try:
            from llmpuffin.services.embeddings import find_similar_global

            results = find_similar_global(db_finding.id, db=db, threshold=threshold)
        except Exception as exc:
            log.warning("Failed to find similar findings: %s", exc)
            return f"Error searching for similar findings: {exc}"

        if not results:
            return "No similar findings found."

        lines = []
        async with db.async_session() as s:
            for fid, score in results:
                f = await s.get(Finding, fid)
                if f is None:
                    continue
                lines.append(
                    f"- [{score:.3f}] #{f.local_id} (run {f.audit_run_id}): "
                    f"{f.title or f.description[:60]} | {f.severity}"
                )
        return "\n".join(lines) if lines else "No similar findings found."

    return {
        "get_threat_model": get_threat_model,
        "get_threat_scenario": get_threat_scenario,
        "report_finding": report_finding,
        "list_findings": list_findings,
        "update_finding": update_finding,
        "delete_finding": delete_finding,
        "validate_finding": validate_finding,
        "get_pull_request": get_pull_request,
        "get_commit": get_commit,
        "finding_attach_file": finding_attach_file,
        "finding_list_attached_files": finding_list_attached_files,
        "get_coverage": get_coverage,
        "get_similar_findings": get_similar_findings,
    }
