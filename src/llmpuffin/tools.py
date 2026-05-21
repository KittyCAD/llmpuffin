"""
Custom tools for the security audit agent.

Threat model query and finding reporting tools. Codebase tools (read, grep,
ls, execute) are provided by the ContainerBackend via deepagents.
"""

from __future__ import annotations

import logging
from typing import Callable

from sqlalchemy import func, select, text
from sqlalchemy import update as sa_update

from llmpuffin.backend import ContainerBackend
from llmpuffin.db import sync_session
from llmpuffin.github import GitHubClient
from llmpuffin.models import Finding, FindingAttachment, FindingLocation
from llmpuffin.sarif import SarifFinding, SarifLocation, SarifReport
from llmpuffin.threat_model import ThreatModel, ThreatModelView

log = logging.getLogger("llmpuffin")


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


def _resolve_finding(audit_run_id: int, local_id: int):
    """Look up a Finding by local_id within the audit run. Returns the Finding or None."""
    try:
        with sync_session() as s:
            return s.execute(
                select(Finding).where(
                    Finding.audit_run_id == audit_run_id,
                    Finding.local_id == local_id,
                )
            ).scalar_one_or_none()
    except Exception:
        return None


def _persist_finding_to_db(
    audit_run_id: int,
    thread_id: str,
    scenario_id: str,
    title: str,
    severity: str,
    difficulty: str,
    description: str,
    impact: str,
    recommendations: str,
    locations: list[dict] | None,
) -> tuple[int, int, str]:
    """Allocate local_id in SQL and insert a finding in one transaction.

    Concurrent transactions are serialized by a per-audit-run advisory lock
    held until commit, so the MAX(local_id) read and the INSERT cannot
    interleave. No retry needed.

    Returns (finding_pk_id, local_id, rule_id).
    """
    next_local_id = (
        select(func.coalesce(func.max(Finding.local_id) + 1, 0))
        .where(Finding.audit_run_id == audit_run_id)
        .scalar_subquery()
    )
    rule_id_expr = func.concat(
        scenario_id + "-",
        func.to_char(next_local_id, text("'FM000'")),
    )

    try:
        with sync_session() as s, s.begin():
            # Serialize concurrent allocations for this audit_run. The lock
            # is released automatically at COMMIT/ROLLBACK.
            s.execute(select(func.pg_advisory_xact_lock(audit_run_id)))
            finding = Finding(
                audit_run_id=audit_run_id,
                thread_id=thread_id,
                local_id=next_local_id,
                rule_id=rule_id_expr,
                title=title,
                scenario_id=scenario_id,
                severity=severity,
                difficulty=difficulty,
                description=description,
                impact=impact,
                recommendations=recommendations,
            )
            s.add(finding)
            s.flush()
            s.refresh(finding, attribute_names=["local_id", "rule_id"])
            for loc in locations or []:
                s.add(
                    FindingLocation(
                        finding_id=finding.id,
                        file_path=loc["file"],
                        start_line=loc.get("line", 0),
                    )
                )
            return finding.id, finding.local_id, finding.rule_id
    except Exception as exc:
        log.exception("Failed to insert finding in audit_run %s: %s", audit_run_id, exc)
        raise RuntimeError(
            f"Failed to insert finding in audit_run {audit_run_id}: {exc}"
        ) from exc


MAX_EXPORT_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


def make_tools(
    report: SarifReport,
    threat_model: ThreatModel,
    audit_run_id: int,
    thread_id: str = "",
    repo_path: str = "",
    github_client: GitHubClient | None = None,
    container_backend: ContainerBackend | None = None,
) -> dict[str, Callable]:
    """Create threat model and finding tools."""

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

    def report_finding(
        scenario_id: str,
        title: str,
        severity: str,
        difficulty: str,
        description: str,
        impact: str,
        recommendations: str,
        locations: list[dict] | None = None,
    ) -> str:
        """Record a security finding. Call this for each vulnerability you discover.

        Returns the finding_id (integer, starting from 0) which you must use
        to reference this finding in update_finding, delete_finding, and
        validate_finding.

        Args:
            scenario_id: The threat scenario ID this finding relates to (e.g. "sqli")
            title: Short one-line summary of the finding (e.g. "SQL injection in login endpoint")
            severity: How severe the issue is: "high", "medium", "low", or "informational"
            difficulty: How hard it is to exploit: "high", "medium", or "low"
            description: What the vulnerability is and where it occurs. Include code evidence.
            impact: What an attacker could achieve by exploiting this.
            recommendations: Concrete steps to fix or mitigate the issue.
            locations: Optional list of locations, each a dict with "file" (str) and "line" (int).
                       Example: [{"file": "src/main.py", "line": 42}]
        """
        # Persist first so we get the authoritative, race-safe local_id +
        # rule_id from the DB. The SARIF entry uses the same values to keep
        # the two stores consistent.
        _, local_id, rule_id = _persist_finding_to_db(
            audit_run_id,
            thread_id,
            scenario_id,
            title,
            severity,
            difficulty,
            description,
            impact,
            recommendations,
            locations,
        )

        sarif_locations = []
        if locations:
            for loc in locations:
                sarif_locations.append(
                    SarifLocation(
                        file_path=loc["file"],
                        start_line=loc.get("line", 0),
                    )
                )
        finding = SarifFinding(
            rule_id=rule_id,
            title=title,
            description=description,
            impact=impact,
            recommendations=recommendations,
            severity=severity,
            difficulty=difficulty,
            locations=sarif_locations,
            threat_scenario_ids=[scenario_id],
        )
        report.add_finding(finding)

        return f"Finding recorded. finding_id: {local_id}"

    def update_finding(
        finding_id: int,
        severity: str | None = None,
        difficulty: str | None = None,
        description: str | None = None,
        impact: str | None = None,
        recommendations: str | None = None,
    ) -> str:
        """Update an existing finding.

        Args:
            finding_id: The finding_id returned by report_finding (0-indexed)
            severity: New severity (optional)
            difficulty: New difficulty (optional)
            description: New description (optional)
            impact: New impact (optional)
            recommendations: New recommendations (optional)
        """
        db_finding = _resolve_finding(audit_run_id, finding_id)
        if not db_finding:
            return f"Finding {finding_id} not found"

        # Update SARIF report
        sarif_finding = next(
            (f for f in report.findings if f.rule_id == db_finding.rule_id), None
        )
        if sarif_finding:
            if severity is not None:
                sarif_finding.severity = severity
            if difficulty is not None:
                sarif_finding.difficulty = difficulty
            if description is not None:
                sarif_finding.description = description
            if impact is not None:
                sarif_finding.impact = impact
            if recommendations is not None:
                sarif_finding.recommendations = recommendations

        # Update DB
        try:
            values = {
                k: v
                for k, v in {
                    "severity": severity,
                    "difficulty": difficulty,
                    "description": description,
                    "impact": impact,
                    "recommendations": recommendations,
                }.items()
                if v is not None
            }
            if values:
                with sync_session() as s:
                    s.execute(
                        sa_update(Finding)
                        .where(
                            Finding.id == db_finding.id,
                            Finding.audit_run_id == audit_run_id,
                        )
                        .values(**values)
                    )
                    s.commit()
        except Exception as exc:
            log.warning("Failed to update finding in DB: %s", exc)

        return f"Finding {finding_id} updated"

    def delete_finding(finding_id: int) -> str:
        """Delete a finding. Use if a finding was reported in error or could not be validated.

        Args:
            finding_id: The finding_id returned by report_finding (0-indexed)
        """
        db_finding = _resolve_finding(audit_run_id, finding_id)
        if not db_finding:
            return f"Finding {finding_id} not found"

        # Remove from SARIF report
        report.findings = [
            f for f in report.findings if f.rule_id != db_finding.rule_id
        ]

        # Soft-delete in DB
        try:
            with sync_session() as s:
                s.execute(
                    sa_update(Finding)
                    .where(
                        Finding.id == db_finding.id,
                        Finding.audit_run_id == audit_run_id,
                    )
                    .values(deleted=True)
                )
                s.commit()
        except Exception as exc:
            log.warning("Failed to soft-delete finding in DB: %s", exc)

        return f"Finding {finding_id} deleted"

    def validate_finding(
        finding_id: int,
        evidence: str,
    ) -> str:
        """Mark a finding as validated with exploit evidence.

        Only call this after you have either (a) traced a complete exploit chain
        from attacker input to impact, or (b) run a live exploit/test that proves
        the vulnerability.

        Args:
            finding_id: The finding_id returned by report_finding (0-indexed)
            evidence: The validation evidence — exploit chain trace or test output
        """
        db_finding = _resolve_finding(audit_run_id, finding_id)
        if not db_finding:
            return f"Finding {finding_id} not found"

        # Update SARIF
        sarif_finding = next(
            (f for f in report.findings if f.rule_id == db_finding.rule_id), None
        )
        if sarif_finding:
            sarif_finding.properties["validated"] = True
            sarif_finding.properties["validated_evidence"] = evidence

        # Update DB
        try:
            with sync_session() as s:
                s.execute(
                    sa_update(Finding)
                    .where(
                        Finding.id == db_finding.id,
                        Finding.audit_run_id == audit_run_id,
                    )
                    .values(validated=True, validated_evidence=evidence)
                )
                s.commit()
        except Exception as exc:
            log.warning("Failed to validate finding in DB: %s", exc)

        return f"Finding {finding_id} validated"

    def list_findings() -> str:
        """List all reported findings with their IDs, titles, severity, and status.

        Use this to see what has been reported so far and which findings
        need validation.
        """
        try:
            with sync_session() as s:
                findings = (
                    s.execute(
                        select(Finding)
                        .where(Finding.audit_run_id == audit_run_id)
                        .order_by(Finding.local_id)
                    )
                    .scalars()
                    .all()
                )
            if not findings:
                return "No findings reported yet."
            lines = []
            for f in findings:
                if f.deleted:
                    lines.append(
                        f"- {f.local_id}: (deleted) {f.title or f.description[:60]}"
                    )
                    continue
                status = "validated" if f.validated else "unvalidated"
                lines.append(
                    f"- {f.local_id}: {f.title or f.description[:60]} | "
                    f"{f.severity}/{f.difficulty} | "
                    f"scenario: {f.scenario_id} | {status}"
                )
            return "\n".join(lines)
        except Exception as exc:
            log.warning("Failed to list findings: %s", exc)
            return "Error listing findings."

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

    def finding_attach_file(
        finding_id: int, file_path: str, description: str = ""
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
        db_finding = _resolve_finding(audit_run_id, finding_id)
        if not db_finding:
            return f"Finding {finding_id} not found"

        # Read file raw via base64 to handle binary content safely.
        import base64

        exit_code, stdout, stderr = container_backend._run(["base64", file_path])
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

        filename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
        try:
            with sync_session() as s:
                att = FindingAttachment(
                    finding_id=db_finding.id,
                    filename=filename,
                    description=description,
                    content=raw,
                    size=len(raw),
                )
                s.add(att)
                s.commit()
        except Exception as exc:
            log.warning("Failed to export file: %s", exc)
            return f"Error saving file: {exc}"

        return (
            f"Exported {filename} ({len(raw)} bytes) attached to finding {finding_id}"
        )

    def finding_list_attached_files(finding_id: int) -> str:
        """List files that have been exported and attached to a finding.

        Args:
            finding_id: The finding_id returned by report_finding (0-indexed)
        """
        db_finding = _resolve_finding(audit_run_id, finding_id)
        if not db_finding:
            return f"Finding {finding_id} not found"

        try:
            with sync_session() as s:
                attachments = (
                    s.execute(
                        select(FindingAttachment)
                        .where(FindingAttachment.finding_id == db_finding.id)
                        .order_by(FindingAttachment.created_at)
                    )
                    .scalars()
                    .all()
                )
            if not attachments:
                return "No files exported for this finding."
            lines = []
            for a in attachments:
                desc = f" — {a.description}" if a.description else ""
                lines.append(f"- {a.filename} ({a.size} bytes){desc}")
            return "\n".join(lines)
        except Exception as exc:
            log.warning("Failed to list exported files: %s", exc)
            return "Error listing files."

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
    }
