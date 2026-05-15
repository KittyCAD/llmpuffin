"""
Custom tools for the security audit agent.

Threat model query and finding reporting tools. Codebase tools (read, grep,
ls, execute) are provided by the ContainerBackend via deepagents.
"""

from __future__ import annotations

import logging
from typing import Callable

from llmpuffin.sarif import SarifFinding, SarifLocation, SarifReport
from llmpuffin.threat_model import ThreatModel

log = logging.getLogger("llmpuffin")

_SEVERITY_TO_LEVEL = {
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}


def _persist_finding_to_db(
    audit_run_id: int | None,
    thread_id: str,
    rule_id: str,
    title: str,
    scenario_id: str,
    severity: str,
    difficulty: str,
    level: str,
    description: str,
    impact: str,
    recommendations: str,
    locations: list[dict] | None,
) -> int | None:
    """Write a finding to Django DB immediately. Returns the Finding pk."""
    if not audit_run_id:
        return None
    try:
        from llmpuffin.models import AuditRun, Finding, FindingLocation

        audit_run = AuditRun.objects.get(pk=audit_run_id)
        finding = Finding.objects.create(
            audit_run=audit_run,
            thread_id=thread_id,
            rule_id=rule_id,
            title=title,
            scenario_id=scenario_id,
            severity=severity,
            difficulty=difficulty,
            level=level,
            description=description,
            impact=impact,
            recommendations=recommendations,
        )
        for loc in locations or []:
            FindingLocation.objects.create(
                finding=finding,
                file_path=loc["file"],
                start_line=loc.get("line", 0),
            )
        return finding.pk
    except Exception as exc:
        log.warning("Failed to persist finding to DB: %s", exc)
        return None


def make_tools(
    report: SarifReport,
    threat_model: ThreatModel,
    audit_run_id: int | None = None,
    thread_id: str = "",
) -> list[Callable]:
    """Create threat model and finding tools."""

    def get_threat_model() -> str:
        """Get an overview of the threat model: components, trust zones, connections, and threat scenarios.

        Call this first to understand what you are auditing.
        """
        lines = []
        lines.append("# Components")
        for c in threat_model.components:
            lines.append(f"  - {c.id}: {c.name} — {c.description}")
            for sub in c.components:
                lines.append(f"    - {sub.id}: {sub.name} — {sub.description}")

        lines.append("\n# Trust Zones")
        for z in threat_model.trust_zones:
            lines.append(
                f"  - {z.id}: {z.name} — {z.description} (components: {', '.join(z.component_ids)})"
            )
            for sub in z.trust_zones:
                lines.append(
                    f"    - {sub.id}: {sub.name} — {sub.description} (components: {', '.join(sub.component_ids)})"
                )

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
        scenario = next(
            (s for s in threat_model.threat_scenarios if s.id == scenario_id), None
        )
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

    # Map finding_id (DB pk) → rule_id for SARIF lookups
    _id_to_rule: dict[int, str] = {}

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

        Returns the finding_id which you must use to reference this finding
        in update_finding, delete_finding, and validate_finding.

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
        level = _SEVERITY_TO_LEVEL.get(severity, "warning")
        sarif_locations = []
        if locations:
            for loc in locations:
                sarif_locations.append(
                    SarifLocation(
                        file_path=loc["file"],
                        start_line=loc.get("line", 0),
                    )
                )
        rule_id = f"{scenario_id}-{len(report.findings) + 1:03d}"
        finding = SarifFinding(
            rule_id=rule_id,
            title=title,
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

        pk = _persist_finding_to_db(
            audit_run_id,
            thread_id,
            rule_id,
            title,
            scenario_id,
            severity,
            difficulty,
            level,
            description,
            impact,
            recommendations,
            locations,
        )
        if pk:
            _id_to_rule[pk] = rule_id

        finding_id = pk or rule_id
        return f"Finding recorded. finding_id: {finding_id}"

    def _resolve_finding(finding_id: int) -> tuple[str | None, int | None]:
        """Resolve a finding_id to (rule_id, pk). Returns error string if not found."""
        rule_id = _id_to_rule.get(finding_id)
        if rule_id:
            return rule_id, finding_id
        return None, None

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
            finding_id: The finding_id returned by report_finding
            severity: New severity (optional)
            difficulty: New difficulty (optional)
            description: New description (optional)
            impact: New impact (optional)
            recommendations: New recommendations (optional)
        """
        rule_id, pk = _resolve_finding(finding_id)
        if not rule_id:
            return f"Finding {finding_id} not found"

        # Update SARIF report
        sarif_finding = next((f for f in report.findings if f.rule_id == rule_id), None)
        if sarif_finding:
            if severity is not None:
                sarif_finding.severity = severity
                sarif_finding.level = _SEVERITY_TO_LEVEL.get(severity, "warning")
            if difficulty is not None:
                sarif_finding.difficulty = difficulty
            if description is not None:
                sarif_finding.description = description
            if impact is not None:
                sarif_finding.impact = impact
            if recommendations is not None:
                sarif_finding.recommendations = recommendations

        # Update DB
        if pk:
            try:
                from llmpuffin.models import Finding

                Finding.objects.filter(pk=pk, audit_run_id=audit_run_id).update(  # type: ignore[attr-defined]
                    **{
                        k: v
                        for k, v in {
                            "severity": severity,
                            "difficulty": difficulty,
                            "level": _SEVERITY_TO_LEVEL.get(severity, None)
                            if severity
                            else None,
                            "description": description,
                            "impact": impact,
                            "recommendations": recommendations,
                        }.items()
                        if v is not None
                    }
                )
            except Exception as exc:
                log.warning("Failed to update finding in DB: %s", exc)

        return f"Finding {finding_id} updated"

    def delete_finding(finding_id: int) -> str:
        """Delete a finding. Use if a finding was reported in error or could not be validated.

        Args:
            finding_id: The finding_id returned by report_finding
        """
        rule_id, pk = _resolve_finding(finding_id)
        if not rule_id:
            return f"Finding {finding_id} not found"

        # Remove from SARIF report
        report.findings = [f for f in report.findings if f.rule_id != rule_id]

        # Soft-delete in DB
        if pk:
            _id_to_rule.pop(pk, None)
            try:
                from llmpuffin.models import Finding

                Finding.objects.filter(pk=pk).update(deleted=True)  # type: ignore[attr-defined]
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
            finding_id: The finding_id returned by report_finding
            evidence: The validation evidence — exploit chain trace or test output
        """
        rule_id, pk = _resolve_finding(finding_id)
        if not rule_id:
            return f"Finding {finding_id} not found"

        # Update SARIF
        sarif_finding = next((f for f in report.findings if f.rule_id == rule_id), None)
        if sarif_finding:
            sarif_finding.properties["validated"] = True
            sarif_finding.properties["validated_evidence"] = evidence

        # Update DB
        if pk:
            try:
                from llmpuffin.models import Finding

                Finding.objects.filter(pk=pk, audit_run_id=audit_run_id).update(  # type: ignore[attr-defined]
                    validated=True,
                    validated_evidence=evidence,
                )
            except Exception as exc:
                log.warning("Failed to validate finding in DB: %s", exc)

        return f"Finding {finding_id} validated"

    def list_findings() -> str:
        """List all reported findings with their IDs, titles, severity, and status.

        Use this to see what has been reported so far and which findings
        need validation.
        """
        if not report.findings:
            return "No findings reported yet."
        lines = []
        for f in report.findings:
            # Find the DB pk for this finding
            pk = next((k for k, v in _id_to_rule.items() if v == f.rule_id), None)
            finding_id = pk or f.rule_id
            validated = f.properties.get("validated", False)
            status = "validated" if validated else "unvalidated"
            lines.append(
                f"- finding_id: {finding_id} | {f.title} | "
                f"{f.severity}/{f.difficulty} | scenario: {f.threat_scenario_ids[0] if f.threat_scenario_ids else '?'} | "
                f"{status}"
            )
        return "\n".join(lines)

    return [
        get_threat_model,
        get_threat_scenario,
        report_finding,
        list_findings,
        update_finding,
        delete_finding,
        validate_finding,
    ]
