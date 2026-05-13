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

_SEVERITY_TO_LEVEL = {"high": "error", "medium": "warning", "low": "note", "informational": "note"}


def _persist_finding_to_db(audit_run_id: int | None, rule_id: str, scenario_id: str,
                           severity: str, difficulty: str, level: str,
                           description: str, impact: str, recommendations: str,
                           locations: list[dict] | None) -> int | None:
    """Write a finding to Django DB immediately. Returns the Finding pk."""
    if not audit_run_id:
        return None
    try:
        from llmpuffin.models import AuditRun, Finding, FindingLocation
        audit_run = AuditRun.objects.get(pk=audit_run_id)
        finding = Finding.objects.create(
            audit_run=audit_run,
            rule_id=rule_id,
            scenario_id=scenario_id,
            severity=severity,
            difficulty=difficulty,
            level=level,
            description=description,
            impact=impact,
            recommendations=recommendations,
        )
        for loc in (locations or []):
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
            lines.append(f"  - {z.id}: {z.name} — {z.description} (components: {', '.join(z.component_ids)})")
            for sub in z.trust_zones:
                lines.append(f"    - {sub.id}: {sub.name} — {sub.description} (components: {', '.join(sub.component_ids)})")

        lines.append("\n# Connections")
        for conn in threat_model.connections:
            lines.append(f"  - {conn.id}: {conn.source_component_id} → {conn.destination_component_id} ({conn.protocol}) — {conn.description}")

        lines.append("\n# Threat Scenarios")
        for s in threat_model.threat_scenarios:
            lines.append(f"  - {s.id}: {s.name} [{s.severity}/{s.category}]")

        return "\n".join(lines)

    def get_threat_scenario(scenario_id: str) -> str:
        """Get full details of a specific threat scenario by ID.

        Args:
            scenario_id: The scenario ID (e.g. "sqli", "auth_bypass")
        """
        scenario = next((s for s in threat_model.threat_scenarios if s.id == scenario_id), None)
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

    # Track rule_id → DB pk for update/delete
    _finding_pks: dict[str, int] = {}

    def report_finding(
        scenario_id: str,
        severity: str,
        difficulty: str,
        description: str,
        impact: str,
        recommendations: str,
        locations: list[dict] | None = None,
    ) -> str:
        """Record a security finding. Call this for each vulnerability you discover.

        Args:
            scenario_id: The threat scenario ID this finding relates to (e.g. "sqli")
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
                sarif_locations.append(SarifLocation(
                    file_path=loc["file"],
                    start_line=loc.get("line", 0),
                ))
        rule_id = f"{scenario_id}-{len(report.findings) + 1:03d}"
        finding = SarifFinding(
            rule_id=rule_id,
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
            audit_run_id, rule_id, scenario_id, severity, difficulty, level,
            description, impact, recommendations, locations,
        )
        if pk:
            _finding_pks[rule_id] = pk

        return f"Finding recorded: {rule_id}"

    def update_finding(
        rule_id: str,
        severity: str | None = None,
        difficulty: str | None = None,
        description: str | None = None,
        impact: str | None = None,
        recommendations: str | None = None,
    ) -> str:
        """Update an existing finding by rule_id.

        Args:
            rule_id: The finding to update (e.g. "sqli-001")
            severity: New severity (optional)
            difficulty: New difficulty (optional)
            description: New description (optional)
            impact: New impact (optional)
            recommendations: New recommendations (optional)
        """
        # Update SARIF report
        sarif_finding = next((f for f in report.findings if f.rule_id == rule_id), None)
        if not sarif_finding:
            return f"Finding '{rule_id}' not found"

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
        pk = _finding_pks.get(rule_id)
        if pk:
            try:
                from llmpuffin.models import Finding
                Finding.objects.filter(pk=pk).update(**{
                    k: v for k, v in {
                        "severity": severity,
                        "difficulty": difficulty,
                        "level": _SEVERITY_TO_LEVEL.get(severity, None) if severity else None,
                        "description": description,
                        "impact": impact,
                        "recommendations": recommendations,
                    }.items() if v is not None
                })
            except Exception as exc:
                log.warning("Failed to update finding in DB: %s", exc)

        return f"Finding updated: {rule_id}"

    def delete_finding(rule_id: str) -> str:
        """Delete a finding by rule_id. Use if a finding was reported in error.

        Args:
            rule_id: The finding to delete (e.g. "sqli-001")
        """
        # Remove from SARIF report
        report.findings = [f for f in report.findings if f.rule_id != rule_id]

        # Remove from DB
        pk = _finding_pks.pop(rule_id, None)
        if pk:
            try:
                from llmpuffin.models import Finding
                Finding.objects.filter(pk=pk).delete()
            except Exception as exc:
                log.warning("Failed to delete finding from DB: %s", exc)

        return f"Finding deleted: {rule_id}"

    return [
        get_threat_model,
        get_threat_scenario,
        report_finding,
        update_finding,
        delete_finding,
    ]
