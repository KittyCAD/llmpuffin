"""
SARIF output generation for audit findings.

SARIF (Static Analysis Results Interchange Format) is the standard
output format for llmpuffin.  Each AuditExecution produces a SARIF
file containing all findings discovered during the agent's review.

This is the **artifact persistence** layer of the harness (parallel.ai):
findings are structured, serializable, and can be consumed by downstream
tools (GitHub Code Scanning, IDEs, CI pipelines).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SarifLocation:
    """A location within a source file."""

    file_path: str
    start_line: int
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None


@dataclass
class SarifFinding:
    """A single security finding.

    Maps to a SARIF 'result' object.  Each finding is tied back to
    one or more threat scenarios from the threat model, maintaining
    traceability from threat model → code → finding.
    """

    rule_id: str
    description: str
    impact: str
    recommendations: str
    severity: str = "medium"  # high, medium, low, informational
    difficulty: str = "medium"  # high, medium, low
    level: str = "warning"  # note, warning, error
    locations: list[SarifLocation] = field(default_factory=list)
    threat_scenario_ids: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class SarifReport:
    """A complete SARIF report for one audit execution."""

    tool_name: str = "llmpuffin"
    tool_version: str = "0.1.0"
    findings: list[SarifFinding] = field(default_factory=list)

    def add_finding(self, finding: SarifFinding) -> None:
        self.findings.append(finding)

    def to_sarif(self) -> dict[str, Any]:
        """Serialize to SARIF 2.1.0 JSON structure."""
        rules: dict[str, dict] = {}
        results: list[dict] = []

        for f in self.findings:
            # Collect unique rules
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "shortDescription": {"text": f.rule_id},
                    "properties": {},
                }

            # Build locations
            locations = []
            for loc in f.locations:
                region: dict[str, Any] = {"startLine": loc.start_line}
                if loc.end_line is not None:
                    region["endLine"] = loc.end_line
                if loc.start_column is not None:
                    region["startColumn"] = loc.start_column
                if loc.end_column is not None:
                    region["endColumn"] = loc.end_column

                locations.append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc.file_path},
                        "region": region,
                    }
                })

            message = f"## Description\n{f.description}\n\n## Impact\n{f.impact}\n\n## Recommendations\n{f.recommendations}"

            result: dict[str, Any] = {
                "ruleId": f.rule_id,
                "level": f.level,
                "message": {"text": message, "markdown": message},
                "locations": locations,
            }

            props: dict[str, Any] = {
                "severity": f.severity,
                "difficulty": f.difficulty,
            }
            if f.threat_scenario_ids:
                props["threatScenarioIds"] = f.threat_scenario_ids
            if f.properties:
                props.update(f.properties)
            result["properties"] = props

            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def write(self, path: Path) -> None:
        """Write the SARIF report to a file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_sarif(), f, indent=2)
