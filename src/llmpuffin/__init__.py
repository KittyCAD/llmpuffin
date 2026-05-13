"""
llmpuffin — Agentic codebase security review harness.

llmpuffin is a **harness** (not a framework, not an orchestrator) that drives
LLM-based security audits of codebases using structured threat models.

Architecture:
  - Threat model (TOML) → declarative task specification
  - AuditEnvironment (Podman) → containerized tool execution
  - Agent (LangGraph) → orchestration / reasoning loop
  - SARIF output → structured, interoperable findings

See the module docstrings for detailed design rationale.
"""

from llmpuffin.audit_environment import AuditEnvironment, AuditExecution, ExecResult
from llmpuffin.harness import Harness, HarnessConfig, HarnessState
from llmpuffin.sarif import SarifFinding, SarifLocation, SarifReport
from llmpuffin.threat_model import (
    Component,
    Connection,
    Severity,
    StrideCategory,
    ThreatModel,
    ThreatScenario,
    TrustZone,
)

__all__ = [
    "AuditEnvironment",
    "AuditExecution",
    "Component",
    "Connection",
    "ExecResult",
    "Harness",
    "HarnessConfig",
    "HarnessState",
    "SarifFinding",
    "SarifLocation",
    "SarifReport",
    "Severity",
    "StrideCategory",
    "ThreatModel",
    "ThreatScenario",
    "TrustZone",
]
