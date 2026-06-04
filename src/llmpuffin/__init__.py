"""
llmpuffin — Agentic codebase security review harness.

llmpuffin is a **harness** (not a framework, not an orchestrator) that drives
LLM-based security audits of codebases using structured threat models.

Architecture:
  - Threat model (TOML) → declarative task specification
  - AuditEnvironment (container) → containerized tool execution
  - Agent (deepagents) → orchestration / reasoning loop
  - SARIF output → structured, interoperable findings

See the module docstrings for detailed design rationale.
"""

from llmpuffin.agent import AuditResult, AuditStatus
from llmpuffin.audit_environment import AuditEnvironment, AuditExecution, ExecResult
from llmpuffin.config import Config, Profile, ProfileAgent, ProfileAudit
from llmpuffin.harness import Harness, HarnessConfig, HarnessState
from llmpuffin.sarif import SarifFinding, SarifLocation, SarifReport
from llmpuffin.threat_model import (
    Component,
    Connection,
    Severity,
    StrideCategory,
    ThreatModel,
    ThreatModelView,
    ThreatScenario,
    TrustZone,
)

__all__ = [
    "Config",
    "Profile",
    "ProfileAgent",
    "ProfileAudit",
    "AuditEnvironment",
    "AuditExecution",
    "AuditResult",
    "AuditStatus",
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
    "ThreatModelView",
    "ThreatScenario",
    "TrustZone",
]
