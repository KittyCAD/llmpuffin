"""
llmpuffin harness — the infrastructure layer surrounding the LLM agent.

# What is a Harness?
#
# A harness is the complete runtime system that manages everything *except*
# the model itself (parallel.ai).  It is NOT an agent framework (like
# LangChain) — frameworks provide building blocks; a harness is a fully
# assembled, opinionated system ready for deployment.  The harness provides
# capabilities and side effects (tools, context, verification) while the
# orchestrator (LangGraph) provides control logic (when/how to invoke the
# model).
#
# Key harness responsibilities (parallel.ai):
#   1. Tool integration layer — connects model to containerized code analysis
#   2. Memory & state management — threat model context, findings so far
#   3. Context engineering — dynamically curate what the model sees each turn
#   4. Verification & guardrails — validate findings, prevent false positives
#   5. Artifact persistence — SARIF output, progress logs
#
# What is a Meta-Harness?  (arxiv:2603.28052)
#
# A meta-harness treats harness design as a *learnable problem*: it enables
# end-to-end optimization of harness components (prompts, evaluation criteria,
# task specs, feedback mechanisms) rather than treating them as fixed.  In our
# case the threat model TOML is the declarative specification layer that a
# meta-harness could optimize over — e.g. automatically refining threat
# scenarios based on audit results across multiple runs.
#
# Design principles we follow:
#   - Declarative specification (threat model TOML, not imperative scripts)
#   - Modularity (swap container runtime, model, tools independently)
#   - Measurability (SARIF output with structured severity/confidence)
#   - Model agnosticism (harness does not depend on a specific LLM)
#   - Separation of concerns (harness ≠ orchestrator ≠ framework)
#   - Incremental execution (subtask verification between steps)

# Threat modeling follows the TRAIL methodology (Trail of Bits):
#   - Decompose system into components and trust zones
#   - Map connections crossing trust boundaries (= attack surface)
#   - Define threat scenarios as actor-connection pairs
#   - Recommend layered mitigations per scenario
"""

from __future__ import annotations

from dataclasses import dataclass, field

from llmpuffin.audit_environment import AuditEnvironment, AuditExecution
from llmpuffin.config import Profile
from llmpuffin.threat_model import ThreatModel


@dataclass
class HarnessConfig:
    """Binds a Profile to a specific run, adding the original TOML for persistence."""

    profile: Profile
    # Original TOML text, stored verbatim on AuditRun/AuditProfile so that
    # runs can be resumed/forked from the web UI without the original file.
    # We keep the raw string rather than regenerating it from Profile so that
    # user comments and formatting are preserved.
    profile_toml: str = ""


@dataclass
class HarnessState:
    """
    Mutable state maintained across the agentic loop.
    """

    threat_model: ThreatModel | None = None
    findings: list[dict] = field(default_factory=list)


class Harness:
    """The main harness orchestrating a security audit.

    The harness lifecycle:
      1. Load threat model (declarative task specification)
      2. Start audit environment (containerized codebase)
      3. For each threat scenario, run the agentic loop:
         a. Provide scenario context to the agent
         b. Agent uses containerized tools to investigate
         c. Verify and collect findings
      4. Produce SARIF output (artifact persistence)
    """

    def __init__(self, config: HarnessConfig) -> None:
        self.config = config
        self.state = HarnessState()

    def load_threat_model(self) -> ThreatModel:
        """Load the threat model from TOML — the declarative spec driving the audit."""
        tm = ThreatModel.from_dir(self.config.profile.threat_model_dir)
        self.state.threat_model = tm
        return tm

    def start_environment(self, container_id: str | None = None) -> AuditExecution:
        """Start the containerized audit environment.

        Args:
            container_id: If given, tries to restart an existing stopped
                container before creating a new one.

        Returns an AuditExecution context manager. Use with `with`:

            with harness.start_environment() as execution:
                ...
        """
        p = self.config.profile
        environment = AuditEnvironment(
            image=p.image,
            code_dir=p.code_dir,
        )
        return environment.start(container_id=container_id)
