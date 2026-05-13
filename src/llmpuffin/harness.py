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
from pathlib import Path

from llmpuffin.audit_environment import AuditEnvironment, AuditExecution
from llmpuffin.threat_model import ThreatModel


@dataclass
class HarnessConfig:
    """Configuration for a single audit harness run.

    This is the declarative specification layer: it binds a threat model
    to an audit environment and configures how the agent should behave.
    """

    # Directory containing .toml files that make up the threat model
    threat_model_dir: Path
    # Container image containing the codebase to audit
    container_image: str
    # Maximum number of agentic loop iterations (matches deepagents default)
    max_iterations: int = 200
    # Working directory inside the container where code lives
    code_dir: str = "/src"
    # Output path for the SARIF results file
    output_path: Path = Path("results.sarif")
    # Enable QuickJS code interpreter for the agent
    interpreter: bool = False
    # Directory for persistent agent memory across sessions (None = no persistence)
    store_dir: Path | None = None
    # PostgreSQL connection string for session checkpointing (None = no checkpointing)
    postgres_connstring: str | None = None


@dataclass
class HarnessState:
    """Mutable state maintained across the agentic loop.

    The harness manages multi-tiered memory:
      - Working context: current threat scenario being investigated
      - Session state: findings accumulated so far, files examined
      - Artifact persistence: SARIF file written incrementally
    """

    threat_model: ThreatModel | None = None
    current_scenario_index: int = 0
    findings: list[dict] = field(default_factory=list)
    files_examined: set[str] = field(default_factory=set)
    iteration: int = 0


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
        self.state.threat_model = ThreatModel.from_dir(self.config.threat_model_dir)
        return self.state.threat_model

    def start_environment(self) -> AuditExecution:
        """Start the containerized audit environment.

        Returns an AuditExecution context manager. Use with `with`:

            with harness.start_environment() as execution:
                ...

        All tool calls (grep, file reads, static analysis) execute inside
        the container — this is the tool integration layer of the harness.
        """
        environment = AuditEnvironment(
            image=self.config.container_image,
            code_dir=self.config.code_dir,
        )
        return environment.start()
