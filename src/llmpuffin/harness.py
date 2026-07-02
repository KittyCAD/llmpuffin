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

import asyncio
import logging
from collections.abc import Coroutine
from dataclasses import dataclass

from llmpuffin.audit_environment import AuditExecution
from llmpuffin.config import Config, Profile
from llmpuffin.threat_model import ThreatModel

log = logging.getLogger("llmpuffin")


@dataclass
class HarnessConfig:
    """Binds a Profile to a specific run, adding the original TOML for persistence."""

    profile: Profile
    # Original TOML text, stored verbatim on AuditRun/AuditProfile so that
    # runs can be resumed/forked from the web UI without the original file.
    # We keep the raw string rather than regenerating it from Profile so that
    # user comments and formatting are preserved.
    profile_toml: str = ""


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

    Task management:
      The harness tracks in-flight audit tasks by thread_id.
      Use ``spawn`` to launch, ``cancel`` to stop a specific thread,
      and ``cancel_all`` for graceful shutdown.
    """

    def __init__(
        self,
        config: HarnessConfig | None = None,
        *,
        global_config: Config | None = None,
    ) -> None:
        self.config = config
        self.global_config = global_config
        self.threat_model: ThreatModel | None = None
        self._tasks: dict[str, asyncio.Task] = {}

    def load_threat_model(self) -> ThreatModel:
        """Load the threat model from TOML — the declarative spec driving the audit."""
        tm = ThreatModel.from_dir(self.config.profile.threat_model_dir)
        self.threat_model = tm
        return tm

    async def start_environment(self, container_id: str | None = None) -> AuditExecution:
        """Start the containerized audit environment.

        Args:
            container_id: If given, tries to restart an existing stopped
                container before creating a new one.

        Returns an AuditExecution context manager. Use with ``with``:

            with harness.start_environment() as execution:
                ...
        """
        p = self.config.profile
        if not self.global_config:
            raise RuntimeError("global_config is required to start an environment")
        cfg = self.global_config
        if cfg.runtime == "nexecutor":
            try:
                from llmpuffin.runtime_nexecutor import NexecutorRuntime
            except ImportError:
                raise RuntimeError(
                    "nexecutor-client is not installed or you are using an outdated version (check if you are using a cached version). "
                    "Install it with: pip install llmpuffin[nexecutor]"
                ) from None

            return await NexecutorRuntime.start(
                image=p.image,
                code_dir=p.code_dir,
                base_url=cfg.nexecutor.url,
                token=cfg.nexecutor.token,
                container_id=container_id,
                backend=cfg.nexecutor.backend or None,
            )
        elif cfg.runtime == "microvm":
            try:
                from llmpuffin.runtime_microvm import MicrovmRuntime
            except ImportError:
                raise RuntimeError(
                    "boto3 is not installed. Install it with: pip install boto3"
                ) from None

            if not cfg.microvm.image_arn:
                raise RuntimeError(
                    "microvm.image_arn is not configured. "
                    "Set it in llmpuffin.toml under [microvm]."
                )

            return await MicrovmRuntime.start(
                image_arn=cfg.microvm.image_arn,
                code_dir=p.code_dir,
                region=cfg.microvm.region,
                profile=cfg.microvm.profile,
                container_id=container_id,
            )
        else:
            from llmpuffin.runtime_podman import PodmanEnvironment

            return await PodmanEnvironment(
                image=p.image,
                code_dir=p.code_dir,
            ).start(container_id=container_id)

    # ── Task management ──

    def spawn(self, thread_id: str, coro: Coroutine) -> asyncio.Task:
        """Launch an audit coroutine and track it by thread_id.

        The task is removed from tracking when it completes. Exceptions
        from the task are logged but not re-raised.
        """
        task = asyncio.create_task(coro)
        self._tasks[thread_id] = task

        def _done(t: asyncio.Task) -> None:
            self._tasks.pop(thread_id, None)
            if not t.cancelled():
                exc = t.exception()
                if exc is not None:
                    log.exception(
                        "Background audit task failed",
                        exc_info=(type(exc), exc, exc.__traceback__),
                    )

        task.add_done_callback(_done)
        return task

    def cancel(self, thread_id: str) -> bool:
        """Cancel a running audit by thread_id. Returns True if found."""
        task = self._tasks.get(thread_id)
        if task is None:
            return False
        task.cancel()
        return True

    async def cancel_all(self, timeout: float = 30.0) -> None:
        """Cancel all in-flight tasks and wait for them to finish."""
        if not self._tasks:
            return
        log.info("Cancelling %d in-flight audit task(s)…", len(self._tasks))
        for t in self._tasks.values():
            t.cancel()
        try:
            await asyncio.wait_for(
                asyncio.gather(*self._tasks.values(), return_exceptions=True),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            log.warning(
                "Audit tasks did not finish within %.0fs; %d still pending",
                timeout,
                len(self._tasks),
            )

    @property
    def running_threads(self) -> set[str]:
        """Thread IDs of currently running audit tasks."""
        return set(self._tasks.keys())
