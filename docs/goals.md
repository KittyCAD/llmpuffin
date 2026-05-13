# Project Goals

llmpuffin is a **harness** for LLM-driven security audits of codebases. The harness is the code that determines what to store, retrieve, and show to the model.

## What llmpuffin does

1. **Review codebases** against a structured threat model
2. **Review changes** to codebases against the same model (planned)

## Core concepts

### Threat model (TOML)

The threat model is the declarative input that drives the audit. It follows the [TRAIL methodology](https://blog.trailofbits.com/2025/02/28/threat-modeling-the-trail-of-bits-way/) from Trail of Bits:

- **Components** — system elements (services, libraries, data stores), organized hierarchically
- **Trust zones** — groups of components sharing a security posture; boundaries exist at zone edges
- **Connections** — data/control flow between components that cross trust boundaries (= attack surface)
- **Threat scenarios** — specific ways an adversary could exploit a boundary-crossing connection, categorized by [STRIDE](https://en.wikipedia.org/wiki/STRIDE_(security)) and severity

The threat model is maintained externally and provided as input. llmpuffin does not generate it.

### Harness

A harness is distinct from an agent framework (LangChain) and an orchestrator (LangGraph). Frameworks provide building blocks. Orchestrators decide when and how to invoke the model. The harness provides **capabilities and side effects**: what context the model sees, what tools it can use, how results are verified and persisted. See [What is an Agent Harness](https://parallel.ai/articles/what-is-an-agent-harness).

The threat model TOML is the **declarative specification layer** — the part of the harness a [meta-harness](https://arxiv.org/abs/2603.28052) could optimize across runs.

### AuditEnvironment / AuditExecution

Each audit target is a container image with the codebase baked in. An `AuditEnvironment` wraps the image; starting it produces an `AuditExecution` — a running Podman container. The agent has arbitrary command execution inside the container (read files, write tests, run static analysis, execute PoCs). The container boundary provides isolation; the host is never touched.

Filesystem layout inside the container:

- `/src` — original codebase (read-only)
- `/workspace` — writable copy (agent's working directory)
- `/tmp` — scratch space

### Output

Results are SARIF files. Each finding links back to the threat scenario(s) that motivated it, maintaining traceability from threat model to code to finding.

## Design principles

- **Declarative specification** — threat model TOML, not imperative scripts
- **Containerized execution** — all agent actions happen inside Podman containers
- **Model agnosticism** — the harness does not depend on a specific LLM
- **Measurability** — structured SARIF output with severity and confidence
- **Separation of concerns** — harness (capabilities) vs orchestrator (control flow) vs framework (abstractions)
