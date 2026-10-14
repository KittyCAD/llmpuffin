# llmpuffin

Agentic codebase security review, driven by structured threat models.

## Setup

Requires [Nix](https://nixos.org/) with flakes enabled.

```
nix develop
uv sync
```

On macOS, initialize the Podman VM once:

```
podman machine init && podman machine start
```

## Database

Start a local PostgreSQL for session checkpointing and audit data (user-local, no daemon):

```
uv run llmpuffin-pg start
uv run llmpuffin-pg status
uv run llmpuffin-pg stop
```

Data lives in `.postgres/pgdata/`, port 5434.

Apply database migrations after starting PostgreSQL:

```
uv run alembic -c src/llmpuffin/alembic.ini upgrade head
```

## Configuration

Global settings live in `llmpuffin.toml` (auto-loaded from cwd):

```toml
[postgres]
url = "postgresql://localhost:5434/llmpuffin"

[web]
port = 8000

[logging]
level = "INFO"
```

Audit profiles live in separate `profile.toml` files:

```toml
[audit]
name = "my-audit"
image = "my-image:latest"
threat_model = "my-audit"

[agent]
model = "claude-sonnet-4-20250514"
max_iterations = 200
skills = ["audit-context-building"]
```

### Nexecutor

The nexecutor runtime uses persistent HTTP sessions with asynchronous command
receipts. It requires a nexecutor server with session support and
`NEXECUTOR_SESSIONS_ENABLED=true`; the old `nexecutor-client` SDK is no longer
needed. Configure the existing server address and authentication as before:

```toml
runtime = "nexecutor"

[nexecutor]
url = "http://localhost:8080"
backend = "k8s" # or "microvm" for a configured MicroVM backend
session_lifetime_seconds = 14400
```

The token setting accepts a bearer token or projected-token file. An empty setting
uses the standard Pod Identity token file when present. Kubernetes session images
need `/bin/sh`, `sleep`, and GNU `timeout`; MicroVM images need the HTTP exec agent.

Tool calls share the same filesystem. llmpuffin sends keepalives while the audit
runs, polls command receipts, and retrieves lost responses by idempotency key.
It stops on unknown command outcomes or changed session history instead of
repeating commands or recreating an empty workspace. Stopping an audit requests
termination of its session. Start new audits when switching from legacy workload
IDs; existing legacy workloads cannot be resumed through the session API.

Deploy nexecutor session support before updating llmpuffin. After other clients
have migrated and old workloads have drained, the operator can set
`NEXECUTOR_LEGACY_WORKLOADS_ENABLED=false`. The nexecutor execution-run guide
contains the server rollout steps and recovery limits.

## Usage

Build the container image and run an audit:

```
# Build + run a single profile
uv run llmpuffin-run -v -p profiles/modeling-app/profile.toml

# Build + run all profiles
uv run llmpuffin-run -v
```

Or use the `llmpuffin` CLI directly:

```
# Run an audit
uv run llmpuffin run -p profiles/modeling-app/profile.toml -v

# Abort orphaned threads (cleanup after crashes)
uv run llmpuffin abort-orphaned-threads
```

Available profiles in `profiles/`:
- `modeling-app` — Zoo Design Studio (KittyCAD/modeling-app)
- `engine` — Geometry Engine (KittyCAD/engine)
- `text-to-cad` — Text-to-CAD service (KittyCAD/text-to-cad)
- `api` — KittyCAD API (KittyCAD/api)

## Web UI

View audit runs and findings:

```
uv run llmpuffin-fastapi
```

- http://localhost:8000/ — audit runs and findings
- http://localhost:8000/profiles/ — audit profiles (create, run)
- http://localhost:8000/checkpoints/ — checkpoint viewer (conversation history)
- http://localhost:8000/memory/ — LLM memory browser

Override the connection string with `LLMPUFFIN_POSTGRES` env var, or set it in `llmpuffin.toml`.

## Development

Always run the check script after making changes — it formats, lints, runs tests, and byte-compiles every module under `src/`:

```
uv run llmpuffin-check
```

This is the canonical pre-commit gate. See `AGENTS.md` for contributor guidelines.

## Embeddings

Finding embeddings power the "similar findings" feature, which identifies duplicate or related findings across audit runs using semantic similarity.

Embeddings are generated locally using [sentence-transformers](https://www.sbert.net/) (`all-MiniLM-L6-v2`, ~80MB model, runs on CPU). No API keys required.

New findings are embedded automatically when reported. To backfill embeddings for existing findings:

```
uv run llmpuffin-embed
```

## Caveats

- **Subagent messages are not visible in checkpoints.** Subagents (threat-model-auditor, finding-validator, function-analyzer) run in their own internal state via deepagents. Only the final summary is returned to the parent thread's checkpoint. Internal subagent tool calls and reasoning are logged to the server console but do not appear in the checkpoint viewer.

- **Stuck threads after crashes.** If the process is killed (SIGKILL, OOM, etc.) before the lifespan can finalize, the thread may remain in `"running"` status. The FastAPI lifespan marks orphaned threads as `"aborted"` on startup. You can also clean them up manually:

  ```
  uv run llmpuffin abort-orphaned-threads
  ```

## Architecture

See `docs/goals.md` for project goals and design rationale.
