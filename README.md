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
uv run alembic -c src/llmpuffin_fastapi/alembic.ini upgrade head
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
threat_model_dir = "threat_model/"

[agent]
model = "claude-sonnet-4-20250514"
max_iterations = 200
skills_dir = "vendor/trailofbits-skills/plugins"
```

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
- http://localhost:8000/store/ — langgraph store browser

Override the connection string with `LLMPUFFIN_POSTGRES` env var, or set it in `llmpuffin.toml`.

## Development

Always run the check script after making changes — it formats, lints, runs tests, and byte-compiles every module under `src/`:

```
uv run llmpuffin-check
```

This is the canonical pre-commit gate. See `AGENTS.md` for contributor guidelines.

## Caveats

- **Subagent messages are not visible in checkpoints.** Subagents (threat-model-auditor, finding-validator, function-analyzer) run in their own internal state via deepagents. Only the final summary is returned to the parent thread's checkpoint. Internal subagent tool calls and reasoning are logged to the server console but do not appear in the checkpoint viewer.

- **Stuck threads after crashes.** If the process is killed (SIGKILL, OOM, etc.) before the lifespan can finalize, the thread may remain in `"running"` status. The FastAPI lifespan marks orphaned threads as `"aborted"` on startup. You can also clean them up manually:

  ```
  uv run llmpuffin abort-orphaned-threads
  ```

## Architecture

See `docs/goals.md` for project goals and design rationale.
