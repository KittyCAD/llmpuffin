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

Start a local PostgreSQL for session checkpointing (user-local, no daemon):

```
uv run llmpuffin-pg start
uv run llmpuffin-pg status
uv run llmpuffin-pg stop
```

Data lives in `.postgres/pgdata/`, port 5434.

Apply database migrations after starting PostgreSQL:

```
uv run llmpuffin-web migrate
```

## Configuration

Global settings live in `llmpuffin.toml` (auto-loaded from cwd):

```toml
[postgres]
url = "postgresql://localhost:5434/llmpuffin"

[web]
port = 8000
debug = true

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

Available profiles in `profiles/`:
- `modeling-app` — Zoo Design Studio (KittyCAD/modeling-app)
- `engine` — Geometry Engine (KittyCAD/engine)
- `text-to-cad` — Text-to-CAD service (KittyCAD/text-to-cad)
- `api` — KittyCAD API (KittyCAD/api)

## Web UI

View audit runs and findings:

```
uv run llmpuffin-web runserver
```

- http://localhost:8000/ — audit runs and findings
- http://localhost:8000/checkpoints/ — checkpoint viewer (conversation history)
- http://localhost:8000/admin/ — admin dashboard

Create an admin user on first setup:

```
uv run llmpuffin-web createsuperuser
```

Override the connection string with `LLMPUFFIN_POSTGRES` env var, or set it in `llmpuffin.toml`.

## Caveats

- **Subagent messages are not visible in checkpoints.** Subagents (threat-model-auditor, finding-validator, function-analyzer) run in their own internal state via deepagents. Only the final summary is returned to the parent thread's checkpoint. Internal subagent tool calls and reasoning are logged to the server console but do not appear in the checkpoint viewer.

- **Graceful shutdown requires `--noreload`.** Run `uv run llmpuffin-web runserver --noreload` for graceful Ctrl+C handling — active audits will finish and save their status as "aborted". With the auto-reloader (default), the parent process kills the child before threads can clean up.

- **Stuck threads after crashes.** If the process is killed (SIGKILL, OOM, etc.) before completion, the thread remains in "running" status. Use the Django admin panel (`/admin/llmpuffin/auditthread/`) and the "Mark as completed" action to reset stuck threads.

## Architecture

See `docs/goals.md` for project goals and design rationale.
