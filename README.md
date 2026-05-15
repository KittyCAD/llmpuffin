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

See `examples/` for ready-to-run setups:

```
# Vulnerable app example
bash examples/vulnerable-app/run.sh

# Zoo Design Studio (modeling-app) example
bash examples/modeling-app/run.sh

# Or run directly with a profile
uv run llmpuffin -v -p examples/vulnerable-app/profile.toml
```

To resume a previous session:

```
uv run llmpuffin -v -p examples/vulnerable-app/profile.toml \
    --thread-id <thread-id-from-previous-run>
```

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

## Architecture

See `docs/goals.md` for project goals and design rationale.
