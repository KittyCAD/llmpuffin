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

## Usage

Define a threat model in TOML (see `examples/threat_model/`), provide a container image with your codebase, and run the audit:

```
# Build example container
podman build -t llmpuffin-example -f examples/Dockerfile examples/

# Run via CLI args
uv run llmpuffin llmpuffin-example examples/threat_model -v \
    --store-dir examples/.store \
    --postgres postgresql://localhost:5434/llmpuffin

# Or via config file
uv run llmpuffin llmpuffin-example -v -c examples/llmpuffin.toml
```

To resume a previous session that was interrupted:

```
uv run llmpuffin llmpuffin-example -v -c examples/llmpuffin.toml \
    --thread-id <thread-id-from-previous-run>
```

## Web UI

View checkpoints and audit findings:

```
uv run llmpuffin-web runserver
```

- http://localhost:8000/ — checkpoint viewer (conversation history)
- http://localhost:8000/admin/ — admin dashboard (manage audit runs, findings)

Create an admin user on first setup:

```
uv run llmpuffin-web createsuperuser
```

Set `LLMPUFFIN_POSTGRES` to override the connection string (default: `postgresql://localhost:5434/llmpuffin`).

## Architecture

See `docs/goals.md` for project goals and design rationale.
