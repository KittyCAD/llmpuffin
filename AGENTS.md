# AGENTS.md

Guidance for coding agents (and humans) working in this repository.

## Always run the check script

After every change, run:

```
uv run llmpuffin-check
```

This is non-negotiable. The script (`src/llmpuffin_dev/check.py`) does, in order:

1. `ruff format src/` — formats all source.
2. `ruff check --fix src/` — lints + auto-fixes.
3. `pytest tests/ -q` — runs the test suite.
4. `compileall src/` — byte-compiles every module to catch syntax/import errors.

The command exits non-zero if any step fails. **Do not declare work done until `llmpuffin-check` passes cleanly.**

## Project layout

- `src/llmpuffin/` — audit harness (agent, tools, threat model, container backend, SARIF output).
  - `agent.py` — deepagents orchestrator. The main agent only has finding-management tools (`MAIN_AGENT_TOOLS`); threat-model tools are scoped to subagents.
  - `subagents/` — one subagent per file. Each module exports a `TOOLS` tuple of tool names and a factory `name(tools)` that builds the spec from the shared tools dict. Shared constants live in `subagents/_constants.py`.
  - `tools.py` — `make_tools(...)` returns a `dict[str, Callable]`; the parent agent and subagents pick the names they need.
  - `models.py` — SQLAlchemy models (`AuditProfile`, `AuditRun`, `AuditThread`, `Finding`, `FindingLocation`).
  - `db.py` — async + sync session factories, `setup_db()`.
- `src/llmpuffin_fastapi/` — FastAPI web UI (Jinja2 + HTMX) and Alembic migrations under `alembic/`.
- `src/llmpuffin_dev/` — developer scripts (`check`, `run`, `postgres`).
- `profiles/` — per-codebase audit profiles.
- `threat_model/` — example threat model TOML files.

## Key conventions

- **Never use the word "AI" in user-facing text.** Use "LLM" instead.
- **Never wipe the database.** Use incremental Alembic migrations under `src/llmpuffin_fastapi/alembic/versions/`.
- **Assume the database is present.** Drop fallback branches that paper over missing Postgres.
- **Tool calls from subagents** are logged to the server console via `_ToolLogHandler` but do not show up in the checkpoint viewer — that is a deepagents architecture constraint.
- **Finding `local_id` allocation** uses a per-`audit_run_id` Postgres advisory lock (`pg_advisory_xact_lock`) inside the insert transaction. A unique constraint `(audit_run_id, local_id)` enforces correctness; the advisory lock prevents the race.
- **Background tasks** are launched via `asyncio.create_task` and tracked in a module-level set in `src/llmpuffin_fastapi/deps.py`. The FastAPI lifespan cancels in-flight tasks on shutdown so `_finalize_audit_run` can mark threads as `"aborted"`.

## Commands

| What                       | Command                                                                |
| -------------------------- | ---------------------------------------------------------------------- |
| Install deps               | `uv sync`                                                              |
| Start PostgreSQL           | `uv run llmpuffin-pg start`                                            |
| Apply migrations           | `uv run alembic -c src/llmpuffin_fastapi/alembic.ini upgrade head`     |
| Create a migration         | `uv run alembic -c src/llmpuffin_fastapi/alembic.ini revision -m "…"`  |
| Run an audit               | `uv run llmpuffin-run -v -p profiles/<profile>/profile.toml`           |
| Run the web UI             | `uv run llmpuffin-fastapi`                                             |
| **Check (lint+test+compile)** | **`uv run llmpuffin-check`**                                        |

## When adding a subagent

1. Create `src/llmpuffin/subagents/<name>.py` with:
   - a `TOOLS` tuple of tool names to grant,
   - a factory function `<name>(tools: dict[str, Callable]) -> dict` returning the deepagents `SubAgent` spec including `"tools": [tools[n] for n in TOOLS]`.
2. Register it in `src/llmpuffin/subagents/__init__.py` `build_subagents()`.
3. If the new subagent introduces a new tool, add it to `tools.py:make_tools` and the relevant `TOOLS` tuples.

## When changing the schema

1. Modify `src/llmpuffin/models.py`.
2. Create an Alembic revision under `src/llmpuffin_fastapi/alembic/versions/` (manually numbered `NNNN_<slug>.py`, following the existing convention).
3. Write both `upgrade()` and `downgrade()`.
4. Apply with `uv run alembic -c src/llmpuffin_fastapi/alembic.ini upgrade head`.
5. Run `uv run llmpuffin-check`.
