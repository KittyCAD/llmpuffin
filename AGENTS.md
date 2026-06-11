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
  - `models.py` — SQLAlchemy models (`AuditProfile`, `AuditRun`, `AuditThread`, `Finding`, `FindingLocation`, `FindingComment`, `FindingAttachment`, `ValidationNote`, `GitHubLink`).
  - `db.py` — `DB` class holding async + sync engines/sessions. Created once and passed explicitly — no global state.
  - `harness.py` — `HarnessConfig` (profile + TOML), `Harness` (threat model loading, container lifecycle, task tracking for running audits).
  - `checkpoint.py` — reading langgraph checkpoint data for the conversation viewer.
  - `system_prompt.py` — default system prompt for the audit agent (overridable per profile).
  - `alembic/` — database migrations.
- `src/llmpuffin_fastapi/` — FastAPI web UI (Jinja2 + HTMX + Alpine.js).
  - `deps.py` — FastAPI dependencies (`get_db`, `get_harness`, `get_llmpuffin_db`, `get_github_client`, `toast`).
  - `templates/` — Jinja2 templates. `_` prefix = partials/macros. `_composer.html` = reusable message composer. `_conversation.html` = polling conversation viewer.
  - `static/app.css` — shadcn-style tokens (HSL triplets), Tailwind v4 browser build for utilities.
- `src/llmpuffin_dev/` — developer scripts (`check`, `run`, `postgres`).
- `profiles/` — per-codebase audit profiles.

## Architecture principles

- **No global mutable state.** `DB` is created once and passed via function args (keyword-only `*, db: DB`). `Harness` lives on `app.state.harness` in FastAPI. No module-level singletons.
- **DB is the source of truth.** No in-memory shadow state (the old `SarifReport` was removed). SARIF export reads from DB.
- **Keyword-only `db` parameter.** All functions taking a `DB` instance use `*, db: DB` to prevent positional misuse.
- **Alpine owns reactivity, htmx owns the network.** Use `@htmx:event` (Alpine listener) when updating Alpine state from htmx events. Use `hx-on::event` (htmx listener) for pure DOM/htmx operations.

## Key conventions

- **Never use the word "AI" in user-facing text.** Use "LLM" instead.
- **Never wipe the database.** Use incremental Alembic migrations under `src/llmpuffin/alembic/versions/`.
- **Assume the database is present.** Drop fallback branches that paper over missing Postgres.
- **Tool calls from subagents** are logged to the server console via `_ToolLogHandler` but do not show up in the checkpoint viewer — that is a deepagents architecture constraint.
- **Finding `local_id` allocation** uses a per-`audit_run_id` Postgres advisory lock (`pg_advisory_xact_lock`) inside the insert transaction. A unique constraint `(audit_run_id, local_id)` enforces correctness; the advisory lock prevents the race.
- **Background audit tasks** are tracked by `Harness._tasks` (dict keyed by thread_id). `harness.spawn(thread_id, coro)` launches, `harness.cancel(thread_id)` stops. The FastAPI lifespan calls `harness.cancel_all()` on shutdown.
- **Inline editing** uses Alpine `x-data="{ editing: false }"` with `x-show` to toggle between display and edit mode. Selects auto-submit on change; text inputs submit on Enter.

## Commands

| What                       | Command                                                                |
| -------------------------- | ---------------------------------------------------------------------- |
| Install deps               | `uv sync`                                                              |
| Start PostgreSQL           | `uv run llmpuffin-pg start`                                            |
| Apply migrations           | `uv run alembic -c src/llmpuffin/alembic.ini upgrade head`             |
| Create a migration         | `uv run alembic -c src/llmpuffin/alembic.ini revision -m "…"`          |
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
2. Create an Alembic revision under `src/llmpuffin/alembic/versions/` (manually numbered `NNNN_<slug>.py`, following the existing convention).
3. Write both `upgrade()` and `downgrade()`.
4. Apply with `uv run alembic -c src/llmpuffin/alembic.ini upgrade head`.
5. Run `uv run llmpuffin-check`.
