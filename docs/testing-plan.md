# Testing Plan

Approved test additions for the llmpuffin codebase.

## Existing Tests
- `tests/test_config.py` — Config env var overrides
- `tests/test_tools.py` — Tool documentation and schema
- `tests/test_grep.py` — ContainerBackend.grep pattern handling

## Approved New Tests

### 1. `tests/test_models.py` — Models unit tests
**Target:** `src/llmpuffin/models.py`
- `GitInfo.github_url()` edge cases:
  - Valid HTTPS GitHub remote → correct blob URL
  - Non-GitHub remote → None
  - Empty remote → None
  - With/without `.git` suffix
  - Short head (< 7 chars), missing head → falls back to "main"
  - With and without line number
- `AuditRun.status` derivation:
  - No threads → "pending"
  - Any thread running → "running"
  - Any thread error (none running) → "error"
  - Any thread recursion_limit → "recursion_limit"
  - All completed → "completed"

### 2. `tests/test_markdown.py` — Markdown sanitization
**Target:** `src/llmpuffin/markdown.py`
- Basic markdown rendering (bold, code blocks, tables)
- XSS prevention:
  - `<script>` tags stripped
  - `onclick` and other event handlers stripped
  - `javascript:` URLs stripped
  - `<iframe>` stripped
- Empty/None input → empty string
- Fenced code blocks preserved
- Links get `rel="noopener noreferrer"`

### 3. `tests/test_config.py` — Profile tests (extend existing)
**Target:** `src/llmpuffin/config.py`
- `Profile.from_toml` / `from_toml_string`:
  - Minimal valid profile
  - All fields populated
  - Extra keys rejected (`extra='forbid'`)
  - Missing required fields raise error
- `Profile.provider` inference:
  - `"anthropic:claude-sonnet-4-20250514"` → `"anthropic"`
  - `"openai:gpt-4"` → `"openai"`
  - `"claude-sonnet-4-20250514"` (bare) → `"anthropic"`
  - `"gpt-4o"` (bare) → `"openai"`
  - `"o3"` (bare) → `"openai"`
  - `"unknown-model"` → `"unknown"`

### 4. `tests/test_db.py` — DB URL rewriting
**Target:** `src/llmpuffin/db.py`
- `_to_async_url`:
  - `postgresql://...` → `postgresql+asyncpg://...`
  - `postgresql+asyncpg://...` → unchanged
- `_to_sync_url`:
  - `postgresql://...` → `postgresql+psycopg://...`
  - `postgresql+psycopg://...` → unchanged
- Preserves user, password, host, port, dbname in URL

### 5. `tests/test_harness_steps.py` — Token injection
**Target:** `src/llmpuffin/harness_steps.py`
- `_inject_token`:
  - HTTPS URL → token injected as `x-access-token:<token>@`
  - Non-HTTPS URL (ssh://, git://) → returned unchanged
  - Token with special characters

### 6. `tests/test_backend.py` — Extended backend tests
**Target:** `src/llmpuffin/backend.py`
Uses same local `_run` pattern as `test_grep.py`.
- `execute()`:
  - Captures stdout and stderr
  - Truncation at max_output_bytes
  - Non-zero exit code appended to output
- `edit()`:
  - Single occurrence replacement
  - Multiple occurrences with replace_all=True
  - Multiple occurrences without replace_all → error
  - String not found → error
  - File not found → error
- `write()`:
  - File already exists → error
  - Creates parent dirs
  - Writes content correctly
- `read()`:
  - Reads with offset/limit
  - File not found → error
- `ls()`:
  - Lists files and dirs
  - Identifies directories vs files

### 7. `tests/test_api.py` — FastAPI integration tests
**Target:** `src/llmpuffin_fastapi/routes/`
Requires: postgres test fixture (test DB), FastAPI TestClient.
- Profiles CRUD:
  - POST create profile
  - GET list profiles
  - GET profile detail
  - PUT update profile
- Runs:
  - GET list runs (empty, with data)
- Findings:
  - GET list findings for a run
- Skills:
  - POST create skill
  - GET list skills
- Threat models:
  - POST create threat model
  - GET list threat models

## Skipped (with rationale)
- `threat_model.py` — straightforward Pydantic + list operations
- `sarif.py` — serialization detail
- `github.py` — formatting is trivial, API methods need real GitHub
- `runtime_nexecutor.py` — better tested via integration
- `runtime_podman.py` — requires Docker daemon
- `runtime_microvm.py` — requires AWS
- `subagents/_utils.py` — 3-line function
- `agent.py` — orchestration code, needs full stack
- `harness.py` — thin wiring layer
- `checkpoint.py` — needs postgres + langgraph tables
- `system_prompt.py` — string constant
- `log.py` — logging setup
- UI templates — excluded by requirement