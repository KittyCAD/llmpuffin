"""TOML configuration loader for llmpuffin.

Two separate files:

  llmpuffin.toml — Global config (postgres, web, logging).
  profile.toml   — Per-audit profile (audit target, agent settings).

Example llmpuffin.toml:

    [postgres]
    url = "postgresql://localhost:5434/llmpuffin"

    [web]
    port = 8000
    debug = true
    secret_key = "change-me-in-prod"
    allowed_hosts = ["*"]
    base_url = "https://llmpuffin.example.com"

    [logging]
    level = "INFO"

Environment variables override TOML values. Convention:

    LLMPUFFIN__<FIELD>                  — top-level fields
    LLMPUFFIN__<SECTION>__<FIELD>       — nested fields

Examples:
    LLMPUFFIN__RUNTIME=nexecutor
    LLMPUFFIN__POSTGRES__URL=postgresql://...
    LLMPUFFIN__WEB__PORT=9000
    LLMPUFFIN__GITHUB__PRIVATE_KEY=...

Example profile.toml:

    [audit]
    name = "my-audit"
    image = "ghcr.io/org/repo:latest"
    threat_model_dir = "threat_model/"
    code_dir = "/src"

    [agent]
    model = "anthropic:claude-sonnet-4-20250514"
    max_iterations = 200
    skills = ["audit-context-building"]
    # interrupt_on = ["execute", "write_file"]
    # system_prompt = "Custom system prompt (overrides default)"

    [anthropic]
    # effort = "high"  # max, xhigh, high, medium, low

    # Or use OpenAI:
    # [agent]
    # model = "openai:o3"
    #
    # [openai]
    # reasoning_effort = "high"  # high, medium, low
    # use_responses_api = true
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict
from pydantic_settings import BaseSettings, SettingsConfigDict

from llmpuffin.system_prompt import DEFAULT_SYSTEM_PROMPT


# -- Global config (llmpuffin.toml) --


class PostgresConfig(BaseModel):
    url: str = "postgresql://localhost:5434/llmpuffin"
    ca_cert: str = ""
    """PEM-encoded CA certificate for TLS connections."""


class WebConfig(BaseModel):
    port: int = 8000
    debug: bool = True
    secret_key: str = "dev-insecure-key-change-in-prod"
    allowed_hosts: list[str] = ["*"]
    base_url: str = ""
    """External base URL (e.g. https://llmpuffin.example.com). Used for backlinks in GitHub issues."""


class GitHubConfig(BaseModel):
    app_id: str = "3779149"
    private_key: str = ""
    installation_id: str = ""
    findings_repo: str = ""
    """Private repo (owner/repo) to create issues in instead of advisories for public repos."""

    @property
    def configured(self) -> bool:
        return bool(self.app_id and self.private_key and self.installation_id)


class AuthConfig(BaseModel):
    enabled: bool = False
    provider_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    groups_claim: str = "groups"
    admin_group: str = "llmpuffin-admin"
    auditor_group: str = "llmpuffin-auditor"

    @property
    def configured(self) -> bool:
        return self.enabled and bool(
            self.provider_url and self.client_id and self.client_secret
        )


class LoggingConfig(BaseModel):
    level: str = "INFO"


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base, recursing into nested dicts."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


class Config(BaseSettings):
    """Global llmpuffin configuration.

    Values are loaded in order (later wins):
      1. Field defaults
      2. llmpuffin.toml (if present)
      3. Environment variables (LLMPUFFIN__* prefix)
    """

    model_config = SettingsConfigDict(
        env_prefix="LLMPUFFIN__",
        env_nested_delimiter="__",
    )

    runtime: Literal["podman", "nexecutor", "microvm"] = "podman"
    nexecutor_url: str = "http://localhost:8080"
    nexecutor_token: str = ""
    microvm_image_arn: str = ""
    microvm_region: str = "us-east-1"
    microvm_profile: str = ""
    postgres: PostgresConfig = PostgresConfig()
    web: WebConfig = WebConfig()
    github: GitHubConfig = GitHubConfig()
    auth: AuthConfig = AuthConfig()
    logging: LoggingConfig = LoggingConfig()

    @classmethod
    def from_toml(cls, path: Path) -> Config:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return cls._from_dict(data)

    @classmethod
    def from_toml_string(cls, toml_str: str) -> Config:
        return cls._from_dict(tomllib.loads(toml_str))

    @classmethod
    def _from_dict(cls, data: dict) -> Config:
        # TOML ints → str for GitHub config fields.
        gh = data.get("github", {})
        for k in ("app_id", "installation_id"):
            if k in gh:
                gh[k] = str(gh[k])
        if gh:
            data["github"] = gh

        # Build from env vars first (via pydantic-settings), then layer
        # TOML underneath as defaults. Env vars win over TOML.
        env_config = cls()
        env_overrides = env_config.model_dump(exclude_defaults=True)
        # Deep-merge: TOML is the base, env overrides on top.
        merged = _deep_merge(data, env_overrides)
        return cls.model_validate(merged)

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        """Load config from path, or search for llmpuffin.toml in cwd."""
        if path:
            return cls.from_toml(path)
        default = Path("llmpuffin.toml")
        if default.exists():
            return cls.from_toml(default)
        return cls()


# -- Profile (profile.toml) --


class ProfileAgent(BaseModel):
    """Agent-level configuration."""

    model_config = ConfigDict(extra="forbid")

    model: str = "anthropic:claude-sonnet-4-20250514"
    max_iterations: int = 200
    interrupt_on: list[str] = []
    skills: list[str] = []
    system_prompt: str = DEFAULT_SYSTEM_PROMPT


class ProfileAnthropic(BaseModel):
    """Anthropic-specific configuration."""

    model_config = ConfigDict(extra="forbid")

    effort: Literal["max", "xhigh", "high", "medium", "low"] | None = None


class ProfileOpenAI(BaseModel):
    """OpenAI-specific configuration."""

    model_config = ConfigDict(extra="forbid")

    reasoning_effort: Literal["high", "medium", "low"] | None = None
    use_responses_api: bool = True


class ProfileRepo(BaseModel):
    """A git repository to clone into the audit container before running.

    Cloned into /src/<repo-name> by default. Use ``path`` to override
    when multiple repos would have the same name.
    """

    model_config = ConfigDict(extra="forbid")

    url: str
    name: str = ""
    lfs: bool = False


class _AuditSection(BaseModel):
    """Validates the [audit] section of a profile TOML."""

    model_config = ConfigDict(extra="forbid")

    name: str
    image: str
    threat_model_dir: str
    code_dir: str = "/src"


class _ProfileToml(BaseModel):
    """Validates the top-level structure of a profile TOML file."""

    model_config = ConfigDict(extra="forbid")

    audit: _AuditSection
    agent: ProfileAgent = ProfileAgent()
    anthropic: ProfileAnthropic = ProfileAnthropic()
    openai: ProfileOpenAI = ProfileOpenAI()
    repo: list[ProfileRepo] = []


class Profile(BaseModel):
    """Per-audit profile loaded from TOML."""

    name: str
    image: str
    threat_model_dir: Path
    code_dir: str = "/src"
    repos: list[ProfileRepo] = []
    agent: ProfileAgent = ProfileAgent()
    anthropic: ProfileAnthropic = ProfileAnthropic()
    openai: ProfileOpenAI = ProfileOpenAI()

    @property
    def provider(self) -> str:
        """Derive the provider from the model string (e.g. 'anthropic:...' → 'anthropic')."""
        model = self.agent.model
        if ":" in model:
            return model.split(":", 1)[0]
        # Infer from model name prefix
        lower = model.lower()
        if lower.startswith(("claude",)):
            return "anthropic"
        if lower.startswith(("gpt-", "o1", "o3", "o4")):
            return "openai"
        return "unknown"

    @classmethod
    def from_toml(cls, path: Path) -> Profile:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return cls._from_dict(data)

    @classmethod
    def from_toml_string(cls, toml_str: str) -> Profile:
        return cls._from_dict(tomllib.loads(toml_str))

    @classmethod
    def _from_dict(cls, data: dict) -> Profile:
        # Validate structure + reject unknown keys via the strict schema.
        parsed = _ProfileToml.model_validate(data)
        return cls(
            name=parsed.audit.name,
            image=parsed.audit.image,
            threat_model_dir=Path(parsed.audit.threat_model_dir),
            code_dir=parsed.audit.code_dir,
            repos=parsed.repo,
            agent=parsed.agent,
            anthropic=parsed.anthropic,
            openai=parsed.openai,
        )


# Backwards compat alias
ProfileAudit = Profile
