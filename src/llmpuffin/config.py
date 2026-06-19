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

    [logging]
    level = "INFO"

Example profile.toml:

    [audit]
    name = "my-audit"
    image = "ghcr.io/org/repo:latest"
    threat_model_dir = "threat_model/"
    code_dir = "/src"

    [agent]
    model = "anthropic:claude-sonnet-4-20250514"
    max_iterations = 200
    skills_dir = "vendor/trailofbits-skills/plugins"
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

import os
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from llmpuffin.system_prompt import DEFAULT_SYSTEM_PROMPT


# -- Global config (llmpuffin.toml) --


class PostgresConfig(BaseModel):
    url: str = "postgresql://localhost:5434/llmpuffin"


class WebConfig(BaseModel):
    port: int = 8000
    debug: bool = True
    secret_key: str = "dev-insecure-key-change-in-prod"
    allowed_hosts: list[str] = ["*"]


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


class Config(BaseModel):
    """Global llmpuffin configuration."""

    runtime: Literal["podman", "nexecutor"] = "podman"
    nexecutor_url: str = "http://localhost:8080"
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
        gh = data.get("github", {})
        # GH_LLMPUFFIN_KEY env var overrides the private_key field.
        if env_key := os.environ.get("GH_LLMPUFFIN_KEY", ""):
            gh["private_key"] = env_key
        # app_id and installation_id come from TOML as ints, store as str.
        if "app_id" in gh:
            gh["app_id"] = str(gh["app_id"])
        if "installation_id" in gh:
            gh["installation_id"] = str(gh["installation_id"])
        data["github"] = gh
        return cls.model_validate(data)

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
    skills_dir: Path | None = None
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


class Profile(BaseModel):
    """Per-audit profile loaded from TOML."""

    name: str
    image: str
    threat_model_dir: Path
    code_dir: str = "/src"
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
            agent=parsed.agent,
            anthropic=parsed.anthropic,
            openai=parsed.openai,
        )


# Backwards compat alias
ProfileAudit = Profile
