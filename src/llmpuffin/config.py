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
    output = "results.sarif"

    [agent]
    model = "anthropic:claude-sonnet-4-20250514"
    max_iterations = 200
    skills_dir = "vendor/trailofbits-skills/plugins"
    # interrupt_on = ["execute", "write_file"]
    # system_prompt = "Custom system prompt (overrides default)"

    [anthropic]
    # effort = "high"  # max, xhigh, high, medium, low
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from llmpuffin.system_prompt import DEFAULT_SYSTEM_PROMPT


# -- Global config (llmpuffin.toml) --


@dataclass
class PostgresConfig:
    url: str = "postgresql://localhost:5434/llmpuffin"


@dataclass
class WebConfig:
    port: int = 8000
    debug: bool = True
    secret_key: str = "dev-insecure-key-change-in-prod"
    allowed_hosts: list[str] = field(default_factory=lambda: ["*"])


@dataclass
class GitHubConfig:
    app_id: str = "3779149"
    private_key: str = ""
    installation_id: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.app_id and self.private_key and self.installation_id)


@dataclass
class AuthConfig:
    enabled: bool = False
    provider_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    # OIDC claim containing group names
    groups_claim: str = "groups"
    # Map llmpuffin roles → OIDC group names
    admin_group: str = "llmpuffin-admin"
    auditor_group: str = "llmpuffin-auditor"

    @property
    def configured(self) -> bool:
        return self.enabled and bool(
            self.provider_url and self.client_id and self.client_secret
        )


@dataclass
class LoggingConfig:
    level: str = "INFO"


@dataclass
class Config:
    """Global llmpuffin configuration."""

    postgres: PostgresConfig = field(default_factory=PostgresConfig)
    web: WebConfig = field(default_factory=WebConfig)
    github: GitHubConfig = field(default_factory=GitHubConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

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
        pg = data.get("postgres", {})
        web = data.get("web", {})
        gh = data.get("github", {})
        auth = data.get("auth", {})
        log = data.get("logging", {})
        return cls(
            postgres=PostgresConfig(
                url=pg.get("url", "postgresql://localhost:5434/llmpuffin"),
            ),
            web=WebConfig(
                port=web.get("port", 8000),
                debug=web.get("debug", True),
                secret_key=web.get("secret_key", "dev-insecure-key-change-in-prod"),
                allowed_hosts=web.get("allowed_hosts", ["*"]),
            ),
            github=GitHubConfig(
                app_id=str(gh.get("app_id", "")),
                private_key=os.environ.get("GH_LLMPUFFIN_KEY", ""),
                installation_id=str(gh.get("installation_id", "")),
            ),
            auth=AuthConfig(
                enabled=auth.get("enabled", False),
                provider_url=auth.get("provider_url", ""),
                client_id=auth.get("client_id", ""),
                client_secret=auth.get("client_secret", ""),
                groups_claim=auth.get("groups_claim", "groups"),
                admin_group=auth.get("admin_group", "llmpuffin-admin"),
                auditor_group=auth.get("auditor_group", "llmpuffin-auditor"),
            ),
            logging=LoggingConfig(
                level=log.get("level", "INFO"),
            ),
        )

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


@dataclass
class ProfileAgent:
    """Agent-level configuration."""

    model: str = "anthropic:claude-sonnet-4-20250514"
    max_iterations: int = 200
    interrupt_on: list[str] = field(default_factory=list)
    skills_dir: Path | None = None
    system_prompt: str = field(default_factory=lambda: DEFAULT_SYSTEM_PROMPT)


@dataclass
class ProfileAnthropic:
    """Anthropic-specific configuration."""

    effort: str | None = None  # max, xhigh, high, medium, low


@dataclass
class Profile:
    """Per-audit profile loaded from TOML."""

    name: str
    image: str
    threat_model_dir: Path
    code_dir: str = "/src"
    agent: ProfileAgent = field(default_factory=ProfileAgent)
    anthropic: ProfileAnthropic = field(default_factory=ProfileAnthropic)

    @classmethod
    def from_toml(cls, path: Path) -> Profile:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return cls._from_dict(data)

    @classmethod
    def from_toml_string(cls, toml_str: str) -> Profile:
        return cls._from_dict(tomllib.loads(toml_str))

    _KNOWN_SECTIONS: ClassVar[set[str]] = {"audit", "agent", "anthropic"}
    _KNOWN_KEYS: ClassVar[dict[str, set[str]]] = {
        "audit": {"name", "image", "threat_model_dir", "code_dir", "output"},
        "agent": {
            "model",
            "max_iterations",
            "interrupt_on",
            "skills_dir",
            "system_prompt",
        },
        "anthropic": {"effort"},
    }

    @classmethod
    def _from_dict(cls, data: dict) -> Profile:
        unknown_sections = set(data.keys()) - cls._KNOWN_SECTIONS
        if unknown_sections:
            raise ValueError(
                f"Unknown profile section(s): {', '.join(sorted(unknown_sections))}"
            )
        for section, keys in cls._KNOWN_KEYS.items():
            unknown_keys = set(data.get(section, {}).keys()) - keys
            if unknown_keys:
                raise ValueError(
                    f"Unknown key(s) in [{section}]: {', '.join(sorted(unknown_keys))}"
                )

        audit = data.get("audit", {})
        agent_data = data.get("agent", {})
        anthropic_data = data.get("anthropic", {})

        skills_dir_str = agent_data.get("skills_dir")
        skills_dir = Path(skills_dir_str) if skills_dir_str else None

        return cls(
            name=audit["name"],
            image=audit["image"],
            threat_model_dir=Path(audit["threat_model_dir"]),
            code_dir=audit.get("code_dir", "/src"),
            agent=ProfileAgent(
                model=agent_data.get("model", "anthropic:claude-sonnet-4-20250514"),
                max_iterations=agent_data.get("max_iterations", 200),
                interrupt_on=agent_data.get("interrupt_on", []),
                skills_dir=skills_dir,
                system_prompt=agent_data.get("system_prompt", DEFAULT_SYSTEM_PROMPT),
            ),
            anthropic=ProfileAnthropic(
                effort=anthropic_data.get("effort"),
            ),
        )


# Backwards compat alias
ProfileAudit = Profile
