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
    model = "claude-sonnet-4-20250514"
    max_iterations = 200
    interpreter = true
    skills_dir = "vendor/trailofbits-skills/plugins"
    # interrupt_on = ["execute", "write_file"]
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


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
class LoggingConfig:
    level: str = "INFO"


@dataclass
class Config:
    """Global llmpuffin configuration."""

    postgres: PostgresConfig = field(default_factory=PostgresConfig)
    web: WebConfig = field(default_factory=WebConfig)
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

    model: str = "claude-sonnet-4-20250514"
    max_iterations: int = 200
    interpreter: bool = False
    interrupt_on: list[str] = field(default_factory=list)
    skills_dir: Path | None = None


@dataclass
class Profile:
    """Per-audit profile loaded from TOML."""

    name: str
    image: str
    threat_model_dir: Path
    code_dir: str = "/src"
    output: Path = Path("results.sarif")
    agent: ProfileAgent = field(default_factory=ProfileAgent)

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
        audit = data.get("audit", {})
        agent_data = data.get("agent", {})

        skills_dir_str = agent_data.get("skills_dir")
        skills_dir = Path(skills_dir_str) if skills_dir_str else None

        return cls(
            name=audit["name"],
            image=audit["image"],
            threat_model_dir=Path(audit["threat_model_dir"]),
            code_dir=audit.get("code_dir", "/src"),
            output=Path(audit.get("output", "results.sarif")),
            agent=ProfileAgent(
                model=agent_data.get("model", "claude-sonnet-4-20250514"),
                max_iterations=agent_data.get("max_iterations", 200),
                interpreter=agent_data.get("interpreter", False),
                interrupt_on=agent_data.get("interrupt_on", []),
                skills_dir=skills_dir,
            ),
        )


# Backwards compat alias
ProfileAudit = Profile
