"""TOML configuration loader for llmpuffin.

Example config file (llmpuffin.toml):

    [audit]
    image = "ghcr.io/org/repo:latest"
    threat_model_dir = "threat_model/"
    model = "claude-sonnet-4-20250514"
    max_iterations = 200
    code_dir = "/src"
    output = "results.sarif"

    [agent]
    interpreter = true

    [store]
    dir = ".llmpuffin/store"

    [checkpoint]
    postgres = "postgresql://localhost:5434/llmpuffin"
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AgentConfig:
    """Agent-level configuration."""

    interpreter: bool = False


@dataclass
class AuditConfig:
    """Top-level audit configuration loaded from TOML."""

    image: str
    threat_model_dir: Path
    model: str = "claude-sonnet-4-20250514"
    max_iterations: int = 200
    code_dir: str = "/src"
    output: Path = Path("results.sarif")
    agent: AgentConfig = field(default_factory=AgentConfig)
    store_dir: Path | None = None
    postgres_connstring: str | None = None

    @classmethod
    def from_toml(cls, path: Path) -> AuditConfig:
        with open(path, "rb") as f:
            data = tomllib.load(f)

        audit = data.get("audit", {})
        agent_data = data.get("agent", {})
        store_data = data.get("store", {})
        checkpoint_data = data.get("checkpoint", {})

        store_dir = Path(store_data["dir"]) if "dir" in store_data else None

        return cls(
            image=audit["image"],
            threat_model_dir=Path(audit["threat_model_dir"]),
            model=audit.get("model", "claude-sonnet-4-20250514"),
            max_iterations=audit.get("max_iterations", 200),
            code_dir=audit.get("code_dir", "/src"),
            output=Path(audit.get("output", "results.sarif")),
            agent=AgentConfig(
                interpreter=agent_data.get("interpreter", False),
            ),
            store_dir=store_dir,
            postgres_connstring=checkpoint_data.get("postgres"),
        )
