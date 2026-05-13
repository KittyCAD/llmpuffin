"""TOML configuration loader for llmpuffin.

Example config file (llmpuffin.toml):

    [audit]
    name = "my-audit"
    image = "ghcr.io/org/repo:latest"
    threat_model_dir = "threat_model/"
    model = "claude-sonnet-4-20250514"
    max_iterations = 200
    code_dir = "/src"
    output = "results.sarif"

    [agent]
    interpreter = true
    skills_dir = "vendor/trailofbits-skills/plugins"
    # interrupt_on = ["execute", "write_file"]

    [store]
    dir = ".llmpuffin/store"

"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ProfileAgent:
    """Agent-level configuration."""

    interpreter: bool = False
    # Tool names that require human approval before execution
    interrupt_on: list[str] = field(default_factory=list)
    # Directory containing plugin subdirs (mirrored 1:1 into /skills/ store)
    skills_dir: Path | None = None


@dataclass
class ProfileAudit:
    """Top-level audit configuration loaded from TOML."""

    name: str
    image: str
    threat_model_dir: Path
    model: str = "claude-sonnet-4-20250514"
    max_iterations: int = 200
    code_dir: str = "/src"
    output: Path = Path("results.sarif")
    agent: ProfileAgent = field(default_factory=ProfileAgent)

    @classmethod
    def from_toml(cls, path: Path) -> ProfileAudit:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return cls._from_dict(data)

    @classmethod
    def from_toml_string(cls, toml_str: str) -> ProfileAudit:
        data = tomllib.loads(toml_str)
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict) -> ProfileAudit:
        audit = data.get("audit", {})
        agent_data = data.get("agent", {})

        skills_dir_str = agent_data.get("skills_dir")
        skills_dir = Path(skills_dir_str) if skills_dir_str else None

        return cls(
            name=audit["name"],
            image=audit["image"],
            threat_model_dir=Path(audit["threat_model_dir"]),
            model=audit.get("model", "claude-sonnet-4-20250514"),
            max_iterations=audit.get("max_iterations", 200),
            code_dir=audit.get("code_dir", "/src"),
            output=Path(audit.get("output", "results.sarif")),
            agent=ProfileAgent(
                interpreter=agent_data.get("interpreter", False),
                interrupt_on=agent_data.get("interrupt_on", []),
                skills_dir=skills_dir,
            ),
        )
