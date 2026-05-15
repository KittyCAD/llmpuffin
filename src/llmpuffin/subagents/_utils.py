"""Shared utilities for subagent definitions."""

from pathlib import Path


def load_agent_md(path: str) -> str:
    """Load an agent .md file and strip YAML frontmatter."""
    text = Path(path).read_text()
    if text.startswith("---"):
        end = text.index("---", 3)
        return text[end + 3 :].strip()
    return text
