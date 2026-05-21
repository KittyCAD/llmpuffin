"""Centralized Markdown → sanitized HTML rendering."""

from __future__ import annotations

import markdown as _markdown
import nh3


def render_markdown(text: str) -> str:
    """Convert Markdown text to sanitized HTML.

    Uses python-markdown for rendering, then nh3 to strip any dangerous
    tags/attributes (scripts, iframes, event handlers, javascript: URLs, etc.).
    """
    if not text:
        return ""
    html = _markdown.markdown(text, extensions=["fenced_code", "tables", "nl2br"])
    return nh3.clean(
        html,
        url_schemes={"http", "https"},
        link_rel="noopener noreferrer",
    )
