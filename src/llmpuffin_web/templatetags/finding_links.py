"""Template tags and filters for finding display."""

import markdown as _markdown
from django import template
from django.utils.html import escape
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter(name="md")
def render_markdown(text: str) -> str:
    """Render markdown text to HTML."""
    if not text:
        return ""
    html = _markdown.markdown(
        text,
        extensions=["fenced_code", "tables", "nl2br"],
    )
    return mark_safe(html)


@register.simple_tag
def location_link(loc, audit_run=None) -> str:
    """Render a FindingLocation as a GitHub link or plain text.

    Uses the structured file_path and start_line from the database directly.
    """
    display = f"{loc.file_path}:{loc.start_line}"
    if audit_run and audit_run.github_repo_url:
        url = audit_run.github_file_url(loc.file_path, loc.start_line)
        if url:
            return mark_safe(
                f'<a href="{escape(url)}" target="_blank">{escape(display)}</a>'
            )
    return escape(display)
