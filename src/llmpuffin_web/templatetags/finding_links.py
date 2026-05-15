"""Template tags for linking finding locations to GitHub."""

from django import template
from django.utils.html import escape
from django.utils.safestring import mark_safe

register = template.Library()


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
