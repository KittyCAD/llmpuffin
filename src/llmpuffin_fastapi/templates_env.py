"""Jinja2 environment with custom filters and globals."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from llmpuffin.markdown import render_markdown

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def _static_hash() -> str:
    """Hash of static assets — changes on every CSS or JS edit."""
    h = hashlib.md5()
    for name in ("app.css", "app.bundle.js"):
        f = STATIC_DIR / name
        if f.exists():
            h.update(f.read_bytes())
    digest = h.hexdigest()[:8]
    return digest if digest != hashlib.md5().hexdigest()[:8] else str(int(time.time()))


def _md(text: str) -> Markup:
    return Markup(render_markdown(text))


def _truncatechars(text: str | None, n: int) -> str:
    if not text:
        return ""
    if len(text) <= n:
        return text
    return text[: max(0, n - 1)] + "..."


def _datetimefmt(value, fmt: str = "short") -> Markup:
    """Render a datetime as a <time> element for client-side local formatting.

    fmt is "short" (date + HH:MM) or "long" (date + HH:MM:SS).
    Falls back to server-side formatting if value lacks isoformat.
    """
    if value is None:
        return Markup("")
    try:
        iso = value.isoformat()
    except AttributeError:
        return Markup(escape(str(value)))
    return Markup(f'<time datetime="{escape(iso)}" data-fmt="{escape(fmt)}">{escape(iso)}</time>')


def _pluralize(value, suffix: str = "s") -> str:
    try:
        n = len(value)
    except TypeError:
        try:
            n = int(value)
        except (TypeError, ValueError):
            return ""
    return "" if n == 1 else suffix


def location_link(loc) -> Markup:
    display = f"{loc.file_path}:{loc.start_line}"
    url = loc.github_url()
    if url:
        return Markup(f'<a href="{escape(url)}" target="_blank">{escape(display)}</a>')
    return Markup(escape(display))


templates.env.filters["md"] = _md
templates.env.filters["truncatechars"] = _truncatechars
templates.env.filters["datetimefmt"] = _datetimefmt
templates.env.filters["pluralize"] = _pluralize
templates.env.globals["location_link"] = location_link
templates.env.globals["static_hash"] = _static_hash
