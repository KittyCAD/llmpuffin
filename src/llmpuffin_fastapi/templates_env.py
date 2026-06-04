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
    """Hash of app.css content — changes on every file edit."""
    css = STATIC_DIR / "app.css"
    if css.exists():
        return hashlib.md5(css.read_bytes()).hexdigest()[:8]
    return str(int(time.time()))


def _md(text: str) -> Markup:
    return Markup(render_markdown(text))


def _truncatechars(text: str | None, n: int) -> str:
    if not text:
        return ""
    if len(text) <= n:
        return text
    return text[: max(0, n - 1)] + "…"


def _datetimefmt(value, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if value is None:
        return ""
    try:
        return value.strftime(fmt)
    except AttributeError:
        return str(value)


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
