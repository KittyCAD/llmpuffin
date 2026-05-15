"""Initialize Django ORM for use outside the web server."""

from __future__ import annotations

import os

_initialized = False


def get_postgres_url() -> str:
    """Get the PostgreSQL connection string from config/env."""
    if url := os.environ.get("LLMPUFFIN_POSTGRES"):
        return url
    from llmpuffin.config import Config

    return Config.load().postgres.url


def setup() -> None:
    """Configure Django settings so models can be used from the harness."""
    global _initialized
    if _initialized:
        return
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "llmpuffin_web.settings")
    import django

    django.setup()
    _initialized = True
