"""Initialize Django ORM for use outside the web server."""

from __future__ import annotations

import os

POSTGRES_URL_DEFAULT = "postgresql://localhost:5434/llmpuffin"

_initialized = False


def get_postgres_url() -> str:
    """Get the PostgreSQL connection string from env, with a default."""
    return os.environ.get("LLMPUFFIN_POSTGRES", POSTGRES_URL_DEFAULT)


def setup() -> None:
    """Configure Django settings so models can be used from the harness."""
    global _initialized
    if _initialized:
        return
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "llmpuffin_web.settings")
    import django

    django.setup()
    _initialized = True
