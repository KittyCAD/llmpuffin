"""Initialize Django ORM for use outside the web server."""

from __future__ import annotations

import os

_initialized = False


def setup() -> None:
    """Configure Django settings so models can be used from the harness."""
    global _initialized
    if _initialized:
        return
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "llmpuffin_web.settings")
    import django
    django.setup()
    _initialized = True
