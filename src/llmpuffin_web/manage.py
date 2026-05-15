"""Entry point: uv run llmpuffin-web runserver"""

from __future__ import annotations

import os
import sys


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "llmpuffin_web.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
