"""Entry point: uv run llmpuffin-web runserver"""

from __future__ import annotations

import os
import sys


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "llmpuffin_web.settings")
    from django.core.management import execute_from_command_line

    # Auto-apply configured port for runserver if no address was given
    if len(sys.argv) >= 2 and sys.argv[1] == "runserver" and len(sys.argv) == 2:
        from llmpuffin.config import Config

        config = Config.load()
        sys.argv.append(str(config.web.port))

    execute_from_command_line(sys.argv)
