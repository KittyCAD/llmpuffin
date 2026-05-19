"""Lint, format, and compile-check all source files. Run via: uv run llmpuffin-check"""

import compileall
import subprocess
import sys


def main() -> None:
    failed = False

    for cmd in [
        ["uv", "run", "ruff", "format", "src/"],
        ["uv", "run", "ruff", "check", "--fix", "src/"],
        ["uv", "run", "pytest", "tests/", "-q"],
    ]:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            failed = True

    if not compileall.compile_dir("src/", quiet=1, force=True):
        failed = True

    sys.exit(1 if failed else 0)
