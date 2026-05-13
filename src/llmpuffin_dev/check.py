"""Compile-check all source files. Run via: uv run llmpuffin-check"""

import compileall
import sys


def main() -> None:
    ok = compileall.compile_dir("src/", quiet=1, force=True)
    sys.exit(0 if ok else 1)
