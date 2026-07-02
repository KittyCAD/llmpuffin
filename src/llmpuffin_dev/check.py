"""Lint, format, and compile-check all source files. Run via: uv run llmpuffin-check"""

import compileall
import subprocess
import sys


def _check_jinja_templates() -> bool:
    """Parse all Jinja2 templates and report syntax errors. Returns True if all OK."""
    try:
        from llmpuffin_fastapi.templates_env import templates, TEMPLATE_DIR
    except ImportError:
        print("⚠ skipping Jinja check (llmpuffin_fastapi not importable)")
        return True

    ok = True
    for path in sorted(TEMPLATE_DIR.rglob("*.html")):
        name = str(path.relative_to(TEMPLATE_DIR))
        try:
            templates.env.get_template(name)
        except Exception as exc:
            print(f"✗ {name}: {exc}")
            ok = False

    if ok:
        count = len(list(TEMPLATE_DIR.rglob("*.html")))
        print(f"✓ {count} Jinja templates OK")
    return ok


def main() -> None:
    failed = False

    for cmd in [
        ["uv", "run", "ruff", "format", "src/"],
        ["uv", "run", "ruff", "check", "--fix", "src/"],
        ["uv", "run", "pyright", "src/"],
        ["uv", "run", "pytest", "tests/", "-q"],
    ]:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            failed = True

    if not compileall.compile_dir("src/", quiet=1, force=True):
        failed = True

    if not _check_jinja_templates():
        failed = True

    sys.exit(1 if failed else 0)
