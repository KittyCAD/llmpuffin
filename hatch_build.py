"""Hatchling build hook — bundles JS with esbuild before building the wheel."""

from __future__ import annotations

import subprocess
import shutil
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

JS_SOURCE = Path("src/llmpuffin_fastapi/static/js/app.ts")
JS_OUTPUT = Path("src/llmpuffin_fastapi/static/app.bundle.js")


class JSBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        root = Path(self.root)
        source = root / JS_SOURCE
        output = root / JS_OUTPUT

        if not source.exists():
            return

        # Install npm deps if needed
        node_modules = root / "node_modules"
        if not node_modules.exists():
            npm = shutil.which("npm")
            if npm is None:
                raise RuntimeError(
                    "npm is required to build JS assets. Install Node.js."
                )
            subprocess.run(
                [npm, "install"], cwd=root, check=True, capture_output=True
            )

        # Bundle with esbuild
        npx = shutil.which("npx")
        if npx is None:
            raise RuntimeError("npx is required to run esbuild")
        subprocess.run(
            [
                npx, "esbuild",
                str(source),
                "--bundle",
                "--minify",
                "--format=iife",
                f"--outfile={output}",
            ],
            cwd=root,
            check=True,
            capture_output=True,
        )
