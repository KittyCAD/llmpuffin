"""CLI entry point for llmpuffin."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from llmpuffin.agent import run_audit
from llmpuffin.harness import HarnessConfig
from llmpuffin.log import setup as setup_logging


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="llmpuffin",
        description="Agentic codebase security review driven by structured threat models.",
    )
    parser.add_argument(
        "image",
        help="Container image with the codebase to audit",
    )
    parser.add_argument(
        "threat_model_dir",
        type=Path,
        help="Directory containing threat model .toml files",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("results.sarif"),
        help="Output SARIF file path (default: results.sarif)",
    )
    parser.add_argument(
        "--code-dir",
        default="/src",
        help="Path to source code inside the container (default: /src)",
    )
    parser.add_argument(
        "--model",
        default="claude-sonnet-4-20250514",
        help="LLM model to use",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=50,
        help="Maximum agent loop iterations per scenario (default: 50)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show debug output (tool results, etc.)",
    )

    args = parser.parse_args()
    setup_logging(verbose=args.verbose)

    config = HarnessConfig(
        threat_model_dir=args.threat_model_dir,
        container_image=args.image,
        max_iterations=args.max_iterations,
        code_dir=args.code_dir,
        output_path=args.output,
    )

    report = asyncio.run(run_audit(config, model_name=args.model))
    n = len(report.findings)
    print(f"Audit complete. {n} finding{'s' if n != 1 else ''} written to {args.output}")


if __name__ == "__main__":
    main()
