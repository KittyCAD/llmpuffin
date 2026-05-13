"""CLI entry point for llmpuffin."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from llmpuffin.agent import AuditStatus, run_audit
from llmpuffin.config import ProfileAudit
from llmpuffin.harness import HarnessConfig
from llmpuffin.log import setup as setup_logging


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="llmpuffin",
        description="Agentic codebase security review driven by structured threat models.",
    )
    parser.add_argument(
        "-c", "--config",
        type=Path,
        help="TOML config file (overrides positional args)",
    )
    parser.add_argument(
        "image",
        nargs="?",
        help="Container image with the codebase to audit",
    )
    parser.add_argument(
        "threat_model_dir",
        nargs="?",
        type=Path,
        help="Directory containing threat model .toml files",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output SARIF file path (default: results.sarif)",
    )
    parser.add_argument(
        "--code-dir",
        default=None,
        help="Path to source code inside the container (default: /src)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="LLM model to use",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Maximum agent loop iterations (default: 200)",
    )
    parser.add_argument(
        "--interpreter",
        action="store_true",
        default=None,
        help="Enable QuickJS code interpreter",
    )
    parser.add_argument(
        "--thread-id",
        default=None,
        help="Resume a previous session by thread ID",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show debug output (tool results, etc.)",
    )

    args = parser.parse_args()
    setup_logging(verbose=args.verbose)

    # Load from TOML config if provided
    if args.config:
        profile_config = ProfileAudit.from_toml(args.config)
        config = HarnessConfig(
            name=profile_config.name,
            threat_model_dir=args.threat_model_dir or profile_config.threat_model_dir,
            container_image=args.image or profile_config.image,
            max_iterations=args.max_iterations if args.max_iterations is not None else profile_config.max_iterations,
            code_dir=args.code_dir or profile_config.code_dir,
            output_path=args.output or profile_config.output,
            interpreter=args.interpreter if args.interpreter is not None else profile_config.agent.interpreter,
            interrupt_on=profile_config.agent.interrupt_on,
            skills_dir=profile_config.agent.skills_dir,
        )
        model_name = args.model or profile_config.model
    else:
        if not args.image or not args.threat_model_dir:
            parser.error("image and threat_model_dir are required (or use -c config.toml)")
        config = HarnessConfig(
            name=args.image,  # use image name as default harness name
            threat_model_dir=args.threat_model_dir,
            container_image=args.image,
            max_iterations=args.max_iterations or 200,
            code_dir=args.code_dir or "/src",
            output_path=args.output or Path("results.sarif"),
            interpreter=bool(args.interpreter),
        )
        model_name = args.model or "claude-sonnet-4-20250514"

    result = asyncio.run(run_audit(config, model_name=model_name, thread_id=args.thread_id))
    n = len(result.report.findings)
    print(f"Audit {result.status}. {n} finding{'s' if n != 1 else ''} written to {config.output_path}")
    if result.thread_id:
        print(f"  Thread ID: {result.thread_id} (use --thread-id to resume)")
    if result.error:
        print(f"  Note: {result.error}")
    if result.status != AuditStatus.COMPLETED:
        sys.exit(1)


if __name__ == "__main__":
    main()
