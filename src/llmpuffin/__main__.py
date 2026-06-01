"""CLI entry point for llmpuffin."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from llmpuffin.agent import AuditStatus, run_audit
from llmpuffin.config import Config, Profile
from llmpuffin.db import _abort_orphaned_threads, setup_db
from llmpuffin.github import client_from_config
from llmpuffin.harness import HarnessConfig
from llmpuffin.log import setup as setup_logging
from llmpuffin.sarif import export_sarif_for_run


async def _async_abort_orphaned():
    await setup_db()
    await _abort_orphaned_threads()


async def _async_main(harness_config: HarnessConfig):
    await setup_db()
    gh = client_from_config()
    return await run_audit(harness_config, github_client=gh)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="llmpuffin",
        description="Agentic codebase security review driven by structured threat models.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- run ---
    run_parser = subparsers.add_parser("run", help="Run an audit")
    run_parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=None,
        help="Global config file (default: ./llmpuffin.toml if present)",
    )
    run_parser.add_argument(
        "-p",
        "--profile",
        type=Path,
        required=True,
        help="Audit profile TOML file",
    )
    run_parser.add_argument(
        "--sarif",
        type=Path,
        default=None,
        help="Export SARIF report to this path after the audit completes",
    )
    run_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show debug output (tool results, etc.)",
    )

    # --- abort-orphaned-threads ---
    abort_parser = subparsers.add_parser(
        "abort-orphaned-threads",
        help="Mark any 'running' threads as 'aborted' (cleanup after crashes)",
    )
    abort_parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=None,
        help="Global config file (default: ./llmpuffin.toml if present)",
    )
    abort_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show debug output (tool results, etc.)",
    )

    args = parser.parse_args()

    global_config = Config.load(args.config)
    os.environ.setdefault("LLMPUFFIN_POSTGRES", global_config.postgres.url)
    setup_logging(verbose=args.verbose, level=global_config.logging.level)

    if args.command == "abort-orphaned-threads":
        asyncio.run(_async_abort_orphaned())
        return

    # --- run ---
    profile_text = args.profile.read_text()
    profile = Profile.from_toml_string(profile_text)

    harness_config = HarnessConfig(
        profile=profile,
        profile_toml=profile_text,
    )

    result = asyncio.run(_async_main(harness_config))
    n = len(result.report.findings)
    print(f"Audit {result.status}. {n} finding{'s' if n != 1 else ''} recorded.")

    # Export SARIF if requested
    sarif_path = args.sarif
    if sarif_path and result.audit_run_id:
        sarif_json = export_sarif_for_run(result.audit_run_id)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(sarif_json)
        print(f"SARIF report written to {sarif_path}")

    if result.error:
        print(f"  Note: {result.error}")
    if result.status != AuditStatus.COMPLETED:
        sys.exit(1)


if __name__ == "__main__":
    main()