"""CLI entry point for llmpuffin."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from llmpuffin.agent import AuditStatus, run_audit
from llmpuffin.config import Config, Profile
from llmpuffin.db import setup_db
from llmpuffin.harness import HarnessConfig
from llmpuffin.log import setup as setup_logging


async def _async_main(harness_config: HarnessConfig):
    await setup_db()
    return await run_audit(harness_config)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="llmpuffin",
        description="Agentic codebase security review driven by structured threat models.",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=None,
        help="Global config file (default: ./llmpuffin.toml if present)",
    )
    parser.add_argument(
        "-p",
        "--profile",
        type=Path,
        required=True,
        help="Audit profile TOML file",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show debug output (tool results, etc.)",
    )

    args = parser.parse_args()

    global_config = Config.load(args.config)
    os.environ.setdefault("LLMPUFFIN_POSTGRES", global_config.postgres.url)
    setup_logging(verbose=args.verbose)

    profile_text = args.profile.read_text()
    profile = Profile.from_toml_string(profile_text)

    harness_config = HarnessConfig(
        profile=profile,
        profile_toml=profile_text,
    )

    result = asyncio.run(_async_main(harness_config))
    n = len(result.report.findings)
    print(
        f"Audit {result.status}. {n} finding{'s' if n != 1 else ''} "
        f"written to {profile.output}"
    )
    if result.error:
        print(f"  Note: {result.error}")
    if result.status != AuditStatus.COMPLETED:
        sys.exit(1)


if __name__ == "__main__":
    main()
