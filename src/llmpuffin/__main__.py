"""CLI entry point for llmpuffin."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import logging

from sqlalchemy import select

from llmpuffin.agent import AuditStatus, run_audit
from llmpuffin.config import Config, Profile
from llmpuffin.db import DB
from llmpuffin.github import client_from_config
from llmpuffin.agent.harness import HarnessConfig
from llmpuffin.log import setup as setup_logging
from llmpuffin.models import AuditProfile, Project
from llmpuffin.services.sarif import export_sarif_for_run

log = logging.getLogger("llmpuffin")


async def _async_abort_orphaned(config: Config):
    db = DB(config.postgres)
    await db.setup()
    await db.abort_orphaned_threads()


async def _resolve_profile_id(
    harness_config: HarnessConfig, *, db: DB, project_name: str
) -> int:
    """Ensure project + profile exist in DB. Returns profile_id."""
    async with db.async_session() as s:
        project = (
            await s.execute(select(Project).where(Project.name == project_name))
        ).scalar_one_or_none()
        if project is None:
            project = Project(name=project_name)
            s.add(project)
            await s.flush()
        db_profile = await AuditProfile.get_or_create(
            s,
            name=harness_config.profile.name,
            profile_toml=harness_config.profile_toml,
            project_id=project.id,
        )
        await s.commit()
        return db_profile.id


async def _async_main(
    harness_config: HarnessConfig,
    *,
    config: Config,
    db: DB,
    project_name: str,
):
    await db.setup()

    if config.backfill_embeddings:
        try:
            from llmpuffin.services.embeddings import backfill_embeddings

            log.info("Backfilling finding embeddings...")
            count = await backfill_embeddings(db=db)
            log.info("Embedding backfill complete: %d finding(s)", count)
        except Exception:
            log.warning("Embedding backfill failed", exc_info=True)

    profile_id = await _resolve_profile_id(
        harness_config, db=db, project_name=project_name
    )

    gh = client_from_config(config.github)
    return await run_audit(
        harness_config,
        db=db,
        global_config=config,
        github_client=gh,
        profile_id=profile_id,
    )


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
        "-v",
        "--verbose",
        action="store_true",
        help="Show debug output (tool results, etc.)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- run ---
    run_parser = subparsers.add_parser("run", help="Run an audit")
    run_parser.add_argument(
        "-p",
        "--profile",
        type=Path,
        required=True,
        help="Audit profile TOML file",
    )
    run_parser.add_argument(
        "--project",
        type=str,
        required=True,
        help="Project name (created if it doesn't exist)",
    )
    run_parser.add_argument(
        "--sarif",
        type=Path,
        default=None,
        help="Export SARIF report to this path after the audit completes",
    )

    # --- abort-orphaned-threads ---
    subparsers.add_parser(
        "abort-orphaned-threads",
        help="Mark any 'running' threads as 'aborted' (cleanup after crashes)",
    )

    args = parser.parse_args()

    global_config = Config.load(args.config)
    setup_logging(verbose=args.verbose, level=global_config.logging.level)

    if args.command == "abort-orphaned-threads":
        asyncio.run(_async_abort_orphaned(global_config))
        return

    # --- run ---
    profile_text = args.profile.read_text()
    profile = Profile.from_toml_string(profile_text)

    harness_config = HarnessConfig(
        profile=profile,
        profile_toml=profile_text,
    )

    db = DB(global_config.postgres)
    result = asyncio.run(
        _async_main(
            harness_config,
            config=global_config,
            db=db,
            project_name=args.project,
        )
    )
    n = result.finding_count
    print(f"Audit {result.status}. {n} finding{'s' if n != 1 else ''} recorded.")

    # Export SARIF if requested
    sarif_path = args.sarif
    if sarif_path and result.audit_run_id:
        sarif_json = export_sarif_for_run(result.audit_run_id, db=db)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(sarif_json)
        print(f"SARIF report written to {sarif_path}")

    if result.error:
        print(f"  Note: {result.error}")
    if result.status != AuditStatus.COMPLETED:
        sys.exit(1)


if __name__ == "__main__":
    main()
