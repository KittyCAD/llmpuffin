"""CLI entry point for llmpuffin."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from llmpuffin.agent import AuditStatus, run_audit
from llmpuffin.config import Config, Profile
from llmpuffin.db import DB
from llmpuffin.github import client_from_config
from llmpuffin.harness import HarnessConfig
from llmpuffin.log import setup as setup_logging
from llmpuffin.sarif import export_sarif_for_run


async def _async_abort_orphaned(config: Config):
    db = DB(config.postgres)
    await db.setup()
    await db.abort_orphaned_threads()


async def _async_import_skill(config: Config, directory: Path, name: str | None):
    from sqlalchemy import select

    from llmpuffin.models import Skill, SkillFile

    db = DB(config.postgres)
    await db.setup()
    skill_name = name or directory.name
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory", file=sys.stderr)
        sys.exit(1)

    async with db.async_session() as s:
        skill = (
            await s.execute(select(Skill).where(Skill.name == skill_name))
        ).scalar_one_or_none()
        if skill is None:
            skill = Skill(name=skill_name)
            s.add(skill)
            await s.flush()
            print(f"Created skill {skill_name!r}")
        else:
            print(f"Updating existing skill {skill_name!r}")

        count = 0
        for file_path in sorted(directory.rglob("*")):
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            rel = str(file_path.relative_to(directory))
            existing = (
                await s.execute(
                    select(SkillFile).where(
                        SkillFile.skill_id == skill.id, SkillFile.path == rel
                    )
                )
            ).scalar_one_or_none()
            if existing:
                existing.content = content
            else:
                s.add(SkillFile(skill_id=skill.id, path=rel, content=content))
            count += 1

        await s.commit()
    print(f"Imported {count} file(s) into skill {skill_name!r}")


async def _async_main(harness_config: HarnessConfig, *, config: Config, db: DB):
    await db.setup()
    gh = client_from_config(config.github)
    return await run_audit(
        harness_config, db=db, global_config=config, github_client=gh
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

    # --- import-skill ---
    import_skill_parser = subparsers.add_parser(
        "import-skill",
        help="Import a skill from a local directory into the database",
    )
    import_skill_parser.add_argument(
        "directory", type=Path, help="Skill directory to import"
    )
    import_skill_parser.add_argument(
        "--name", type=str, default=None, help="Skill name (default: directory name)"
    )

    args = parser.parse_args()

    global_config = Config.load(args.config)
    setup_logging(verbose=args.verbose, level=global_config.logging.level)

    if args.command == "abort-orphaned-threads":
        asyncio.run(_async_abort_orphaned(global_config))
        return

    if args.command == "import-skill":
        asyncio.run(_async_import_skill(global_config, args.directory, args.name))
        return

    # --- run ---
    profile_text = args.profile.read_text()
    profile = Profile.from_toml_string(profile_text)

    harness_config = HarnessConfig(
        profile=profile,
        profile_toml=profile_text,
    )

    db = DB(global_config.postgres)
    result = asyncio.run(_async_main(harness_config, config=global_config, db=db))
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
