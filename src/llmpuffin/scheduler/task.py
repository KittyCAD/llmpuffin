"""Background task that polls for due schedules and launches audits."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import TYPE_CHECKING

from llmpuffin.agent import create_audit_run, run_audit
from llmpuffin.agent.harness import Harness, HarnessConfig
from llmpuffin.config import Config, Profile
from llmpuffin.scheduler.service import SchedulerService

if TYPE_CHECKING:
    from llmpuffin.db import DB
    from llmpuffin.github import GitHubClient

log = logging.getLogger("llmpuffin")

POLL_INTERVAL_SECONDS = 60


async def scheduler_loop(
    *,
    db: DB,
    config: Config,
    harness: Harness,
    github_client: GitHubClient | None = None,
) -> None:
    """Run forever, checking for due schedules every minute."""
    svc = SchedulerService(db)
    log.info("Scheduler started (poll every %ds)", POLL_INTERVAL_SECONDS)

    while True:
        try:
            await _tick(svc, db=db, config=config, harness=harness, github_client=github_client)
        except asyncio.CancelledError:
            log.info("Scheduler stopped")
            return
        except Exception:
            log.exception("Scheduler tick failed")

        try:
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            log.info("Scheduler stopped")
            return


async def _tick(
    svc: SchedulerService,
    *,
    db: DB,
    config: Config,
    harness: Harness,
    github_client: GitHubClient | None,
) -> None:
    due = await svc.find_due()
    if not due:
        return

    log.info("Scheduler: %d schedule(s) due", len(due))
    for sched in due:
        try:
            profile = Profile.from_toml_string(sched.profile.profile_toml)
        except Exception as exc:
            log.warning(
                "Scheduler: invalid config for profile %d: %s",
                sched.profile_id, exc,
            )
            await svc.record_error(sched.id, str(exc))
            continue

        harness_config = HarnessConfig(
            profile=profile, profile_toml=sched.profile.profile_toml
        )
        tid = uuid.uuid4().hex[:12]

        try:
            run_id = await create_audit_run(
                harness_config, tid, db=db, profile_id=sched.profile_id
            )
        except Exception as exc:
            log.warning("Scheduler: failed to create run for schedule %d: %s", sched.id, exc)
            await svc.record_error(sched.id, str(exc))
            continue

        await svc.record_start(sched.id, run_id)
        harness.spawn(
            tid,
            run_audit(
                harness_config,
                db=db,
                global_config=config,
                thread_id=tid,
                github_client=github_client,
                profile_id=sched.profile_id,
                audit_run_id=run_id,
            ),
        )
        log.info(
            "Scheduler: launched audit run %d for profile %d (schedule %d)",
            run_id, sched.profile_id, sched.id,
        )
