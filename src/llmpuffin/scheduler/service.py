"""Scheduler service — CRUD and due-check logic for scheduled audits."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from croniter import croniter
from sqlalchemy import select, update as sa_update
from sqlalchemy.orm import selectinload

from llmpuffin.db import DB
from llmpuffin.scheduler.models import AuditSchedule, ScheduleRun

log = logging.getLogger("llmpuffin")


class SchedulerService:
    def __init__(self, db: DB):
        self.db = db

    # ── CRUD ──

    async def get(self, schedule_id: int) -> AuditSchedule | None:
        async with self.db.async_session() as s:
            return (
                await s.execute(
                    select(AuditSchedule)
                    .where(AuditSchedule.id == schedule_id)
                    .options(selectinload(AuditSchedule.runs))
                )
            ).scalar_one_or_none()

    async def get_for_profile(self, profile_id: int) -> AuditSchedule | None:
        async with self.db.async_session() as s:
            return (
                await s.execute(
                    select(AuditSchedule)
                    .where(AuditSchedule.profile_id == profile_id)
                    .options(selectinload(AuditSchedule.runs))
                )
            ).scalar_one_or_none()

    async def upsert(
        self, profile_id: int, cron_expr: str, *, enabled: bool = True
    ) -> AuditSchedule:
        """Create or update a schedule for a profile (one schedule per profile)."""
        if not croniter.is_valid(cron_expr):
            raise ValueError(f"Invalid cron expression: {cron_expr}")

        async with self.db.async_session() as s:
            existing = (
                await s.execute(
                    select(AuditSchedule).where(
                        AuditSchedule.profile_id == profile_id
                    )
                )
            ).scalar_one_or_none()

            if existing:
                existing.cron_expr = cron_expr
                existing.enabled = enabled
                await s.commit()
                await s.refresh(existing)
                return existing

            schedule = AuditSchedule(
                profile_id=profile_id,
                cron_expr=cron_expr,
                enabled=enabled,
            )
            s.add(schedule)
            await s.commit()
            await s.refresh(schedule)
            return schedule

    async def delete(self, schedule_id: int) -> bool:
        async with self.db.async_session() as s:
            sched = await s.get(AuditSchedule, schedule_id)
            if sched is None:
                return False
            await s.delete(sched)
            await s.commit()
            return True

    async def set_enabled(self, schedule_id: int, enabled: bool) -> bool:
        async with self.db.async_session() as s:
            result = await s.execute(
                sa_update(AuditSchedule)
                .where(AuditSchedule.id == schedule_id)
                .values(enabled=enabled)
            )
            await s.commit()
            return result.rowcount > 0  # pyright: ignore[reportAttributeAccessIssue]

    # ── Due-check ──

    async def find_due(self) -> list[AuditSchedule]:
        """Find all enabled schedules that are due to run.

        A schedule is due if it has no runs, or if the most recent run's
        created_at is before the previous cron tick.
        """
        now = datetime.now(timezone.utc)

        async with self.db.async_session() as s:
            schedules = (
                await s.execute(
                    select(AuditSchedule)
                    .where(AuditSchedule.enabled.is_(True))
                    .options(
                        selectinload(AuditSchedule.runs),
                        selectinload(AuditSchedule.profile),
                    )
                )
            ).scalars().all()

        due = []
        for sched in schedules:
            cron = croniter(sched.cron_expr, now)
            prev_tick = cron.get_prev(datetime).replace(tzinfo=timezone.utc)

            if not sched.runs:
                due.append(sched)
                continue

            last_run = sched.runs[0]  # ordered desc by created_at
            last_at = last_run.created_at
            if last_at.tzinfo is None:
                last_at = last_at.replace(tzinfo=timezone.utc)

            if last_at < prev_tick:
                due.append(sched)

        return due

    # ── Run recording ──

    async def record_start(
        self, schedule_id: int, audit_run_id: int
    ) -> ScheduleRun:
        async with self.db.async_session() as s:
            run = ScheduleRun(
                schedule_id=schedule_id,
                audit_run_id=audit_run_id,
                status="started",
            )
            s.add(run)
            await s.commit()
            await s.refresh(run)
            return run

    async def record_error(
        self, schedule_id: int, error: str
    ) -> ScheduleRun:
        async with self.db.async_session() as s:
            run = ScheduleRun(
                schedule_id=schedule_id,
                status="error",
                error=error,
            )
            s.add(run)
            await s.commit()
            await s.refresh(run)
            return run
