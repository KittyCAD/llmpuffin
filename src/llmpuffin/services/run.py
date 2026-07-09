"""Audit run data access operations."""

from __future__ import annotations

from sqlalchemy import func, select, update as sa_update
from sqlalchemy.orm import selectinload

from llmpuffin.db import DB
from llmpuffin.models import AuditProfile, AuditRun, AuditThread, Finding


class RunService:
    def __init__(self, db: DB):
        self.db = db

    async def list_all(self) -> tuple[list[AuditRun], dict[int, int]]:
        """List all runs with finding counts. Returns (runs, {run_id: count})."""
        async with self.db.async_session() as s:
            rows = (
                (
                    await s.execute(
                        select(AuditRun)
                        .options(
                            selectinload(AuditRun.profile),
                            selectinload(AuditRun.threads),
                        )
                        .order_by(AuditRun.started_at.desc())
                    )
                )
                .scalars()
                .all()
            )

            finding_counts = {
                row[0]: row[1]
                for row in (
                    await s.execute(
                        select(Finding.audit_run_id, func.count(Finding.id))
                        .where(Finding.status != "deleted")
                        .group_by(Finding.audit_run_id)
                    )
                ).all()
            }
            return list(rows), finding_counts

    async def get(self, run_id: int, *, with_findings: bool = False) -> AuditRun | None:
        async with self.db.async_session() as s:
            opts = [
                selectinload(AuditRun.profile),
                selectinload(AuditRun.threads),
            ]
            if with_findings:
                opts.extend(
                    [
                        selectinload(AuditRun.findings).selectinload(Finding.locations),
                        selectinload(AuditRun.findings).selectinload(
                            Finding.github_link
                        ),
                    ]
                )
            return (
                await s.execute(
                    select(AuditRun).options(*opts).where(AuditRun.id == run_id)
                )
            ).scalar_one_or_none()

    async def delete(self, run_id: int) -> str | None:
        """Delete a run. Returns error message if can't delete, None on success."""
        async with self.db.async_session() as s:
            run = (
                await s.execute(
                    select(AuditRun)
                    .options(selectinload(AuditRun.threads))
                    .where(AuditRun.id == run_id)
                )
            ).scalar_one_or_none()
            if run is None:
                return "not_found"
            if run.status == "running":
                return "Cannot delete a running audit"
            await s.delete(run)
            await s.commit()
            return None

    async def mark_thread_orphaned(self, thread_id: str) -> None:
        """Mark a non-running thread as errored."""
        async with self.db.async_session() as s:
            await s.execute(
                sa_update(AuditThread)
                .where(AuditThread.thread_id == thread_id)
                .values(status="error", error="Orphaned thread (not running)")
            )
            await s.commit()

    async def unlink_finding_fork(self, run_id: int, thread_id: str) -> bool:
        """Unlink a finding from its fork thread. Returns True if a finding was updated."""
        async with self.db.async_session() as s:
            result = await s.execute(
                sa_update(Finding)
                .where(
                    Finding.fork_thread_id == thread_id,
                    Finding.audit_run_id == run_id,
                )
                .values(fork_thread_id="")
            )
            await s.commit()
            return (result.rowcount or 0) > 0  # pyright: ignore[reportAttributeAccessIssue]

    async def sync_profile_toml(self, run_id: int) -> str | None:
        """Copy the latest profile_toml from the parent profile to this run.

        Returns error message or None on success.
        """
        async with self.db.async_session() as s:
            run = (
                await s.execute(
                    select(AuditRun)
                    .options(selectinload(AuditRun.profile))
                    .where(AuditRun.id == run_id)
                )
            ).scalar_one_or_none()
            if run is None:
                return "not_found"
            if not run.profile:
                return "Run has no linked profile"
            run.profile_toml = run.profile.profile_toml
            await s.commit()
            return None
