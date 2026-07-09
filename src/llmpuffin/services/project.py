"""Project CRUD operations."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from llmpuffin.db import DB
from llmpuffin.models import AuditProfile, AuditRun, Finding, Project


class ProjectService:
    def __init__(self, db: DB):
        self.db = db

    async def list_all(self) -> list[tuple[Project, int, int]]:
        """List all projects with profile and run counts.

        Returns list of (project, profile_count, run_count).
        """
        async with self.db.async_session() as s:
            profile_counts_sq = (
                select(
                    AuditProfile.project_id,
                    func.count(AuditProfile.id).label("cnt"),
                )
                .group_by(AuditProfile.project_id)
                .subquery()
            )
            run_counts_sq = (
                select(
                    AuditProfile.project_id,
                    func.count(AuditRun.id).label("cnt"),
                )
                .join(AuditRun, AuditRun.profile_id == AuditProfile.id)
                .group_by(AuditProfile.project_id)
                .subquery()
            )
            stmt = (
                select(
                    Project,
                    func.coalesce(profile_counts_sq.c.cnt, 0),
                    func.coalesce(run_counts_sq.c.cnt, 0),
                )
                .outerjoin(profile_counts_sq, Project.id == profile_counts_sq.c.project_id)
                .outerjoin(run_counts_sq, Project.id == run_counts_sq.c.project_id)
                .order_by(Project.name)
            )
            rows = (await s.execute(stmt)).all()
            return [(row[0], row[1], row[2]) for row in rows]

    async def get(
        self, project_id: int, *, with_profiles: bool = False
    ) -> Project | None:
        async with self.db.async_session() as s:
            stmt = select(Project).where(Project.id == project_id)
            if with_profiles:
                stmt = stmt.options(selectinload(Project.profiles))
            return (await s.execute(stmt)).scalar_one_or_none()

    async def create(self, name: str, description: str = "") -> Project:
        async with self.db.async_session() as s:
            project = Project(name=name, description=description)
            s.add(project)
            await s.commit()
            await s.refresh(project)
            return project

    async def update(self, project_id: int, name: str, description: str) -> bool:
        async with self.db.async_session() as s:
            project = (
                await s.execute(select(Project).where(Project.id == project_id))
            ).scalar_one_or_none()
            if project is None:
                return False
            project.name = name
            project.description = description
            await s.commit()
            return True

    async def patch(self, project_id: int, **fields) -> bool:
        """Update individual fields on a project. Returns False if not found."""
        allowed = {"name", "description"}
        async with self.db.async_session() as s:
            project = (
                await s.execute(select(Project).where(Project.id == project_id))
            ).scalar_one_or_none()
            if project is None:
                return False
            for k, v in fields.items():
                if k in allowed and v is not None:
                    setattr(project, k, v)
            await s.commit()
            return True

    async def delete(self, project_id: int) -> str | None:
        """Delete a project. Returns error message or None on success."""
        async with self.db.async_session() as s:
            project = (
                await s.execute(select(Project).where(Project.id == project_id))
            ).scalar_one_or_none()
            if project is None:
                return "not_found"
            await s.delete(project)
            await s.commit()
            return None

    async def global_stats(self) -> dict:
        """Return global statistics: finding counts by severity, total runs."""
        async with self.db.async_session() as s:
            severity_rows = (
                await s.execute(
                    select(Finding.severity, func.count(Finding.id))
                    .where(Finding.status.notin_(["deleted", "duplicate"]))
                    .group_by(Finding.severity)
                )
            ).all()
            severity_counts = {row[0]: row[1] for row in severity_rows}

            total_runs = (
                await s.execute(select(func.count(AuditRun.id)))
            ).scalar() or 0

            total_findings = sum(severity_counts.values())

            return {
                "total_runs": total_runs,
                "total_findings": total_findings,
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "informational": severity_counts.get("informational", 0),
            }