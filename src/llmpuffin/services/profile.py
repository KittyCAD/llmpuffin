"""Audit profile CRUD operations."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from llmpuffin.db import DB
from llmpuffin.models import AuditProfile, AuditRun


class ProfileService:
    def __init__(self, db: DB):
        self.db = db

    async def list_all(self, *, project_id: int | None = None) -> list[AuditProfile]:
        async with self.db.async_session() as s:
            stmt = select(AuditProfile).order_by(AuditProfile.name)
            if project_id is not None:
                stmt = stmt.where(AuditProfile.project_id == project_id)
            return list((await s.execute(stmt)).scalars().all())

    async def get(
        self, profile_id: int, *, with_runs: bool = False
    ) -> AuditProfile | None:
        async with self.db.async_session() as s:
            stmt = select(AuditProfile).where(AuditProfile.id == profile_id)
            if with_runs:
                stmt = stmt.options(
                    selectinload(AuditProfile.runs).selectinload(AuditRun.threads)
                )
            return (await s.execute(stmt)).scalar_one_or_none()

    async def create(
        self, name: str, profile_toml: str, *, project_id: int
    ) -> AuditProfile:
        async with self.db.async_session() as s:
            profile = AuditProfile(
                name=name, profile_toml=profile_toml, project_id=project_id, jit=False
            )
            s.add(profile)
            await s.commit()
            await s.refresh(profile)
            return profile

    async def update(
        self,
        profile_id: int,
        name: str,
        profile_toml: str,
        *,
        project_id: int | None = None,
    ) -> bool:
        """Update a profile. Returns False if not found."""
        async with self.db.async_session() as s:
            profile = (
                await s.execute(
                    select(AuditProfile).where(AuditProfile.id == profile_id)
                )
            ).scalar_one_or_none()
            if profile is None:
                return False
            profile.name = name
            profile.profile_toml = profile_toml
            if project_id is not None:
                profile.project_id = project_id
            await s.commit()
            return True

    async def patch(self, profile_id: int, **fields) -> bool:
        """Update individual fields on a profile. Returns False if not found."""
        allowed = {"name", "profile_toml", "project_id"}
        async with self.db.async_session() as s:
            profile = (
                await s.execute(
                    select(AuditProfile).where(AuditProfile.id == profile_id)
                )
            ).scalar_one_or_none()
            if profile is None:
                return False
            for k, v in fields.items():
                if k in allowed and v is not None:
                    setattr(profile, k, v)
            await s.commit()
            return True

    async def delete(self, profile_id: int) -> str | None:
        """Delete a profile. Returns error message or None on success."""
        async with self.db.async_session() as s:
            profile = (
                await s.execute(
                    select(AuditProfile)
                    .options(selectinload(AuditProfile.runs).selectinload(AuditRun.threads))
                    .where(AuditProfile.id == profile_id)
                )
            ).scalar_one_or_none()
            if profile is None:
                return "not_found"
            running = any(r.status == "running" for r in profile.runs)
            if running:
                return "Cannot delete a profile with running audits"
            await s.delete(profile)
            await s.commit()
            return None