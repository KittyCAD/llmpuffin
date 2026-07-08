"""Audit profile CRUD operations."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from llmpuffin.db import DB
from llmpuffin.models import AuditProfile, AuditRun


class ProfileService:
    def __init__(self, db: DB):
        self.db = db

    async def list_all(self) -> list[AuditProfile]:
        async with self.db.async_session() as s:
            return list(
                (await s.execute(select(AuditProfile).order_by(AuditProfile.name)))
                .scalars()
                .all()
            )

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

    async def create(self, name: str, profile_toml: str) -> AuditProfile:
        async with self.db.async_session() as s:
            profile = AuditProfile(name=name, profile_toml=profile_toml, jit=False)
            s.add(profile)
            await s.commit()
            await s.refresh(profile)
            return profile

    async def update(self, profile_id: int, name: str, profile_toml: str) -> bool:
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
            await s.commit()
            return True
