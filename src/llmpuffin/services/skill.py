"""Skill CRUD operations."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from llmpuffin.db import DB
from llmpuffin.models import Skill, SkillFile


class SkillService:
    def __init__(self, db: DB):
        self.db = db

    async def list_all(self) -> list[Skill]:
        async with self.db.async_session() as s:
            return list(
                (
                    await s.execute(
                        select(Skill)
                        .options(selectinload(Skill.files))
                        .order_by(Skill.name)
                    )
                )
                .scalars()
                .all()
            )

    async def get(self, skill_id: int) -> Skill | None:
        async with self.db.async_session() as s:
            return (
                await s.execute(
                    select(Skill)
                    .options(selectinload(Skill.files))
                    .where(Skill.id == skill_id)
                )
            ).scalar_one_or_none()

    async def get_file(self, skill_id: int, file_id: int) -> SkillFile | None:
        async with self.db.async_session() as s:
            return (
                await s.execute(
                    select(SkillFile).where(
                        SkillFile.id == file_id, SkillFile.skill_id == skill_id
                    )
                )
            ).scalar_one_or_none()

    async def create(self, name: str, description: str = "") -> Skill | None:
        """Create a skill. Returns None if name already exists."""
        async with self.db.async_session() as s:
            existing = (
                await s.execute(select(Skill).where(Skill.name == name))
            ).scalar_one_or_none()
            if existing:
                return None
            skill = Skill(name=name, description=description)
            s.add(skill)
            await s.commit()
            await s.refresh(skill)
            return skill

    async def upsert_file(self, skill_id: int, path: str, content: str) -> None:
        """Create or update a file in a skill."""
        async with self.db.async_session() as s:
            existing = (
                await s.execute(
                    select(SkillFile).where(
                        SkillFile.skill_id == skill_id, SkillFile.path == path
                    )
                )
            ).scalar_one_or_none()
            if existing:
                existing.content = content
            else:
                s.add(SkillFile(skill_id=skill_id, path=path, content=content))
            await s.commit()

    async def delete(self, skill_id: int) -> str | None:
        """Delete a skill. Returns the skill name, or None if not found."""
        async with self.db.async_session() as s:
            skill = (
                await s.execute(select(Skill).where(Skill.id == skill_id))
            ).scalar_one_or_none()
            if skill is None:
                return None
            name = skill.name
            await s.delete(skill)
            await s.commit()
            return name

    async def delete_file(self, skill_id: int, file_id: int) -> str | None:
        """Delete a file. Returns the file path, or None if not found."""
        async with self.db.async_session() as s:
            sf = (
                await s.execute(
                    select(SkillFile).where(
                        SkillFile.id == file_id, SkillFile.skill_id == skill_id
                    )
                )
            ).scalar_one_or_none()
            if sf is None:
                return None
            path = sf.path
            await s.delete(sf)
            await s.commit()
            return path

    async def import_directory(self, skill_id: int, directory: Path) -> int:
        """Import all files from a directory into a skill. Returns file count."""
        count = 0
        async with self.db.async_session() as s:
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
                            SkillFile.skill_id == skill_id, SkillFile.path == rel
                        )
                    )
                ).scalar_one_or_none()
                if existing:
                    existing.content = content
                else:
                    s.add(SkillFile(skill_id=skill_id, path=rel, content=content))
                count += 1
            await s.commit()
        return count
