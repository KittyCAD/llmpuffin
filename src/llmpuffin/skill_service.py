"""Skill CRUD operations."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select

from llmpuffin.db import DB
from llmpuffin.models import SkillFile


class SkillService:
    def __init__(self, db: DB):
        self.db = db

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
