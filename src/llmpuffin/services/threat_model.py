"""Threat model CRUD operations."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from llmpuffin.db import DB
from llmpuffin.models import ThreatModelDB, ThreatModelFile


class ThreatModelService:
    def __init__(self, db: DB):
        self.db = db

    async def list_all(self) -> list[ThreatModelDB]:
        async with self.db.async_session() as s:
            return list(
                (
                    await s.execute(
                        select(ThreatModelDB)
                        .options(selectinload(ThreatModelDB.files))
                        .order_by(ThreatModelDB.name)
                    )
                )
                .scalars()
                .all()
            )

    async def get(self, tm_id: int) -> ThreatModelDB | None:
        async with self.db.async_session() as s:
            return (
                await s.execute(
                    select(ThreatModelDB)
                    .options(selectinload(ThreatModelDB.files))
                    .where(ThreatModelDB.id == tm_id)
                )
            ).scalar_one_or_none()

    async def get_file(self, tm_id: int, file_id: int) -> ThreatModelFile | None:
        async with self.db.async_session() as s:
            return (
                await s.execute(
                    select(ThreatModelFile).where(
                        ThreatModelFile.id == file_id,
                        ThreatModelFile.threat_model_id == tm_id,
                    )
                )
            ).scalar_one_or_none()

    async def create(self, name: str, description: str = "") -> ThreatModelDB | None:
        """Create a threat model. Returns None if name already exists."""
        async with self.db.async_session() as s:
            existing = (
                await s.execute(select(ThreatModelDB).where(ThreatModelDB.name == name))
            ).scalar_one_or_none()
            if existing:
                return None
            tm = ThreatModelDB(name=name, description=description)
            s.add(tm)
            await s.commit()
            await s.refresh(tm)
            return tm

    async def upsert_file(self, tm_id: int, path: str, content: str) -> None:
        """Create or update a file in a threat model."""
        async with self.db.async_session() as s:
            existing = (
                await s.execute(
                    select(ThreatModelFile).where(
                        ThreatModelFile.threat_model_id == tm_id,
                        ThreatModelFile.path == path,
                    )
                )
            ).scalar_one_or_none()
            if existing:
                existing.content = content
            else:
                s.add(
                    ThreatModelFile(threat_model_id=tm_id, path=path, content=content)
                )
            await s.commit()

    async def delete(self, tm_id: int) -> str | None:
        """Delete a threat model. Returns the name, or None if not found."""
        async with self.db.async_session() as s:
            tm = (
                await s.execute(select(ThreatModelDB).where(ThreatModelDB.id == tm_id))
            ).scalar_one_or_none()
            if tm is None:
                return None
            name = tm.name
            await s.delete(tm)
            await s.commit()
            return name

    async def delete_file(self, tm_id: int, file_id: int) -> str | None:
        """Delete a file. Returns the file path, or None if not found."""
        async with self.db.async_session() as s:
            tmf = (
                await s.execute(
                    select(ThreatModelFile).where(
                        ThreatModelFile.id == file_id,
                        ThreatModelFile.threat_model_id == tm_id,
                    )
                )
            ).scalar_one_or_none()
            if tmf is None:
                return None
            path = tmf.path
            await s.delete(tmf)
            await s.commit()
            return path

    async def import_directory(self, threat_model_id: int, directory: Path) -> int:
        """Import all files from a directory into a threat model. Returns file count."""
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
                        select(ThreatModelFile).where(
                            ThreatModelFile.threat_model_id == threat_model_id,
                            ThreatModelFile.path == rel,
                        )
                    )
                ).scalar_one_or_none()
                if existing:
                    existing.content = content
                else:
                    s.add(
                        ThreatModelFile(
                            threat_model_id=threat_model_id,
                            path=rel,
                            content=content,
                        )
                    )
                count += 1
            await s.commit()
        return count
