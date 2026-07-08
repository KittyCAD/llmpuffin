"""Threat model CRUD operations."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select

from llmpuffin.db import DB
from llmpuffin.models import ThreatModelFile


class ThreatModelService:
    def __init__(self, db: DB):
        self.db = db

    async def import_directory(self, threat_model_id: int, directory: Path) -> int:
        """Import all TOML files from a directory into a threat model. Returns file count."""
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
