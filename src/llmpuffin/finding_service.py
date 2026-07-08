"""Centralized finding CRUD operations.

All finding database operations go through FindingService, which is used
by both the agent tools and the FastAPI routes.
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy import update as sa_update

from llmpuffin.db import DB
from llmpuffin.models import (
    Finding,
    FindingAttachment,
    FindingComment,
    FindingLocation,
    ValidationNote,
)

log = logging.getLogger("llmpuffin")

# Fields whose changes should trigger an embedding refresh.
_EMBEDDING_FIELDS = {"title", "description", "exploit_scenario"}


class FindingService:
    """Finding CRUD operations.

    Constructed once with a ``DB`` reference (e.g. on ``app.state``).
    Methods that operate on local_ids take ``audit_run_id`` as a parameter.
    PK-based methods don't need it.
    """

    def __init__(self, db: DB):
        self.db = db

    # ── helpers ──

    async def _refresh_embedding(self, finding_pk: int) -> None:
        """Best-effort: regenerate embedding after text fields change."""
        try:
            from llmpuffin.embeddings import embed_finding

            embed_finding(finding_pk, db=self.db)
        except Exception as exc:
            log.debug("Embedding refresh skipped for finding %d: %s", finding_pk, exc)

    # ── local_id-based (agent tools) ──

    async def resolve(self, audit_run_id: int, local_id: int) -> Finding | None:
        """Look up a Finding by local_id within the audit run."""
        async with self.db.async_session() as s:
            return (
                await s.execute(
                    select(Finding).where(
                        Finding.audit_run_id == audit_run_id,
                        Finding.local_id == local_id,
                    )
                )
            ).scalar_one_or_none()

    async def create(
        self,
        audit_run_id: int,
        *,
        thread_id: str,
        title: str,
        severity: str,
        difficulty: str,
        description: str,
        exploit_scenario: str,
        recommendations: str,
        locations: list[dict] | None = None,
        tool_call_id: str = "",
    ) -> tuple[int, int]:
        """Insert a finding with serialized local_id allocation.

        Concurrent transactions are serialized by a per-audit-run advisory lock
        held until commit, so the MAX(local_id) read and the INSERT cannot
        interleave.

        Returns (finding_pk_id, local_id).
        """
        next_local_id = (
            select(func.coalesce(func.max(Finding.local_id) + 1, 0))
            .where(Finding.audit_run_id == audit_run_id)
            .scalar_subquery()
        )

        async with self.db.async_session() as s:
            async with s.begin():
                await s.execute(select(func.pg_advisory_xact_lock(audit_run_id)))
                finding = Finding(
                    audit_run_id=audit_run_id,
                    thread_id=thread_id,
                    local_id=next_local_id,
                    title=title,
                    severity=severity,
                    difficulty=difficulty,
                    description=description,
                    exploit_scenario=exploit_scenario,
                    recommendations=recommendations,
                    tool_call_id=tool_call_id,
                )
                s.add(finding)
                await s.flush()
                await s.refresh(finding, attribute_names=["local_id"])
                for loc in locations or []:
                    s.add(
                        FindingLocation(
                            finding_id=finding.id,
                            file_path=loc["file"],
                            start_line=loc.get("line", 0),
                            origin_remote=loc.get("origin_remote", ""),
                            head=loc.get("head", ""),
                        )
                    )
                return finding.id, finding.local_id

    async def update(
        self, audit_run_id: int, local_id: int, **fields
    ) -> Finding | None:
        """Update a finding's fields by local_id. Returns the finding, or None if not found.

        Only non-None values in fields are applied. Refreshes embedding if
        text fields change.
        """
        finding = await self.resolve(audit_run_id, local_id)
        if not finding:
            return None

        values = {k: v for k, v in fields.items() if v is not None}
        if values:
            async with self.db.async_session() as s:
                await s.execute(
                    sa_update(Finding)
                    .where(
                        Finding.id == finding.id,
                        Finding.audit_run_id == audit_run_id,
                    )
                    .values(**values)
                )
                await s.commit()
            if values.keys() & _EMBEDDING_FIELDS:
                await self._refresh_embedding(finding.id)
        return finding

    async def delete(self, audit_run_id: int, local_id: int) -> Finding | None:
        """Soft-delete a finding. Returns the finding, or None if not found."""
        finding = await self.resolve(audit_run_id, local_id)
        if not finding:
            return None

        async with self.db.async_session() as s:
            await s.execute(
                sa_update(Finding)
                .where(
                    Finding.id == finding.id,
                    Finding.audit_run_id == audit_run_id,
                )
                .values(status="deleted")
            )
            await s.commit()
        return finding

    async def validate(
        self,
        audit_run_id: int,
        local_id: int,
        *,
        evidence: str,
        thread_id: str = "",
        tool_call_id: str = "",
    ) -> Finding | None:
        """Add a validation note and mark the finding as validated.

        Returns the finding, or None if not found.
        """
        finding = await self.resolve(audit_run_id, local_id)
        if not finding:
            return None

        async with self.db.async_session() as s:
            s.add(
                ValidationNote(
                    finding_id=finding.id,
                    thread_id=thread_id,
                    tool_call_id=tool_call_id,
                    evidence=evidence,
                )
            )
            await s.execute(
                sa_update(Finding)
                .where(
                    Finding.id == finding.id,
                    Finding.audit_run_id == audit_run_id,
                )
                .values(validated=True)
            )
            await s.commit()
        return finding

    async def list_all(self, audit_run_id: int) -> list[Finding]:
        """List all findings for an audit run, ordered by local_id."""
        async with self.db.async_session() as s:
            result = await s.execute(
                select(Finding)
                .where(Finding.audit_run_id == audit_run_id)
                .order_by(Finding.local_id)
            )
            return list(result.scalars().all())

    async def attach_file(
        self,
        audit_run_id: int,
        local_id: int,
        *,
        filename: str,
        content: bytes,
        description: str = "",
        thread_id: str = "",
        tool_call_id: str = "",
    ) -> FindingAttachment | None:
        """Attach a file to a finding. Returns the attachment, or None if finding not found."""
        finding = await self.resolve(audit_run_id, local_id)
        if not finding:
            return None

        async with self.db.async_session() as s:
            att = FindingAttachment(
                finding_id=finding.id,
                filename=filename,
                description=description,
                content=content,
                size=len(content),
                thread_id=thread_id,
                tool_call_id=tool_call_id,
            )
            s.add(att)
            await s.commit()
            await s.refresh(att)
            return att

    async def list_attachments(
        self, audit_run_id: int, local_id: int
    ) -> list[FindingAttachment] | None:
        """List attachments for a finding. Returns None if finding not found."""
        finding = await self.resolve(audit_run_id, local_id)
        if not finding:
            return None

        async with self.db.async_session() as s:
            result = await s.execute(
                select(FindingAttachment)
                .where(FindingAttachment.finding_id == finding.id)
                .order_by(FindingAttachment.created_at)
            )
            return list(result.scalars().all())

    # ── PK-based (web UI) ──

    async def update_by_pk(self, finding_pk: int, **fields) -> bool:
        """Update a finding by primary key. Returns True if the finding existed.

        Refreshes embedding if text fields change.
        """
        values = {k: v for k, v in fields.items() if v is not None}
        if not values:
            return True

        async with self.db.async_session() as s:
            result = await s.execute(
                sa_update(Finding).where(Finding.id == finding_pk).values(**values)
            )
            await s.commit()
            if result.rowcount == 0:  # pyright: ignore[reportAttributeAccessIssue]
                return False

        if values.keys() & _EMBEDDING_FIELDS:
            await self._refresh_embedding(finding_pk)
        return True

    async def merge_duplicates(self, keep_id: int, duplicate_ids: list[int]) -> int:
        """Mark findings as duplicates, keeping one as canonical.

        Returns the number of findings marked as duplicate.
        """
        count = 0
        for fid in duplicate_ids:
            if fid != keep_id:
                await self.update_by_pk(fid, status="duplicate")
                count += 1
        return count

    def build_fork_message(self, finding: Finding, user_message: str = "") -> str:
        """Build the user message for a finding fork conversation."""
        context = (
            f"This conversation is forked to investigate finding #{finding.local_id}.\n"
            f"Title: {finding.title}\n"
            f"Severity: {finding.severity} | Difficulty: {finding.difficulty}\n"
            f"Description: {finding.description[:500]}\n\n"
        )
        return context + (
            user_message.strip()
            or "Investigate this finding further. Try to validate or refute it."
        )

    async def set_fork_thread(self, finding_pk: int, fork_thread_id: str) -> None:
        """Set the fork_thread_id on a finding."""
        async with self.db.async_session() as s:
            await s.execute(
                sa_update(Finding)
                .where(Finding.id == finding_pk)
                .values(fork_thread_id=fork_thread_id)
            )
            await s.commit()

    async def add_comment(self, finding_pk: int, body: str) -> FindingComment:
        """Add a comment to a finding."""
        async with self.db.async_session() as s:
            comment = FindingComment(finding_id=finding_pk, body=body)
            s.add(comment)
            await s.commit()
            await s.refresh(comment)
            return comment

    async def update_comment(self, comment_id: int, finding_pk: int, body: str) -> bool:
        """Update a comment's body. Returns True if found."""
        async with self.db.async_session() as s:
            comment = (
                await s.execute(
                    select(FindingComment).where(
                        FindingComment.id == comment_id,
                        FindingComment.finding_id == finding_pk,
                    )
                )
            ).scalar_one_or_none()
            if comment is None:
                return False
            comment.body = body
            await s.commit()
            return True

    async def delete_comment(self, comment_id: int, finding_pk: int) -> bool:
        """Delete a comment. Returns True if found."""
        async with self.db.async_session() as s:
            comment = (
                await s.execute(
                    select(FindingComment).where(
                        FindingComment.id == comment_id,
                        FindingComment.finding_id == finding_pk,
                    )
                )
            ).scalar_one_or_none()
            if comment is None:
                return False
            await s.delete(comment)
            await s.commit()
            return True
