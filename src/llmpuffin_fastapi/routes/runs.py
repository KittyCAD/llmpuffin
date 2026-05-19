"""Audit run routes."""

from __future__ import annotations

import logging
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from llmpuffin.agent import fork_audit, run_audit
from llmpuffin.config import Profile
from llmpuffin.harness import HarnessConfig
from llmpuffin.models import AuditRun, AuditThread, Finding

from llmpuffin_fastapi.deps import get_db, spawn_audit
from llmpuffin_fastapi.templates_env import templates

log = logging.getLogger("llmpuffin")
router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def runs_list(
    request: Request, db: Annotated[AsyncSession, Depends(get_db)]
):
    rows = (
        await db.execute(
            select(AuditRun)
            .options(
                selectinload(AuditRun.profile),
                selectinload(AuditRun.threads),
            )
            .order_by(AuditRun.started_at.desc())
        )
    ).scalars().all()

    # Annotate finding counts (non-deleted)
    finding_counts = dict(
        (
            await db.execute(
                select(Finding.audit_run_id, func.count(Finding.id))
                .where(Finding.deleted.is_(False))
                .group_by(Finding.audit_run_id)
            )
        ).all()
    )

    runs = []
    for r in rows:
        runs.append(
            {
                "id": r.id,
                "profile": r.profile,
                "container_image": r.container_image,
                "model_name": r.model_name,
                "status": r.status,
                "thread_count": len(r.threads),
                "finding_count": finding_counts.get(r.id, 0),
                "started_at": r.started_at,
                "finished_at": r.finished_at,
            }
        )
    return templates.TemplateResponse(
        request, "runs_list.html", {"runs": runs}
    )


@router.get("/runs/{run_id}/", response_class=HTMLResponse)
async def run_detail(
    run_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    success: str | None = None,
    error: str | None = None,
):
    run = (
        await db.execute(
            select(AuditRun)
            .options(
                selectinload(AuditRun.profile),
                selectinload(AuditRun.threads),
                selectinload(AuditRun.findings).selectinload(Finding.locations),
            )
            .where(AuditRun.id == run_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(
        request,
        "run_detail.html",
        {
            "run": run,
            "threads": run.threads,
            "findings": run.findings,
            "success": success,
            "error": error,
        },
    )


@router.post("/runs/{run_id}/delete/")
async def run_delete(run_id: int, db: Annotated[AsyncSession, Depends(get_db)]):
    run = (
        await db.execute(
            select(AuditRun)
            .options(selectinload(AuditRun.threads))
            .where(AuditRun.id == run_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404)
    if run.status == "running":
        return RedirectResponse(
            f"/runs/{run_id}/?error={quote('Cannot delete a running audit')}",
            status_code=303,
        )
    await db.delete(run)
    await db.commit()
    return RedirectResponse("/", status_code=303)


def _toml_for_run(run: AuditRun) -> str:
    return run.profile_toml or (run.profile.profile_toml if run.profile else "")


@router.post("/runs/{run_id}/resume/{thread_id}/")
async def run_resume(
    run_id: int,
    thread_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    message: Annotated[str, Form()] = "",
):
    run = (
        await db.execute(
            select(AuditRun)
            .options(selectinload(AuditRun.profile))
            .where(AuditRun.id == run_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404)
    thread = (
        await db.execute(
            select(AuditThread).where(
                AuditThread.audit_run_id == run_id,
                AuditThread.thread_id == thread_id,
            )
        )
    ).scalar_one_or_none()
    if thread is None:
        raise HTTPException(status_code=404)
    if thread.status == "running":
        return RedirectResponse(
            f"/runs/{run_id}/?error={quote('Thread is already running')}",
            status_code=303,
        )

    toml_str = _toml_for_run(run)
    if not toml_str:
        return RedirectResponse(
            f"/runs/{run_id}/?error={quote('No config available for resume')}",
            status_code=303,
        )

    profile = Profile.from_toml_string(toml_str)
    harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
    spawn_audit(
        run_audit(
            harness_config,
            thread_id=thread_id,
            user_message=message.strip() or None,
        )
    )
    return RedirectResponse(
        f"/runs/{run_id}/?success={quote(f'Resumed from thread {thread_id}')}",
        status_code=303,
    )


@router.post("/runs/{run_id}/fork/{thread_id}/")
async def run_fork(
    run_id: int,
    thread_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    message: Annotated[str, Form()],
):
    run = (
        await db.execute(
            select(AuditRun)
            .options(selectinload(AuditRun.profile))
            .where(AuditRun.id == run_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404)
    thread = (
        await db.execute(
            select(AuditThread).where(
                AuditThread.audit_run_id == run_id,
                AuditThread.thread_id == thread_id,
            )
        )
    ).scalar_one_or_none()
    if thread is None:
        raise HTTPException(status_code=404)
    if thread.status == "running":
        return RedirectResponse(
            f"/runs/{run_id}/?error={quote('Thread is still running, cannot fork')}",
            status_code=303,
        )
    msg = message.strip()
    if not msg:
        return RedirectResponse(
            f"/runs/{run_id}/?error={quote('Fork requires a message')}",
            status_code=303,
        )

    toml_str = _toml_for_run(run)
    if not toml_str:
        return RedirectResponse(
            f"/runs/{run_id}/?error={quote('No config available for fork')}",
            status_code=303,
        )

    profile = Profile.from_toml_string(toml_str)
    harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
    spawn_audit(
        fork_audit(
            harness_config,
            source_thread_id=thread_id,
            user_message=msg,
        )
    )
    return RedirectResponse(
        f"/runs/{run_id}/?success={quote(f'Forked from thread {thread_id}')}",
        status_code=303,
    )
