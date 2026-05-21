"""Checkpoint routes."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from llmpuffin.agent import run_audit
from llmpuffin.config import Profile
from llmpuffin.github import GitHubClient
from llmpuffin.harness import HarnessConfig
from llmpuffin.models import AuditRun, AuditThread, Finding

from llmpuffin_fastapi.checkpoint import get_session, list_sessions
from llmpuffin_fastapi.deps import get_db, get_github_client, spawn_audit, toast
from llmpuffin_fastapi.templates_env import templates

log = logging.getLogger("llmpuffin")
router = APIRouter()


@router.get("/checkpoints/", response_class=HTMLResponse)
async def checkpoints_list(request: Request):
    sessions = await list_sessions()
    return templates.TemplateResponse(
        request, "checkpoints_list.html", {"sessions": sessions}
    )


async def _get_audit_thread(db: AsyncSession, thread_id: str) -> AuditThread | None:
    return (
        await db.execute(
            select(AuditThread)
            .options(selectinload(AuditThread.audit_run).selectinload(AuditRun.profile))
            .where(AuditThread.thread_id == thread_id)
        )
    ).scalar_one_or_none()


@router.get("/checkpoints/{thread_id}/", response_class=HTMLResponse)
async def checkpoint_detail(
    thread_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    session = await get_session(thread_id)
    if session is None:
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "title": "Checkpoint not found",
                "message": f"No checkpoint data for thread {thread_id}.",
            },
            status_code=404,
        )
    audit_thread = await _get_audit_thread(db, thread_id)
    findings: list[Finding] = []
    if audit_thread is not None:
        findings = list(
            (
                await db.execute(
                    select(Finding)
                    .where(
                        Finding.audit_run_id == audit_thread.audit_run_id,
                        Finding.deleted.is_(False),
                    )
                    .order_by(Finding.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
    return templates.TemplateResponse(
        request,
        "checkpoint_detail.html",
        {
            "session": session,
            "audit_thread": audit_thread,
            "findings": findings,
        },
    )


@router.get("/checkpoints/{thread_id}/messages/", response_class=HTMLResponse)
async def checkpoint_messages(
    thread_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    session = await get_session(thread_id)
    if session is None:
        return HTMLResponse("")
    audit_thread = await _get_audit_thread(db, thread_id)
    return templates.TemplateResponse(
        request,
        "_checkpoint_messages.html",
        {"session": session, "audit_thread": audit_thread},
    )


@router.post("/checkpoints/{thread_id}/resume/")
async def checkpoint_resume(
    thread_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
    message: Annotated[str, Form()] = "",
):
    audit_thread = await _get_audit_thread(db, thread_id)
    if audit_thread is None:
        raise HTTPException(status_code=404)
    redirect = f"/checkpoints/{thread_id}/"
    if audit_thread.status == "running":
        return toast(request, "error", "Thread is already running", redirect_to=redirect)

    run = audit_thread.audit_run
    toml_str = run.profile_toml or (run.profile.profile_toml if run.profile else "")
    if not toml_str:
        return toast(request, "error", "No config available", redirect_to=redirect)

    msg = message.strip()
    if not msg:
        return toast(request, "error", "Message is required", redirect_to=redirect)

    profile = Profile.from_toml_string(toml_str)
    harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
    spawn_audit(run_audit(harness_config, thread_id=thread_id, user_message=msg, github_client=gh))
    return toast(request, "success", "Resumed", redirect_to=redirect)
