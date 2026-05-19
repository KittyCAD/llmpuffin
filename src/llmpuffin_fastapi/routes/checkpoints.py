"""Checkpoint routes."""

from __future__ import annotations

import logging
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from llmpuffin.agent import run_audit
from llmpuffin.config import Profile
from llmpuffin.harness import HarnessConfig
from llmpuffin.models import AuditRun, AuditThread

from llmpuffin_fastapi.checkpoint import get_session, list_sessions
from llmpuffin_fastapi.deps import get_db, spawn_audit
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
    success: str | None = None,
    error: str | None = None,
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
    return templates.TemplateResponse(
        request,
        "checkpoint_detail.html",
        {
            "session": session,
            "audit_thread": audit_thread,
            "success": success,
            "error": error,
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
    db: Annotated[AsyncSession, Depends(get_db)],
    message: Annotated[str, Form()] = "",
):
    audit_thread = await _get_audit_thread(db, thread_id)
    if audit_thread is None:
        raise HTTPException(status_code=404)
    if audit_thread.status == "running":
        return RedirectResponse(
            f"/checkpoints/{thread_id}/?error={quote('Thread is already running')}",
            status_code=303,
        )

    run = audit_thread.audit_run
    toml_str = run.profile_toml or (run.profile.profile_toml if run.profile else "")
    if not toml_str:
        return RedirectResponse(
            f"/checkpoints/{thread_id}/?error={quote('No config available')}",
            status_code=303,
        )

    msg = message.strip()
    if not msg:
        return RedirectResponse(
            f"/checkpoints/{thread_id}/?error={quote('Message is required')}",
            status_code=303,
        )

    profile = Profile.from_toml_string(toml_str)
    harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
    spawn_audit(run_audit(harness_config, thread_id=thread_id, user_message=msg))
    return RedirectResponse(
        f"/checkpoints/{thread_id}/?success={quote('Resumed')}", status_code=303
    )
