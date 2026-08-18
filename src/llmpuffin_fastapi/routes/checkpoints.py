"""Checkpoint routes."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from llmpuffin.agent import run_audit
from llmpuffin.config import Config, Profile
from llmpuffin.github import GitHubClient
from llmpuffin.agent.harness import HarnessConfig
from llmpuffin.models import AuditRun, AuditThread, Finding, HumanQuestion

from llmpuffin.agent.checkpoint import get_session, list_sessions
from llmpuffin.db import DB
from llmpuffin.agent.harness import Harness
from llmpuffin_fastapi.deps import (
    get_config,
    get_db,
    get_github_client,
    get_harness,
    get_llmpuffin_db,
    toast,
)
from llmpuffin_fastapi.templates_env import templates

log = logging.getLogger("llmpuffin")
router = APIRouter()


@router.get("/checkpoints/", response_class=HTMLResponse)
async def checkpoints_list(
    request: Request, llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)]
):
    sessions = await list_sessions(db=llmpuffin_db)
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
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
):
    session = await get_session(thread_id, db=llmpuffin_db)
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
    highlighted_ids: set[int] = set()
    if audit_thread is not None:
        all_findings = list(
            (
                await db.execute(
                    select(Finding)
                    .where(Finding.audit_run_id == audit_thread.audit_run_id)
                    .order_by(Finding.local_id.desc())
                )
            )
            .scalars()
            .all()
        )
        # Findings whose fork_thread_id points to this thread go first.
        highlighted = [f for f in all_findings if f.fork_thread_id == thread_id]
        rest = [f for f in all_findings if f.fork_thread_id != thread_id]
        findings = highlighted + rest
        highlighted_ids = {f.id for f in highlighted}

    # Load pending human questions for this thread.
    pending_questions: list[HumanQuestion] = []
    if audit_thread is not None:
        pending_questions = list(
            (
                await db.execute(
                    select(HumanQuestion)
                    .where(
                        HumanQuestion.thread_id == thread_id,
                        HumanQuestion.answered_at.is_(None),
                    )
                    .order_by(HumanQuestion.created_at)
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
            "highlighted_finding_ids": highlighted_ids,
            "pending_questions": pending_questions,
        },
    )


@router.get("/checkpoints/{thread_id}/messages/", response_class=HTMLResponse)
async def checkpoint_messages(
    thread_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
):
    session = await get_session(thread_id, db=llmpuffin_db)
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
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    harness: Annotated[Harness, Depends(get_harness)],
    config: Annotated[Config, Depends(get_config)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
    message: Annotated[str, Form()] = "",
):
    audit_thread = await _get_audit_thread(db, thread_id)
    if audit_thread is None:
        raise HTTPException(status_code=404)
    redirect = f"/checkpoints/{thread_id}/"
    if audit_thread.status == "running":
        return toast(
            request, "error", "Thread is already running", redirect_to=redirect
        )

    run = audit_thread.audit_run
    toml_str = run.profile_toml or (run.profile.profile_toml if run.profile else "")
    if not toml_str:
        return toast(request, "error", "No config available", redirect_to=redirect)

    msg = message.strip()
    if not msg:
        return toast(request, "error", "Message is required", redirect_to=redirect)

    profile = Profile.from_toml_string(toml_str)
    harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
    harness.spawn(
        thread_id,
        run_audit(
            harness_config,
            db=llmpuffin_db,
            global_config=config,
            thread_id=thread_id,
            user_message=msg,
            github_client=gh,
        ),
    )
    return toast(request, "success", "Resumed", redirect_to=redirect)


@router.post("/checkpoints/{thread_id}/answer/{question_id}/")
async def checkpoint_answer(
    thread_id: str,
    question_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    harness: Annotated[Harness, Depends(get_harness)],
    config: Annotated[Config, Depends(get_config)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
):
    from datetime import datetime, timezone

    audit_thread = await _get_audit_thread(db, thread_id)
    if audit_thread is None:
        raise HTTPException(status_code=404)
    redirect = f"/checkpoints/{thread_id}/"

    # Combine selected choices + free text into the answer.
    form = await request.form()
    selected = form.getlist("selected")
    free_text = str(form.get("answer") or "").strip()
    parts = []
    if selected:
        parts.append("Selected: " + ", ".join(str(s) for s in selected))
    if free_text:
        parts.append(free_text)
    answer = "\n".join(parts)
    if not answer:
        return toast(request, "error", "Answer cannot be empty", redirect_to=redirect)

    # Update the question.
    question = (
        await db.execute(select(HumanQuestion).where(HumanQuestion.id == question_id))
    ).scalar_one_or_none()
    if question is None:
        return toast(request, "error", "Question not found", redirect_to=redirect)
    if question.answered_at is not None:
        return toast(request, "error", "Already answered", redirect_to=redirect)
    question.answer = answer
    question.answered_at = datetime.now(timezone.utc)
    await db.commit()

    # Resume with Command(resume=answer).
    run = audit_thread.audit_run
    toml_str = run.profile_toml or (run.profile.profile_toml if run.profile else "")
    if not toml_str:
        return toast(request, "error", "No config available", redirect_to=redirect)

    profile = Profile.from_toml_string(toml_str)
    harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
    harness.spawn(
        thread_id,
        run_audit(
            harness_config,
            db=llmpuffin_db,
            global_config=config,
            thread_id=thread_id,
            resume_answer=answer,
            github_client=gh,
        ),
    )
    return toast(
        request, "success", "Answer sent, audit resuming", redirect_to=redirect
    )


@router.post("/checkpoints/{thread_id}/stop/")
async def checkpoint_stop(
    thread_id: str,
    request: Request,
    harness: Annotated[Harness, Depends(get_harness)],
):
    if harness.cancel(thread_id):
        return Response(status_code=204)
    return Response(status_code=404)
