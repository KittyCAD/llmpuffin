"""Audit run routes."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from llmpuffin.agent import fork_audit, run_audit
from llmpuffin.config import Config, Profile
from llmpuffin.github import GitHubClient
from llmpuffin.harness import HarnessConfig
from llmpuffin.models import AuditRun, AuditThread, Finding
from llmpuffin.sarif import export_sarif_for_run

from llmpuffin.db import DB
from llmpuffin.harness import Harness
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


@router.get("/")
async def root_redirect():
    return RedirectResponse("/profiles/", status_code=303)


@router.get("/runs/", response_class=HTMLResponse)
async def runs_list(request: Request, db: Annotated[AsyncSession, Depends(get_db)]):
    rows = (
        (
            await db.execute(
                select(AuditRun)
                .options(
                    selectinload(AuditRun.profile),
                    selectinload(AuditRun.threads),
                )
                .order_by(AuditRun.started_at.desc())
            )
        )
        .scalars()
        .all()
    )

    # Annotate finding counts (non-deleted)
    finding_counts = dict(
        (
            await db.execute(
                select(Finding.audit_run_id, func.count(Finding.id))
                .where(Finding.status != "deleted")
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
    return templates.TemplateResponse(request, "runs_list.html", {"runs": runs})


@router.get("/runs/{run_id}/", response_class=HTMLResponse)
async def run_detail(
    run_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    run = (
        await db.execute(
            select(AuditRun)
            .options(
                selectinload(AuditRun.profile),
                selectinload(AuditRun.threads),
                selectinload(AuditRun.findings).selectinload(Finding.locations),
                selectinload(AuditRun.findings).selectinload(Finding.github_link),
            )
            .where(AuditRun.id == run_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(
        request,
        "run_detail.html",
        {"run": run, "threads": run.threads, "findings": run.findings},
    )


@router.post("/runs/{run_id}/delete/")
async def run_delete(
    run_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
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
        return toast(
            request,
            "error",
            "Cannot delete a running audit",
            redirect_to=f"/runs/{run_id}/",
        )
    await db.delete(run)
    await db.commit()
    return toast(
        request, "success", f"Deleted run #{run_id}", redirect_to="/runs/", refresh=True
    )


def _toml_for_run(run: AuditRun) -> str:
    return run.profile_toml or (run.profile.profile_toml if run.profile else "")


@router.get("/runs/{run_id}/sarif/")
async def run_sarif_export(
    run_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
):
    run = (
        await db.execute(select(AuditRun).where(AuditRun.id == run_id))
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404)
    sarif_json = export_sarif_for_run(run_id, db=llmpuffin_db)
    return Response(
        content=sarif_json,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="llmpuffin-run-{run_id}.sarif.json"'
        },
    )


@router.post("/runs/{run_id}/resume/{thread_id}/")
async def run_resume(
    run_id: int,
    thread_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    harness: Annotated[Harness, Depends(get_harness)],
    config: Annotated[Config, Depends(get_config)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
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
    redirect = f"/runs/{run_id}/"
    if thread.status == "running":
        return toast(
            request, "error", "Thread is already running", redirect_to=redirect
        )

    toml_str = _toml_for_run(run)
    if not toml_str:
        return toast(
            request, "error", "No config available for resume", redirect_to=redirect
        )

    profile = Profile.from_toml_string(toml_str)
    harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
    harness.spawn(
        thread_id,
        run_audit(
            harness_config,
            db=llmpuffin_db,
            global_config=config,
            thread_id=thread_id,
            user_message=message.strip() or None,
            github_client=gh,
        ),
    )
    return toast(
        request,
        "success",
        f"Resumed from thread {thread_id}",
        redirect_to=redirect,
        refresh=True,
    )


@router.post("/runs/{run_id}/fork/{thread_id}/")
async def run_fork(
    run_id: int,
    thread_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    harness: Annotated[Harness, Depends(get_harness)],
    config: Annotated[Config, Depends(get_config)],
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
    redirect = f"/runs/{run_id}/"
    if thread.status == "running":
        return toast(
            request,
            "error",
            "Thread is still running, cannot fork",
            redirect_to=redirect,
        )
    msg = message.strip()
    if not msg:
        return toast(request, "error", "Fork requires a message", redirect_to=redirect)

    toml_str = _toml_for_run(run)
    if not toml_str:
        return toast(
            request, "error", "No config available for fork", redirect_to=redirect
        )

    import uuid as _uuid

    new_tid = _uuid.uuid4().hex[:12]
    profile = Profile.from_toml_string(toml_str)
    harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
    harness.spawn(
        new_tid,
        fork_audit(
            harness_config,
            source_thread_id=thread_id,
            user_message=msg,
            db=llmpuffin_db,
            global_config=config,
            thread_id=new_tid,
        ),
    )
    return toast(
        request,
        "success",
        f"Forked from thread {thread_id}",
        redirect_to=redirect,
        refresh=True,
    )


@router.post("/runs/{run_id}/stop/{thread_id}/")
async def run_stop(
    run_id: int,
    thread_id: str,
    request: Request,
    harness: Annotated[Harness, Depends(get_harness)],
):
    redirect = f"/runs/{run_id}/"
    if harness.cancel(thread_id):
        return toast(
            request,
            "success",
            f"Stopping thread {thread_id}",
            redirect_to=redirect,
            refresh=True,
        )
    return toast(
        request, "error", "Thread not found or not running", redirect_to=redirect
    )


@router.post("/runs/{run_id}/unlink/{thread_id}/")
async def run_unlink_finding(
    run_id: int,
    thread_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Unlink a finding from its fork thread."""
    redirect = f"/runs/{run_id}/?tab=threads"
    result = await db.execute(
        sa_update(Finding)
        .where(Finding.fork_thread_id == thread_id, Finding.audit_run_id == run_id)
        .values(fork_thread_id="")
    )
    await db.commit()
    if result.rowcount == 0:
        return toast(request, "error", "No linked finding found", redirect_to=redirect)
    return toast(
        request, "success", "Finding unlinked", redirect_to=redirect, refresh=True
    )
