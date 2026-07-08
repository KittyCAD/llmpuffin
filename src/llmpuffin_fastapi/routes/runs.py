"""Audit run routes."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from llmpuffin.agent import fork_audit, run_audit
from llmpuffin.config import Config, Profile
from llmpuffin.github import GitHubClient
from llmpuffin.agent.harness import HarnessConfig
from llmpuffin.services.sarif import export_sarif_for_run

from llmpuffin.db import DB
from llmpuffin.agent.harness import Harness
from llmpuffin.services.run import RunService
from llmpuffin_fastapi.deps import (
    get_config,
    get_github_client,
    get_harness,
    get_llmpuffin_db,
    get_run_service,
    toast,
)
from llmpuffin_fastapi.templates_env import templates

log = logging.getLogger("llmpuffin")
router = APIRouter()


@router.get("/")
async def root_redirect():
    return RedirectResponse("/profiles/", status_code=303)


@router.get("/runs/", response_class=HTMLResponse)
async def runs_list(
    request: Request, svc: Annotated[RunService, Depends(get_run_service)]
):
    rows, finding_counts = await svc.list_all()

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
    svc: Annotated[RunService, Depends(get_run_service)],
):
    run = await svc.get(run_id, with_findings=True)
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
    svc: Annotated[RunService, Depends(get_run_service)],
):
    error = await svc.delete(run_id)
    if error == "not_found":
        raise HTTPException(status_code=404)
    if error:
        return toast(request, "error", error, redirect_to=f"/runs/{run_id}/")
    return toast(
        request, "success", f"Deleted run #{run_id}", redirect_to="/runs/", refresh=True
    )


def _toml_for_run(run) -> str:
    return run.profile_toml or (run.profile.profile_toml if run.profile else "")


@router.get("/runs/{run_id}/coverage/", response_class=HTMLResponse)
async def run_coverage(
    run_id: int,
    request: Request,
    svc: Annotated[RunService, Depends(get_run_service)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
):
    run = await svc.get(run_id)
    if run is None:
        raise HTTPException(status_code=404)

    from llmpuffin.services.coverage import build_coverage_tree, load_coverage_for_run

    all_files, accessed = load_coverage_for_run(run_id, db=llmpuffin_db)
    tree = build_coverage_tree(all_files, accessed) if all_files else None

    return templates.TemplateResponse(
        request,
        "run_coverage.html",
        {
            "run": run,
            "tree": tree,
            "total_files": len(all_files),
            "accessed_files": len(accessed & set(all_files)),
        },
    )


@router.get("/runs/{run_id}/sarif/")
async def run_sarif_export(
    run_id: int,
    svc: Annotated[RunService, Depends(get_run_service)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
):
    run = await svc.get(run_id)
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
    svc: Annotated[RunService, Depends(get_run_service)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    harness: Annotated[Harness, Depends(get_harness)],
    config: Annotated[Config, Depends(get_config)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
    message: Annotated[str, Form()] = "",
):
    run = await svc.get(run_id)
    if run is None:
        raise HTTPException(status_code=404)
    redirect = f"/runs/{run_id}/"

    # Check thread exists and isn't running.
    thread = next((t for t in run.threads if t.thread_id == thread_id), None)
    if thread is None:
        raise HTTPException(status_code=404)
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
    svc: Annotated[RunService, Depends(get_run_service)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    harness: Annotated[Harness, Depends(get_harness)],
    config: Annotated[Config, Depends(get_config)],
    message: Annotated[str, Form()],
):
    run = await svc.get(run_id)
    if run is None:
        raise HTTPException(status_code=404)
    redirect = f"/runs/{run_id}/"

    thread = next((t for t in run.threads if t.thread_id == thread_id), None)
    if thread is None:
        raise HTTPException(status_code=404)
    if thread.status == "running" and not config.features.enabled(
        "fork_running_threads"
    ):
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
    svc: Annotated[RunService, Depends(get_run_service)],
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
    await svc.mark_thread_orphaned(thread_id)
    return toast(
        request, "success", "Thread already stopped", redirect_to=redirect, refresh=True
    )


@router.post("/runs/{run_id}/unlink/{thread_id}/")
async def run_unlink_finding(
    run_id: int,
    thread_id: str,
    request: Request,
    svc: Annotated[RunService, Depends(get_run_service)],
):
    """Unlink a finding from its fork thread."""
    redirect = f"/runs/{run_id}/?tab=threads"
    if not await svc.unlink_finding_fork(run_id, thread_id):
        return toast(request, "error", "No linked finding found", redirect_to=redirect)
    return toast(
        request, "success", "Finding unlinked", redirect_to=redirect, refresh=True
    )
