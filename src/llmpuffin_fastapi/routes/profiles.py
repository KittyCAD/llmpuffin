"""Profile routes."""

from __future__ import annotations

import logging
import tomllib
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

from llmpuffin.agent import create_audit_run, run_audit
from llmpuffin.config import Config, Profile
from llmpuffin.github import GitHubClient
from llmpuffin.agent.harness import HarnessConfig

from llmpuffin.db import DB
from llmpuffin.agent.harness import Harness
from llmpuffin.scheduler.service import SchedulerService
from llmpuffin.services.profile import ProfileService
from llmpuffin.services.project import ProjectService
from llmpuffin_fastapi.deps import (
    get_config,
    get_github_client,
    get_harness,
    get_llmpuffin_db,
    get_profile_service,
    get_project_service,
    get_scheduler_service,
    toast,
)
from llmpuffin_fastapi.templates_env import templates

log = logging.getLogger("llmpuffin")
router = APIRouter()


@router.get("/profiles/", response_class=HTMLResponse)
async def profiles_list(
    request: Request,
    svc: Annotated[ProfileService, Depends(get_profile_service)],
):
    rows = await svc.list_all()
    profiles = []
    for p in rows:
        try:
            cfg = p.parsed_config()
            image = cfg.get("audit", {}).get("image", "")
        except Exception:
            image = "(invalid TOML)"
        profiles.append(
            {
                "id": p.id,
                "name": p.name,
                "image": image,
                "updated_at": p.updated_at,
                "jit": p.jit,
                "project_id": p.project_id,
            }
        )
    return templates.TemplateResponse(
        request, "profiles_list.html", {"profiles": profiles}
    )


@router.get("/projects/{project_id}/profiles/new/", response_class=HTMLResponse)
async def profile_new(
    project_id: int,
    request: Request,
    project_svc: Annotated[ProjectService, Depends(get_project_service)],
):
    project = await project_svc.get(project_id)
    if project is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(request, "profile_new.html", {"project": project})


@router.post("/projects/{project_id}/profiles/create/")
async def profile_create(
    project_id: int,
    request: Request,
    svc: Annotated[ProfileService, Depends(get_profile_service)],
    project_svc: Annotated[ProjectService, Depends(get_project_service)],
    name: Annotated[str, Form()] = "",
    profile_toml: Annotated[str, Form()] = "",
):
    project = await project_svc.get(project_id)
    if project is None:
        raise HTTPException(status_code=404)
    redirect = f"/projects/{project_id}/profiles/new/"
    name = name.strip()
    profile_toml = profile_toml.strip()
    if not name or not profile_toml:
        return toast(
            request, "error", "Name and config are required", redirect_to=redirect
        )
    try:
        tomllib.loads(profile_toml)
    except Exception as exc:
        return toast(request, "error", f"Invalid TOML: {exc}", redirect_to=redirect)
    await svc.create(name, profile_toml, project_id=project_id)
    return toast(
        request,
        "success",
        f"Created {name}",
        redirect_to=f"/projects/{project_id}/",
        refresh=True,
    )


@router.get("/profiles/{profile_id}/", response_class=HTMLResponse)
async def profile_detail_get(
    profile_id: int,
    request: Request,
    svc: Annotated[ProfileService, Depends(get_profile_service)],
    project_svc: Annotated[ProjectService, Depends(get_project_service)],
    scheduler_svc: Annotated[SchedulerService, Depends(get_scheduler_service)],
):
    profile = await svc.get(profile_id, with_runs=True)
    if profile is None:
        raise HTTPException(status_code=404)
    projects = await project_svc.list_all()
    schedule = await scheduler_svc.get_for_profile(profile_id)
    return templates.TemplateResponse(
        request,
        "profile_detail.html",
        {
            "profile": profile,
            "runs": profile.runs,
            "projects": [(p.id, p.name) for p, _, _ in projects],
            "schedule": schedule,
        },
    )


@router.post("/profiles/{profile_id}/edit/")
async def profile_edit(
    profile_id: int,
    request: Request,
    svc: Annotated[ProfileService, Depends(get_profile_service)],
    name: Annotated[str | None, Form()] = None,
    profile_toml: Annotated[str | None, Form()] = None,
    project_id: Annotated[int | None, Form()] = None,
):
    redirect = f"/profiles/{profile_id}/"
    fields: dict = {}
    if name is not None:
        name = name.strip()
        if not name:
            return toast(request, "error", "Name cannot be empty", redirect_to=redirect)
        fields["name"] = name
    if profile_toml is not None:
        try:
            tomllib.loads(profile_toml)
        except Exception as exc:
            return toast(request, "error", f"Invalid TOML: {exc}", redirect_to=redirect)
        fields["profile_toml"] = profile_toml
    if project_id is not None:
        fields["project_id"] = project_id
    if not fields:
        return toast(request, "error", "No fields to update", redirect_to=redirect)
    if not await svc.patch(profile_id, **fields):
        raise HTTPException(status_code=404)
    return toast(request, "success", "Saved.", redirect_to=redirect, refresh=True)


@router.post("/profiles/{profile_id}/run/")
async def profile_run(
    profile_id: int,
    request: Request,
    svc: Annotated[ProfileService, Depends(get_profile_service)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    harness: Annotated[Harness, Depends(get_harness)],
    config: Annotated[Config, Depends(get_config)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
):
    profile_db = await svc.get(profile_id)
    if profile_db is None:
        raise HTTPException(status_code=404)
    redirect = f"/profiles/{profile_id}/"
    try:
        parsed = Profile.from_toml_string(profile_db.profile_toml)
    except Exception as exc:
        return toast(request, "error", f"Invalid config: {exc}", redirect_to=redirect)
    harness_config = HarnessConfig(profile=parsed, profile_toml=profile_db.profile_toml)
    import uuid

    tid = uuid.uuid4().hex[:12]
    run_id = await create_audit_run(
        harness_config, tid, db=llmpuffin_db, profile_id=profile_db.id
    )
    harness.spawn(
        tid,
        run_audit(
            harness_config,
            db=llmpuffin_db,
            global_config=config,
            thread_id=tid,
            github_client=gh,
            profile_id=profile_db.id,
            audit_run_id=run_id,
        ),
    )
    return toast(
        request,
        "success",
        "Audit started",
        redirect_to=f"/runs/{run_id}/",
        refresh=True,
    )


@router.post("/profiles/{profile_id}/delete/")
async def profile_delete(
    profile_id: int,
    request: Request,
    svc: Annotated[ProfileService, Depends(get_profile_service)],
):
    error = await svc.delete(profile_id)
    if error == "not_found":
        raise HTTPException(status_code=404)
    if error:
        return toast(request, "error", error, redirect_to=f"/profiles/{profile_id}/")
    return toast(
        request, "success", "Profile deleted", redirect_to="/profiles/", refresh=True
    )


# ── Schedule routes ──


@router.post("/profiles/{profile_id}/schedule/")
async def schedule_upsert(
    profile_id: int,
    request: Request,
    svc: Annotated[ProfileService, Depends(get_profile_service)],
    scheduler_svc: Annotated[SchedulerService, Depends(get_scheduler_service)],
    cron_expr: Annotated[str, Form()],
    enabled: Annotated[bool, Form()] = True,
):
    profile = await svc.get(profile_id)
    if profile is None:
        raise HTTPException(status_code=404)
    redirect = f"/profiles/{profile_id}/"
    cron_expr = cron_expr.strip()
    if not cron_expr:
        return toast(request, "error", "Cron expression required", redirect_to=redirect)
    try:
        await scheduler_svc.upsert(profile_id, cron_expr, enabled=enabled)
    except ValueError as exc:
        return toast(request, "error", str(exc), redirect_to=redirect)
    return toast(
        request, "success", "Schedule saved", redirect_to=redirect, refresh=True
    )


@router.post("/profiles/{profile_id}/schedule/delete/")
async def schedule_delete(
    profile_id: int,
    request: Request,
    scheduler_svc: Annotated[SchedulerService, Depends(get_scheduler_service)],
):
    redirect = f"/profiles/{profile_id}/"
    schedule = await scheduler_svc.get_for_profile(profile_id)
    if schedule is None:
        return toast(request, "error", "No schedule found", redirect_to=redirect)
    await scheduler_svc.delete(schedule.id)
    return toast(
        request, "success", "Schedule removed", redirect_to=redirect, refresh=True
    )
