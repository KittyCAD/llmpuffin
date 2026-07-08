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
from llmpuffin.harness import HarnessConfig

from llmpuffin.db import DB
from llmpuffin.harness import Harness
from llmpuffin.profile_service import ProfileService
from llmpuffin_fastapi.deps import (
    get_config,
    get_github_client,
    get_harness,
    get_llmpuffin_db,
    get_profile_service,
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
            }
        )
    return templates.TemplateResponse(
        request, "profiles_list.html", {"profiles": profiles}
    )


@router.post("/profiles/create/")
async def profile_create(
    request: Request,
    svc: Annotated[ProfileService, Depends(get_profile_service)],
    name: Annotated[str, Form()] = "",
    profile_toml: Annotated[str, Form()] = "",
):
    name = name.strip()
    profile_toml = profile_toml.strip()
    if not name or not profile_toml:
        return toast(
            request, "error", "Name and config are required", redirect_to="/profiles/"
        )
    try:
        tomllib.loads(profile_toml)
    except Exception as exc:
        return toast(request, "error", f"Invalid TOML: {exc}", redirect_to="/profiles/")
    await svc.create(name, profile_toml)
    return toast(
        request, "success", f"Created {name}", redirect_to="/profiles/", refresh=True
    )


@router.get("/profiles/{profile_id}/", response_class=HTMLResponse)
async def profile_detail_get(
    profile_id: int,
    request: Request,
    svc: Annotated[ProfileService, Depends(get_profile_service)],
):
    profile = await svc.get(profile_id, with_runs=True)
    if profile is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(
        request,
        "profile_detail.html",
        {"profile": profile, "runs": profile.runs},
    )


@router.post("/profiles/{profile_id}/", response_class=HTMLResponse)
async def profile_detail_post(
    profile_id: int,
    request: Request,
    svc: Annotated[ProfileService, Depends(get_profile_service)],
    name: Annotated[str, Form()] = "",
    profile_toml: Annotated[str, Form()] = "",
):
    redirect = f"/profiles/{profile_id}/"
    try:
        tomllib.loads(profile_toml)
    except Exception as exc:
        return toast(request, "error", f"Invalid TOML: {exc}", redirect_to=redirect)

    if not await svc.update(profile_id, name.strip(), profile_toml):
        raise HTTPException(status_code=404)
    return toast(
        request, "success", "Profile saved.", redirect_to=redirect, refresh=True
    )


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
