"""Profile routes."""

from __future__ import annotations

import logging
import tomllib
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
from llmpuffin.models import AuditProfile

from llmpuffin_fastapi.deps import get_db, spawn_audit
from llmpuffin_fastapi.templates_env import templates

log = logging.getLogger("llmpuffin")
router = APIRouter()


@router.get("/profiles/", response_class=HTMLResponse)
async def profiles_list(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    error: str | None = None,
    success: str | None = None,
):
    rows = (
        await db.execute(
            select(AuditProfile).where(AuditProfile.jit.is_(False))
        )
    ).scalars().all()
    profiles = []
    for p in rows:
        try:
            cfg = p.parsed_config()
            image = cfg.get("audit", {}).get("image", "")
        except Exception:
            image = "(invalid TOML)"
        profiles.append(
            {"id": p.id, "name": p.name, "image": image, "updated_at": p.updated_at}
        )
    return templates.TemplateResponse(
        request,
        "profiles_list.html",
        {"profiles": profiles, "error": error, "success": success},
    )


@router.post("/profiles/create/")
async def profile_create(
    db: Annotated[AsyncSession, Depends(get_db)],
    name: Annotated[str, Form()] = "",
    profile_toml: Annotated[str, Form()] = "",
):
    name = name.strip()
    profile_toml = profile_toml.strip()
    if not name or not profile_toml:
        return RedirectResponse(
            f"/profiles/?error={quote('Name and config are required')}",
            status_code=303,
        )
    try:
        tomllib.loads(profile_toml)
    except Exception as exc:
        return RedirectResponse(
            f"/profiles/?error={quote(f'Invalid TOML: {exc}')}", status_code=303
        )
    db.add(AuditProfile(name=name, profile_toml=profile_toml, jit=False))
    await db.commit()
    return RedirectResponse("/profiles/", status_code=303)


@router.get("/profiles/{profile_id}/", response_class=HTMLResponse)
async def profile_detail_get(
    profile_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    error: str | None = None,
    success: str | None = None,
):
    profile = (
        await db.execute(
            select(AuditProfile)
            .options(selectinload(AuditProfile.runs))
            .where(AuditProfile.id == profile_id)
        )
    ).scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(
        request,
        "profile_detail.html",
        {
            "profile": profile,
            "runs": profile.runs,
            "error": error,
            "success": success,
        },
    )


@router.post("/profiles/{profile_id}/", response_class=HTMLResponse)
async def profile_detail_post(
    profile_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    name: Annotated[str, Form()] = "",
    profile_toml: Annotated[str, Form()] = "",
):
    profile = (
        await db.execute(
            select(AuditProfile)
            .options(selectinload(AuditProfile.runs))
            .where(AuditProfile.id == profile_id)
        )
    ).scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404)

    ctx: dict = {"profile": profile, "runs": profile.runs}
    try:
        tomllib.loads(profile_toml)
    except Exception as exc:
        ctx["error"] = f"Invalid TOML: {exc}"
        return templates.TemplateResponse(request, "profile_detail.html", ctx)

    profile.name = name.strip()
    profile.profile_toml = profile_toml
    await db.commit()
    ctx["success"] = "Profile saved."
    return templates.TemplateResponse(request, "profile_detail.html", ctx)


@router.post("/profiles/{profile_id}/run/")
async def profile_run(
    profile_id: int, db: Annotated[AsyncSession, Depends(get_db)]
):
    profile = (
        await db.execute(
            select(AuditProfile).where(AuditProfile.id == profile_id)
        )
    ).scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404)
    try:
        parsed = Profile.from_toml_string(profile.profile_toml)
    except Exception as exc:
        return RedirectResponse(
            f"/profiles/{profile_id}/?error={quote(f'Invalid config: {exc}')}",
            status_code=303,
        )
    harness_config = HarnessConfig(profile=parsed, profile_toml=profile.profile_toml)
    spawn_audit(run_audit(harness_config))
    return RedirectResponse(
        f"/profiles/{profile_id}/?success={quote('Audit started')}", status_code=303
    )
