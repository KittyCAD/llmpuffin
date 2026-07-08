"""Skill management routes."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from llmpuffin.services.skill import SkillService
from llmpuffin_fastapi.deps import get_skill_service, toast
from llmpuffin_fastapi.templates_env import templates

router = APIRouter()


@router.get("/skills/", response_class=HTMLResponse)
async def skills_list(
    request: Request,
    svc: Annotated[SkillService, Depends(get_skill_service)],
):
    rows = await svc.list_all()
    return templates.TemplateResponse(request, "skills_list.html", {"skills": rows})


@router.get("/skills/{skill_id}/", response_class=HTMLResponse)
async def skill_detail(
    request: Request,
    skill_id: int,
    svc: Annotated[SkillService, Depends(get_skill_service)],
):
    skill = await svc.get(skill_id)
    if skill is None:
        raise HTTPException(404)
    return templates.TemplateResponse(request, "skill_detail.html", {"skill": skill})


@router.get("/skills/{skill_id}/files/{file_id}/")
async def skill_file_content(
    skill_id: int,
    file_id: int,
    svc: Annotated[SkillService, Depends(get_skill_service)],
):
    sf = await svc.get_file(skill_id, file_id)
    if sf is None:
        raise HTTPException(404)
    return JSONResponse({"id": sf.id, "path": sf.path, "content": sf.content})


@router.post("/skills/create/")
async def skill_create(
    request: Request,
    svc: Annotated[SkillService, Depends(get_skill_service)],
    name: str = Form(...),
    description: str = Form(""),
):
    skill = await svc.create(name, description)
    if skill is None:
        return toast(
            request, "error", f"Skill {name!r} already exists", redirect_to="/skills/"
        )
    return toast(
        request,
        "success",
        f"Created skill {name!r}",
        redirect_to="/skills/",
        refresh=True,
    )


@router.post("/skills/{skill_id}/upload/")
async def skill_upload_file(
    request: Request,
    skill_id: int,
    svc: Annotated[SkillService, Depends(get_skill_service)],
    path: str = Form(...),
    content: str = Form(...),
):
    skill = await svc.get(skill_id)
    if skill is None:
        raise HTTPException(404)
    await svc.upsert_file(skill_id, path, content)
    return toast(
        request,
        "success",
        f"Saved {path}",
        redirect_to=f"/skills/{skill_id}/",
        refresh=True,
    )


@router.post("/skills/{skill_id}/import/")
async def skill_import_directory(
    request: Request,
    skill_id: int,
    svc: Annotated[SkillService, Depends(get_skill_service)],
    directory: str = Form(...),
):
    """Import all files from a local directory into a skill."""
    skill = await svc.get(skill_id)
    if skill is None:
        raise HTTPException(404)

    dir_path = Path(directory)
    if not dir_path.is_dir():
        return toast(
            request,
            "error",
            f"Directory not found: {directory}",
            redirect_to=f"/skills/{skill_id}/",
        )

    count = await svc.import_directory(skill_id, dir_path)
    return toast(
        request,
        "success",
        f"Imported {count} file(s)",
        redirect_to=f"/skills/{skill_id}/",
        refresh=True,
    )


@router.post("/skills/{skill_id}/delete/")
async def skill_delete(
    request: Request,
    skill_id: int,
    svc: Annotated[SkillService, Depends(get_skill_service)],
):
    name = await svc.delete(skill_id)
    if name is None:
        raise HTTPException(404)
    return toast(
        request,
        "success",
        f"Deleted skill {name!r}",
        redirect_to="/skills/",
        refresh=True,
    )


@router.post("/skills/{skill_id}/files/{file_id}/delete/")
async def skill_file_delete(
    request: Request,
    skill_id: int,
    file_id: int,
    svc: Annotated[SkillService, Depends(get_skill_service)],
):
    path = await svc.delete_file(skill_id, file_id)
    if path is None:
        raise HTTPException(404)
    return toast(
        request,
        "success",
        f"Deleted {path}",
        redirect_to=f"/skills/{skill_id}/",
        refresh=True,
    )
