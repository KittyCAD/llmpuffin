"""Skill management routes."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from llmpuffin.models import Skill, SkillFile
from llmpuffin_fastapi.deps import get_db, toast
from llmpuffin_fastapi.templates_env import templates

log = logging.getLogger("llmpuffin")
router = APIRouter()


@router.get("/skills/", response_class=HTMLResponse)
async def skills_list(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    rows = (
        (
            await db.execute(
                select(Skill).options(selectinload(Skill.files)).order_by(Skill.name)
            )
        )
        .scalars()
        .all()
    )
    return templates.TemplateResponse(request, "skills_list.html", {"skills": rows})


@router.get("/skills/{skill_id}/", response_class=HTMLResponse)
async def skill_detail(
    request: Request,
    skill_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    skill = (
        await db.execute(
            select(Skill).options(selectinload(Skill.files)).where(Skill.id == skill_id)
        )
    ).scalar_one_or_none()
    if skill is None:
        raise HTTPException(404)
    return templates.TemplateResponse(request, "skill_detail.html", {"skill": skill})


@router.get("/skills/{skill_id}/files/{file_id}/")
async def skill_file_content(
    skill_id: int,
    file_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    sf = (
        await db.execute(
            select(SkillFile).where(
                SkillFile.id == file_id, SkillFile.skill_id == skill_id
            )
        )
    ).scalar_one_or_none()
    if sf is None:
        raise HTTPException(404)
    return JSONResponse({"id": sf.id, "path": sf.path, "content": sf.content})


@router.post("/skills/create/")
async def skill_create(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    name: str = Form(...),
    description: str = Form(""),
):
    existing = (
        await db.execute(select(Skill).where(Skill.name == name))
    ).scalar_one_or_none()
    if existing:
        return toast(
            request, "error", f"Skill {name!r} already exists", redirect_to="/skills/"
        )

    skill = Skill(name=name, description=description)
    db.add(skill)
    await db.commit()
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
    db: Annotated[AsyncSession, Depends(get_db)],
    path: str = Form(...),
    content: str = Form(...),
):
    skill = (
        await db.execute(select(Skill).where(Skill.id == skill_id))
    ).scalar_one_or_none()
    if skill is None:
        raise HTTPException(404)

    # Upsert: update if path exists, else insert
    existing = (
        await db.execute(
            select(SkillFile).where(
                SkillFile.skill_id == skill_id, SkillFile.path == path
            )
        )
    ).scalar_one_or_none()
    if existing:
        existing.content = content
    else:
        db.add(SkillFile(skill_id=skill_id, path=path, content=content))
    await db.commit()
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
    db: Annotated[AsyncSession, Depends(get_db)],
    directory: str = Form(...),
):
    """Import all files from a local directory into a skill."""
    skill = (
        await db.execute(select(Skill).where(Skill.id == skill_id))
    ).scalar_one_or_none()
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

    count = 0
    for file_path in sorted(dir_path.rglob("*")):
        if not file_path.is_file():
            continue
        try:
            content = file_path.read_text()
        except (UnicodeDecodeError, OSError):
            continue

        rel = str(file_path.relative_to(dir_path))
        existing = (
            await db.execute(
                select(SkillFile).where(
                    SkillFile.skill_id == skill_id, SkillFile.path == rel
                )
            )
        ).scalar_one_or_none()
        if existing:
            existing.content = content
        else:
            db.add(SkillFile(skill_id=skill_id, path=rel, content=content))
        count += 1

    await db.commit()
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
    db: Annotated[AsyncSession, Depends(get_db)],
):
    skill = (
        await db.execute(select(Skill).where(Skill.id == skill_id))
    ).scalar_one_or_none()
    if skill is None:
        raise HTTPException(404)
    await db.delete(skill)
    await db.commit()
    return toast(
        request,
        "success",
        f"Deleted skill {skill.name!r}",
        redirect_to="/skills/",
        refresh=True,
    )


@router.post("/skills/{skill_id}/files/{file_id}/delete/")
async def skill_file_delete(
    request: Request,
    skill_id: int,
    file_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    sf = (
        await db.execute(
            select(SkillFile).where(
                SkillFile.id == file_id, SkillFile.skill_id == skill_id
            )
        )
    ).scalar_one_or_none()
    if sf is None:
        raise HTTPException(404)
    await db.delete(sf)
    await db.commit()
    return toast(
        request,
        "success",
        f"Deleted {sf.path}",
        redirect_to=f"/skills/{skill_id}/",
        refresh=True,
    )
