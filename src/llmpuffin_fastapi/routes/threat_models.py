"""Threat model management routes."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from llmpuffin.models import ThreatModelDB, ThreatModelFile
from llmpuffin_fastapi.deps import get_db, toast
from llmpuffin_fastapi.templates_env import templates

log = logging.getLogger("llmpuffin")
router = APIRouter()


@router.get("/threat-models/", response_class=HTMLResponse)
async def threat_models_list(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    rows = (
        (
            await db.execute(
                select(ThreatModelDB)
                .options(selectinload(ThreatModelDB.files))
                .order_by(ThreatModelDB.name)
            )
        )
        .scalars()
        .all()
    )
    return templates.TemplateResponse(
        request, "threat_models_list.html", {"threat_models": rows}
    )


@router.get("/threat-models/{tm_id}/", response_class=HTMLResponse)
async def threat_model_detail(
    request: Request,
    tm_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    tm = (
        await db.execute(
            select(ThreatModelDB)
            .options(selectinload(ThreatModelDB.files))
            .where(ThreatModelDB.id == tm_id)
        )
    ).scalar_one_or_none()
    if tm is None:
        raise HTTPException(404)
    return templates.TemplateResponse(
        request, "threat_model_detail.html", {"threat_model": tm}
    )


@router.post("/threat-models/create/")
async def threat_model_create(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    name: str = Form(...),
    description: str = Form(""),
):
    existing = (
        await db.execute(select(ThreatModelDB).where(ThreatModelDB.name == name))
    ).scalar_one_or_none()
    if existing:
        return toast(
            request,
            "error",
            f"Threat model {name!r} already exists",
            redirect_to="/threat-models/",
        )

    tm = ThreatModelDB(name=name, description=description)
    db.add(tm)
    await db.commit()
    return toast(
        request,
        "success",
        f"Created threat model {name!r}",
        redirect_to="/threat-models/",
        refresh=True,
    )


@router.post("/threat-models/{tm_id}/upload/")
async def threat_model_upload_file(
    request: Request,
    tm_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    path: str = Form(...),
    content: str = Form(...),
):
    tm = (
        await db.execute(select(ThreatModelDB).where(ThreatModelDB.id == tm_id))
    ).scalar_one_or_none()
    if tm is None:
        raise HTTPException(404)

    existing = (
        await db.execute(
            select(ThreatModelFile).where(
                ThreatModelFile.threat_model_id == tm_id,
                ThreatModelFile.path == path,
            )
        )
    ).scalar_one_or_none()
    if existing:
        existing.content = content
    else:
        db.add(ThreatModelFile(threat_model_id=tm_id, path=path, content=content))
    await db.commit()
    return toast(
        request,
        "success",
        f"Saved {path}",
        redirect_to=f"/threat-models/{tm_id}/",
        refresh=True,
    )


@router.post("/threat-models/{tm_id}/import/")
async def threat_model_import_directory(
    request: Request,
    tm_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    directory: str = Form(...),
):
    """Import all files from a local directory into a threat model."""
    tm = (
        await db.execute(select(ThreatModelDB).where(ThreatModelDB.id == tm_id))
    ).scalar_one_or_none()
    if tm is None:
        raise HTTPException(404)

    dir_path = Path(directory)
    if not dir_path.is_dir():
        return toast(
            request,
            "error",
            f"Directory not found: {directory}",
            redirect_to=f"/threat-models/{tm_id}/",
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
                select(ThreatModelFile).where(
                    ThreatModelFile.threat_model_id == tm_id,
                    ThreatModelFile.path == rel,
                )
            )
        ).scalar_one_or_none()
        if existing:
            existing.content = content
        else:
            db.add(ThreatModelFile(threat_model_id=tm_id, path=rel, content=content))
        count += 1

    await db.commit()
    return toast(
        request,
        "success",
        f"Imported {count} file(s)",
        redirect_to=f"/threat-models/{tm_id}/",
        refresh=True,
    )


@router.post("/threat-models/{tm_id}/delete/")
async def threat_model_delete(
    request: Request,
    tm_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    tm = (
        await db.execute(select(ThreatModelDB).where(ThreatModelDB.id == tm_id))
    ).scalar_one_or_none()
    if tm is None:
        raise HTTPException(404)
    await db.delete(tm)
    await db.commit()
    return toast(
        request,
        "success",
        f"Deleted threat model {tm.name!r}",
        redirect_to="/threat-models/",
        refresh=True,
    )


@router.post("/threat-models/{tm_id}/files/{file_id}/delete/")
async def threat_model_file_delete(
    request: Request,
    tm_id: int,
    file_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    tmf = (
        await db.execute(
            select(ThreatModelFile).where(
                ThreatModelFile.id == file_id,
                ThreatModelFile.threat_model_id == tm_id,
            )
        )
    ).scalar_one_or_none()
    if tmf is None:
        raise HTTPException(404)
    await db.delete(tmf)
    await db.commit()
    return toast(
        request,
        "success",
        f"Deleted {tmf.path}",
        redirect_to=f"/threat-models/{tm_id}/",
        refresh=True,
    )
