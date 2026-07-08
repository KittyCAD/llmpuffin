"""Threat model management routes."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from llmpuffin.threat_model_service import ThreatModelService
from llmpuffin_fastapi.deps import get_threat_model_service, toast
from llmpuffin_fastapi.templates_env import templates

router = APIRouter()


@router.get("/threat-models/", response_class=HTMLResponse)
async def threat_models_list(
    request: Request,
    svc: Annotated[ThreatModelService, Depends(get_threat_model_service)],
):
    rows = await svc.list_all()
    return templates.TemplateResponse(
        request, "threat_models_list.html", {"threat_models": rows}
    )


@router.get("/threat-models/{tm_id}/", response_class=HTMLResponse)
async def threat_model_detail(
    request: Request,
    tm_id: int,
    svc: Annotated[ThreatModelService, Depends(get_threat_model_service)],
):
    tm = await svc.get(tm_id)
    if tm is None:
        raise HTTPException(404)
    return templates.TemplateResponse(
        request, "threat_model_detail.html", {"threat_model": tm}
    )


@router.get("/threat-models/{tm_id}/files/{file_id}/")
async def threat_model_file_content(
    tm_id: int,
    file_id: int,
    svc: Annotated[ThreatModelService, Depends(get_threat_model_service)],
):
    tmf = await svc.get_file(tm_id, file_id)
    if tmf is None:
        raise HTTPException(404)
    return JSONResponse({"id": tmf.id, "path": tmf.path, "content": tmf.content})


@router.post("/threat-models/create/")
async def threat_model_create(
    request: Request,
    svc: Annotated[ThreatModelService, Depends(get_threat_model_service)],
    name: str = Form(...),
    description: str = Form(""),
):
    tm = await svc.create(name, description)
    if tm is None:
        return toast(
            request,
            "error",
            f"Threat model {name!r} already exists",
            redirect_to="/threat-models/",
        )
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
    svc: Annotated[ThreatModelService, Depends(get_threat_model_service)],
    path: str = Form(...),
    content: str = Form(...),
):
    tm = await svc.get(tm_id)
    if tm is None:
        raise HTTPException(404)
    await svc.upsert_file(tm_id, path, content)
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
    svc: Annotated[ThreatModelService, Depends(get_threat_model_service)],
    directory: str = Form(...),
):
    """Import all files from a local directory into a threat model."""
    tm = await svc.get(tm_id)
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

    count = await svc.import_directory(tm_id, dir_path)
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
    svc: Annotated[ThreatModelService, Depends(get_threat_model_service)],
):
    name = await svc.delete(tm_id)
    if name is None:
        raise HTTPException(404)
    return toast(
        request,
        "success",
        f"Deleted threat model {name!r}",
        redirect_to="/threat-models/",
        refresh=True,
    )


@router.post("/threat-models/{tm_id}/files/{file_id}/delete/")
async def threat_model_file_delete(
    request: Request,
    tm_id: int,
    file_id: int,
    svc: Annotated[ThreatModelService, Depends(get_threat_model_service)],
):
    path = await svc.delete_file(tm_id, file_id)
    if path is None:
        raise HTTPException(404)
    return toast(
        request,
        "success",
        f"Deleted {path}",
        redirect_to=f"/threat-models/{tm_id}/",
        refresh=True,
    )
