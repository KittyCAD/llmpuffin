"""Project routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

from llmpuffin.services.project import ProjectService
from llmpuffin_fastapi.deps import get_project_service, toast
from llmpuffin_fastapi.templates_env import templates

router = APIRouter()


@router.get("/home/", response_class=HTMLResponse)
async def home(
    request: Request,
    svc: Annotated[ProjectService, Depends(get_project_service)],
):
    stats = await svc.global_stats()
    return templates.TemplateResponse(request, "home.html", {"stats": stats})


@router.get("/projects/", response_class=HTMLResponse)
async def projects_list(
    request: Request,
    svc: Annotated[ProjectService, Depends(get_project_service)],
):
    rows = await svc.list_all()
    projects = [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "profile_count": pc,
            "run_count": rc,
            "updated_at": p.updated_at,
        }
        for p, pc, rc in rows
    ]
    return templates.TemplateResponse(
        request, "projects_list.html", {"projects": projects}
    )


@router.get("/projects/new/", response_class=HTMLResponse)
async def project_new(request: Request):
    return templates.TemplateResponse(request, "project_new.html", {})


@router.post("/projects/create/")
async def project_create(
    request: Request,
    svc: Annotated[ProjectService, Depends(get_project_service)],
    name: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
):
    name = name.strip()
    if not name:
        return toast(
            request, "error", "Name is required", redirect_to="/projects/new/"
        )
    project = await svc.create(name, description.strip())
    return toast(
        request,
        "success",
        f"Created {name}",
        redirect_to=f"/projects/{project.id}/",
        refresh=True,
    )


@router.get("/projects/{project_id}/", response_class=HTMLResponse)
async def project_detail(
    project_id: int,
    request: Request,
    svc: Annotated[ProjectService, Depends(get_project_service)],
):
    project = await svc.get(project_id, with_profiles=True)
    if project is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(
        request,
        "project_detail.html",
        {"project": project, "profiles": project.profiles},
    )


@router.post("/projects/{project_id}/", response_class=HTMLResponse)
async def project_update(
    project_id: int,
    request: Request,
    svc: Annotated[ProjectService, Depends(get_project_service)],
    name: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
):
    redirect = f"/projects/{project_id}/"
    if not name.strip():
        return toast(request, "error", "Name is required", redirect_to=redirect)
    if not await svc.update(project_id, name.strip(), description.strip()):
        raise HTTPException(status_code=404)
    return toast(
        request, "success", "Project saved.", redirect_to=redirect, refresh=True
    )


@router.post("/projects/{project_id}/delete/")
async def project_delete(
    project_id: int,
    request: Request,
    svc: Annotated[ProjectService, Depends(get_project_service)],
):
    error = await svc.delete(project_id)
    if error == "not_found":
        raise HTTPException(status_code=404)
    if error:
        return toast(
            request, "error", error, redirect_to=f"/projects/{project_id}/"
        )
    return toast(
        request,
        "success",
        "Project deleted",
        redirect_to="/projects/",
        refresh=True,
    )
