"""About page."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from llmpuffin_fastapi.templates_env import templates

router = APIRouter()


@router.get("/about/", response_class=HTMLResponse)
async def about(request: Request):
    return templates.TemplateResponse(request, "about.html", {})
