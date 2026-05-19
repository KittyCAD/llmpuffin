"""Langgraph store browse routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from llmpuffin_fastapi.store import list_items, list_namespaces
from llmpuffin_fastapi.templates_env import templates

router = APIRouter()


@router.get("/store/", response_class=HTMLResponse)
async def store_list(request: Request):
    namespaces = await list_namespaces()
    return templates.TemplateResponse(
        request, "store_list.html", {"namespaces": namespaces}
    )


@router.get("/store/{prefix:path}/", response_class=HTMLResponse)
async def store_namespace(prefix: str, request: Request):
    items = await list_items(prefix)
    return templates.TemplateResponse(
        request, "store_namespace.html", {"prefix": prefix, "items": items}
    )
