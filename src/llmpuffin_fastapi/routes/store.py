"""Langgraph store browse routes."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from llmpuffin_fastapi.deps import toast
from llmpuffin_fastapi.store import delete_item, list_items, list_namespaces, update_item
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


@router.post("/store/{prefix:path}/edit/")
async def store_item_edit(
    prefix: str,
    request: Request,
    key: Annotated[str, Form()],
    value_json: Annotated[str, Form()],
):
    redirect = f"/store/{prefix}/"
    try:
        value = json.loads(value_json)
    except json.JSONDecodeError as exc:
        return toast(request, "error", f"Invalid JSON: {exc}", redirect_to=redirect)
    if not isinstance(value, dict):
        return toast(
            request, "error", "Value must be a JSON object", redirect_to=redirect
        )
    await update_item(prefix, key, value)
    return toast(
        request, "success", f"Saved {key}", redirect_to=redirect, refresh=True
    )


@router.post("/store/{prefix:path}/delete/")
async def store_item_delete(
    prefix: str,
    request: Request,
    key: Annotated[str, Form()],
):
    await delete_item(prefix, key)
    return toast(
        request,
        "success",
        f"Deleted {key}",
        redirect_to=f"/store/{prefix}/",
        refresh=True,
    )
