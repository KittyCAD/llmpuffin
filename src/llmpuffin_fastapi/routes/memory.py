"""LLM memory browser routes."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse

from llmpuffin.db import DB
from llmpuffin_fastapi.deps import get_llmpuffin_db, toast
from llmpuffin_fastapi.memory import (
    delete_all,
    delete_item,
    list_items,
    list_namespaces,
    update_item,
)
from llmpuffin_fastapi.templates_env import templates

router = APIRouter()


@router.get("/memory/", response_class=HTMLResponse)
async def memory_list(
    request: Request, llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)]
):
    namespaces = await list_namespaces(llmpuffin_db.url)
    return templates.TemplateResponse(
        request, "memory_list.html", {"namespaces": namespaces}
    )


@router.get("/memory/{prefix:path}/", response_class=HTMLResponse)
async def memory_namespace(
    prefix: str,
    request: Request,
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
):
    items = await list_items(prefix, llmpuffin_db.url)
    return templates.TemplateResponse(
        request, "memory_namespace.html", {"prefix": prefix, "items": items}
    )


@router.post("/memory/{prefix:path}/edit/")
async def memory_item_edit(
    prefix: str,
    request: Request,
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    key: Annotated[str, Form()],
    value_json: Annotated[str, Form()],
):
    redirect = f"/memory/{prefix}/"
    try:
        value = json.loads(value_json)
    except json.JSONDecodeError as exc:
        return toast(request, "error", f"Invalid JSON: {exc}", redirect_to=redirect)
    if not isinstance(value, dict):
        return toast(
            request, "error", "Value must be a JSON object", redirect_to=redirect
        )
    await update_item(prefix, key, value, llmpuffin_db.url)
    return toast(request, "success", f"Saved {key}", redirect_to=redirect, refresh=True)


@router.post("/memory/{prefix:path}/delete/")
async def memory_item_delete(
    prefix: str,
    request: Request,
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    key: Annotated[str, Form()],
):
    await delete_item(prefix, key, llmpuffin_db.url)
    return toast(
        request,
        "success",
        f"Deleted {key}",
        redirect_to=f"/memory/{prefix}/",
        refresh=True,
    )


@router.post("/memory/clear-all/")
async def memory_clear_all(
    request: Request,
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
):
    count = await delete_all(llmpuffin_db.url)
    return toast(
        request,
        "success",
        f"Deleted {count} item(s) from memory",
        redirect_to="/memory/",
        refresh=True,
    )
