"""FastAPI dependencies + background-task registry."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncIterator, Coroutine
from urllib.parse import quote

from fastapi import Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from llmpuffin.db import async_session
from llmpuffin.github import GitHubClient

log = logging.getLogger("llmpuffin")

# Initialized once during app lifespan, used via get_github_client dependency.
_github_client: GitHubClient | None = None


def set_github_client(client: GitHubClient) -> None:
    global _github_client
    _github_client = client


def get_github_client() -> GitHubClient | None:
    return _github_client


def is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


def toast(
    request: Request,
    level: str,
    message: str,
    *,
    redirect_to: str,
    refresh: bool = False,
) -> Response:
    """Return a toast notification.

    For HTMX requests:
      - Always sends HX-Trigger with the toast event.
      - If refresh=True, also sends HX-Refresh so the page reloads (toast survives
        via ?level=… query carried by the reload? — no, easier: store in
        sessionStorage on the toast event handler so it persists across reload).
        Simpler: use HX-Location to navigate to redirect_to with the toast query.
      - Otherwise just 204 (caller's page stays as-is).
    For plain requests: 303 redirect to `redirect_to` with ?level=message query.
    """
    payload = json.dumps({"toast": {"level": level, "message": message}})
    if is_htmx(request):
        headers = {"HX-Trigger": payload}
        if refresh:
            headers["HX-Location"] = redirect_to
        return Response(status_code=204, headers=headers)
    sep = "&" if "?" in redirect_to else "?"
    return RedirectResponse(
        f"{redirect_to}{sep}{level}={quote(message)}", status_code=303
    )

# Strong references to in-flight audit tasks so they aren't GC'd.
_tasks: set[asyncio.Task] = set()


def spawn_audit(coro: Coroutine) -> asyncio.Task:
    """Schedule a fire-and-forget audit coroutine on the running loop."""
    task = asyncio.create_task(coro)
    _tasks.add(task)

    def _done(t: asyncio.Task) -> None:
        _tasks.discard(t)
        if not t.cancelled():
            exc = t.exception()
            if exc is not None:
                log.exception(
                    "Background audit task failed",
                    exc_info=(type(exc), exc, exc.__traceback__),
                )

    task.add_done_callback(_done)
    return task


async def get_db() -> AsyncIterator[AsyncSession]:
    async with async_session() as s:
        yield s
