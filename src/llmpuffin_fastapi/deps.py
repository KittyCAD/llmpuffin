"""FastAPI dependencies."""

from __future__ import annotations

import json
import logging
from typing import AsyncIterator
from urllib.parse import quote

from fastapi import Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from llmpuffin.config import Config
from llmpuffin.db import DB
from llmpuffin.github import GitHubClient
from llmpuffin.harness import Harness

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


def get_base_url(request: Request) -> str:
    """Return the configured external base URL, or empty string if not set."""
    config: Config = request.app.state.config
    return config.web.base_url.rstrip("/")


def get_config(request: Request) -> Config:
    """FastAPI dependency returning the Config instance from app state."""
    return request.app.state.config


def get_harness(request: Request) -> Harness:
    """FastAPI dependency returning the Harness instance from app state."""
    return request.app.state.harness


def get_llmpuffin_db(request: Request) -> DB:
    """FastAPI dependency returning the DB instance from app state."""
    return request.app.state.db


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an AsyncSession."""
    db: DB = request.app.state.db
    async with db.async_session() as s:
        yield s


def dispatch_audit(
    request: Request,
    thread_id: str,
    profile_toml: str,
    coro,
    *,
    user_message: str | None = None,
    profile_id: int | None = None,
    audit_run_id: int | None = None,
) -> None:
    """Dispatch an audit via Temporal (if enabled) or in-process spawn."""
    temporal_client = request.app.state.temporal_client
    if temporal_client is not None:
        import asyncio

        from llmpuffin.temporal import AuditParams, start_audit

        # Close the unused coroutine to avoid warnings.
        coro.close()
        config: Config = request.app.state.config
        asyncio.ensure_future(
            start_audit(
                temporal_client,
                AuditParams(
                    profile_toml=profile_toml,
                    thread_id=thread_id,
                    user_message=user_message,
                    profile_id=profile_id,
                    audit_run_id=audit_run_id,
                ),
                task_queue=config.temporal.task_queue,
            )
        )
    else:
        harness: Harness = request.app.state.harness
        harness.spawn(thread_id, coro)


async def dispatch_cancel(request: Request, thread_id: str) -> bool:
    """Cancel a running audit via Temporal or in-process. Returns True if found."""
    temporal_client = request.app.state.temporal_client
    if temporal_client is not None:
        from llmpuffin.temporal import cancel_workflow

        try:
            await cancel_workflow(temporal_client, f"audit-{thread_id}")
            return True
        except Exception:
            try:
                await cancel_workflow(temporal_client, f"fork-{thread_id}")
                return True
            except Exception:
                return False
    else:
        harness: Harness = request.app.state.harness
        return harness.cancel(thread_id)


def dispatch_fork(
    request: Request,
    new_thread_id: str,
    profile_toml: str,
    coro,
    *,
    source_thread_id: str,
    user_message: str,
    profile_id: int | None = None,
    audit_run_id: int | None = None,
) -> None:
    """Dispatch a fork via Temporal (if enabled) or in-process spawn."""
    temporal_client = request.app.state.temporal_client
    if temporal_client is not None:
        import asyncio

        from llmpuffin.temporal import ForkParams, start_fork

        coro.close()
        config: Config = request.app.state.config
        asyncio.ensure_future(
            start_fork(
                temporal_client,
                ForkParams(
                    profile_toml=profile_toml,
                    source_thread_id=source_thread_id,
                    new_thread_id=new_thread_id,
                    user_message=user_message,
                    profile_id=profile_id,
                    audit_run_id=audit_run_id,
                ),
                task_queue=config.temporal.task_queue,
            )
        )
    else:
        harness: Harness = request.app.state.harness
        harness.spawn(new_thread_id, coro)
