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
from llmpuffin.services.finding import FindingService
from llmpuffin.github import GitHubClient
from llmpuffin.agent.harness import Harness
from llmpuffin.services.profile import ProfileService
from llmpuffin.services.project import ProjectService
from llmpuffin.services.run import RunService
from llmpuffin.services.skill import SkillService
from llmpuffin.services.threat_model import ThreatModelService

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
        via ?level=... query carried by the reload? — no, easier: store in
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


def get_finding_service(request: Request) -> FindingService:
    return request.app.state.finding_service


def get_project_service(request: Request) -> ProjectService:
    return request.app.state.project_service


def get_profile_service(request: Request) -> ProfileService:
    return request.app.state.profile_service


def get_run_service(request: Request) -> RunService:
    return request.app.state.run_service


def get_skill_service(request: Request) -> SkillService:
    return request.app.state.skill_service


def get_threat_model_service(request: Request) -> ThreatModelService:
    return request.app.state.threat_model_service


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an AsyncSession."""
    db: DB = request.app.state.db
    async with db.async_session() as s:
        yield s
