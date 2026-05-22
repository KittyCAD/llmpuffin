"""OIDC authentication for llmpuffin.

Uses authlib to handle the OAuth2/OIDC authorization code flow.
Session data is stored in Starlette's signed cookie session.

When auth is disabled (default), all requests pass through as an
anonymous admin user.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from llmpuffin.config import AuthConfig

log = logging.getLogger("llmpuffin")

router = APIRouter()
_oauth = OAuth()
_auth_config: AuthConfig | None = None


@dataclass
class User:
    sub: str
    name: str
    email: str
    role: str  # "admin", "auditor", "viewer"

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_auditor(self) -> bool:
        return self.role in ("admin", "auditor")


ANONYMOUS_ADMIN = User(sub="anonymous", name="Anonymous", email="", role="admin")


def setup_auth(app, config: AuthConfig, secret_key: str) -> None:
    """Configure OIDC auth on the FastAPI app. Must be called before app starts."""
    global _auth_config
    _auth_config = config

    app.add_middleware(SessionMiddleware, secret_key=secret_key)

    if not config.configured:
        log.info("Auth disabled — all users are anonymous admins")
        return

    _oauth.register(
        name="oidc",
        client_id=config.client_id,
        client_secret=config.client_secret,
        server_metadata_url=f"{config.provider_url.rstrip('/')}/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email"},
    )
    app.include_router(router, prefix="/auth")

    log.info("Auth enabled — OIDC provider: %s", config.provider_url)


def get_current_user(request: Request) -> User | None:
    """Read the current user from the session. Returns None if not logged in."""
    if not _auth_config or not _auth_config.configured:
        return ANONYMOUS_ADMIN
    user_data = request.session.get("user")
    if not user_data:
        return None
    return User(**user_data)


def _resolve_role(groups: list[str], config: AuthConfig) -> str:
    if config.admin_group in groups:
        return "admin"
    if config.auditor_group in groups:
        return "auditor"
    return "viewer"


# ── Routes ──


@router.get("/login")
async def login(request: Request):
    redirect_uri = str(request.url_for("auth_callback"))
    return await _oauth.oidc.authorize_redirect(request, redirect_uri)


@router.get("/callback")
async def auth_callback(request: Request):
    token = await _oauth.oidc.authorize_access_token(request)
    userinfo = token.get("userinfo") or {}

    groups = userinfo.get(_auth_config.groups_claim, [])
    if isinstance(groups, str):
        groups = [groups]

    role = _resolve_role(groups, _auth_config)

    request.session["user"] = {
        "sub": userinfo.get("sub", ""),
        "name": userinfo.get("name", ""),
        "email": userinfo.get("email", ""),
        "role": role,
    }

    log.info("User logged in: %s (%s)", userinfo.get("name"), role)
    return RedirectResponse("/")


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")
