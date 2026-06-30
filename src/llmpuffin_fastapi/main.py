"""FastAPI app + uvicorn entrypoint for llmpuffin."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from llmpuffin.config import Config
from llmpuffin.db import DB
from llmpuffin.github import client_from_config
from llmpuffin.harness import Harness
from llmpuffin.log import setup as setup_logging

from llmpuffin_fastapi.auth import get_current_user, setup_auth
from llmpuffin_fastapi.deps import set_github_client
from llmpuffin_fastapi.routes import (
    about,
    checkpoints,
    findings,
    profiles,
    runs,
    skills,
    threat_models,
)
from llmpuffin_fastapi.routes import store as store_routes

log = logging.getLogger("llmpuffin")

_SHUTDOWN_TIMEOUT = 30.0

# Paths that don't require authentication.
_PUBLIC_PATHS = frozenset({"/auth/login", "/auth/callback", "/auth/logout", "/healthz"})


@asynccontextmanager
async def _lifespan(app: FastAPI):
    config: Config = app.state.config
    setup_logging(level=config.logging.level)
    log.info("llmpuffin starting on port %s", config.web.port)
    await app.state.db.setup()
    set_github_client(client_from_config(config.github))

    try:
        yield
    finally:
        await app.state.harness.cancel_all(timeout=_SHUTDOWN_TIMEOUT)


def create_app() -> FastAPI:
    config = Config.load()
    app = FastAPI(title="llmpuffin", lifespan=_lifespan)
    app.state.config = config
    app.state.db = DB(config.postgres)
    # Shared harness for task tracking. Individual audits create their own
    # Harness instances for config/threat-model, but this one owns the
    # task registry so we can cancel running audits from the web UI.
    app.state.harness = Harness(global_config=config)
    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    app.include_router(runs.router)
    app.include_router(profiles.router)
    app.include_router(checkpoints.router)
    app.include_router(findings.router)
    app.include_router(skills.router)
    app.include_router(threat_models.router)
    app.include_router(store_routes.router)
    app.include_router(about.router)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    # Auth middleware checks session — must be added BEFORE SessionMiddleware
    # (Starlette middleware is LIFO: last added = outermost).
    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        path = request.url.path
        if path.startswith("/static") or path in _PUBLIC_PATHS:
            return await call_next(request)

        user = get_current_user(request)
        if user is None:
            return RedirectResponse("/auth/login")

        request.state.user = user
        return await call_next(request)

    # setup_auth adds SessionMiddleware (outermost) + registers OIDC routes.
    setup_auth(app, config.auth, secret_key=config.web.secret_key)

    return app


app = create_app()


def main() -> None:
    """Run uvicorn on the port configured in llmpuffin.toml."""
    config = Config.load()
    uvicorn.run(
        "llmpuffin_fastapi.main:app",
        host="0.0.0.0",
        port=config.web.port,
        reload=config.web.debug,
    )


if __name__ == "__main__":
    main()
