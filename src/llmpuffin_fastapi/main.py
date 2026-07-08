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
from llmpuffin.services.finding import FindingService
from llmpuffin.github import client_from_config
from llmpuffin.agent.harness import Harness
from llmpuffin.log import setup as setup_logging
from llmpuffin.services.profile import ProfileService
from llmpuffin.services.run import RunService
from llmpuffin.services.skill import SkillService
from llmpuffin.services.threat_model import ThreatModelService

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
from llmpuffin_fastapi.routes import memory as memory_routes

log = logging.getLogger("llmpuffin")

# Paths that don't require authentication.
_PUBLIC_PATHS = frozenset({"/auth/login", "/auth/callback", "/auth/logout", "/healthz"})


@asynccontextmanager
async def _lifespan(app: FastAPI):
    config: Config = app.state.config
    setup_logging(level=config.logging.level)
    log.info("llmpuffin starting on port %s", config.web.port)
    await app.state.db.setup()
    set_github_client(client_from_config(config.github))

    if config.backfill_embeddings:
        try:
            from llmpuffin.services.embeddings import backfill_embeddings

            log.info("Backfilling finding embeddings...")
            count = await backfill_embeddings(db=app.state.db)
            log.info("Embedding backfill complete: %d finding(s)", count)
        except Exception:
            log.warning("Embedding backfill failed", exc_info=True)

    try:
        yield
    finally:
        harness: Harness = app.state.harness
        running = harness.running_threads
        if running and config.web.wait_on_shutdown:
            log.info("Waiting for %d audit(s) to finish...", len(running))
            await harness.wait_all()
            log.info("All audits finished")
        else:
            await harness.cancel_all()


def create_app() -> FastAPI:
    config = Config.load()
    app = FastAPI(title="llmpuffin", lifespan=_lifespan)
    app.state.config = config
    app.state.db = DB(config.postgres)
    app.state.finding_service = FindingService(app.state.db)
    app.state.profile_service = ProfileService(app.state.db)
    app.state.run_service = RunService(app.state.db)
    app.state.skill_service = SkillService(app.state.db)
    app.state.threat_model_service = ThreatModelService(app.state.db)
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
    app.include_router(memory_routes.router)
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
