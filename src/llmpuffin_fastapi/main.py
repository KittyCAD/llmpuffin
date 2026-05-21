"""FastAPI app + uvicorn entrypoint for llmpuffin."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from pathlib import Path

from llmpuffin.config import Config
from llmpuffin.db import setup_db
from llmpuffin.log import setup as setup_logging

from llmpuffin.github import client_from_config
from llmpuffin_fastapi.deps import _tasks, set_github_client
from llmpuffin_fastapi.routes import about, checkpoints, findings, profiles, runs
from llmpuffin_fastapi.routes import store as store_routes

log = logging.getLogger("llmpuffin")

# Max seconds to wait for in-flight audits to cancel + finalize on shutdown.
_SHUTDOWN_TIMEOUT = 30.0


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Configure logging here (after uvicorn has installed its own handlers)
    # so the `llmpuffin` logger isn't masked by uvicorn's dictConfig.
    config = Config.load()
    setup_logging(level=config.logging.level)
    log.info("llmpuffin starting on port %s", config.web.port)
    await setup_db()
    set_github_client(client_from_config())

    try:
        yield
    finally:
        if _tasks:
            log.info("Cancelling %d in-flight audit task(s)…", len(_tasks))
            for t in list(_tasks):
                t.cancel()
            try:
                await asyncio.wait_for(
                    asyncio.gather(*_tasks, return_exceptions=True),
                    timeout=_SHUTDOWN_TIMEOUT,
                )
            except asyncio.TimeoutError:
                log.warning(
                    "Audit tasks did not finish within %.0fs of shutdown; %d still pending",
                    _SHUTDOWN_TIMEOUT,
                    len(_tasks),
                )


def create_app() -> FastAPI:
    app = FastAPI(title="llmpuffin", lifespan=_lifespan)
    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    app.include_router(runs.router)
    app.include_router(profiles.router)
    app.include_router(checkpoints.router)
    app.include_router(findings.router)
    app.include_router(store_routes.router)
    app.include_router(about.router)
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
