"""FastAPI app + uvicorn entrypoint for llmpuffin."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from llmpuffin.config import Config
from llmpuffin.db import setup_db
from llmpuffin.log import setup as setup_logging

from llmpuffin_fastapi.routes import checkpoints, findings, profiles, runs
from llmpuffin_fastapi.routes import store as store_routes

log = logging.getLogger("llmpuffin")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    await setup_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="llmpuffin", lifespan=_lifespan)
    app.include_router(runs.router)
    app.include_router(profiles.router)
    app.include_router(checkpoints.router)
    app.include_router(findings.router)
    app.include_router(store_routes.router)
    return app


app = create_app()


def main() -> None:
    """Run uvicorn on the port configured in llmpuffin.toml."""
    import uvicorn

    config = Config.load()
    setup_logging()
    uvicorn.run(
        "llmpuffin_fastapi.main:app",
        host="0.0.0.0",
        port=config.web.port,
        reload=config.web.debug,
    )


if __name__ == "__main__":
    main()
