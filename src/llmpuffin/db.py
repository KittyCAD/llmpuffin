"""SQLAlchemy engine/session factories and one-time setup for llmpuffin."""

from __future__ import annotations

import logging
import os
from typing import AsyncIterator
from urllib.parse import urlparse, urlunparse

from sqlalchemy import update
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine

log = logging.getLogger("llmpuffin")


def get_postgres_url() -> str:
    """Get the canonical postgresql:// URL from env or config."""
    if url := os.environ.get("LLMPUFFIN_POSTGRES"):
        return url
    from llmpuffin.config import Config

    return Config.load().postgres.url


def _to_async_url(url: str) -> str:
    """Rewrite postgresql:// → postgresql+asyncpg:// for async engine."""
    parts = urlparse(url)
    scheme = parts.scheme
    if "+" not in scheme:
        scheme = f"{scheme}+asyncpg"
    return urlunparse(parts._replace(scheme=scheme))


def _to_sync_url(url: str) -> str:
    """Rewrite postgresql:// → postgresql+psycopg:// for sync engine."""
    parts = urlparse(url)
    scheme = parts.scheme
    if "+" not in scheme:
        scheme = f"{scheme}+psycopg"
    return urlunparse(parts._replace(scheme=scheme))


_async_engine: AsyncEngine | None = None
_async_sessionmaker: async_sessionmaker[AsyncSession] | None = None
_sync_engine = None
_sync_sessionmaker: sessionmaker[Session] | None = None


def get_async_engine() -> AsyncEngine:
    global _async_engine, _async_sessionmaker
    if _async_engine is None:
        url = _to_async_url(get_postgres_url())
        _async_engine = create_async_engine(url, pool_pre_ping=True)
        _async_sessionmaker = async_sessionmaker(
            _async_engine, expire_on_commit=False, class_=AsyncSession
        )
    return _async_engine


def async_session() -> AsyncSession:
    """Create a new AsyncSession. Use as `async with async_session() as s:`."""
    get_async_engine()
    assert _async_sessionmaker is not None
    return _async_sessionmaker()


def get_sync_engine():
    global _sync_engine, _sync_sessionmaker
    if _sync_engine is None:
        url = _to_sync_url(get_postgres_url())
        _sync_engine = create_engine(url, pool_pre_ping=True)
        _sync_sessionmaker = sessionmaker(
            _sync_engine, expire_on_commit=False, class_=Session
        )
    return _sync_engine


def sync_session() -> Session:
    """Create a new sync Session. Use as `with sync_session() as s:`."""
    get_sync_engine()
    assert _sync_sessionmaker is not None
    return _sync_sessionmaker()


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an AsyncSession."""
    async with async_session() as s:
        yield s


async def _abort_orphaned_threads() -> None:
    """Mark any 'running' threads as 'aborted' on startup.

    When the process is killed (SIGKILL, OOM) the finalizer never runs and
    the thread stays running forever.
    """
    from llmpuffin.models import AuditThread

    async with async_session() as s:
        result = await s.execute(
            update(AuditThread)
            .where(AuditThread.status == "running")
            .values(status="aborted", error="Aborted: process restarted")
        )
        await s.commit()
        if result.rowcount:
            log.info(
                "Marked %d orphaned running thread(s) as aborted on startup",
                result.rowcount,
            )


async def _setup_langgraph_tables() -> None:
    """Create langgraph checkpoint/store tables if they don't exist."""
    url = get_postgres_url()
    try:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
        from langgraph.store.postgres.aio import AsyncPostgresStore

        async with AsyncPostgresSaver.from_conn_string(url) as cp:
            await cp.setup()
        async with AsyncPostgresStore.from_conn_string(url) as store:
            await store.setup()
    except Exception as exc:
        log.warning("Could not create langgraph tables: %s", exc)


async def setup_db() -> None:
    """One-time DB setup: orphan cleanup + langgraph table init.

    Schema migrations are managed by Alembic — run `alembic upgrade head`
    before starting the app for the first time.
    """
    get_async_engine()
    # await _abort_orphaned_threads()
    await _setup_langgraph_tables()
