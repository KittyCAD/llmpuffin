"""SQLAlchemy engine/session factories and one-time setup for llmpuffin."""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse, urlunparse

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.store.postgres.aio import AsyncPostgresStore
from sqlalchemy import create_engine, update
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from llmpuffin.config import PostgresConfig
from llmpuffin.models import AuditThread

log = logging.getLogger("llmpuffin")


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


def _async_ssl_args(ca_cert: str) -> dict:
    """Build connect_args for asyncpg (uses ssl.SSLContext)."""
    import ssl

    ctx = ssl.create_default_context(cadata=ca_cert)
    return {"ssl": ctx}


def _sync_ssl_args(ca_cert: str) -> dict:
    """Build connect_args for psycopg (uses sslmode + sslrootcert)."""
    import tempfile

    tmp = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    tmp.write(ca_cert.encode())
    tmp.close()
    return {"sslmode": "verify-full", "sslrootcert": tmp.name}


class DB:
    """Database connection holder — owns both async and sync engines/sessions.

    Create once at startup, then pass through the app to wherever it's needed.
    """

    def __init__(self, postgres: PostgresConfig) -> None:
        self.url = postgres.url
        self._ca_cert = postgres.ca_cert

        async_url = _to_async_url(self.url)
        async_connect = _async_ssl_args(self._ca_cert) if self._ca_cert else {}
        self._async_engine: AsyncEngine = create_async_engine(
            async_url, pool_pre_ping=True, **({"connect_args": async_connect} if async_connect else {})
        )
        self._async_sessionmaker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self._async_engine, expire_on_commit=False, class_=AsyncSession
        )

        sync_url = _to_sync_url(self.url)
        sync_connect = _sync_ssl_args(self._ca_cert) if self._ca_cert else {}
        self._sync_engine = create_engine(
            sync_url, pool_pre_ping=True, **({"connect_args": sync_connect} if sync_connect else {})
        )
        self._sync_sessionmaker: sessionmaker[Session] = sessionmaker(
            self._sync_engine, expire_on_commit=False, class_=Session
        )

    @property
    def async_engine(self) -> AsyncEngine:
        return self._async_engine

    def async_session(self) -> AsyncSession:
        """Create a new AsyncSession. Use as `async with db.async_session() as s:`."""
        return self._async_sessionmaker()

    def sync_session(self) -> Session:
        """Create a new sync Session. Use as `with db.sync_session() as s:`."""
        return self._sync_sessionmaker()

    async def setup(self) -> None:
        """One-time DB setup: langgraph table init.

        Schema migrations are managed by Alembic — run `alembic upgrade head`
        before starting the app for the first time.
        """
        await self._setup_langgraph_tables()

    async def abort_orphaned_threads(self) -> None:
        """Mark any 'running' threads as 'aborted'.

        When the process is killed (SIGKILL, OOM) the finalizer never runs and
        the thread stays running forever.
        """
        async with self.async_session() as s:
            result = await s.execute(
                update(AuditThread)
                .where(AuditThread.status == "running")
                .values(status="aborted", error="Aborted: process restarted")
            )
            await s.commit()
            if result.rowcount:
                log.info(
                    "Marked %d orphaned running thread(s) as aborted",
                    result.rowcount,
                )

    async def _setup_langgraph_tables(self) -> None:
        """Create langgraph checkpoint/store tables if they don't exist."""
        try:
            async with AsyncPostgresSaver.from_conn_string(self.url) as cp:
                await cp.setup()
            async with AsyncPostgresStore.from_conn_string(self.url) as store:
                await store.setup()
        except Exception as exc:
            log.warning("Could not create langgraph tables: %s", exc)
