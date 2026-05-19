"""FastAPI dependencies + background-task registry."""

from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator, Coroutine

from sqlalchemy.ext.asyncio import AsyncSession

from llmpuffin.db import async_session

log = logging.getLogger("llmpuffin")

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
