"""Temporal workflow/activity definitions for audit execution.

Optional backend: when ``[temporal] enabled = true`` in config, audits run
as Temporal workflows on separate worker processes.  When disabled (default),
audits run in-process via ``harness.spawn()`` / ``asyncio.create_task()``.

Usage:
    # Start a worker (separate process):
    uv run python -m llmpuffin.temporal

    # From the web server:
    from llmpuffin.temporal import start_audit
    await start_audit(client, AuditParams(...))
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import timedelta

from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.worker import Worker

log = logging.getLogger("llmpuffin")


async def _run_with_heartbeat(coro) -> object:
    """Run a coroutine in a task while sending Temporal heartbeats.

    If the activity is cancelled, the running task is cancelled too.
    """
    task = asyncio.create_task(coro)
    try:
        while not task.done():
            await asyncio.sleep(10)
            activity.heartbeat()
        return task.result()
    except asyncio.CancelledError:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        raise


# ── Serializable dataclasses ──


@dataclass
class AuditParams:
    profile_toml: str
    thread_id: str | None = None
    user_message: str | None = None
    profile_id: int | None = None
    audit_run_id: int | None = None


@dataclass
class ForkParams:
    profile_toml: str
    source_thread_id: str
    new_thread_id: str
    user_message: str
    profile_id: int | None = None
    audit_run_id: int | None = None


@dataclass
class AuditResultData:
    finding_count: int
    status: str
    error: str | None
    thread_id: str
    audit_run_id: int


# ── Activities ──


@activity.defn
async def run_audit_activity(params: AuditParams) -> AuditResultData:
    from llmpuffin.agent import run_audit
    from llmpuffin.config import Config, Profile
    from llmpuffin.db import DB
    from llmpuffin.github import client_from_config
    from llmpuffin.harness import HarnessConfig

    config = Config.load()
    db = DB(config.postgres)
    await db.setup()

    profile = Profile.from_toml_string(params.profile_toml)
    harness_config = HarnessConfig(profile=profile, profile_toml=params.profile_toml)
    gh = client_from_config(config.github)

    result = await _run_with_heartbeat(
        run_audit(
            harness_config,
            db=db,
            global_config=config,
            thread_id=params.thread_id,
            user_message=params.user_message,
            github_client=gh,
            profile_id=params.profile_id,
            audit_run_id=params.audit_run_id,
        )
    )

    return AuditResultData(
        finding_count=result.finding_count,
        status=result.status.value,
        error=result.error,
        thread_id=result.thread_id,
        audit_run_id=result.audit_run_id,
    )


@activity.defn
async def fork_audit_activity(params: ForkParams) -> AuditResultData:
    from llmpuffin.agent import fork_audit
    from llmpuffin.config import Config, Profile
    from llmpuffin.db import DB
    from llmpuffin.github import client_from_config
    from llmpuffin.harness import HarnessConfig

    config = Config.load()
    db = DB(config.postgres)
    await db.setup()

    profile = Profile.from_toml_string(params.profile_toml)
    harness_config = HarnessConfig(profile=profile, profile_toml=params.profile_toml)
    gh = client_from_config(config.github)

    result = await _run_with_heartbeat(
        fork_audit(
            harness_config,
            source_thread_id=params.source_thread_id,
            db=db,
            global_config=config,
            thread_id=params.new_thread_id,
            user_message=params.user_message,
            github_client=gh,
            profile_id=params.profile_id,
            audit_run_id=params.audit_run_id,
        )
    )

    return AuditResultData(
        finding_count=result.finding_count,
        status=result.status.value,
        error=result.error,
        thread_id=result.thread_id,
        audit_run_id=result.audit_run_id,
    )


# ── Workflows ──


@workflow.defn
class AuditWorkflow:
    @workflow.run
    async def run(self, params: AuditParams) -> AuditResultData:
        return await workflow.execute_activity(
            run_audit_activity,
            params,
            start_to_close_timeout=timedelta(hours=8),
            heartbeat_timeout=timedelta(minutes=5),
        )


@workflow.defn
class ForkWorkflow:
    @workflow.run
    async def run(self, params: ForkParams) -> AuditResultData:
        return await workflow.execute_activity(
            fork_audit_activity,
            params,
            start_to_close_timeout=timedelta(hours=8),
            heartbeat_timeout=timedelta(minutes=5),
        )


# ── Client helpers ──


async def connect(url: str = "localhost:7233", namespace: str = "default") -> Client:
    return await Client.connect(url, namespace=namespace)


async def start_audit(
    client: Client,
    params: AuditParams,
    *,
    task_queue: str = "llmpuffin-audits",
) -> str:
    handle = await client.start_workflow(
        AuditWorkflow.run,
        params,
        id=f"audit-{params.thread_id or 'new'}",
        task_queue=task_queue,
    )
    return handle.id


async def start_fork(
    client: Client,
    params: ForkParams,
    *,
    task_queue: str = "llmpuffin-audits",
) -> str:
    handle = await client.start_workflow(
        ForkWorkflow.run,
        params,
        id=f"fork-{params.new_thread_id}",
        task_queue=task_queue,
    )
    return handle.id


async def cancel_workflow(client: Client, workflow_id: str) -> None:
    handle = client.get_workflow_handle(workflow_id)
    await handle.cancel()


# ── Worker entrypoint ──


async def run_worker() -> None:
    from llmpuffin.config import Config

    config = Config.load()
    tc = config.temporal

    client = await Client.connect(tc.url, namespace=tc.namespace)
    log.info("Temporal worker connected to %s (ns=%s)", tc.url, tc.namespace)

    worker = Worker(
        client,
        task_queue=tc.task_queue,
        workflows=[AuditWorkflow, ForkWorkflow],
        activities=[run_audit_activity, fork_audit_activity],
    )
    log.info("Starting worker on queue %r", tc.task_queue)
    await worker.run()


def main() -> None:
    """Entrypoint for ``llmpuffin-worker`` script."""
    from llmpuffin.config import Config
    from llmpuffin.log import setup as setup_logging

    config = Config.load()
    setup_logging(level=config.logging.level)
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
