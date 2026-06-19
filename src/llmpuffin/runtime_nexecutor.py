"""Nexecutor runtime for AuditExecution.

Talks to a remote nexecutor service via the nexecutor-client SDK.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from types import TracebackType

from nexecutor_client import Client
from nexecutor_client.api.workloads import (
    destroy_workload,
    exec_command,
    run_workload,
    stop_workload,
)
from nexecutor_client.models.create_workload_request import CreateWorkloadRequest
from nexecutor_client.models.exec_request import ExecRequest
from nexecutor_client.models.exec_response import ExecResponse

from llmpuffin.audit_environment import ExecResult, GitInfo, _capture_git_info

log = logging.getLogger("llmpuffin")


@dataclass
class NexecutorEnvironment:
    """A container image ready to be instantiated via nexecutor."""

    image: str
    code_dir: str = "/src"
    base_url: str = ""

    def start(self, container_id: str | None = None) -> NexecutorExecution:
        """Create and start a workload, or resume an existing one."""
        base_url = self.base_url
        client = Client(base_url=base_url, timeout=3000.0)

        if container_id:
            log.info("Resuming nexecutor workload %s", container_id[:12])
            return NexecutorExecution(
                _workload_id=container_id,
                _client=client,
                _code_dir=self.code_dir,
            )

        resp = run_workload.sync(
            client=client,
            body=CreateWorkloadRequest(
                image=self.image,
                command=["sleep", "infinity"],
            ),
        )
        if resp is None or not hasattr(resp, "id"):
            raise RuntimeError(f"Failed to create nexecutor workload: {resp}")

        workload_id = resp.id
        log.info("Created nexecutor workload %s", workload_id[:12])

        return NexecutorExecution(
            _workload_id=workload_id,
            _client=client,
            _code_dir=self.code_dir,
        )


@dataclass
class NexecutorExecution:
    """AuditExecution backed by a nexecutor workload."""

    _workload_id: str
    _client: Client
    _code_dir: str

    @property
    def container_id(self) -> str:
        return self._workload_id

    @property
    def code_dir(self) -> str:
        return self._code_dir

    def __enter__(self) -> NexecutorExecution:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.stop()

    def exec(self, command: list[str], timeout: int = 300) -> ExecResult:
        """Execute a command inside the workload."""
        client = self._client.with_timeout(timeout=float(timeout + 10))
        resp = exec_command.sync(
            id=self._workload_id,
            client=client,
            body=ExecRequest(
                command=command,
                workdir=self._code_dir,
                timeout_secs=timeout,
            ),
        )

        if resp is None or not isinstance(resp, ExecResponse):
            raise RuntimeError(f"Exec failed: {resp}")

        if resp.timed_out:
            raise TimeoutError(
                f"Command timed out after {timeout}s: {command}"
            )

        return ExecResult(
            command=command,
            exit_code=resp.exit_code,
            stdout=resp.stdout,
            stderr=resp.stderr,
        )

    def capture_git_info(self) -> GitInfo:
        return _capture_git_info(self)

    def stop(self, timeout: int = 30, remove: bool = False) -> None:
        """Stop the workload."""
        try:
            stop_workload.sync(id=self._workload_id, client=self._client)
        except Exception as exc:
            log.debug("stop failed (workload may already be stopped): %s", exc)

        if remove:
            try:
                destroy_workload.sync(id=self._workload_id, client=self._client)
            except Exception as exc:
                log.debug("destroy failed: %s", exc)


