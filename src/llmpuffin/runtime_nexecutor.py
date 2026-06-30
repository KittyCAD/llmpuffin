"""Nexecutor runtime for AuditExecution.

Talks to a remote nexecutor service via the nexecutor-client SDK.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from types import TracebackType

from nexecutor_client import AuthenticatedClient
from nexecutor_client.api.workloads import (
    destroy_workload,
    exec_command,
    get_workload,
    run_workload,
    stop_workload,
)
from nexecutor_client.models.create_workload_request import CreateWorkloadRequest
from nexecutor_client.models.error import Error
from nexecutor_client.models.exec_request import ExecRequest
from nexecutor_client.models.exec_response import ExecResponse
from nexecutor_client.models.workload_response import WorkloadResponse
from nexecutor_client.models.workload_status import WorkloadStatus

from llmpuffin.audit_environment import ExecResult, GitInfo, _capture_git_info

log = logging.getLogger("llmpuffin")

# AWS Pod Identity / EKS OIDC projected token path.
_POD_IDENTITY_TOKEN_FILE = (
    "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token"
)


def _resolve_token(token: str) -> str:
    """Resolve a token value.

    If token is a file path that exists, read the token from it.
    If empty, try the standard AWS Pod Identity token file.
    Otherwise return the token string as-is.
    """
    if not token:
        if os.path.isfile(_POD_IDENTITY_TOKEN_FILE):
            return open(_POD_IDENTITY_TOKEN_FILE).read().strip()
        return ""
    if os.path.isfile(token):
        return open(token).read().strip()
    return token


def _make_client(base_url: str, token: str) -> AuthenticatedClient:
    """Create an AuthenticatedClient, skipping the auth header if token is empty."""
    if token:
        return AuthenticatedClient(base_url=base_url, token=token, timeout=3000.0)
    return AuthenticatedClient(base_url=base_url, token="", prefix="", timeout=3000.0)


@dataclass
class NexecutorRuntime:
    """AuditExecution backed by a nexecutor workload.

    Handles creation, exec, and automatic re-creation if the workload
    disappears (404 on exec).
    """

    image: str
    _client: AuthenticatedClient
    _code_dir: str
    _workload_id: str = ""
    _token_source: str = ""
    _base_url: str = ""

    @classmethod
    def start(
        cls,
        image: str,
        code_dir: str,
        base_url: str,
        token: str = "",
        container_id: str | None = None,
    ) -> NexecutorRuntime:
        resolved_token = _resolve_token(token)
        client = _make_client(base_url, resolved_token)
        rt = cls(
            image=image,
            _client=client,
            _code_dir=code_dir,
            _token_source=token,
            _base_url=base_url,
        )

        if container_id:
            log.info("Resuming nexecutor workload %s", container_id[:12])
            rt._workload_id = container_id
        else:
            rt._create_workload()

        return rt

    def _create_workload(self) -> None:
        resp = run_workload.sync(
            client=self._client,
            body=CreateWorkloadRequest(
                image=self.image,
                command=["sleep", "infinity"],
            ),
        )
        if resp is None or not hasattr(resp, "id"):
            raise RuntimeError(f"Failed to create nexecutor workload: {resp}")
        self._workload_id = resp.id
        log.info("Created nexecutor workload %s", self._workload_id[:12])
        self._wait_until_running()

    def _wait_until_running(
        self, poll_interval: float = 1.0, timeout: float = 120.0
    ) -> None:
        """Poll until the workload reaches 'running' status."""
        deadline = time.monotonic() + timeout
        while True:
            resp = get_workload.sync(id=self._workload_id, client=self._client)
            if isinstance(resp, WorkloadResponse):
                if resp.status == WorkloadStatus.RUNNING:
                    log.info("Workload %s is running", self._workload_id[:12])
                    return
                if resp.status == WorkloadStatus.FAILED:
                    raise RuntimeError(
                        f"Workload {self._workload_id[:12]} failed to start"
                    )
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Workload {self._workload_id[:12]} not running after {timeout}s"
                )
            time.sleep(poll_interval)

    @property
    def container_id(self) -> str:
        return self._workload_id

    @property
    def code_dir(self) -> str:
        return self._code_dir

    def _refresh_client(self) -> None:
        """Re-read the token (handles rotation) and rebuild the client."""
        token = _resolve_token(self._token_source)
        self._client = _make_client(self._base_url, token)
        log.info("Refreshed nexecutor auth token")

    def __enter__(self) -> NexecutorRuntime:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.stop()

    def exec(self, command: list[str], timeout: int = 300) -> ExecResult:
        """Execute a command inside the workload.

        If the workload has disappeared (404), re-creates it and retries once.
        """
        body = ExecRequest(
            command=command,
            workdir=self._code_dir,
            timeout_secs=timeout,
        )
        log.debug("nexecutor exec: %s", body.to_dict())
        client = self._client.with_timeout(timeout=float(timeout + 10))

        resp = exec_command.sync(
            id=self._workload_id,
            client=client,
            body=body,
        )

        # Auth error — refresh token and retry once.
        if isinstance(resp, Error) and (
            "unauthorized" in resp.message.lower()
            or "forbidden" in resp.message.lower()
        ):
            log.warning("Auth error, refreshing token and retrying")
            self._refresh_client()
            client = self._client.with_timeout(timeout=float(timeout + 10))
            resp = exec_command.sync(id=self._workload_id, client=client, body=body)

        # Workload gone — recreate and retry once.
        if isinstance(resp, Error) and "not found" in resp.message.lower():
            log.warning("Workload %s gone, recreating", self._workload_id[:12])
            self._create_workload()
            resp = exec_command.sync(id=self._workload_id, client=client, body=body)

        if resp is None or not isinstance(resp, ExecResponse):
            raise RuntimeError(f"Exec failed: {resp}")

        if resp.timed_out:
            raise TimeoutError(f"Command timed out after {timeout}s: {command}")

        return ExecResult(
            command=command,
            exit_code=resp.exit_code,
            stdout=resp.stdout,
            stderr=resp.stderr,
        )

    def capture_git_info(self) -> GitInfo | None:
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
