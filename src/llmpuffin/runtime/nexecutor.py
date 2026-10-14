"""Persistent nexecutor sessions with asynchronous HTTP command receipts."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Literal
from urllib.parse import quote

import httpx
from pydantic import BaseModel

from llmpuffin.audit_environment import ExecResult, GitInfo, _capture_git_info

log = logging.getLogger("llmpuffin")
_POD_IDENTITY_TOKEN_FILE = (
    "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token"
)
_POLL_INTERVAL = 0.5
_HEARTBEAT_INTERVAL = 60.0


class _Session(BaseModel):
    id: str
    observation_incarnation: str
    status: Literal[
        "creating", "starting", "running", "stopping", "stopped", "failed", "deleted"
    ]
    image: str


class _Execution(BaseModel):
    id: str
    session_id: str
    status: Literal["running", "completed", "timed_out", "unknown"]
    exit_code: int | None
    stdout: str
    stderr: str
    output_truncated: bool


def _resolve_token(token: str) -> str:
    path = token or _POD_IDENTITY_TOKEN_FILE
    if os.path.isfile(path):
        with open(path) as source:
            return source.read().strip()
    return token


@dataclass
class NexecutorRuntime:
    image: str
    _code_dir: str
    _base_url: str
    _token_source: str = field(default="", repr=False)
    _session_id: str = ""
    _incarnation: str = ""
    _heartbeat_task: asyncio.Task[None] | None = field(default=None, repr=False)
    _stopped: bool = False
    _stop_acknowledged: bool = False

    @classmethod
    async def start(
        cls,
        image: str,
        code_dir: str,
        base_url: str,
        token: str = "",
        container_id: str | None = None,
        backend: str | None = None,
        session_lifetime_seconds: int = 14400,
    ) -> NexecutorRuntime:
        rt = cls(image, code_dir, base_url.rstrip("/"), token)
        cleanup_on_error = container_id is None
        try:
            if container_id:
                rt._session_id = container_id
                session = _Session.model_validate(
                    await rt._request("GET", rt._session_path)
                )
            else:
                key = uuid.uuid4().hex
                body: dict[str, Any] = {
                    "idempotency_key": key,
                    "image": image,
                    "lifetime_seconds": session_lifetime_seconds,
                }
                if backend:
                    body["backend"] = backend
                session = _Session.model_validate(
                    await rt._submit(
                        "/v1/sessions", body, f"/v1/sessions-by-idempotency-key/{key}"
                    )
                )
                rt._session_id = session.id
            if session.image != image:
                raise RuntimeError("Existing nexecutor session uses a different image")
            cleanup_on_error = True
            rt._incarnation = session.observation_incarnation
            async with asyncio.timeout(300):
                while session.status in {"creating", "starting"}:
                    await asyncio.sleep(_POLL_INTERVAL)
                    session = _Session.model_validate(
                        await rt._request("GET", rt._session_path)
                    )
                    rt._check_session(session)
            rt._check_session(session)
            if session.status != "running":
                raise RuntimeError(
                    f"Nexecutor session {session.id} is {session.status}; its workspace cannot be resumed"
                )
            rt._heartbeat_task = asyncio.create_task(rt._heartbeat())
            return rt
        except BaseException:
            if rt._session_id and cleanup_on_error:
                await rt.astop()
            raise

    @property
    def container_id(self) -> str:
        return self._session_id

    @property
    def code_dir(self) -> str:
        return self._code_dir

    @property
    def _session_path(self) -> str:
        return f"/v1/sessions/{quote(self._session_id, safe='')}"

    def _headers(self) -> dict[str, str]:
        # Read projected tokens on every request to handle rotation during audits.
        token = _resolve_token(self._token_source)
        return {"Authorization": f"Bearer {token}"} if token else {}

    async def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        # Requests are short lived; command runtime never sets the HTTP timeout.
        # Keeping clients scoped here also permits sync context-manager cleanup.
        async with httpx.AsyncClient(timeout=10.0) as client:
            for attempt in range(5 if method == "GET" else 2):
                try:
                    response = await client.request(
                        method,
                        self._base_url + path,
                        headers=self._headers(),
                        json=body,
                    )
                    if response.status_code == 401 and attempt == 0:
                        continue
                    if method == "GET" and response.status_code >= 500 and attempt < 4:
                        await asyncio.sleep(_POLL_INTERVAL)
                        continue
                    response.raise_for_status()
                    return response.json()
                except httpx.TransportError:
                    if method != "GET" or attempt == 4:
                        raise
                    await asyncio.sleep(_POLL_INTERVAL)
        raise RuntimeError("Nexecutor request did not return a response")

    async def _submit(self, path: str, body: dict, recovery_path: str) -> Any:
        try:
            return await self._request("POST", path, body)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code < 500:
                raise
        except (httpx.TransportError, ValueError):
            pass
        # The command may already be executing. Recover its receipt using only
        # GETs; even 404 must never trigger resubmission or a fresh session.
        for attempt in range(5):
            try:
                return await self._request("GET", recovery_path)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 404:
                    raise
            if attempt < 4:
                await asyncio.sleep(_POLL_INTERVAL)
        raise RuntimeError(
            "Nexecutor submission outcome is unknown; refusing to execute it again"
        )

    def _check_session(self, session: _Session) -> None:
        if (
            session.id != self._session_id
            or session.observation_incarnation != self._incarnation
        ):
            raise RuntimeError(
                "Nexecutor session history changed; refusing to reuse an uncertain workspace"
            )

    async def _heartbeat(self) -> None:
        while True:
            await asyncio.sleep(_HEARTBEAT_INTERVAL)
            try:
                session = _Session.model_validate(
                    await self._request("POST", self._session_path + "/keepalive")
                )
                self._check_session(session)
                if session.status != "running":
                    return
            except Exception as exc:
                log.warning("Nexecutor session keepalive failed: %s", exc)

    async def exec(
        self, command: list[str], timeout: int = 300, workdir: str | None = None
    ) -> ExecResult:
        if self._stopped:
            raise RuntimeError("Nexecutor session is stopped")
        if not 1 <= timeout <= 3600:
            raise ValueError(
                "Nexecutor command timeout must be between 1 and 3600 seconds"
            )
        key = uuid.uuid4().hex
        body = {
            "idempotency_key": key,
            "session_incarnation": self._incarnation,
            "command": command,
            "workdir": workdir or self._code_dir,
            "timeout_seconds": timeout,
        }
        try:
            async with asyncio.timeout(timeout + 90):
                result = _Execution.model_validate(
                    await self._submit(
                        self._session_path + "/executions",
                        body,
                        self._session_path + f"/executions-by-idempotency-key/{key}",
                    )
                )
                execution_id = result.id
                while True:
                    if (
                        result.session_id != self._session_id
                        or result.id != execution_id
                    ):
                        raise RuntimeError(
                            "Nexecutor returned a mismatched command receipt"
                        )
                    if result.status != "running":
                        break
                    await asyncio.sleep(_POLL_INTERVAL)
                    result = _Execution.model_validate(
                        await self._request(
                            "GET",
                            self._session_path
                            + f"/executions/{quote(execution_id, safe='')}",
                        )
                    )
                if result.status == "unknown":
                    raise RuntimeError(
                        f"Nexecutor command {execution_id} has an unknown outcome; it will not be retried"
                    )
        except BaseException:
            # Cancellation/ambiguous execution can leave code running. Request
            # termination of the entire session before releasing the audit.
            await self.astop()
            raise
        if result.status == "timed_out":
            raise TimeoutError(f"Nexecutor command timed out after {timeout}s")
        if result.exit_code is None:
            raise RuntimeError("Nexecutor command completed without an exit code")
        if result.output_truncated:
            raise RuntimeError(
                "Nexecutor command output exceeded the capture limit; request smaller output"
            )
        return ExecResult(
            command=command,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    async def capture_git_info(self) -> GitInfo | None:
        return await _capture_git_info(self)

    def __enter__(self) -> NexecutorRuntime:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.stop()

    def _cancel_heartbeat(self) -> None:
        if self._heartbeat_task:
            self._heartbeat_task.cancel()

    async def astop(self) -> None:
        self._cancel_heartbeat()
        if self._stop_acknowledged:
            return
        self._stopped = True
        try:
            await self._request("POST", self._session_path + "/stop")
            self._stop_acknowledged = True
        except Exception as exc:
            log.warning("Nexecutor session stop could not be confirmed: %s", exc)

    def stop(self, timeout: int = 30, remove: bool = False) -> None:
        self._cancel_heartbeat()
        if self._stop_acknowledged:
            return
        self._stopped = True
        try:
            with httpx.Client(timeout=float(timeout)) as client:
                for attempt in range(2):
                    response = client.post(
                        self._base_url + self._session_path + "/stop",
                        headers=self._headers(),
                    )
                    if response.status_code == 401 and attempt == 0:
                        continue
                    response.raise_for_status()
                    self._stop_acknowledged = True
                    break
        except Exception as exc:
            log.warning("Nexecutor session stop could not be confirmed: %s", exc)
