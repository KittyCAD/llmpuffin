"""AWS Lambda MicroVM runtime for AuditExecution.

Creates and manages MicroVMs via the lambda-microvms boto3 client.
Commands are executed via HTTP against the microvm-agent running
inside the VM.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from types import TracebackType

import boto3
import httpx

from llmpuffin.audit_environment import ExecResult, GitInfo, _capture_git_info

log = logging.getLogger("llmpuffin")

# How long to wait for MicroVM to reach RUNNING state
_POLL_INTERVAL = 2
_POLL_MAX_ATTEMPTS = 150  # 5 minutes


@dataclass
class MicrovmRuntime:
    """AuditExecution backed by an AWS Lambda MicroVM.

    Handles creation, HTTP-based exec, and automatic re-creation
    if the MicroVM disappears.
    """

    image_arn: str
    _code_dir: str
    _client: object  # boto3 lambda-microvms client
    _microvm_id: str = ""
    _endpoint: str = ""
    _auth_token: str = ""
    _region: str = "us-east-1"

    @classmethod
    def start(
        cls,
        image_arn: str,
        code_dir: str,
        region: str = "us-east-1",
        profile: str = "",
        container_id: str | None = None,
    ) -> MicrovmRuntime:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        client = session.client("lambda-microvms", region_name=region)
        rt = cls(
            image_arn=image_arn,
            _code_dir=code_dir,
            _client=client,
            _region=region,
        )

        if container_id:
            log.info("Resuming MicroVM %s", container_id)
            rt._microvm_id = container_id
            try:
                rt._refresh_endpoint()
            except Exception as exc:
                log.warning("Could not resume MicroVM %s: %s — creating new one", container_id, exc)
                rt._create_microvm()
        else:
            rt._create_microvm()

        return rt

    def _create_microvm(self) -> None:
        resp = self._client.run_microvm(
            imageIdentifier=self.image_arn,
            egressNetworkConnectors=[
                f"arn:aws:lambda:{self._region}:aws:network-connector:aws-network-connector:INTERNET_EGRESS"
            ],
            ingressNetworkConnectors=[
                f"arn:aws:lambda:{self._region}:aws:network-connector:aws-network-connector:HTTP_INGRESS"
            ],
            idlePolicy={
                "autoResumeEnabled": False,
                "maxIdleDurationSeconds": 900,
                "suspendedDurationSeconds": 1800,
            },
            maximumDurationInSeconds=14400,  # 4 hours
        )
        self._microvm_id = resp["microvmId"]
        self._endpoint = resp["endpoint"]
        log.info("Created MicroVM %s at %s", self._microvm_id, self._endpoint)
        self._wait_for_running()
        self._refresh_auth_token()

    def _wait_for_running(self) -> None:
        import time

        for _ in range(_POLL_MAX_ATTEMPTS):
            resp = self._client.get_microvm(microvmIdentifier=self._microvm_id)
            state = resp.get("state", "UNKNOWN")
            if state == "RUNNING":
                log.info("MicroVM %s is running", self._microvm_id)
                return
            if state in ("TERMINATED", "FAILED"):
                raise RuntimeError(f"MicroVM {self._microvm_id} entered {state} state")
            time.sleep(_POLL_INTERVAL)
        raise TimeoutError(
            f"MicroVM {self._microvm_id} did not reach RUNNING within {_POLL_INTERVAL * _POLL_MAX_ATTEMPTS}s"
        )

    def _refresh_endpoint(self) -> None:
        resp = self._client.get_microvm(microvmIdentifier=self._microvm_id)
        self._endpoint = resp["endpoint"]
        state = resp.get("state", "UNKNOWN")
        if state == "SUSPENDED":
            log.info("MicroVM %s is suspended, resuming", self._microvm_id)
            self._client.resume_microvm(microvmIdentifier=self._microvm_id)
            self._wait_for_running()
        elif state != "RUNNING":
            raise RuntimeError(f"MicroVM {self._microvm_id} is in {state} state")
        self._refresh_auth_token()

    def _refresh_auth_token(self) -> None:
        resp = self._client.create_microvm_auth_token(
            microvmIdentifier=self._microvm_id,
            expirationInMinutes=60,
            allowedPorts=[{"allPorts": {}}],
        )
        self._auth_token = resp["authToken"]["X-aws-proxy-auth"]

    @property
    def container_id(self) -> str:
        return self._microvm_id

    @property
    def code_dir(self) -> str:
        return self._code_dir

    def __enter__(self) -> MicrovmRuntime:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.stop()

    def exec(self, command: list[str], timeout: int = 300) -> ExecResult:
        """Execute a command inside the MicroVM via the agent HTTP API."""
        url = f"https://{self._endpoint}/exec"

        body = {
            "command": command,
            "workdir": self._code_dir,
            "timeout_secs": timeout,
        }

        try:
            resp = httpx.post(
                url,
                json=body,
                headers={
                    "X-aws-proxy-auth": self._auth_token,
                    "X-aws-proxy-port": "8080",
                },
                timeout=float(timeout + 30),
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                # Token expired, refresh and retry
                self._refresh_auth_token()
                resp = httpx.post(
                    url,
                    json=body,
                    headers={
                        "X-aws-proxy-auth": self._auth_token,
                        "X-aws-proxy-port": "8080",
                    },
                    timeout=float(timeout + 30),
                )
            else:
                raise

        data = resp.json()
        if resp.status_code != 200:
            raise RuntimeError(f"Exec failed: {data}")

        if data.get("timed_out"):
            raise TimeoutError(f"Command timed out after {timeout}s: {command}")

        return ExecResult(
            command=command,
            exit_code=data["exit_code"],
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
        )

    def capture_git_info(self) -> GitInfo | None:
        return _capture_git_info(self)

    def stop(self, timeout: int = 30, remove: bool = False) -> None:
        """Suspend the MicroVM (or terminate if remove=True).

        The idle policy will handle eventual termination.
        """
        if remove:
            try:
                self._client.terminate_microvm(microvmIdentifier=self._microvm_id)
                log.info("Terminated MicroVM %s", self._microvm_id)
            except Exception as exc:
                log.debug("terminate failed: %s", exc)
        else:
            try:
                self._client.suspend_microvm(microvmIdentifier=self._microvm_id)
                log.info("Suspended MicroVM %s", self._microvm_id)
            except Exception as exc:
                log.debug("suspend failed: %s", exc)
