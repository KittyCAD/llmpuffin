"""Podman/Docker runtime for AuditExecution.

Talks to the Podman daemon via its Docker-compatible API using docker-py.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

import docker
from docker.models.containers import Container

from llmpuffin.audit_environment import ExecResult, GitInfo, _capture_git_info

log = logging.getLogger("llmpuffin")


def _get_podman_socket() -> str | None:
    """Discover the Podman API socket path."""
    import subprocess

    env_host = os.environ.get("DOCKER_HOST")
    if env_host:
        return env_host

    try:
        result = subprocess.run(
            [
                "podman",
                "machine",
                "inspect",
                "--format",
                "{{.ConnectionInfo.PodmanSocket.Path}}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        sock = result.stdout.strip()
        if result.returncode == 0 and sock and Path(sock).exists():
            return f"unix://{sock}"
    except Exception:
        pass

    return None


@dataclass
class PodmanEnvironment:
    """A container image ready to be instantiated via Podman/Docker."""

    image: str
    code_dir: str = "/src"
    base_url: str | None = None

    def start(self, container_id: str | None = None) -> PodmanExecution:
        """Start a container from this environment's image, or resume an existing one."""
        base_url = self.base_url or _get_podman_socket()
        if not base_url:
            raise RuntimeError(
                "Could not discover Podman socket. Set DOCKER_HOST or start a Podman machine."
            )
        client = docker.DockerClient(base_url=base_url, timeout=3000)

        if container_id:
            try:
                existing = client.containers.get(container_id)
                if existing.status in ("exited", "stopped", "created"):
                    log.info("Restarting container %s", container_id[:12])
                    existing.start()
                    return PodmanExecution(
                        container=existing, client=client, _code_dir=self.code_dir
                    )
                if existing.status == "running":
                    log.info("Container already running: %s", container_id[:12])
                    return PodmanExecution(
                        container=existing, client=client, _code_dir=self.code_dir
                    )
            except Exception as e:
                log.warning(e)
                log.info("Container %s not found, creating new one", container_id[:12])

        container: Container = client.containers.run(
            self.image,
            detach=True,
            command=["sleep", "infinity"],
            working_dir=self.code_dir,
        )
        return PodmanExecution(
            container=container, client=client, _code_dir=self.code_dir
        )


@dataclass
class PodmanExecution:
    """AuditExecution backed by a Podman/Docker container."""

    container: Container
    client: docker.DockerClient
    _code_dir: str

    @property
    def container_id(self) -> str:
        return self.container.id

    @property
    def code_dir(self) -> str:
        return self._code_dir

    def __enter__(self) -> PodmanExecution:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.stop()

    def exec(
        self, command: list[str], timeout: int = 300, workdir: str | None = None
    ) -> ExecResult:
        """Execute a command inside the container."""
        api = self.client.api
        exec_id = api.exec_create(
            self.container.id,
            command,
            workdir=workdir or self._code_dir,
        )["Id"]

        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(api.exec_start, exec_id, demux=True)
        try:
            output = future.result(timeout=timeout)
        except FuturesTimeoutError:
            import threading

            def _kill():
                try:
                    kill_id = api.exec_create(
                        self.container.id, ["kill", "-9", "-1"], workdir="/"
                    )["Id"]
                    api.exec_start(kill_id)
                except Exception:
                    pass

            threading.Thread(target=_kill, daemon=True).start()
            pool.shutdown(wait=False, cancel_futures=True)
            raise TimeoutError(
                f"Command timed out after {timeout}s: {command}"
            ) from None
        finally:
            pool.shutdown(wait=False)

        inspect = api.exec_inspect(exec_id)
        exit_code = inspect.get("ExitCode")
        if exit_code is None:
            exit_code = -1

        stdout = output[0].decode() if output[0] else ""
        stderr = output[1].decode() if output[1] else ""

        return ExecResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )

    def capture_git_info(self) -> GitInfo | None:
        return _capture_git_info(self)

    def stop(self, timeout: int = 30, remove: bool = False) -> None:
        """Stop the container (preserving it for later restart)."""
        try:
            self.container.kill()
        except Exception as exc:
            log.debug("kill() failed (container may already be dead): %s", exc)

        try:
            self.container.wait(timeout=timeout)
        except Exception as exc:
            raise TimeoutError(
                f"Container {self.container.id} did not stop within {timeout}s"
            ) from exc

        if remove:
            self.container.remove(force=True)
