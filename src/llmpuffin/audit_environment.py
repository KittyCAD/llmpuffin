"""
AuditEnvironment — containerized execution for security audits.

An AuditEnvironment wraps a container image that has the target codebase
baked in.  When started, it produces an AuditExecution — a running
container where the agent can execute tool calls (grep, read files,
run static analysis, etc.).

This is the **tool integration layer** of the harness (parallel.ai):
the model never touches the host; all side effects happen inside the
container.  This provides both security isolation and reproducibility.

We talk to the Podman daemon via its Docker-compatible API using the
docker-py library.
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

log = logging.getLogger("llmpuffin")


def _get_podman_socket() -> str | None:
    """Discover the Podman API socket path.

    Checks DOCKER_HOST first, then falls back to ``podman machine inspect``
    to find the local forwarded API socket (macOS with podman machine),
    then XDG_RUNTIME_DIR (Linux rootless).
    """
    import subprocess

    env_host = os.environ.get("DOCKER_HOST")
    if env_host:
        return env_host

    # macOS: podman machine exposes a local forwarded socket
    try:
        result = subprocess.run(
            ["podman", "machine", "inspect",
             "--format", "{{.ConnectionInfo.PodmanSocket.Path}}"],
            capture_output=True, text=True, timeout=5,
        )
        sock = result.stdout.strip()
        if result.returncode == 0 and sock and Path(sock).exists():
            return f"unix://{sock}"
    except Exception:
        pass

    return None


@dataclass
class AuditEnvironment:
    """A container image ready to be instantiated for auditing.

    Each AuditEnvironment represents a specific codebase snapshot.
    You can start multiple AuditExecutions from the same environment
    (e.g. to parallelize threat scenario investigation).
    """

    # OCI image reference (e.g. "ghcr.io/org/repo:sha-abc123")
    image: str
    # Where the source code lives inside the container
    code_dir: str = "/src"
    # Docker/Podman connection URI (None = default socket)
    base_url: str | None = None

    def start(self, container_id: str | None = None) -> AuditExecution:
        """Start a container from this environment's image, or resume an existing one.

        Args:
            container_id: If given, tries to restart an existing stopped
                container with this ID. Falls back to creating a new one.

        Returns an AuditExecution context manager.
        """
        base_url = self.base_url or _get_podman_socket()
        if not base_url:
            raise RuntimeError(
                "Could not discover Podman socket. Set DOCKER_HOST or start a Podman machine."
            )
        client = docker.DockerClient(base_url=base_url, timeout=3000)

        # Try to resume an existing container by ID
        if container_id:
            try:
                existing = client.containers.get(container_id)
                if existing.status in ("exited", "stopped", "created"):
                    log.info("Restarting container %s", container_id[:12])
                    existing.start()
                    return AuditExecution(
                        container=existing, client=client, code_dir=self.code_dir
                    )
                if existing.status == "running":
                    log.info("Container already running: %s", container_id[:12])
                    return AuditExecution(
                        container=existing, client=client, code_dir=self.code_dir
                    )
            except Exception as e:
                log.warn(e)
                log.info("Container %s not found, creating new one", container_id[:12])

        # Create a new container
        container: Container = client.containers.run(
            self.image,
            detach=True,
            command=["sleep", "infinity"],
            working_dir=self.code_dir,
        )
        return AuditExecution(
            container=container,
            client=client,
            code_dir=self.code_dir,
        )


@dataclass
class AuditExecution:
    """A running container where the agent executes tool calls.

    This is the runtime side of the tool integration layer.  The agent
    requests commands (grep, cat, semgrep, etc.) and the harness
    executes them inside this container, returning stdout/stderr.

    The execution is stateful: files written by one command are visible
    to subsequent commands (within the /tmp tmpfs).
    """

    container: Container
    client: docker.DockerClient
    code_dir: str

    def __enter__(self) -> AuditExecution:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.stop()

    def exec(self, command: list[str], timeout: int = 300) -> ExecResult:
        """Execute a command inside the container.

        Args:
            command: Command and arguments to run.
            timeout: Maximum seconds before the command is killed.
                     Raises TimeoutError if exceeded.
        """
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                self.container.exec_run,
                command,
                workdir=self.code_dir,
                demux=True,
            )
            try:
                exit_code, output = future.result(timeout=timeout)
            except FuturesTimeoutError:
                raise TimeoutError(
                    f"Command timed out after {timeout}s: {command}"
                ) from None

        if exit_code is None:
            raise RuntimeError(f"exec_run returned None exit code for: {command}")

        stdout = output[0].decode() if output[0] else ""
        stderr = output[1].decode() if output[1] else ""

        return ExecResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )

    def stop(self, timeout: int = 30, remove: bool = False) -> None:
        """Stop the container (preserving it for later restart).

        Args:
            timeout: Maximum seconds to wait for the container to stop.
            remove: If True, also remove the container after stopping.
        """
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


@dataclass
class ExecResult:
    """Result of a command execution inside the container."""

    command: list[str]
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0