"""Container backend for deepagents — runs all operations inside a container.

This backend implements `SandboxBackendProtocol` by delegating every
file and shell operation to a running `AuditExecution` container.
The host is never touched.
"""

from __future__ import annotations

import fnmatch
import re
import uuid

from deepagents.backends.protocol import (
    EditResult,
    ExecuteResponse,
    FileData,
    FileInfo,
    GlobResult,
    GrepMatch,
    GrepResult,
    LsResult,
    ReadResult,
    SandboxBackendProtocol,
    WriteResult,
)

from llmpuffin.audit_environment import AuditExecution
from llmpuffin.coverage import CoverageTracker

DEFAULT_EXECUTE_TIMEOUT = 120


class ContainerBackend(SandboxBackendProtocol):
    """Deepagents backend that executes everything inside a container.

    All file and shell operations are delegated to the container via
    `AuditExecution.exec()`. The host filesystem is never accessed.

    The async `a*` methods are the primary implementations — they call
    the async `exec()` directly. The sync methods exist for the protocol
    but should not be called in production (deepagents prefers the async
    variants).
    """

    def __init__(
        self,
        execution: AuditExecution,
        *,
        timeout: int = DEFAULT_EXECUTE_TIMEOUT,
        max_output_bytes: int = 100_000,
        coverage: CoverageTracker | None = None,
    ) -> None:
        self._exec = execution
        self._default_timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._sandbox_id = f"container-{uuid.uuid4().hex[:8]}"
        self.coverage = coverage

    @property
    def id(self) -> str:
        return self._sandbox_id

    async def _run(
        self, cmd: list[str], timeout: int | None = None
    ) -> tuple[int, str, str]:
        """Run a command in the container, return (exit_code, stdout, stderr)."""
        t = timeout if timeout is not None else self._default_timeout
        result = await self._exec.exec(cmd, timeout=t)
        return result.exit_code, result.stdout, result.stderr

    # -- Async implementations (primary) --

    async def aexecute(
        self,
        command: str,
        *,
        timeout: int | None = None,
    ) -> ExecuteResponse:
        exit_code, stdout, stderr = await self._run(
            ["/bin/sh", "-c", command],
            timeout=timeout,
        )

        parts = []
        if stdout:
            parts.append(stdout)
        if stderr:
            for line in stderr.strip().split("\n"):
                parts.append(f"[stderr] {line}")

        output = "\n".join(parts) if parts else "<no output>"

        truncated = False
        if len(output) > self._max_output_bytes:
            output = output[: self._max_output_bytes]
            output += f"\n\n... Output truncated at {self._max_output_bytes} bytes."
            truncated = True

        if exit_code != 0:
            output = f"{output.rstrip()}\n\nExit code: {exit_code}"

        if self.coverage:
            self.coverage.record_exec(command, stdout)

        return ExecuteResponse(
            output=output,
            exit_code=exit_code,
            truncated=truncated,
        )

    async def als(self, path: str) -> LsResult:
        exit_code, stdout, stderr = await self._run(
            ["ls", "-1apL", "--time-style=+%s", path],
        )
        if exit_code != 0:
            return LsResult(error=f"Error: {stderr.strip() or 'Cannot list ' + path}")

        # Use stat for richer info
        exit_code2, stdout2, _ = await self._run(
            [
                "stat",
                "--printf",
                "%n\\t%F\\t%s\\t%Y\\n",
                *[
                    f"{path.rstrip('/')}/{e.rstrip('/')}"
                    for e in stdout.strip().split("\n")
                    if e and e != "." and e != ".."
                ],
            ],
        )

        entries: list[FileInfo] = []
        if exit_code2 == 0 and stdout2.strip():
            for line in stdout2.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 4:
                    entries.append(
                        FileInfo(
                            path=parts[0],
                            is_dir=parts[1] == "directory",
                            size=int(parts[2]) if parts[2].isdigit() else None,  # pyright: ignore[reportArgumentType]
                            modified_at=parts[3],
                        )
                    )
        else:
            # Fallback: just names
            for entry in sorted(stdout.strip().split("\n")):
                if entry and entry != "." and entry != "..":
                    entries.append(
                        FileInfo(
                            path=f"{path.rstrip('/')}/{entry.rstrip('/')}",
                            is_dir=entry.endswith("/"),
                        )
                    )

        return LsResult(entries=sorted(entries, key=lambda e: e["path"]))

    async def aread(
        self,
        file_path: str,
        offset: int = 0,
        limit: int = 2000,
    ) -> ReadResult:
        # Use sed for offset/limit
        start = offset + 1
        end = offset + limit
        exit_code, stdout, stderr = await self._run(
            ["sed", "-n", f"{start},{end}p", file_path],
        )
        if exit_code != 0:
            return ReadResult(error=f"Error: File '{file_path}' not found")

        if self.coverage:
            self.coverage.record_read(file_path)

        return ReadResult(
            file_data=FileData(
                content=stdout,
                encoding="utf-8",
            )
        )

    async def agrep(
        self,
        pattern: str,
        path: str | None = None,
        glob: str | None = None,
    ) -> GrepResult:
        search_path = path or "."
        cmd = ["grep", "-rn", "-H"]
        if glob:
            cmd.extend(["--include", glob])
        # Use -e to pass the pattern explicitly — prevents patterns starting
        # with '-' (e.g. "->foo") from being interpreted as options.
        cmd.extend(["-e", pattern, search_path])

        exit_code, stdout, stderr = await self._run(cmd)
        if exit_code == 2:
            return GrepResult(error=f"Error: {stderr.strip()}")

        matches: list[GrepMatch] = []
        for line in stdout.strip().split("\n"):
            if not line:
                continue
            # grep -Hrn output: file:line:text
            m = re.match(r"^(.+?):(\d+):(.*)$", line)
            if m:
                matches.append(
                    GrepMatch(
                        path=m.group(1),
                        line=int(m.group(2)),
                        text=m.group(3),
                    )
                )

        # Optimization to make this tool call better.
        if not matches and glob and "*" not in glob:
            hint = (
                f"No matches found. Note: the glob parameter ({glob!r}) is a "
                f"filename pattern (e.g. '*.js'), not a file path. "
                f"To search a specific file, pass it as the path parameter instead."
            )
            return GrepResult(error=hint)

        return GrepResult(matches=matches)

    async def aglob(self, pattern: str, path: str = "/") -> GlobResult:  # pyright: ignore[reportIncompatibleMethodOverride]
        # Use find + fnmatch
        search_path = path or "/"
        exit_code, stdout, _ = await self._run(
            ["find", search_path, "-type", "f", "-o", "-type", "d"],
        )
        if exit_code != 0:
            return GlobResult(matches=[])

        matches: list[FileInfo] = []
        for entry in sorted(stdout.strip().split("\n")):
            if entry and fnmatch.fnmatch(entry, pattern):
                matches.append(FileInfo(path=entry))

        return GlobResult(matches=matches)

    async def awrite(self, file_path: str, content: str) -> WriteResult:
        # Check if file exists
        exit_code, _, _ = await self._run(["test", "-e", file_path])
        if exit_code == 0:
            return WriteResult(error=f"Error: File '{file_path}' already exists")

        # Ensure parent dir exists
        parent = file_path.rsplit("/", 1)[0] if "/" in file_path else "."
        await self._run(["mkdir", "-p", parent])

        # Write via stdin-like approach using sh -c with heredoc
        escaped = content.replace("'", "'\\''")
        exit_code, _, stderr = await self._run(
            ["sh", "-c", f"printf '%s' '{escaped}' > {file_path}"],
        )
        if exit_code != 0:
            return WriteResult(error=f"Error: {stderr.strip()}")

        return WriteResult(path=file_path)

    async def aedit(
        self,
        file_path: str,
        old_string: str,
        new_string: str,
        replace_all: bool = False,
    ) -> EditResult:
        # Read current content
        exit_code, content, stderr = await self._run(["cat", file_path])
        if exit_code != 0:
            return EditResult(error=f"Error: File '{file_path}' not found")

        count = content.count(old_string)
        if count == 0:
            return EditResult(error=f"Error: String not found in '{file_path}'")
        if count > 1 and not replace_all:
            return EditResult(
                error=f"Error: String occurs {count} times in '{file_path}'. "
                "Use replace_all=True to replace all occurrences."
            )

        if replace_all:
            new_content = content.replace(old_string, new_string)
        else:
            new_content = content.replace(old_string, new_string, 1)

        # Write back
        escaped = new_content.replace("'", "'\\''")
        exit_code, _, stderr = await self._run(
            ["sh", "-c", f"printf '%s' '{escaped}' > {file_path}"],
        )
        if exit_code != 0:
            return EditResult(error=f"Error: {stderr.strip()}")

        if self.coverage:
            self.coverage.record_edit(file_path)

        return EditResult(path=file_path, occurrences=count)

    # -- Sync fallbacks (used by deepagents if async not available) --
    # These delegate to the async versions via asyncio. In practice,
    # deepagents will call the a* methods directly.

    def execute(self, command: str, *, timeout: int | None = None) -> ExecuteResponse:
        import asyncio

        return asyncio.run(self.aexecute(command, timeout=timeout))

    def ls(self, path: str) -> LsResult:
        import asyncio

        return asyncio.run(self.als(path))

    def read(self, file_path: str, offset: int = 0, limit: int = 2000) -> ReadResult:
        import asyncio

        return asyncio.run(self.aread(file_path, offset, limit))

    def grep(
        self, pattern: str, path: str | None = None, glob: str | None = None
    ) -> GrepResult:
        import asyncio

        return asyncio.run(self.agrep(pattern, path, glob))

    def glob(self, pattern: str, path: str = "/") -> GlobResult:  # pyright: ignore[reportIncompatibleMethodOverride]
        import asyncio

        return asyncio.run(self.aglob(pattern, path))

    def write(self, file_path: str, content: str) -> WriteResult:
        import asyncio

        return asyncio.run(self.awrite(file_path, content))

    def edit(
        self,
        file_path: str,
        old_string: str,
        new_string: str,
        replace_all: bool = False,
    ) -> EditResult:
        import asyncio

        return asyncio.run(self.aedit(file_path, old_string, new_string, replace_all))
