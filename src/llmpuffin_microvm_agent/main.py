"""MicroVM agent — HTTP command executor for Lambda MicroVMs.

Runs inside a Lambda MicroVM and exposes a JSON API for executing
commands, compatible with the llmpuffin AuditExecution protocol.

Endpoints:
    POST /exec   — Run a command and return stdout/stderr/exit_code
    GET  /health — Health check
    POST /aws/lambda-microvms/runtime/v1/{hook} — Lambda lifecycle hooks
"""

from __future__ import annotations

import os
import subprocess

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

DEFAULT_PORT = 8080
DEFAULT_TIMEOUT = 300

app = FastAPI(title="llmpuffin-microvm-agent")


class ExecRequest(BaseModel):
    command: list[str]
    workdir: str = "/"
    timeout_secs: int = DEFAULT_TIMEOUT


class ExecResponse(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/exec")
async def exec_command(req: ExecRequest) -> ExecResponse:
    if not os.path.isdir(req.workdir):
        return ExecResponse(
            exit_code=1,
            stdout="",
            stderr=f"Working directory does not exist: {req.workdir}",
            timed_out=False,
        )

    try:
        result = subprocess.run(
            req.command,
            capture_output=True,
            text=True,
            cwd=req.workdir,
            timeout=req.timeout_secs,
        )
        return ExecResponse(
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=False,
        )
    except subprocess.TimeoutExpired:
        return ExecResponse(
            exit_code=-1,
            stdout="",
            stderr=f"Command timed out after {req.timeout_secs}s",
            timed_out=True,
        )
    except FileNotFoundError as exc:
        return ExecResponse(
            exit_code=127,
            stdout="",
            stderr=str(exc),
            timed_out=False,
        )


# Lambda lifecycle hooks — accept all and return 200.
@app.api_route(
    "/aws/lambda-microvms/runtime/v1/{hook}",
    methods=["GET", "POST"],
)
async def lifecycle_hook(hook: str):
    return {"status": "ok"}


def main():
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    uvicorn.run(
        "llmpuffin_microvm_agent.main:app",
        host="0.0.0.0",
        port=port,
    )


if __name__ == "__main__":
    main()
