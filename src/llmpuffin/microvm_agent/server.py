"""Minimal HTTP command executor that runs inside a Lambda MicroVM.

Exposes a JSON API for executing commands, compatible with the
llmpuffin AuditExecution protocol. Runs on port 8080 (the MicroVM
default ingress port).

Endpoints:
    POST /exec  — Run a command and return stdout/stderr/exit_code
    GET  /health — Health check
"""

import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

DEFAULT_PORT = 8080
DEFAULT_TIMEOUT = 300


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._json_response(200, {"status": "ok"})
        # Lambda lifecycle hooks
        elif self.path.startswith("/aws/lambda-microvms/runtime/v1/"):
            self._json_response(200, {"status": "ok"})
        else:
            self._json_response(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/exec":
            self._handle_exec()
        # Lambda lifecycle hooks — accept all
        elif self.path.startswith("/aws/lambda-microvms/runtime/v1/"):
            self._json_response(200, {"status": "ok"})
        else:
            self._json_response(404, {"error": "not found"})

    def _handle_exec(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
        except (json.JSONDecodeError, ValueError):
            self._json_response(400, {"error": "invalid JSON"})
            return

        command = body.get("command")
        if not command or not isinstance(command, list):
            self._json_response(400, {"error": "command must be a non-empty list of strings"})
            return

        workdir = body.get("workdir", "/")
        timeout_secs = body.get("timeout_secs", DEFAULT_TIMEOUT)

        if not os.path.isdir(workdir):
            self._json_response(200, {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"Working directory does not exist: {workdir}",
                "timed_out": False,
            })
            return

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                cwd=workdir,
                timeout=timeout_secs,
            )
            self._json_response(200, {
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "timed_out": False,
            })
        except subprocess.TimeoutExpired:
            self._json_response(200, {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout_secs}s",
                "timed_out": True,
            })
        except FileNotFoundError as exc:
            self._json_response(200, {
                "exit_code": 127,
                "stdout": "",
                "stderr": str(exc),
                "timed_out": False,
            })
        except Exception as exc:
            self._json_response(500, {"error": str(exc)})

    def _json_response(self, status: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Quieter logging
        pass


def main():
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"microvm-agent listening on port {port}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
