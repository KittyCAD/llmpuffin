"""Start/stop a user-local PostgreSQL for development.

Run via: uv run llmpuffin-pg start
         uv run llmpuffin-pg stop
         uv run llmpuffin-pg status
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

PGDATA = Path(".postgres/pgdata")
PGLOG = Path(".postgres/pg.log")
PGPORT = os.environ.get("LLMPUFFIN_PGPORT", "5434")
PGDATABASE = "llmpuffin"


def _pgctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["pg_ctl", *args],
        env={**os.environ, "PGDATA": str(PGDATA)},
        capture_output=True,
        text=True,
    )


def _psql(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["psql", "-h", "localhost", "-p", PGPORT, *args],
        capture_output=True,
        text=True,
    )


def start() -> None:
    if not PGDATA.exists():
        print(f"Initializing database in {PGDATA} ...")
        PGDATA.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["initdb", "--no-locale", "-E", "UTF8", "-D", str(PGDATA)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            sys.exit(1)

    # Check if already running
    r = _pgctl("status")
    if r.returncode == 0:
        print(f"PostgreSQL already running (port {PGPORT})")
        return

    print(f"Starting PostgreSQL on port {PGPORT} ...")
    r = _pgctl(
        "start",
        "-l",
        str(PGLOG),
        "-o",
        f"-p {PGPORT} -k /tmp",
    )
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        sys.exit(1)

    # Create database if it doesn't exist
    check = _psql(
        "-d",
        "postgres",
        "-tc",
        f"SELECT 1 FROM pg_database WHERE datname = '{PGDATABASE}'",
    )
    if PGDATABASE not in (check.stdout or ""):
        print(f"Creating database '{PGDATABASE}' ...")
        _psql("-d", "postgres", "-c", f"CREATE DATABASE {PGDATABASE}")

    print(
        f"PostgreSQL running. Connection: postgresql://localhost:{PGPORT}/{PGDATABASE}"
    )


def stop() -> None:
    r = _pgctl("status")
    if r.returncode != 0:
        print("PostgreSQL is not running")
        return

    print("Stopping PostgreSQL ...")
    r = _pgctl("stop", "-m", "fast")
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        sys.exit(1)
    print("Stopped.")


def status() -> None:
    r = _pgctl("status")
    if r.returncode == 0:
        print(f"PostgreSQL running (port {PGPORT})")
        print(f"  Connection: postgresql://localhost:{PGPORT}/{PGDATABASE}")
        print(f"  Data: {PGDATA}")
    else:
        print("PostgreSQL is not running")


def connstring() -> str:
    return f"postgresql://localhost:{PGPORT}/{PGDATABASE}"


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="llmpuffin-pg", description="Manage local dev PostgreSQL"
    )
    parser.add_argument(
        "action", choices=["start", "stop", "status"], help="Action to perform"
    )
    args = parser.parse_args()

    {"start": start, "stop": stop, "status": status}[args.action]()
