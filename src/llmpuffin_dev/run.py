"""Build container image and run audits. Run via: uv run llmpuffin-run [-p profile.toml]"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


PROFILES_DIR = Path("profiles")
SHARED_DOCKERFILE = PROFILES_DIR / "Dockerfile"
SHARED_IMAGE = "llmpuffin-workspace"


def _build_image() -> None:
    """Build the shared workspace image with all repos."""
    if not SHARED_DOCKERFILE.exists():
        print(f"Dockerfile not found at {SHARED_DOCKERFILE}", file=sys.stderr)
        sys.exit(1)

    print(f"Building image {SHARED_IMAGE}...")
    cmd = [
        "podman",
        "build",
        "-t",
        SHARED_IMAGE,
        "-f",
        str(SHARED_DOCKERFILE),
    ]
    gh_token = os.environ.get("GH_TOKEN", "")
    if gh_token:
        cmd.extend(["--build-arg", f"GH_TOKEN={gh_token}"])
    cmd.append(str(PROFILES_DIR))

    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"Failed to build image {SHARED_IMAGE}", file=sys.stderr)
        sys.exit(1)


def _discover_profiles() -> list[Path]:
    """Find all profile.toml files in the profiles/ directory."""
    if not PROFILES_DIR.is_dir():
        return []
    return sorted(PROFILES_DIR.glob("*/profile.toml"))


def _run_profile(profile_path: Path, verbose: bool) -> int:
    """Run a single profile. Returns the exit code."""
    cmd = ["uv", "run", "llmpuffin", "-p", str(profile_path.resolve())]
    if verbose:
        cmd.append("-v")
    return subprocess.run(cmd).returncode


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="llmpuffin-run",
        description="Build workspace image and run security audit(s).",
    )
    parser.add_argument(
        "-p",
        "--profile",
        type=Path,
        default=None,
        help="Audit profile TOML file (omit to run all profiles in profiles/)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show debug output",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip building the Docker image",
    )
    args = parser.parse_args()

    if not args.no_build:
        _build_image()

    if args.profile:
        sys.exit(_run_profile(args.profile, args.verbose))

    # Run all profiles
    profiles = _discover_profiles()
    if not profiles:
        print("No profiles found in profiles/", file=sys.stderr)
        sys.exit(1)

    print(
        f"Running {len(profiles)} profile(s): {', '.join(p.parent.name for p in profiles)}"
    )
    failed = []
    for profile_path in profiles:
        print(f"\n{'=' * 60}")
        print(f"Profile: {profile_path.parent.name}")
        print(f"{'=' * 60}")
        rc = _run_profile(profile_path, args.verbose)
        if rc != 0:
            failed.append(profile_path.parent.name)

    if failed:
        print(f"\nFailed: {', '.join(failed)}")
        sys.exit(1)
