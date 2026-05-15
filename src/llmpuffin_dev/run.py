"""Build container images and run audits. Run via: uv run llmpuffin-run [-p profile.toml]"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from llmpuffin.config import Profile

PROFILES_DIR = Path("profiles")


def _find_dockerfile(profile_dir: Path) -> Path | None:
    """Look for a Dockerfile next to the profile."""
    dockerfile = profile_dir / "Dockerfile"
    if dockerfile.exists():
        return dockerfile
    return None


def _build_image(image_name: str, dockerfile: Path) -> None:
    """Build the container image with podman."""
    import os

    print(f"Building image {image_name} from {dockerfile}...")
    cmd = [
        "podman",
        "build",
        "-t",
        image_name,
        "-f",
        str(dockerfile),
    ]
    gh_token = os.environ.get("GH_TOKEN", "")
    if gh_token:
        cmd.extend(["--build-arg", f"GH_TOKEN={gh_token}"])
    cmd.append(str(dockerfile.parent))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"Failed to build image {image_name}", file=sys.stderr)
        sys.exit(1)


def _discover_profiles() -> list[Path]:
    """Find all profile.toml files in the profiles/ directory."""
    if not PROFILES_DIR.is_dir():
        return []
    return sorted(PROFILES_DIR.glob("*/profile.toml"))


def _run_profile(profile_path: Path, verbose: bool) -> int:
    """Build and run a single profile. Returns the exit code."""
    profile_path = profile_path.resolve()
    profile = Profile.from_toml(profile_path)

    dockerfile = _find_dockerfile(profile_path.parent)
    if dockerfile is None:
        print(f"No Dockerfile found in {profile_path.parent}.", file=sys.stderr)
        return 1
    _build_image(profile.image, dockerfile)

    cmd = ["uv", "run", "llmpuffin", "-p", str(profile_path)]
    if verbose:
        cmd.append("-v")

    return subprocess.run(cmd).returncode


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="llmpuffin-run",
        description="Build container image(s) and run security audit(s).",
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
    args = parser.parse_args()

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
