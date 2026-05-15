#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="llmpuffin-vulnerable-app"

echo "Building example container image..."
podman build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"

echo "Running audit..."
uv run llmpuffin -v -p "$SCRIPT_DIR/profile.toml"

echo "Results: $SCRIPT_DIR/results.sarif"
