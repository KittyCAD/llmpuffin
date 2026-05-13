# llmpuffin

Agentic codebase security review, driven by structured threat models.

## Setup

Requires [Nix](https://nixos.org/) with flakes enabled.

```
nix develop
uv sync
```

On macOS, initialize the Podman VM once:

```
podman machine init && podman machine start
```

## Usage

Define a threat model in TOML (see `examples/threat_model.toml`), provide a container image with your codebase, and run the audit.

## Architecture

See `docs/goals.md` for project goals and design rationale.
