{
  description = "llmpuffin – agentic codebase security review harness";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        isDarwin = pkgs.stdenv.isDarwin;
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            # Python toolchain
            uv
            python313

            # Container runtime
            # On macOS podman runs a Linux VM via `podman machine`.
            # On Linux it's truly rootless with no daemon.
            podman

            # Database (user-local, no daemon)
            postgresql
          ] ++ pkgs.lib.optionals isDarwin [
            # macOS needs qemu for the podman machine VM
            qemu
          ];

          shellHook = ''
            echo "llmpuffin dev shell"
            echo "  python: $(python3 --version)"
            echo "  uv:     $(uv --version)"
            echo "  podman: $(podman --version)"
          '' + pkgs.lib.optionalString isDarwin ''
            # Hint: run `podman machine init && podman machine start`
            # on first use to set up the Linux VM for containers.
            if ! podman machine inspect 2>/dev/null | grep -q '"State": "running"'; then
              echo ""
              echo "  NOTE: podman machine is not running."
              echo "  Run: podman machine init && podman machine start"
            fi
          '';
        };
      });
}
