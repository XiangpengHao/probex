{
  description = "Probex Flake Configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        # Fetch daisyUI bundle files (for devShell)
        daisyui-bundle = pkgs.fetchurl {
          url = "https://github.com/saadeghi/daisyui/releases/download/v5.5.14/daisyui.mjs";
          sha256 = "sha256-ZhCaZQYZiADXoO3UwaAqv3cxiYu87LEiZuonefopRUw=";
        };
        daisyui-theme-bundle = pkgs.fetchurl {
          url = "https://github.com/saadeghi/daisyui/releases/download/v5.5.14/daisyui-theme.mjs";
          sha256 = "sha256-PPO2fLQ7eB+ROYnpmK5q2LHIoWUE+EcxYmvjC+gzgSw=";
        };

        probex = pkgs.callPackage ./nix/package.nix {
          src = ./.;
          cargoLockFile = ./Cargo.lock;
        };
      in
      {
        packages = {
          inherit probex;
          default = probex;
        };

        devShells.default =
          with pkgs;
          mkShell {
            packages = [
              openssl
              pkg-config
              eza
              fd
              llvmPackages.bintools
              lldb
              wasm-bindgen-cli
              binaryen
              nixd
              tailwindcss_4
              dioxus-cli
              rustc
              cargo
              clippy
              rustfmt
              bpf-linker
              bpftools
              lld
            ];
            env = {
              RUSTC_BOOTSTRAP = "1";
              PROBEX_NO_BUILD_STD = "1";
            };
            shellHook = ''
              # Setup daisyUI vendor files
              VENDOR_DIR="vendor"
              mkdir -p "$VENDOR_DIR"
              if [ ! -f "$VENDOR_DIR/daisyui.mjs" ] || [ "${daisyui-bundle}" -nt "$VENDOR_DIR/daisyui.mjs" ]; then
                echo "Setting up daisyUI bundle files..."
                cp -f "${daisyui-bundle}" "$VENDOR_DIR/daisyui.mjs"
                cp -f "${daisyui-theme-bundle}" "$VENDOR_DIR/daisyui-theme.mjs"
                echo "daisyUI files ready in $VENDOR_DIR"
              fi
            '';
          };
      }
    );
}
