{
  description = "Probex Flake Configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      nixpkgs,
      rust-overlay,
      flake-utils,
      crane,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rustToolchain = pkgs.rust-bin.selectLatestNightlyWith (
          toolchain:
          toolchain.default.override {
            extensions = [
              "rust-src"
              "llvm-tools-preview"
            ];
            targets = [ "wasm32-unknown-unknown" "x86_64-unknown-linux-gnu" ];
          }
        );
        # Fetch daisyUI bundle files
        daisyui-bundle = pkgs.fetchurl {
          url = "https://github.com/saadeghi/daisyui/releases/download/v5.5.14/daisyui.mjs";
          sha256 = "sha256-ZhCaZQYZiADXoO3UwaAqv3cxiYu87LEiZuonefopRUw=";
        };
        daisyui-theme-bundle = pkgs.fetchurl {
          url = "https://github.com/saadeghi/daisyui/releases/download/v5.5.14/daisyui-theme.mjs";
          sha256 = "sha256-PPO2fLQ7eB+ROYnpmK5q2LHIoWUE+EcxYmvjC+gzgSw=";
        };

        # Build bpf-linker from source using crane
        bpf-linker-src = pkgs.fetchFromGitHub {
          owner = "aya-rs";
          repo = "bpf-linker";
          rev = "v0.10.1";
          hash = "sha256-WFMQlaM18v5FsrsjmAl1nPGNMnBW3pjXmkfOfv3Izq0=";
        };

        # Combine LLVM dev (llvm-config) and lib (libLLVM.so) outputs
        llvm-combined = pkgs.symlinkJoin {
          name = "llvm-combined";
          paths = [
            pkgs.llvmPackages_22.llvm.dev
            pkgs.llvmPackages_22.libllvm.lib
          ];
        };

        bpf-linker-crane = pkgs.rustPlatform.buildRustPackage {
          pname = "bpf-linker";
          version = "0.10.1";
          src = bpf-linker-src;
          cargoHash = "sha256-m/mlN1EL5jYxprNXvMbuVzBsewdIOFX0ebNQWfByEHQ=";
          buildNoDefaultFeatures = true;
          buildFeatures = [ "llvm-22" ];
          doCheck = false;
          nativeBuildInputs = with pkgs; [
            clang
            pkg-config
          ];
          buildInputs = with pkgs; [
            llvmPackages_22.libllvm
            zlib
          ];
          LLVM_PREFIX = llvm-combined;
        };

        probex-runner = pkgs.writeShellApplication {
          name = "probex";
          runtimeInputs = with pkgs; [
            binaryen
            bpftools
            bpf-linker-crane
            clang
            coreutils
            dioxus-cli
            findutils
            gnugrep
            llvmPackages.bintools
            openssl
            pkg-config
            rustToolchain
            wasm-bindgen-cli
            which
          ];
          text = ''
            set -euo pipefail

            if [ "$#" -eq 0 ]; then
              echo "Launching probex viewer (no trace file specified)..."
            fi

            if [ ! -f Cargo.toml ] || [ ! -d probex ] || [ ! -d probex-viewer ]; then
              echo "Run this command from the probex workspace root."
              exit 2
            fi

            mkdir -p vendor
            cp -f "${daisyui-bundle}" vendor/daisyui.mjs
            cp -f "${daisyui-theme-bundle}" vendor/daisyui-theme.mjs

            echo "Building probex (frontend auto-bundled by build.rs)..."
            cargo build --release -p probex

            if [ "''${EUID:-$(id -u)}" -ne 0 ]; then
              sudo_cmd=""
              if [ -x /run/wrappers/bin/sudo ]; then
                sudo_cmd=/run/wrappers/bin/sudo
              elif [ -x /usr/bin/sudo ]; then
                sudo_cmd=/usr/bin/sudo
              elif command -v sudo >/dev/null 2>&1; then
                sudo_cmd="$(command -v sudo)"
              fi

              if [ -z "$sudo_cmd" ]; then
                echo "Root privileges required for eBPF tracing, but sudo was not found."
                echo "Run as root, or install/configure sudo and retry."
                exit 1
              fi

              echo "Re-running probex with $sudo_cmd for eBPF privileges..."
              exec "$sudo_cmd" -E target/release/probex "$@"
            fi

            exec target/release/probex "$@"
          '';
        };
      in
      rec {
        packages = {
          probex = probex-runner;
          default = probex-runner;
        };

        apps = {
          probex = flake-utils.lib.mkApp { drv = probex-runner; };
          default = apps.probex;
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
              rustToolchain
              bpf-linker-crane
              bpftools
            ];
            shellHook = ''
              # Setup daisyUI vendor files
              VENDOR_DIR="vendor"
              mkdir -p "$VENDOR_DIR"
              # Copy daisyUI files from Nix store if they don't exist or are outdated
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
