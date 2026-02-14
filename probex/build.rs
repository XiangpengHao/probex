use anyhow::{Context as _, anyhow};
use std::{ffi::OsString, fs, path::Path, path::PathBuf, process::Command};

fn main() -> anyhow::Result<()> {
    ensure_frontend_bundle()?;
    ensure_ebpf_binary()
}

fn ensure_ebpf_binary() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=assets/ebpf");
    println!("cargo:rerun-if-env-changed=PROBEX_SKIP_EBPF_BUILD");
    println!("cargo:rerun-if-env-changed=PROBEX_FORCE_EBPF_BUILD");

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .context("CARGO_MANIFEST_DIR is missing for probex build script")?,
    );
    let out_dir =
        PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| anyhow!("OUT_DIR not set"))?);
    let output_binary = out_dir.join("probex");
    let arch = bpf_target_arch()?;
    let prebuilt_binary = manifest_dir
        .join("assets")
        .join("ebpf")
        .join(arch)
        .join("probex");
    let force_build = std::env::var("PROBEX_FORCE_EBPF_BUILD").as_deref() == Ok("1");

    if !force_build && prebuilt_binary.is_file() {
        let _ = fs::copy(&prebuilt_binary, &output_binary).with_context(|| {
            format!(
                "failed to copy prebuilt eBPF binary {} -> {}",
                prebuilt_binary.display(),
                output_binary.display()
            )
        })?;
        return Ok(());
    }

    if std::env::var("PROBEX_SKIP_EBPF_BUILD").as_deref() == Ok("1") {
        return Err(anyhow!(
            "embedded eBPF binary missing at {}",
            prebuilt_binary.display()
        ));
    }

    build_ebpf_from_source(&output_binary)
}

fn build_ebpf_from_source(output_binary: &Path) -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "probex-ebpf")
        .ok_or_else(|| anyhow!("probex-ebpf package not found"))?;
    let cargo_metadata::Package { manifest_path, .. } = ebpf_package;
    let root_dir = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
        .as_std_path();
    println!("cargo:rerun-if-changed={}", root_dir.display());

    let out_dir = output_binary
        .parent()
        .ok_or_else(|| anyhow!("output path has no parent: {}", output_binary.display()))?;
    let target_dir = out_dir.join("probex-ebpf");
    let target = bpf_target_triple()?;
    let bpf_target_arch = bpf_target_arch()?;
    let mut rustflags = OsString::from("--cfg=bpf_target_arch=\"");
    rustflags.push(&bpf_target_arch);
    rustflags.push("\"\x1f-Cdebuginfo=2\x1f-Clink-arg=--btf");

    let cargo_bin = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut cmd = Command::new(&cargo_bin);
    cmd.current_dir(root_dir)
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
        .args([
            "build",
            "--package",
            "probex-ebpf",
            "-Z",
            "build-std=core",
            "--bins",
            "--release",
            "--target",
            target.as_str(),
            "--target-dir",
        ])
        .arg(&target_dir);

    let status = cmd
        .status()
        .with_context(|| format!("failed to run {cmd:?}"))?;
    if !status.success() {
        return Err(anyhow!("{cmd:?} failed: {status:?}"));
    }

    let built_binary = target_dir.join(target).join("release").join("probex");
    let _ = fs::copy(&built_binary, output_binary).with_context(|| {
        format!(
            "failed to copy eBPF binary {} -> {}",
            built_binary.display(),
            output_binary.display()
        )
    })?;
    Ok(())
}

fn bpf_target_triple() -> anyhow::Result<String> {
    let endian = std::env::var("CARGO_CFG_TARGET_ENDIAN")
        .context("CARGO_CFG_TARGET_ENDIAN not set for eBPF build")?;
    let prefix = match endian.as_str() {
        "big" => "bpfeb",
        "little" => "bpfel",
        _ => return Err(anyhow!("unsupported CARGO_CFG_TARGET_ENDIAN: {endian}")),
    };
    Ok(format!("{prefix}-unknown-none"))
}

fn bpf_target_arch() -> anyhow::Result<String> {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH")
        .context("CARGO_CFG_TARGET_ARCH not set for eBPF build")?;
    if arch.starts_with("riscv64") {
        Ok("riscv64".to_string())
    } else {
        Ok(arch)
    }
}

fn ensure_frontend_bundle() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=assets/viewer");
    let viewer_source_paths = [
        "../probex-viewer/Cargo.toml",
        "../probex-viewer/Dioxus.toml",
        "../probex-viewer/tailwind.css",
        "../probex-viewer/src",
        "../probex-viewer/assets",
    ];
    for path in &viewer_source_paths {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=PROBEX_SKIP_FRONTEND_BUNDLE");
    println!("cargo:rerun-if-env-changed=PROBEX_FORCE_FRONTEND_BUNDLE");
    println!("cargo:rerun-if-env-changed=DX_BIN");

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .context("CARGO_MANIFEST_DIR is missing for probex build script")?,
    );
    let embedded_assets_dir = manifest_dir.join("assets").join("viewer");
    let embedded_index = embedded_assets_dir.join("index.html");
    let force_bundle = std::env::var("PROBEX_FORCE_FRONTEND_BUNDLE").as_deref() == Ok("1");

    if !force_bundle && embedded_index.is_file() {
        // Check if any source file is newer than the embedded bundle
        let embedded_mtime = fs::metadata(&embedded_index)
            .and_then(|m| m.modified())
            .ok();

        if let Some(embedded_mtime) = embedded_mtime {
            let needs_rebuild = viewer_source_paths.iter().any(|path| {
                let full_path = manifest_dir.join(path);
                newest_mtime(&full_path)
                    .map(|src_mtime| src_mtime > embedded_mtime)
                    .unwrap_or(false)
            });

            if !needs_rebuild {
                return Ok(());
            }
        }
    }

    if std::env::var("PROBEX_SKIP_FRONTEND_BUNDLE").as_deref() == Ok("1") {
        if embedded_index.is_file() {
            return Ok(());
        }
        return Err(anyhow!(
            "embedded viewer assets missing at {}",
            embedded_index.display()
        ));
    }

    let workspace_root = manifest_dir
        .parent()
        .ok_or_else(|| anyhow!("probex crate has no workspace root parent"))?;
    let viewer_manifest = workspace_root.join("probex-viewer").join("Cargo.toml");
    let bundled_public_dir = workspace_root
        .join("target")
        .join("dx")
        .join("probex-viewer")
        .join("release")
        .join("web")
        .join("public");
    let bundled_index = bundled_public_dir.join("index.html");

    if !viewer_manifest.is_file() {
        return Err(anyhow!(
            "embedded viewer assets missing at {} and probex-viewer source was not found at {}",
            embedded_index.display(),
            viewer_manifest.display()
        ));
    }

    let dx_bin = std::env::var_os("DX_BIN").unwrap_or_else(|| OsString::from("dx"));
    let status = Command::new(&dx_bin)
        .current_dir(workspace_root)
        .args([
            "bundle",
            "--release",
            "--platform",
            "web",
            "-p",
            "probex-viewer",
        ])
        .status()
        .with_context(|| {
            format!(
                "failed to run {:?} bundle --release --platform web -p probex-viewer",
                dx_bin
            )
        })?;

    if !status.success() {
        return Err(anyhow!(
            "frontend bundle command failed with status {status}. \
             Install dioxus-cli + wasm toolchain, or run \
             `dx bundle --release --platform web -p probex-viewer` manually."
        ));
    }

    if !bundled_index.is_file() {
        return Err(anyhow!(
            "frontend bundle completed but missing {}",
            bundled_index.display()
        ));
    }

    sync_frontend_assets(&bundled_public_dir, &embedded_assets_dir)?;
    if !embedded_index.is_file() {
        return Err(anyhow!(
            "frontend assets sync completed but missing {}",
            embedded_index.display()
        ));
    }

    Ok(())
}

fn sync_frontend_assets(source_dir: &Path, target_dir: &Path) -> anyhow::Result<()> {
    if !source_dir.is_dir() {
        return Err(anyhow!(
            "frontend source directory does not exist: {}",
            source_dir.display()
        ));
    }

    if target_dir.exists() {
        fs::remove_dir_all(target_dir).with_context(|| {
            format!(
                "failed to clear existing frontend assets at {}",
                target_dir.display()
            )
        })?;
    }
    fs::create_dir_all(target_dir).with_context(|| {
        format!(
            "failed to create frontend assets directory {}",
            target_dir.display()
        )
    })?;

    copy_dir_recursive(source_dir, target_dir)?;
    fs::write(target_dir.join(".gitkeep"), "\n").with_context(|| {
        format!(
            "failed to keep placeholder file in {}",
            target_dir.display()
        )
    })?;
    Ok(())
}

fn newest_mtime(path: &Path) -> Option<std::time::SystemTime> {
    if path.is_file() {
        return fs::metadata(path).and_then(|m| m.modified()).ok();
    }

    if path.is_dir() {
        let mut newest: Option<std::time::SystemTime> = None;
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if let Some(mtime) = newest_mtime(&entry.path()) {
                    newest = Some(match newest {
                        Some(current) if current >= mtime => current,
                        _ => mtime,
                    });
                }
            }
        }
        return newest;
    }

    None
}

fn copy_dir_recursive(source_dir: &Path, target_dir: &Path) -> anyhow::Result<()> {
    for entry in fs::read_dir(source_dir)
        .with_context(|| format!("failed to list {}", source_dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read {}", source_dir.display()))?;
        let source_path = entry.path();
        let target_path = target_dir.join(entry.file_name());
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to read file type for {}", source_path.display()))?;

        if file_type.is_dir() {
            fs::create_dir_all(&target_path).with_context(|| {
                format!(
                    "failed to create frontend assets directory {}",
                    target_path.display()
                )
            })?;
            copy_dir_recursive(&source_path, &target_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &target_path).with_context(|| {
                format!(
                    "failed to copy frontend asset {} -> {}",
                    source_path.display(),
                    target_path.display()
                )
            })?;
        }
    }

    Ok(())
}
