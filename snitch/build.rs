use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;
use std::{ffi::OsString, fs, path::Path, path::PathBuf, process::Command};

fn main() -> anyhow::Result<()> {
    ensure_frontend_bundle()?;

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "snitch-ebpf")
        .ok_or_else(|| anyhow!("snitch-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}

fn ensure_frontend_bundle() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=assets/viewer");
    for path in [
        "../snitch-viewer/Cargo.toml",
        "../snitch-viewer/Dioxus.toml",
        "../snitch-viewer/tailwind.css",
        "../snitch-viewer/src",
        "../snitch-viewer/assets",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=SNITCH_SKIP_FRONTEND_BUNDLE");
    println!("cargo:rerun-if-env-changed=SNITCH_FORCE_FRONTEND_BUNDLE");
    println!("cargo:rerun-if-env-changed=DX_BIN");

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .context("CARGO_MANIFEST_DIR is missing for snitch build script")?,
    );
    let embedded_assets_dir = manifest_dir.join("assets").join("viewer");
    let embedded_index = embedded_assets_dir.join("index.html");
    let force_bundle = std::env::var("SNITCH_FORCE_FRONTEND_BUNDLE").as_deref() == Ok("1");

    if !force_bundle && embedded_index.is_file() {
        return Ok(());
    }

    if std::env::var("SNITCH_SKIP_FRONTEND_BUNDLE").as_deref() == Ok("1") {
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
        .ok_or_else(|| anyhow!("snitch crate has no workspace root parent"))?;
    let viewer_manifest = workspace_root.join("snitch-viewer").join("Cargo.toml");
    let bundled_public_dir = workspace_root
        .join("target")
        .join("dx")
        .join("snitch-viewer")
        .join("release")
        .join("web")
        .join("public");
    let bundled_index = bundled_public_dir.join("index.html");

    if !viewer_manifest.is_file() {
        return Err(anyhow!(
            "embedded viewer assets missing at {} and snitch-viewer source was not found at {}",
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
            "snitch-viewer",
        ])
        .status()
        .with_context(|| {
            format!(
                "failed to run {:?} bundle --release --platform web -p snitch-viewer",
                dx_bin
            )
        })?;

    if !status.success() {
        return Err(anyhow!(
            "frontend bundle command failed with status {status}. \
             Install dioxus-cli + wasm toolchain, or run \
             `dx bundle --release --platform web -p snitch-viewer` manually."
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
