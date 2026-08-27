//! Build-time pre-initialization in the deploy path (README.md §4.3).
//!
//! Wizer runs a module's initializer once, at deploy, and snapshots the
//! resulting linear memory back into the module's data segments. Wasmtime then
//! maps that image copy-on-write into every instance, so the boot cost is paid
//! here rather than on every request.
//!
//! The runtime needs no knowledge of this: Wizer drops the init export after
//! consuming it, and the worker's rule is simply "call `_initialize` if the
//! module still has one".

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::process::Command;

/// The WASI reactor initializer.
///
/// Duplicated from `nebula-runtime` rather than depending on the engine: the
/// control plane does not execute wasm, and pulling in wasmtime to learn one
/// string would be backwards.
pub const INIT_EXPORT: &str = "_initialize";

/// Looked up on `PATH`.
pub const WIZER_BIN: &str = "wizer";

#[derive(Debug)]
pub enum WizerError {
    /// Wizer ran and rejected the module. The artifact is the caller's problem,
    /// so this becomes a 400.
    Failed(String),
    /// Wizer is not installed. That is the operator's problem, not the
    /// caller's, so the deploy proceeds un-wizened rather than failing.
    Unavailable,
    Io(io::Error),
}

impl std::fmt::Display for WizerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(detail) => write!(f, "wizer rejected the module: {detail}"),
            Self::Unavailable => f.write_str("wizer is not installed"),
            Self::Io(err) => write!(f, "wizer could not be run: {err}"),
        }
    }
}

/// Whether this artifact should go through Wizer.
///
/// Two conditions. It has to be a *binary* module (Wizer cannot read `.wat`
/// text, which the runtime happily accepts and the tests lean on), and it has
/// to actually export an initializer, since Wizer fails outright when the
/// function it was told to run is missing.
pub fn should_wizen(artifact: &[u8]) -> bool {
    artifact.starts_with(b"\0asm") && exports_initializer(artifact)
}

/// Reads the export section with `wasmparser`.
///
/// Parsing the section is cheap and exact. The alternative (running Wizer and
/// treating "no such function" as "nothing to do") cannot tell that apart from
/// a module whose initializer genuinely failed, which is the one distinction
/// this whole path exists to make.
fn exports_initializer(artifact: &[u8]) -> bool {
    for payload in wasmparser::Parser::new(0).parse_all(artifact) {
        let Ok(wasmparser::Payload::ExportSection(exports)) = payload else {
            // Anything else, including a parse error: not our business here. A
            // malformed module fails later, on its own terms.
            continue;
        };
        for export in exports {
            match export {
                Ok(export) if export.name == INIT_EXPORT => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    }
    false
}

/// Runs Wizer over `artifact`, returning the pre-initialized module.
///
/// `scratch` is a directory the control plane owns; the temporaries are named
/// by pid and a counter so concurrent deploys cannot collide.
pub async fn wizen(artifact: &[u8], scratch: &Path) -> Result<Vec<u8>, WizerError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let stem = format!(
        "wizer-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let input = scratch.join(format!("{stem}.in.wasm"));
    let output = scratch.join(format!("{stem}.out.wasm"));

    tokio::fs::write(&input, artifact)
        .await
        .map_err(WizerError::Io)?;

    let spawned = Command::new(WIZER_BIN)
        .arg("--allow-wasi")
        .arg("--init-func")
        .arg(INIT_EXPORT)
        .arg("-o")
        .arg(&output)
        .arg(&input)
        .output()
        .await;

    let result = match spawned {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Err(WizerError::Unavailable),
        Err(err) => Err(WizerError::Io(err)),
        Ok(finished) if !finished.status.success() => {
            let detail = String::from_utf8_lossy(&finished.stderr)
                .trim()
                .lines()
                .last()
                .unwrap_or("no detail")
                .to_string();
            Err(WizerError::Failed(detail))
        }
        Ok(_) => tokio::fs::read(&output).await.map_err(WizerError::Io),
    };

    cleanup(&[input, output]).await;
    result
}

async fn cleanup(paths: &[PathBuf]) {
    for path in paths {
        let _ = tokio::fs::remove_file(path).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wat_text_is_never_wizened() {
        // The runtime accepts `.wat`; Wizer does not. Passing text to Wizer
        // would turn every text deploy into a 400.
        assert!(!should_wizen(b"(module)"));
        assert!(!should_wizen(b""));
        assert!(!should_wizen(b"not wasm at all"));
    }

    #[test]
    fn a_binary_module_without_an_initializer_is_left_alone() {
        // Smallest valid module: magic + version, no sections.
        let empty = b"\0asm\x01\0\0\0";
        assert!(!should_wizen(empty));
    }

    #[test]
    fn a_binary_module_exporting_the_initializer_is_selected() {
        let wizened = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../guests/examples/heavy_init/dist/initialized.wasm"),
        );
        let raw = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../guests/examples/heavy_init/dist/heavy_init.wasm"),
        );
        let (Ok(wizened), Ok(raw)) = (wizened, raw) else {
            eprintln!("SKIPPED: guest artifacts missing; see `bash guests/build.sh`.");
            return;
        };

        assert!(
            should_wizen(&raw),
            "the raw guest still exports an initializer"
        );
        assert!(
            !should_wizen(&wizened),
            "an already-wizened guest must not be wizened twice: Wizer consumed \
             and dropped the export, which is exactly the signal this reads"
        );
    }
}
