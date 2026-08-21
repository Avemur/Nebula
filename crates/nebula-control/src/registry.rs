//! Module registry (README.md §3.1, §8.1).
//!
//! Local disk in v1. Artifacts are addressed by SHA-256 of their bytes, never by
//! `function_id`, so a new version is a new name and there is no invalidation
//! protocol.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// §4.1 streams artifacts in 256 KiB chunks.
pub const CHUNK_BYTES: usize = 256 * 1024;

/// §6.4 caps artifacts at 32 MiB.
pub const MAX_ARTIFACT_BYTES: usize = 32 << 20;

#[derive(Debug)]
pub struct Registry {
    dir: PathBuf,
}

impl Registry {
    pub fn new(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Stores an artifact and returns its content hash.
    pub fn put(&self, wasm: &[u8]) -> io::Result<String> {
        if wasm.len() > MAX_ARTIFACT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact exceeds the 32 MiB cap",
            ));
        }
        let hash = content_hash_hex(wasm);
        fs::write(self.path(&hash)?, wasm)?;
        Ok(hash)
    }

    pub fn read(&self, hash: &str) -> io::Result<Vec<u8>> {
        fs::read(self.path(hash)?)
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.path(hash).map(|path| path.is_file()).unwrap_or(false)
    }

    /// Builds the on-disk path for `hash`, rejecting anything that is not a
    /// hash.
    ///
    /// `hash` arrives from the network on every `FetchModule`. Without this
    /// check a caller could ask for `../../etc/passwd` and the registry would
    /// hand it over — `Path::join` is perfectly happy to escape its parent.
    /// Validating the *shape* is the fix, not sanitising the string.
    fn path(&self, hash: &str) -> io::Result<PathBuf> {
        if !is_content_hash(hash) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "content_hash must be 64 hex characters",
            ));
        }
        Ok(self.dir.join(format!("{hash}.wasm")))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// SHA-256 of `wasm`, hex encoded.
pub fn content_hash_hex(wasm: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(wasm)
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn is_content_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_registry() -> Registry {
        let dir = std::env::temp_dir().join(format!(
            "nebula-registry-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Registry::new(dir).expect("registry")
    }

    #[test]
    fn put_then_read_round_trips() {
        let registry = temp_registry();
        let hash = registry.put(b"(module)").unwrap();

        assert_eq!(hash.len(), 64);
        assert!(registry.contains(&hash));
        assert_eq!(registry.read(&hash).unwrap(), b"(module)");
    }

    #[test]
    fn identical_bytes_get_identical_names() {
        let registry = temp_registry();
        assert_eq!(
            registry.put(b"same").unwrap(),
            registry.put(b"same").unwrap()
        );
        assert_ne!(
            registry.put(b"same").unwrap(),
            registry.put(b"other").unwrap()
        );
    }

    #[test]
    fn path_traversal_is_refused() {
        let registry = temp_registry();
        for attempt in [
            "../../etc/passwd",
            "..",
            "/etc/passwd",
            "aa/../bb",
            "",
            "not-hex-but-exactly-sixty-four-characters-long-xxxxxxxxxxxxxxxxxx",
        ] {
            assert!(
                registry.read(attempt).is_err(),
                "registry served a non-hash name: {attempt:?}"
            );
            assert!(!registry.contains(attempt));
        }
    }

    #[test]
    fn a_missing_hash_is_not_found() {
        let registry = temp_registry();
        let absent = "0".repeat(64);
        assert!(!registry.contains(&absent));
        assert!(registry.read(&absent).is_err());
    }

    #[test]
    fn oversized_artifacts_are_refused() {
        let registry = temp_registry();
        let huge = vec![0u8; MAX_ARTIFACT_BYTES + 1];
        assert!(registry.put(&huge).is_err());
    }
}
