//! Module registry (README.md §3.1, §8.1).
//!
//! Local disk in v1. Artifacts are addressed by SHA-256 of their bytes, never by
//! `function_id`, so a new version is a new name and there is no invalidation
//! protocol.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The deployment table lives beside the artifacts it names.
pub const DEPLOYMENTS_FILE: &str = "deployments.json";

/// On-disk format version for [`Deployments`].
pub const DEPLOYMENTS_VERSION: u32 = 1;

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

    fn deployments_path(&self) -> PathBuf {
        self.dir.join(DEPLOYMENTS_FILE)
    }

    /// Reads the deployment table, or an empty one on a fresh node.
    ///
    /// A missing file is normal. A *corrupt* one is not silently discarded —
    /// that would look like every function vanishing with no explanation — so it
    /// surfaces as an error the caller has to decide about.
    pub fn load_deployments(&self) -> io::Result<Deployments> {
        match fs::read(self.deployments_path()) {
            Ok(bytes) => {
                let deployments: Deployments = serde_json::from_slice(&bytes)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                if deployments.version != DEPLOYMENTS_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "deployments.json is version {}, expected {DEPLOYMENTS_VERSION}",
                            deployments.version
                        ),
                    ));
                }
                Ok(deployments)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Deployments::new()),
            Err(err) => Err(err),
        }
    }

    /// Writes the deployment table via a temporary and a rename, so a crash
    /// mid-write leaves the previous table intact rather than a half file.
    pub fn save_deployments(&self, deployments: &Deployments) -> io::Result<()> {
        let path = self.deployments_path();
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        fs::write(&tmp, serde_json::to_vec_pretty(deployments)?)?;
        fs::rename(&tmp, &path)
    }
}

/// The name-to-artifact table, kept beside the artifacts it points at.
///
/// One file rather than a file per function: a `function_id` arrives from a URL,
/// and the surest way not to have to defend it against path traversal is never
/// to put it in a path.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Deployments {
    /// Bumped when the on-disk shape changes. An unrecognised version is
    /// refused rather than half-read.
    pub version: u32,
    /// `function_id` to content hash. Ordered so the file has a stable diff.
    pub functions: BTreeMap<String, String>,
}

impl Deployments {
    pub fn new() -> Self {
        Self {
            version: DEPLOYMENTS_VERSION,
            functions: BTreeMap::new(),
        }
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
    fn deployments_round_trip_across_a_restart() {
        let registry = temp_registry();
        assert!(registry.load_deployments().unwrap().functions.is_empty());

        let mut deployments = Deployments::new();
        deployments
            .functions
            .insert("echo".to_string(), "a".repeat(64));
        registry.save_deployments(&deployments).unwrap();

        // A second `Registry` over the same directory is what a restart looks
        // like.
        let restarted = Registry::new(registry.dir()).unwrap();
        let loaded = restarted.load_deployments().unwrap();
        assert_eq!(loaded.version, DEPLOYMENTS_VERSION);
        assert_eq!(loaded.functions.get("echo"), Some(&"a".repeat(64)));
    }

    #[test]
    fn a_corrupt_deployment_table_is_reported_not_ignored() {
        // Silently starting empty would look like every function vanishing for
        // no reason.
        let registry = temp_registry();
        std::fs::write(registry.dir().join(DEPLOYMENTS_FILE), b"{not json").unwrap();
        assert!(registry.load_deployments().is_err());
    }

    #[test]
    fn an_unknown_deployment_version_is_refused() {
        let registry = temp_registry();
        std::fs::write(
            registry.dir().join(DEPLOYMENTS_FILE),
            br#"{"version":99,"functions":{}}"#,
        )
        .unwrap();
        assert!(registry.load_deployments().is_err());
    }

    #[test]
    fn oversized_artifacts_are_refused() {
        let registry = temp_registry();
        let huge = vec![0u8; MAX_ARTIFACT_BYTES + 1];
        assert!(registry.put(&huge).is_err());
    }
}
