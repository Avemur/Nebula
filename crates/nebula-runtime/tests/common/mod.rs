#![allow(dead_code)] // each test binary uses a different subset

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use nebula_runtime::Runtime;

/// One runtime per test binary.
///
/// Every `Runtime` builds an `Engine`, and the pooling allocator reserves
/// address space per engine (risk R1), so tests share one rather than each
/// building its own.
pub fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new(temp_dir("rt")).expect("runtime construction"))
}

/// A fresh, empty directory under the system temp dir.
pub fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "nebula-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}
