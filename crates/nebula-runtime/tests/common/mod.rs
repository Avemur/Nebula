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

/// A single-shot HTTP server on loopback, returning its port.
///
/// A real socket rather than a mock: the client under test is hand-written, and
/// the bugs it can have (framing, the `Host` header, reading to EOF) are
/// exactly the ones a mock would paper over.
pub fn one_shot_server(response: &'static str) -> u16 {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}
