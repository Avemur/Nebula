//! Worker node: the gRPC receiver wrapped around `nebula-runtime` (§3.2).
//!
//! Library plus binary so the pool, the service, and the heartbeat loop are
//! testable without launching a process.

pub mod exec_pool;
pub mod heartbeat;
pub mod server;

/// Structured span output on stdout (§14).
///
/// `FmtSpan::CLOSE` prints each span's duration as it closes, which is what
/// turns `grpc_execute → fetch_module → compile_l1 → wasm_execute` into a
/// latency breakdown instead of a log. Filter with `NEBULA_LOG`.
///
/// Idempotent, so tests may call it freely.
pub fn init_tracing() {
    init_tracing_with_default("info");
}

/// As [`init_tracing`], with an explicit default filter.
///
/// Tests pass `"off"` so a normal `cargo test` stays quiet; set `NEBULA_LOG`
/// to turn the tree back on for one run.
pub fn init_tracing_with_default(default: &str) {
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::EnvFilter;

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("NEBULA_LOG").unwrap_or_else(|_| EnvFilter::new(default)),
        )
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .try_init();
}
