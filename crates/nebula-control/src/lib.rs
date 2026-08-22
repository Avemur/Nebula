//! Control plane: scheduler, module registry, membership (§3.1).
//!
//! Library plus binary rather than a bare binary so the scheduler and the
//! membership tracker are testable on their own — and so `pub` means something
//! instead of every method tripping `dead_code` until `main` happens to call it.
//!
//! Serves two surfaces: the `NebulaControl` gRPC mesh that workers speak, and
//! the HTTP gateway of §11.1 that clients speak.

pub mod gateway;
pub mod membership;
pub mod registry;
pub mod ring;
pub mod server;
pub mod wizer;

/// Structured span output on stdout (§14).
///
/// `FmtSpan::CLOSE` is the whole point: it prints each span's *duration* when it
/// closes, which is what turns the span tree into a latency breakdown rather
/// than a log. Filter with `NEBULA_LOG`, e.g. `NEBULA_LOG=nebula_control=debug`.
///
/// No OpenTelemetry collector: `tracing` alone answers "where did the time go",
/// and a collector is infrastructure to run, not a question to answer.
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
