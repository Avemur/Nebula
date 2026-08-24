//! Control plane: scheduler, module registry, membership (§3.1).
//!
//! Library plus binary rather than a bare binary so the scheduler and the
//! membership tracker are testable on their own — and so `pub` means something
//! instead of every method tripping `dead_code` until `main` happens to call it.
//!
//! Serves two surfaces: the `NebulaControl` gRPC mesh that workers speak, and
//! the HTTP gateway of §11.1 that clients speak.

pub mod gateway;
pub mod idempotency;
pub mod membership;
pub mod ratelimit;
pub mod registry;
pub mod ring;
pub mod server;
pub mod trace;
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

#[cfg(test)]
mod architecture {
    /// The control plane must never gain a compiler.
    ///
    /// §11.1 makes this an architectural boundary, not a preference: Cranelift
    /// compiling a hostile artifact is the largest attack surface in the system,
    /// and it belongs on a replaceable worker rather than on the node that owns
    /// routing, membership, and the registry. A boundary nobody checks is a
    /// boundary that erodes on the first convenient afternoon, so this reads the
    /// manifest and fails if the engine ever appears.
    #[test]
    fn the_control_plane_has_no_engine() {
        let manifest = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
        )
        .expect("own manifest");

        // Comments are stripped first. The manifest documents *why* the engine
        // is absent, so a plain substring search finds the explanation and
        // reports it as the violation.
        let declarations: String = manifest
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");

        for forbidden in ["wasmtime", "nebula-runtime"] {
            assert!(
                !declarations.contains(forbidden),
                "nebula-control gained a dependency on `{forbidden}`. Compilation \
                 happens lazily on the worker data plane (README.md §11.1); if \
                 deploy-time validation is genuinely needed, have a *worker* \
                 validate and report back."
            );
        }
    }
}
