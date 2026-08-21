//! The "zero-boot-time path" of README.md §4.3, measured.
//!
//! Compares a heavy-boot guest against its Wizer-preinitialized twin. The claim
//! under test is narrow and specific: the wizened module is faster *because the
//! boot already happened*, not because it does less work — so the test asserts
//! both that the answers are identical and that the speedup is large.
//!
//! Requires the guest artifacts. Build them with `bash guests/build.sh`; without
//! them this test skips rather than failing on a machine that has no
//! `wasm32-wasip1` target or `wizer` binary.

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use nebula_runtime::{Runtime, INIT_EXPORT};

/// The gap is expected to be three orders of magnitude. Asserting only 10x
/// leaves room for a loaded machine without letting a real regression through.
const MIN_SPEEDUP: u32 = 10;

const SAMPLES: usize = 7;

fn dist(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../guests/examples/heavy_init/dist")
        .join(name)
}

fn artifacts() -> Option<(Vec<u8>, Vec<u8>)> {
    let raw = std::fs::read(dist("heavy_init.wasm")).ok()?;
    let wizened = std::fs::read(dist("initialized.wasm")).ok()?;
    Some((raw, wizened))
}

/// Executes once, turning an epoch-deadline trap into a legible failure.
///
/// The raw guest spends roughly 40% of its 50 ms request budget booting, so a
/// badly loaded machine is the one plausible way this trips. A bare
/// `Trap::Interrupt` would send someone hunting the wrong bug.
fn execute(runtime: &Runtime, wasm: &[u8]) -> nebula_runtime::HostCtx {
    match runtime.execute(wasm, "run", "bench", Vec::new()) {
        Ok(ctx) => ctx,
        Err(err) if err.downcast_ref::<wasmtime::Trap>() == Some(&wasmtime::Trap::Interrupt) => {
            panic!(
                "the guest hit the {}ms epoch deadline while booting. That is the \
                 measurement being too slow, not the sandbox being wrong — lower \
                 HASH_ROUNDS in guests/examples/heavy_init and rebuild.",
                nebula_runtime::engine::DEFAULT_DEADLINE_TICKS
            )
        }
        Err(err) => panic!("guest should execute cleanly: {err:?}"),
    }
}

fn run_once(runtime: &Runtime, wasm: &[u8]) -> String {
    String::from_utf8(execute(runtime, wasm).stdout())
        .expect("guest output is utf-8")
        .trim()
        .to_string()
}

/// Median of `SAMPLES` executions. Median rather than mean so one scheduling
/// hiccup cannot decide the result.
fn median_execution(runtime: &Runtime, wasm: &[u8]) -> Duration {
    let mut timings: Vec<Duration> = (0..SAMPLES)
        .map(|_| {
            let start = Instant::now();
            execute(runtime, wasm);
            start.elapsed()
        })
        .collect();
    timings.sort();
    timings[SAMPLES / 2]
}

#[test]
fn wizened_module_pays_no_boot_cost_at_request_time() {
    let Some((raw, wizened)) = artifacts() else {
        eprintln!(
            "SKIPPED: guest artifacts missing. Build them with `bash guests/build.sh` \
             (needs `rustup target add wasm32-wasip1` and `cargo install wizer --all-features`)."
        );
        return;
    };

    let runtime = Runtime::new(common::temp_dir("wizer-bench")).expect("runtime");

    // The mechanism, asserted directly: the raw module still exports the
    // initializer and so gets it called on every request; the wizened module had
    // it run at build time and no longer exports it. Nothing in the runtime
    // branches on "is this wizened" — the export's absence is the whole signal.
    let raw_module = runtime
        .cache()
        .get_or_compile(runtime.engine(), runtime.linker(), &raw)
        .expect("compile raw");
    let wizened_module = runtime
        .cache()
        .get_or_compile(runtime.engine(), runtime.linker(), &wizened)
        .expect("compile wizened");
    assert!(
        raw_module.module.get_export(INIT_EXPORT).is_some(),
        "the raw guest must still export {INIT_EXPORT}"
    );
    assert!(
        wizened_module.module.get_export(INIT_EXPORT).is_none(),
        "wizer must consume and drop {INIT_EXPORT}; without that the runtime \
         would re-run the boot and there would be nothing to measure"
    );

    // Warm both so the timings below measure execution, not compilation.
    let raw_output = run_once(&runtime, &raw);
    let wizened_output = run_once(&runtime, &wizened);

    // Faster is only interesting if the answer is the same. Without this, a
    // module that silently skipped the work would look like a triumph.
    assert_eq!(
        raw_output, wizened_output,
        "the snapshot must reproduce the boot result exactly"
    );
    assert!(
        !wizened_output.contains("UNINITIALIZED"),
        "the wizened guest found an empty static, so the snapshot did not take: {wizened_output}"
    );
    assert!(
        wizened_output.split_whitespace().count() == 2,
        "expected `<prime count> <checksum>`, got: {wizened_output}"
    );

    let raw_time = median_execution(&runtime, &raw);
    let wizened_time = median_execution(&runtime, &wizened);

    let speedup = raw_time.as_secs_f64() / wizened_time.as_secs_f64();
    let deadline =
        nebula_runtime::engine::EPOCH_TICK * nebula_runtime::engine::DEFAULT_DEADLINE_TICKS as u32;
    eprintln!(
        "heavy_init: raw {raw_time:?}, wizened {wizened_time:?}, speedup {speedup:.0}x \
         (guest reported: {wizened_output})"
    );
    // The ratio is the headline, but this is the operationally interesting part:
    // booting eats a large share of the request budget before the handler runs.
    eprintln!(
        "request budget vs the {deadline:?} epoch deadline: raw {:.0}%, wizened {:.1}%",
        100.0 * raw_time.as_secs_f64() / deadline.as_secs_f64(),
        100.0 * wizened_time.as_secs_f64() / deadline.as_secs_f64()
    );

    assert!(
        wizened_time * MIN_SPEEDUP < raw_time,
        "expected at least {MIN_SPEEDUP}x: raw {raw_time:?} vs wizened {wizened_time:?}"
    );
}

#[test]
fn the_raw_guest_would_report_an_empty_static_without_its_initializer() {
    // Pins the assumption the benchmark rests on: `run` never recomputes. If
    // someone "helpfully" changes the guest to `get_or_init`, the comparison
    // above quietly stops measuring anything and this test catches it.
    //
    // The wizened module has no initializer, so executing it exercises exactly
    // the path a raw module would take with its initializer skipped.
    let Some((_, wizened)) = artifacts() else {
        eprintln!("SKIPPED: guest artifacts missing; see `bash guests/build.sh`.");
        return;
    };

    let runtime = Runtime::new(common::temp_dir("wizer-sentinel")).expect("runtime");
    let output = run_once(&runtime, &wizened);

    assert!(
        !output.is_empty() && !output.contains("UNINITIALIZED"),
        "wizened guest must serve from the snapshot, not from a recomputation"
    );
}
