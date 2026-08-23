//! The JavaScript interpreter guest of README.md §22.1.
//!
//! Three claims are under test, and they are different claims:
//!
//! 1. **It works as a tool.** Source in on stdin, output out on stdout, objects
//!    rendered legibly, and a thrown exception reported rather than swallowed.
//! 2. **It is still a guest.** §6's ceilings apply to an interpreter exactly as
//!    they apply to anything else, even though it now parses attacker-authored
//!    source on every request.
//! 3. **The cost is where the measurement says it is.** The Wizer snapshot is
//!    verified to take — and then measured, and it turns out to buy almost
//!    nothing here. §22.1 records that rather than the hope it replaced.
//!
//! Requires the artifacts from `bash guests/build.sh`; without them these skip
//! rather than failing on a machine with no `wasm32-wasip1` target or `wizer`.

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use nebula_runtime::{HostCtx, Runtime, INIT_EXPORT};

/// What "usable as an agent tool" means numerically: a comfortable fraction of
/// the 50 ms default deadline, with enough margin that a loaded machine does
/// not turn the benchmark into a flaky trap. Measured at ~4 ms.
const MAX_EXECUTION: Duration = Duration::from_millis(25);

const SAMPLES: usize = 9;

fn dist(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../guests/interpreters/js/dist")
        .join(name)
}

/// The wizened artifact — the one that would actually be deployed.
fn interpreter() -> Option<Vec<u8>> {
    std::fs::read(dist("initialized.wasm")).ok()
}

fn skip(what: &str) {
    eprintln!(
        "SKIPPED ({what}): JS interpreter artifacts missing. Build them with \
         `bash guests/build.sh` (needs `rustup target add wasm32-wasip1` and \
         `cargo install wizer --all-features`)."
    );
}

/// Evaluates `source` and returns the trimmed response body.
///
/// Goes through `output()` rather than `stdout()` deliberately: that is the
/// method the worker uses to build the response (§22.1), so this exercises the
/// path a real request takes.
fn eval(runtime: &Runtime, wasm: &[u8], source: &str) -> String {
    String::from_utf8(run(runtime, wasm, source).output())
        .expect("interpreter output is utf-8")
        .trim()
        .to_string()
}

fn run(runtime: &Runtime, wasm: &[u8], source: &str) -> HostCtx {
    match runtime.execute(wasm, "run", "js", source.as_bytes().to_vec()) {
        Ok(ctx) => ctx,
        Err(err) if err.downcast_ref::<wasmtime::Trap>() == Some(&wasmtime::Trap::Interrupt) => {
            panic!(
                "the interpreter hit the {}ms epoch deadline evaluating `{source}`. On a \
                 wizened artifact that is a real regression — the realm should already \
                 exist — so check that `bash guests/build.sh` ran Wizer.",
                nebula_runtime::engine::DEFAULT_DEADLINE_TICKS
            )
        }
        Err(err) => panic!("interpreter should run cleanly: {err:?}"),
    }
}

// ---------------------------------------------------------------------------
// It works as a tool
// ---------------------------------------------------------------------------

#[test]
fn agent_authored_source_arrives_as_the_request_body() {
    let Some(wasm) = interpreter() else {
        return skip("source as payload");
    };
    let runtime = Runtime::new(common::temp_dir("js-eval")).expect("runtime");

    // The completion value is the answer, so the smallest useful tool call is
    // an expression and nothing else.
    assert_eq!(eval(&runtime, &wasm, "1 + 1"), "2");
    assert_eq!(eval(&runtime, &wasm, "[3,1,2].sort().join('-')"), "1-2-3");

    // console.log is what an agent reaches for by reflex.
    assert_eq!(
        eval(&runtime, &wasm, "console.log('hello'); undefined"),
        "hello"
    );

    // Objects render as JSON, not as `[object Object]`, which would tell an
    // agent nothing at all.
    assert_eq!(
        eval(&runtime, &wasm, "({a: 1, b: [2]})"),
        r#"{"a":1,"b":[2]}"#
    );

    // A statement-only script must not have a spurious `undefined` appended.
    assert_eq!(eval(&runtime, &wasm, "let x = 5;"), "");

    // The realm is complete, not a toy: these are the intrinsics that make
    // building one expensive in the first place.
    assert_eq!(
        eval(&runtime, &wasm, "JSON.stringify({n: Math.max(1,2)})"),
        r#"{"n":2}"#
    );
    assert_eq!(eval(&runtime, &wasm, "'a1b2'.replace(/[0-9]/g, '')"), "ab");
}

#[test]
fn a_thrown_exception_is_reported_not_swallowed() {
    let Some(wasm) = interpreter() else {
        return skip("exception reporting");
    };
    let runtime = Runtime::new(common::temp_dir("js-throw")).expect("runtime");

    // §22.1: an uncaught exception is a successful execution of the sandbox.
    // The tenant's program ran and threw, exactly as `node -e` would report —
    // and `X-Nebula-Fault` stays reserved for Nebula failing, which is the
    // distinction an agent has to act on differently.
    let output = eval(&runtime, &wasm, "null.x");
    assert!(
        output.starts_with("Uncaught"),
        "an exception must be reported with a prefix an agent can match: {output}"
    );
    assert!(
        output.contains("TypeError"),
        "the error class is the half an agent can act on: {output}"
    );

    // A syntax error is the most likely failure of generated code, and it
    // happens before any evaluation at all.
    let output = eval(&runtime, &wasm, "function (");
    assert!(
        output.starts_with("Uncaught"),
        "a syntax error must be reported too: {output}"
    );
}

#[test]
fn one_scripts_globals_cannot_reach_the_next_request() {
    let Some(wasm) = interpreter() else {
        return skip("isolation");
    };
    let runtime = Runtime::new(common::temp_dir("js-isolation")).expect("runtime");

    // The snapshot is mapped copy-on-write into a *fresh instance per request*
    // (§4.2). This is the test that would catch someone "optimising" that into
    // a reused instance — the change that would make §13 need an argument
    // instead of a structure.
    assert_eq!(
        eval(&runtime, &wasm, "globalThis.leak = 'secret'; 'set'"),
        "set"
    );
    assert_eq!(eval(&runtime, &wasm, "typeof globalThis.leak"), "undefined");
}

// ---------------------------------------------------------------------------
// It is still a guest
// ---------------------------------------------------------------------------

#[test]
fn the_interpreter_is_bounded_by_the_same_ceilings_as_any_other_guest() {
    let Some(wasm) = interpreter() else {
        return skip("sandbox ceilings");
    };
    let runtime = Runtime::new(common::temp_dir("js-sandbox")).expect("runtime");

    // The guest is now a compiler running attacker-authored source on every
    // request (§22.1). That does not weaken the threat model, and this is the
    // test that says so out loud: an infinite loop in JS is still just an
    // infinite loop in WASM, and the epoch deadline of §6.1 ends it.
    let err = runtime
        .execute(&wasm, "run", "js", b"while (true) {}".to_vec())
        .expect_err("an infinite loop must not return");
    assert_eq!(
        err.downcast_ref::<wasmtime::Trap>(),
        Some(&wasmtime::Trap::Interrupt),
        "a runaway script must hit the epoch deadline, not run forever: {err:?}"
    );

    // Allocation is bounded by §6.3 the same way. The guest either traps or is
    // interrupted while trying; what must not happen is a successful
    // unbounded allocation.
    let err = runtime
        .execute(
            &wasm,
            "run",
            "js",
            b"const a = []; for (;;) a.push(new Array(100000).fill(7));".to_vec(),
        )
        .expect_err("an unbounded allocation must not succeed");
    eprintln!("js allocation storm ended as: {err}");
}

// ---------------------------------------------------------------------------
// Wizer is what makes it viable
// ---------------------------------------------------------------------------

/// The snapshot took, and the honest cost breakdown that goes with it.
///
/// The mechanism is asserted; the *size* of the win is only reported. That
/// split is deliberate — see the timings this prints. Building a JS realm turns
/// out to be roughly half a millisecond in Boa, while instantiating a 7 MiB
/// module is roughly four. So Wizer is a real but modest win here, and
/// asserting a large multiple would be asserting a number the machine does not
/// produce. §22.1 records the measurement rather than the hope.
#[test]
fn the_realm_arrives_snapshotted_rather_than_rebuilt() {
    let (Ok(raw), Ok(wizened)) = (
        std::fs::read(dist("nebula_js.wasm")),
        std::fs::read(dist("initialized.wasm")),
    ) else {
        return skip("wizer measurement");
    };

    let runtime = Runtime::new(common::temp_dir("js-wizer")).expect("runtime");

    let raw_module = runtime
        .cache()
        .get_or_compile(runtime.engine(), runtime.linker(), &raw)
        .expect("compile raw");
    let wizened_module = runtime
        .cache()
        .get_or_compile(runtime.engine(), runtime.linker(), &wizened)
        .expect("compile wizened");
    assert!(raw_module.module.get_export(INIT_EXPORT).is_some());
    assert!(
        wizened_module.module.get_export(INIT_EXPORT).is_none(),
        "wizer must consume and drop {INIT_EXPORT}"
    );

    // The discriminating assertion, and the reason `realm_probe` exists. `run`
    // rebuilds the realm when it finds an empty slot, so a snapshot that never
    // took would still produce correct answers — just slower — and every test
    // above would pass while the feature was broken. The wizened artifact has
    // no `_initialize` for the host to call, so `warm` has exactly one possible
    // cause.
    let probe = String::from_utf8(
        runtime
            .execute(&wizened, "realm_probe", "js", Vec::new())
            .expect("probe runs")
            .stdout(),
    )
    .expect("utf-8");
    assert_eq!(
        probe.trim(),
        "warm",
        "the wizened artifact built its realm at request time, so the Wizer \
         snapshot did not take"
    );

    // Same answer from both, or "faster" would only mean "did less".
    const PROGRAM: &str = "JSON.stringify([1,2,3].map(n => n * Math.PI))";
    let raw_answer = eval(&runtime, &raw, PROGRAM);
    let wizened_answer = eval(&runtime, &wizened, PROGRAM);
    assert_eq!(
        raw_answer, wizened_answer,
        "the snapshotted realm must behave identically to a freshly built one"
    );
    assert!(
        raw_answer.starts_with('['),
        "expected a JSON array, got: {raw_answer}"
    );

    let raw_time = median(&runtime, &raw, PROGRAM);
    let wizened_time = median(&runtime, &wizened, PROGRAM);
    let deadline =
        nebula_runtime::engine::EPOCH_TICK * nebula_runtime::engine::DEFAULT_DEADLINE_TICKS as u32;

    eprintln!(
        "js interpreter ({} MiB artifact): raw {raw_time:?}, wizened {wizened_time:?}",
        wizened.len() >> 20
    );
    eprintln!(
        "share of the {deadline:?} request budget: raw {:.0}%, wizened {:.0}%",
        100.0 * raw_time.as_secs_f64() / deadline.as_secs_f64(),
        100.0 * wizened_time.as_secs_f64() / deadline.as_secs_f64()
    );

    // The claim that actually matters for a tool: it serves well inside the
    // default deadline. Stable by roughly 6x, unlike a ratio between two
    // numbers that differ by 10%.
    assert!(
        wizened_time < MAX_EXECUTION,
        "the interpreter must serve inside the request budget: {wizened_time:?}"
    );
}

/// Instantiation cost is dominated by artifact size, not by boot work.
///
/// This is the finding that reframes §22.1, so it gets its own test rather than
/// living in a comment: a 7 MiB interpreter costs milliseconds to instantiate
/// before it does anything, and no amount of pre-initialization changes that.
/// The lever for a faster JS tool is a smaller interpreter.
#[test]
fn instantiation_cost_tracks_artifact_size() {
    let Some(big) = interpreter() else {
        return skip("size scaling");
    };
    let runtime = Runtime::new(common::temp_dir("js-size")).expect("runtime");

    const TINY: &str = r#"(module (func (export "run")))"#;
    let tiny_time = median_of(|| {
        runtime
            .execute(TINY.as_bytes(), "run", "js", Vec::new())
            .expect("tiny runs");
    });
    // `realm_probe` rather than `run`: no parsing, no evaluation, so what is
    // left is instantiation and nothing else.
    let big_time = median_of(|| {
        runtime
            .execute(&big, "realm_probe", "js", Vec::new())
            .expect("interpreter runs");
    });

    eprintln!(
        "instantiate: {} B module {tiny_time:?}, {} MiB module {big_time:?}",
        TINY.len(),
        big.len() >> 20
    );

    assert!(
        big_time > tiny_time * 3,
        "expected artifact size to dominate instantiation: tiny {tiny_time:?} \
         vs {big_time:?}. If this stops being true the guidance in §22.1 — that \
         interpreter size is the lever — needs remeasuring."
    );
}

fn median_of(mut once: impl FnMut()) -> Duration {
    let mut timings: Vec<Duration> = (0..SAMPLES)
        .map(|_| {
            let start = Instant::now();
            once();
            start.elapsed()
        })
        .collect();
    timings.sort();
    timings[SAMPLES / 2]
}

fn median(runtime: &Runtime, wasm: &[u8], source: &str) -> Duration {
    // Warm the compile cache so the timings measure execution, not Cranelift.
    let _ = eval(runtime, wasm, source);

    let mut timings: Vec<Duration> = (0..SAMPLES)
        .map(|_| {
            let start = Instant::now();
            run(runtime, wasm, source);
            start.elapsed()
        })
        .collect();
    timings.sort();
    timings[SAMPLES / 2]
}
