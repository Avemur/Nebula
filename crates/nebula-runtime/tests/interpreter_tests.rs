//! The JavaScript interpreter guest of README.md §22.1.
//!
//! Three claims are under test, and they are different claims:
//!
//! 1. **It works as a tool.** Source in on stdin, output out on stdout, objects
//!    rendered legibly, and a thrown exception reported rather than swallowed.
//! 2. **It is still a guest.** §6's ceilings apply to an interpreter exactly as
//!    they apply to anything else, even though it now parses attacker-authored
//!    source on every request.
//! 3. **The cost is where the measurement says it is.** Instantiating a 7 MiB
//!    module dominates everything else this guest does, which is why it is no
//!    longer wizened — §22.1 measured the snapshot as buying nothing, and
//!    §22.8 needed the import slot Wizer was standing in.
//!
//! Requires the artifacts from `bash guests/build.sh`; without them these skip
//! rather than failing on a machine with no `wasm32-wasip1` target or `wizer`.

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use nebula_runtime::egress::Policy;
use nebula_runtime::{HostCtx, Runtime, INIT_EXPORT};

const SAMPLES: usize = 9;

fn dist(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../guests/interpreters/js/dist")
        .join(name)
}

/// The artifact that would actually be deployed.
fn interpreter() -> Option<Vec<u8>> {
    std::fs::read(dist("nebula_js.wasm")).ok()
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
                "the interpreter hit the {}ms epoch deadline evaluating `{source}`. \
                 Building the realm plus instantiating a 7 MiB module is ~4 ms, so \
                 this is a loaded machine or a real regression, not a tight budget.",
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

/// The interpreter must not export the WASI reactor initializer.
///
/// This is a build-breaking invariant, not a preference. `PUT /functions/{id}`
/// runs Wizer on anything exporting `_initialize` (§11.1), and Wizer has to
/// instantiate the module to run it — which it cannot do, because
/// `nebula.http_get` is not a WASI import. Re-adding the export would turn
/// every deploy of this guest into a `400`, and the only clue would be a Wizer
/// error about an unsatisfiable import.
#[test]
fn the_interpreter_does_not_ask_to_be_wizened() {
    let Some(wasm) = interpreter() else {
        return skip("wizer opt-out");
    };
    let runtime = Runtime::new(common::temp_dir("js-nowizen")).expect("runtime");
    let module = runtime
        .cache()
        .get_or_compile(runtime.engine(), runtime.linker(), &wasm)
        .expect("compile");

    assert!(
        module.module.get_export(INIT_EXPORT).is_none(),
        "the interpreter exports {INIT_EXPORT}, so the deploy pipeline will try \
         to wizen it and fail on the `nebula.http_get` import"
    );
    assert!(
        std::fs::read(dist("initialized.wasm")).is_err(),
        "a stale wizened artifact is still on disk; re-run `bash guests/build.sh`"
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

// ---------------------------------------------------------------------------
// Egress (§22.8)
// ---------------------------------------------------------------------------

#[test]
fn a_script_cannot_reach_the_network_by_default() {
    let Some(wasm) = interpreter() else {
        return skip("egress default");
    };
    // No `with_egress`, so the policy is empty. This is the default a fresh
    // deployment runs with, and it is the only thing between an agent-authored
    // script and the rest of the network.
    let runtime = Runtime::new(common::temp_dir("js-egress-off")).expect("runtime");

    let answer = eval(
        &runtime,
        &wasm,
        "try { httpGet('http://example.com/'); 'reached' } catch (e) { 'blocked' }",
    );
    assert_eq!(answer, "blocked");
}

#[test]
fn a_refusal_is_catchable_javascript_rather_than_a_dead_script() {
    let Some(wasm) = interpreter() else {
        return skip("egress refusal");
    };
    let runtime = Runtime::new(common::temp_dir("js-egress-refuse"))
        .expect("runtime")
        .with_egress(Policy::new(["api.example.com"]));

    // A refusal has to be an exception a script can catch, not a trap and not
    // an empty string. An empty string would be indistinguishable from a page
    // that really was empty, and a trap would kill a script for asking a
    // question it was allowed to ask and told no (§7.2).
    let answer = eval(
        &runtime,
        &wasm,
        "try { httpGet('http://blocked.test/'); 'reached' } catch (e) { 'caught: ' + e.message }",
    );
    assert!(answer.starts_with("caught: "), "{answer}");
    assert!(answer.contains("blocked.test"), "{answer}");
}

#[test]
fn an_allowed_host_comes_back_to_the_script_whole() {
    let Some(wasm) = interpreter() else {
        return skip("egress fetch");
    };
    let port = common::one_shot_server(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nhello, agent!",
    );

    // Loopback needs the escape hatch; the address check has its own tests.
    let runtime = Runtime::new(common::temp_dir("js-egress-on"))
        .expect("runtime")
        .with_egress(Policy::new(["127.0.0.1"]).allow_private_addresses());

    // The whole point of the feature, from the layer an agent actually writes
    // at: source in, network out, text back.
    let answer = eval(
        &runtime,
        &wasm,
        &format!("httpGet('http://127.0.0.1:{port}/').split('\\r\\n\\r\\n')[1]"),
    );
    assert_eq!(answer, "hello, agent!");
}
