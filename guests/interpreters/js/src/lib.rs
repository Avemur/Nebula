//! A JavaScript interpreter guest (README.md §22.1).
//!
//! This is the guest that makes Nebula usable by an LLM agent. An agent writes
//! JavaScript; it does not compile Rust to `wasm32-wasip1`. So rather than
//! deploying a module per snippet — a toolchain, a `PUT`, a new `function_id`
//! and a guaranteed cache miss every time — this module is deployed **once**
//! and the agent's source arrives as the **request body**. Every snippet then
//! runs on the hot path of §4.2 and hits the module cache.
//!
//! # Interface
//!
//! * **stdin** — the source to evaluate. The runtime pipes the request body in.
//! * **stdout** — the response body: whatever `console.log` printed, followed by
//!   the completion value when it is not `undefined`.
//!
//! Nothing but WASI is imported, and that is not a style choice: Wizer has to
//! instantiate the module to run `_initialize`, so every import must be
//! satisfiable at build time (README.md R2). `nebula.request_read` and
//! `nebula.response_write` are therefore unavailable here, and stdin/stdout
//! carry the request instead.
//!
//! # Why Wizer matters more here than anywhere else
//!
//! Building a JS realm means constructing every intrinsic — `Object`, `Array`,
//! `JSON`, `Math`, `RegExp` — before a single line of user code runs. That is
//! the §4.3 boot cost in its purest form. `_initialize` builds the realm and
//! parks it; Wizer runs that at build time and snapshots the result into the
//! module's data segments, so each request starts from a realm that is already
//! there via `memory_init_cow`.
//!
//! # Isolation
//!
//! The snapshot is restored copy-on-write into a *fresh instance per request*
//! (§4.2), so a script that scribbles on `globalThis` scribbles on its own
//! private copy and it dies with the instance. The invariant is unchanged.

use std::cell::RefCell;
use std::io::Read;

use boa_engine::{js_string, Context, JsError, JsResult, JsValue, NativeFunction, Source};

// A thread local rather than a `static`: `Context` is `!Sync`, and
// `wasm32-wasip1` is single-threaded, so this compiles down to a plain
// location in linear memory — which is exactly what Wizer snapshots.
thread_local! {
    /// The realm, built once and snapshotted by Wizer.
    static ENGINE: RefCell<Option<Context>> = const { RefCell::new(None) };
}

/// Console shim, in JS because it is shorter in JS.
///
/// `__nebula_fmt` exists because `String({a: 1})` is `"[object Object]"`, which
/// tells an agent nothing. JSON first, `String` as the fallback — and the
/// `catch` covers cyclic structures, which throw rather than returning
/// `undefined`.
const PRELUDE: &str = r#"
globalThis.__nebula_fmt = (v) => {
  if (typeof v === 'string') return v;
  try { const s = JSON.stringify(v); return s === undefined ? String(v) : s; }
  catch (e) { return String(v); }
};
globalThis.console = {
  log:   (...a) => __nebula_print(a.map(__nebula_fmt).join(' ')),
  info:  (...a) => __nebula_print(a.map(__nebula_fmt).join(' ')),
  warn:  (...a) => __nebula_print(a.map(__nebula_fmt).join(' ')),
  error: (...a) => __nebula_print(a.map(__nebula_fmt).join(' ')),
  debug: (...a) => __nebula_print(a.map(__nebula_fmt).join(' ')),
};
"#;

/// Backs the console shim. A Rust closure inside the guest, not a WASM import —
/// which is the only reason the console survives wizening.
fn print(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let line = args.first().cloned().unwrap_or_default().to_string(ctx)?;
    println!("{}", line.to_std_string_escaped());
    Ok(JsValue::undefined())
}

fn build() -> Context {
    let mut ctx = Context::default();
    ctx.register_global_callable(
        js_string!("__nebula_print"),
        1,
        NativeFunction::from_fn_ptr(print),
    )
    .expect("register __nebula_print");
    // Panicking here is deliberate: it fails the Wizer step loudly at build
    // time rather than shipping an artifact whose console is silently missing.
    ctx.eval(Source::from_bytes(PRELUDE)).expect("prelude");
    ctx
}

/// Run by Wizer at build time; run by the host per request if this artifact was
/// never wizened (§4.3).
#[export_name = "_initialize"]
pub extern "C" fn initialize() {
    ENGINE.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(build());
        }
    });
}

/// Diagnostic export: prints `warm` if the realm arrived already built.
///
/// `run` falls back to building the realm when it finds an empty slot, which is
/// the right behaviour and also the perfect way to hide a snapshot that never
/// took — both artifacts would work, one would just be slower, and a benchmark
/// would report the difference as noise. Called on the wizened artifact, which
/// has no `_initialize` for the host to call, `warm` can only mean the snapshot.
#[export_name = "realm_probe"]
pub extern "C" fn realm_probe() {
    ENGINE.with(|cell| {
        println!("{}", if cell.borrow().is_some() { "warm" } else { "cold" });
    });
}

/// The handler. Reads source from stdin, evaluates it, prints what it produced.
#[export_name = "run"]
pub extern "C" fn run() {
    let mut source = Vec::new();
    if let Err(err) = std::io::stdin().read_to_end(&mut source) {
        println!("Uncaught Error: could not read request body: {err}");
        return;
    }

    ENGINE.with(|cell| {
        let mut slot = cell.borrow_mut();
        // `get_or_insert_with` rather than `expect`: an un-wizened artifact is
        // slow, not broken, and it is the control arm of the benchmark.
        let ctx = slot.get_or_insert_with(build);
        eval(ctx, &source);
    });
}

/// Evaluate, then report.
///
/// **An uncaught exception is a 200, not a fault.** The sandbox did its job:
/// the tenant's program ran and threw, exactly as `node -e` would report it.
/// `X-Nebula-Fault` (§11.1) stays reserved for Nebula failing — a timeout, a
/// memory ceiling, an unreachable worker — because those are the ones an agent
/// must handle differently from "my code has a bug in it".
fn eval(ctx: &mut Context, source: &[u8]) {
    let value = match ctx.eval(Source::from_bytes(source)) {
        Ok(value) => value,
        Err(err) => {
            println!("Uncaught {err}");
            return;
        }
    };

    // A statement-only script completes with `undefined`; printing that would
    // append a spurious line to every response that only used `console.log`.
    if value.is_undefined() {
        return;
    }

    match format_value(ctx, &value) {
        Ok(text) => println!("{text}"),
        Err(err) => println!("Uncaught {err}"),
    }
}

/// Formats through the same `__nebula_fmt` the console uses, so the completion
/// value and a logged value never render differently.
fn format_value(ctx: &mut Context, value: &JsValue) -> JsResult<String> {
    let fmt = ctx.global_object().get(js_string!("__nebula_fmt"), ctx)?;
    let fmt = fmt
        .as_callable()
        .ok_or_else(|| {
            JsError::from_opaque(JsValue::from(js_string!("__nebula_fmt is missing")))
        })?;
    let text = fmt.call(&JsValue::undefined(), &[value.clone()], ctx)?;
    Ok(text.to_string(ctx)?.to_std_string_escaped())
}
