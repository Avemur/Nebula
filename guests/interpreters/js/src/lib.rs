//! A JavaScript interpreter guest (README.md §22.1).
//!
//! This is the guest that makes Nebula usable by an LLM agent. An agent writes
//! JavaScript; it does not compile Rust to `wasm32-wasip1`. So rather than
//! deploying a module per snippet (a toolchain, a `PUT`, a new `function_id`
//! and a guaranteed cache miss every time), this module is deployed **once**
//! and the agent's source arrives as the **request body**. Every snippet then
//! runs on the hot path of §4.2 and hits the module cache.
//!
//! # Interface
//!
//! * **stdin**: the source to evaluate. The runtime pipes the request body in.
//! * **stdout**: the response body, whatever `console.log` printed, followed by
//!   the completion value when it is not `undefined`.
//! * **`session.get/set`**: state that survives between requests sharing a
//!   partition key (§22.5).
//! * **`httpGet(url)`**: the network, when an operator allows it (§22.8).
//!
//! The request arrives on stdin rather than through `nebula.request_read`
//! because that is what a wizenable guest can do, and this guest is no longer
//! wizened. The channel stayed because it works and because swapping it would
//! change the contract in §22.1 for no gain.
//!
//! # Why this is not wizened
//!
//! It was, until egress landed. Wizer has to instantiate a module to run its
//! initializer, so **every import must be satisfiable at build time** (README.md
//! R2), which means a wizenable guest can import nothing but WASI, and
//! `nebula.http_get` would be unsatisfiable.
//!
//! Giving that up cost nothing, and that is measured rather than assumed: §22.1
//! found Boa builds a realm in well under a millisecond, while the snapshot
//! *added* ~150 KiB to an artifact whose instantiation cost is dominated by
//! size. Raw and wizened measured the same. So the guest keeps no
//! `_initialize`, builds its realm on first use, and can reach the network when
//! an operator allows it.
//!
//! # Isolation
//!
//! Every request gets a *fresh instance* (§4.2), so a script that scribbles on
//! `globalThis` scribbles on its own private copy and it dies with the
//! instance. The invariant is unchanged, and it never depended on the snapshot.

use std::cell::RefCell;
use std::io::Read;

use boa_engine::{
    js_string, Context, JsError, JsNativeError, JsResult, JsValue, NativeFunction, Source,
};

// Outbound HTTP (README.md §22.8). Refused unless an operator allowlisted the
// host, which is why the JS side reports a refusal as an exception rather than
// as an empty string: a script must be able to tell "blocked" from "the page
// was empty".
#[link(wasm_import_module = "nebula")]
extern "C" {
    fn http_get(url_ptr: *const u8, url_len: u32, out_ptr: *mut u8, out_len: u32) -> i32;
    fn kv_get(kptr: *const u8, klen: u32, vptr: *mut u8, vlen: u32) -> i32;
    fn kv_set(kptr: *const u8, klen: u32, vptr: *const u8, vlen: u32) -> i32;
}

/// Matches the host's own cap (§22.8), so the only truncation that can happen
/// is the one the host already refused.
const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Matches the host's per-value cap (§6.4).
const MAX_VALUE_BYTES: usize = 64 << 10;

// A thread local rather than a `static`: `Context` is `!Sync`, and
// `wasm32-wasip1` is single-threaded, so this compiles down to a plain
// location in linear memory.
thread_local! {
    /// The realm, built on first use and reused for the rest of the request.
    static ENGINE: RefCell<Option<Context>> = const { RefCell::new(None) };
}

/// Console shim, in JS because it is shorter in JS.
///
/// `__nebula_fmt` exists because `String({a: 1})` is `"[object Object]"`, which
/// tells an agent nothing. JSON first, `String` as the fallback, and the
/// `catch` covers cyclic structures, which throw rather than returning
/// `undefined`.
const PRELUDE: &str = r#"
globalThis.__nebula_fmt = (v) => {
  if (typeof v === 'string') return v;
  try { const s = JSON.stringify(v); return s === undefined ? String(v) : s; }
  catch (e) { return String(v); }
};
globalThis.httpGet = (url) => __nebula_http_get(String(url));
globalThis.session = {
  get: (k) => __nebula_kv_get(String(k)),
  set: (k, v) => __nebula_kv_set(String(k), typeof v === 'string' ? v : JSON.stringify(v)),
};
globalThis.console = {
  log:   (...a) => __nebula_print(a.map(__nebula_fmt).join(' ')),
  info:  (...a) => __nebula_print(a.map(__nebula_fmt).join(' ')),
  warn:  (...a) => __nebula_print(a.map(__nebula_fmt).join(' ')),
  error: (...a) => __nebula_print(a.map(__nebula_fmt).join(' ')),
  debug: (...a) => __nebula_print(a.map(__nebula_fmt).join(' ')),
};
"#;

/// Backs the console shim. A Rust function inside the guest rather than a WASM
/// import, so it costs the host nothing and needs no policy.
fn print(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let line = args.first().cloned().unwrap_or_default().to_string(ctx)?;
    println!("{}", line.to_std_string_escaped());
    Ok(JsValue::undefined())
}

/// Backs `httpGet`. Returns the raw HTTP response (status line, headers,
/// blank line, body) because a script that cannot tell `200` from `404` will
/// treat an error page as data.
fn fetch(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let url = args
        .first()
        .cloned()
        .unwrap_or_default()
        .to_string(ctx)?
        .to_std_string_escaped();

    let mut buffer = vec![0u8; MAX_RESPONSE_BYTES];
    let written = unsafe {
        http_get(
            url.as_ptr(),
            url.len() as u32,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };

    if written < 0 {
        // The host deliberately does not say *why*: a script told which hosts
        // are blocked can enumerate the allowlist one request at a time (§22.8).
        return Err(JsNativeError::error()
            .with_message(format!("httpGet refused: {url}"))
            .into());
    }

    let written = (written as usize).min(buffer.len());
    Ok(js_string!(String::from_utf8_lossy(&buffer[..written]).as_ref()).into())
}

/// Backs `session.get`. Returns `null` for a key that was never written, which
/// a script needs in order to tell "not yet" from "nothing".
fn session_get(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let key = args
        .first()
        .cloned()
        .unwrap_or_default()
        .to_string(ctx)?
        .to_std_string_escaped();

    let mut buffer = vec![0u8; MAX_VALUE_BYTES];
    let length = unsafe {
        kv_get(
            key.as_ptr(),
            key.len() as u32,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };
    if length < 0 {
        return Ok(JsValue::null());
    }

    let length = (length as usize).min(buffer.len());
    Ok(js_string!(String::from_utf8_lossy(&buffer[..length]).as_ref()).into())
}

/// Backs `session.set`. Returns `true` when the store accepted it.
///
/// A refusal is a boolean rather than an exception: a full node is a condition
/// the script can work around, and §7.2's convention is that recoverable
/// refusals are values.
fn session_set(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let key = args
        .first()
        .cloned()
        .unwrap_or_default()
        .to_string(ctx)?
        .to_std_string_escaped();
    let value = args
        .get(1)
        .cloned()
        .unwrap_or_default()
        .to_string(ctx)?
        .to_std_string_escaped();

    let accepted = unsafe {
        kv_set(
            key.as_ptr(),
            key.len() as u32,
            value.as_ptr(),
            value.len() as u32,
        )
    };
    Ok(JsValue::from(accepted >= 0))
}

fn build() -> Context {
    let mut ctx = Context::default();
    ctx.register_global_callable(
        js_string!("__nebula_print"),
        1,
        NativeFunction::from_fn_ptr(print),
    )
    .expect("register __nebula_print");
    ctx.register_global_callable(
        js_string!("__nebula_http_get"),
        1,
        NativeFunction::from_fn_ptr(fetch),
    )
    .expect("register __nebula_http_get");
    ctx.register_global_callable(
        js_string!("__nebula_kv_get"),
        1,
        NativeFunction::from_fn_ptr(session_get),
    )
    .expect("register __nebula_kv_get");
    ctx.register_global_callable(
        js_string!("__nebula_kv_set"),
        2,
        NativeFunction::from_fn_ptr(session_set),
    )
    .expect("register __nebula_kv_set");
    // Panicking here is deliberate: a realm whose console or `httpGet` failed
    // to register is one where every script fails in a way that looks like the
    // script's fault. Better to trap on the first request than to mislead every
    // one after it.
    ctx.eval(Source::from_bytes(PRELUDE)).expect("prelude");
    ctx
}

/// Diagnostic export: builds the realm and prints nothing else.
///
/// Deliberately *not* `_initialize`. That name is the WASI reactor convention
/// (§4.3) and the control plane's deploy pipeline wizens anything exporting it,
/// which would fail here, because Wizer cannot satisfy `nebula.http_get`. This
/// exists so a benchmark can time instantiation without also timing a parse.
#[export_name = "realm_probe"]
pub extern "C" fn realm_probe() {
    ENGINE.with(|cell| {
        let mut slot = cell.borrow_mut();
        slot.get_or_insert_with(build);
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
        // The realm is built on first use. It was a Wizer snapshot until egress
        // arrived; §22.1 measured the difference as nothing.
        let ctx = slot.get_or_insert_with(build);
        eval(ctx, &source);
    });
}

/// Evaluate, then report.
///
/// **An uncaught exception is a 200, not a fault.** The sandbox did its job:
/// the tenant's program ran and threw, exactly as `node -e` would report it.
/// `X-Nebula-Fault` (§11.1) stays reserved for Nebula failing (a timeout, a
/// memory ceiling, an unreachable worker), because those are the ones an agent
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
