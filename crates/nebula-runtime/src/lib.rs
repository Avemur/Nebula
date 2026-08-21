//! Nebula's in-process WASM execution core (DESIGN.md §5).
//!
//! Deliberately has no networking dependency: the sandbox tests and, later, the
//! benchmark harness link this directly, so the security and latency goals can
//! be tested without a cluster. gRPC and clustering live in `nebula-worker`.

pub mod engine;
pub mod host;

use wasmtime::{Engine, Linker, Module, Result, Store, StoreLimits};

/// Per-request host state.
///
/// One of these per `Store`, never shared or reused across requests — that is
/// what makes tenant isolation structural rather than argued (§4.2, §13
/// invariant 2).
#[derive(Debug)]
pub struct HostCtx {
    /// `(level, message)` pairs from `nebula.log`. Stands in for the structured
    /// log sink until `tracing` lands.
    pub logs: Vec<(i32, String)>,
    limits: StoreLimits,
}

impl Default for HostCtx {
    fn default() -> Self {
        Self {
            logs: Vec::new(),
            limits: engine::store_limits(),
        }
    }
}

/// A fresh store with both a limiter and an epoch deadline installed.
///
/// Both are set here rather than at the call site so there is no path to a
/// `Store` that runs guest code without them (§13, invariant 3).
pub fn new_store(engine: &Engine) -> Store<HostCtx> {
    let mut store = Store::new(engine, HostCtx::default());
    store.limiter(|ctx| &mut ctx.limits);
    store.set_epoch_deadline(engine::DEFAULT_DEADLINE_TICKS);
    store
}

/// A linker with the `nebula` namespace registered. WASI arrives next.
pub fn linker(engine: &Engine) -> Result<Linker<HostCtx>> {
    let mut linker = Linker::new(engine);
    host::add_to_linker(&mut linker)?;
    Ok(linker)
}

/// Compile `wasm`, instantiate it, and call the exported `entry` function.
///
/// Returns the store's `HostCtx` so the caller can read what the guest
/// produced. A guest trap surfaces as `Err` — Phase 3 maps that to the typed
/// `Outcome` of §11.2 rather than an error, but at this layer an error is the
/// honest representation.
pub fn run(engine: &Engine, wasm: &[u8], entry: &str) -> Result<HostCtx> {
    let module = Module::new(engine, wasm)?;
    let linker = linker(engine)?;
    let mut store = new_store(engine);
    let instance = linker.instantiate(&mut store, &module)?;
    instance
        .get_typed_func::<(), ()>(&mut store, entry)?
        .call(&mut store, ())?;
    Ok(store.into_data())
}
