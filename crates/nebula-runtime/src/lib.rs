//! Nebula's in-process WASM execution core (README.md §5).
//!
//! Deliberately has no networking dependency: the sandbox tests and, later, the
//! benchmark harness link this directly, so the security and latency goals can
//! be tested without a cluster. gRPC and clustering live in `nebula-worker`.

pub mod cache;
pub mod engine;
pub mod host;
pub mod kv;

/// Re-exported so dependents can name `Trap`, `Error`, and `Result` without
/// declaring their own `wasmtime` dependency and risking a version skew against
/// the one the engine was built with.
pub use wasmtime;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use wasmtime::{Engine, Linker, Result, Store, StoreLimits};
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::WasiCtxBuilder;

use crate::cache::Cache;
use crate::kv::Kv;

/// The WASI reactor initializer (§4.3).
///
/// A guest with expensive boot work exports this. A guest that has been through
/// Wizer had it run at build time and no longer exports it — which is the whole
/// of the "zero-boot-time path": one code path, and a wizened module simply has
/// nothing here to call.
pub const INIT_EXPORT: &str = "_initialize";

/// Per-request host state.
///
/// One of these per `Store`, never shared or reused across requests — that is
/// what makes tenant isolation structural rather than argued (§4.2, §13
/// invariant 2). The KV handle is the one exception, and it is namespaced by
/// `tenant` on every access.
pub struct HostCtx {
    /// `(level, message)` pairs from `nebula.log`. Stands in for the structured
    /// log sink until `tracing` lands.
    pub logs: Vec<(i32, String)>,
    /// Request body, readable by the guest through `nebula.request_read`.
    pub request: Vec<u8>,
    /// Response accumulated through `nebula.response_write`.
    pub response: Vec<u8>,
    pub tenant: String,
    kv: Arc<Kv>,
    stdout_pipe: MemoryOutputPipe,
    stderr_pipe: MemoryOutputPipe,
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

impl HostCtx {
    fn new(tenant: String, request: Vec<u8>, kv: Arc<Kv>) -> Self {
        let stdout_pipe = MemoryOutputPipe::new(host::MAX_STDIO_BYTES);
        let stderr_pipe = MemoryOutputPipe::new(host::MAX_STDIO_BYTES);

        // §7.1. The builder's defaults already give no preopens, no env, no
        // args, and closed stdin; sockets are switched off explicitly rather
        // than relying on "allowed but every address denied".
        let wasi = WasiCtxBuilder::new()
            .stdout(stdout_pipe.clone())
            .stderr(stderr_pipe.clone())
            .allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false)
            .build_p1();

        Self {
            logs: Vec::new(),
            request,
            response: Vec::new(),
            tenant,
            kv,
            stdout_pipe,
            stderr_pipe,
            wasi,
            limits: engine::store_limits(),
        }
    }

    /// Bytes the guest wrote to WASI stdout. Captured, never inherited.
    pub fn stdout(&self) -> Vec<u8> {
        self.stdout_pipe.contents().to_vec()
    }

    /// Bytes the guest wrote to WASI stderr.
    pub fn stderr(&self) -> Vec<u8> {
        self.stderr_pipe.contents().to_vec()
    }

    pub(crate) fn kv(&self) -> &Kv {
        &self.kv
    }
}

impl fmt::Debug for HostCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostCtx")
            .field("tenant", &self.tenant)
            .field("logs", &self.logs)
            .field("request_len", &self.request.len())
            .field("response_len", &self.response.len())
            .finish_non_exhaustive()
    }
}

/// Engine, linker, module cache, and KV shim for one node.
///
/// Construction is expensive (it reserves the pooling allocator's address space
/// and spawns the epoch ticker), so a process builds one and shares it.
pub struct Runtime {
    engine: Engine,
    linker: Linker<HostCtx>,
    cache: Cache,
    kv: Arc<Kv>,
}

impl Runtime {
    pub fn new(cache_dir: impl Into<PathBuf>) -> Result<Self> {
        Self::with_budget(cache_dir, cache::DEFAULT_L1_BYTES)
    }

    pub fn with_budget(cache_dir: impl Into<PathBuf>, l1_budget: usize) -> Result<Self> {
        let engine = engine::engine()?;
        engine::spawn_epoch_ticker(&engine);

        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |ctx: &mut HostCtx| &mut ctx.wasi)?;
        host::add_to_linker(&mut linker)?;

        Ok(Self {
            cache: Cache::with_budget(cache_dir, l1_budget)?,
            engine,
            linker,
            kv: Arc::new(Kv::new()),
        })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn linker(&self) -> &Linker<HostCtx> {
        &self.linker
    }

    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    pub fn kv(&self) -> &Arc<Kv> {
        &self.kv
    }

    /// Fetch-or-compile, instantiate, and call the exported `entry` function.
    ///
    /// Returns the store's `HostCtx` so the caller can read what the guest
    /// produced. A guest trap surfaces as `Err` — Phase 3 maps that to the typed
    /// `Outcome` of §11.2 rather than an error, but at this layer an error is
    /// the honest representation.
    pub fn execute(
        &self,
        wasm: &[u8],
        entry: &str,
        tenant: &str,
        request: Vec<u8>,
    ) -> Result<HostCtx> {
        let cached = self
            .cache
            .get_or_compile(&self.engine, &self.linker, wasm)?;
        let mut store = self.new_store(tenant, request);
        let instance = cached.pre.instantiate(&mut store)?;

        // Presence is checked with `get_func` rather than by treating a failed
        // `get_typed_func` as "absent" — that would silently skip an
        // initializer with an unexpected signature instead of reporting it.
        if instance.get_func(&mut store, INIT_EXPORT).is_some() {
            instance
                .get_typed_func::<(), ()>(&mut store, INIT_EXPORT)?
                .call(&mut store, ())?;
        }

        instance
            .get_typed_func::<(), ()>(&mut store, entry)?
            .call(&mut store, ())?;
        Ok(store.into_data())
    }

    /// A fresh store with both a limiter and an epoch deadline installed.
    ///
    /// Both are set here rather than at the call site so there is no path to a
    /// `Store` that runs guest code without them (§13, invariant 3).
    fn new_store(&self, tenant: &str, request: Vec<u8>) -> Store<HostCtx> {
        let ctx = HostCtx::new(tenant.to_string(), request, self.kv.clone());
        let mut store = Store::new(&self.engine, ctx);
        store.limiter(|ctx| &mut ctx.limits);
        store.set_epoch_deadline(engine::DEFAULT_DEADLINE_TICKS);
        store
    }
}
