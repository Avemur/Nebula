//! Engine configuration, resource ceilings, and the epoch ticker.
//!
//! See README.md §5.1 (engine config), §6.1 (epochs), §6.3–6.4 (limits).

use std::thread::{self, JoinHandle};
use std::time::Duration;

use wasmtime::{
    Config, Engine, InstanceAllocationStrategy, OptLevel, PoolingAllocationConfig, Result,
    StoreLimits, StoreLimitsBuilder,
};

/// README.md §6.4. Per-function overrides arrive with the registry in Phase 3;
/// until then these are the only values in the system.
///
/// Default per-function linear memory ceiling, enforced per store by
/// [`store_limits`].
pub const MAX_MEMORY_BYTES: usize = 128 << 20; // 128 MiB

/// Largest ceiling any function may ever be granted.
///
/// The pooling allocator reserves this much address space per slot, so it must
/// be at least any per-function ceiling (§6.3). Deliberately kept *above*
/// [`MAX_MEMORY_BYTES`] so the per-store limiter is the binding constraint and
/// the pool is only the backstop — if the two were equal, dropping the limiter
/// would go unnoticed because the pool would silently enforce the same number.
pub const POOL_MAX_MEMORY_BYTES: usize = 256 << 20; // 256 MiB
pub const MAX_WASM_STACK_BYTES: usize = 512 << 10; // 512 KiB
pub const MAX_TABLE_ELEMENTS: usize = 10_000;
pub const MAX_CONCURRENT_INSTANCES: u32 = 64;

/// Epoch tick period. Also the deadline granularity: a deadline of N ticks is
/// enforced to within one tick (§6.1, risk R7).
pub const EPOCH_TICK: Duration = Duration::from_millis(1);

/// 50 ms at [`EPOCH_TICK`].
pub const DEFAULT_DEADLINE_TICKS: u64 = 50;

/// One engine per process, shared across all tenants. Construction is
/// expensive — it reserves the pooling allocator's address space up front —
/// so this is called once at startup, never per request.
pub fn engine() -> Result<Engine> {
    let mut cfg = Config::new();
    cfg.epoch_interruption(true); // §6.1: wall-clock deadlines
    cfg.consume_fuel(false); // §6.2: fuel is a per-function opt-in, later
    cfg.memory_init_cow(true); // §4.3: CoW memory images
    cfg.max_wasm_stack(MAX_WASM_STACK_BYTES);
    cfg.wasm_threads(false); // §2: single-threaded guests only
    cfg.cranelift_opt_level(OptLevel::Speed);

    // The pooling allocator is what makes the sub-ms target reachable:
    // instantiation becomes a slot handoff plus an mmap (§5.1). It also caps
    // concurrent instances, which is a resource limit in its own right (§6.4).
    let mut pool = PoolingAllocationConfig::default();
    pool.total_core_instances(MAX_CONCURRENT_INSTANCES);
    pool.total_memories(MAX_CONCURRENT_INSTANCES);
    pool.total_tables(MAX_CONCURRENT_INSTANCES);
    pool.max_memory_size(POOL_MAX_MEMORY_BYTES);
    pool.table_elements(MAX_TABLE_ELEMENTS);
    cfg.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));

    Engine::new(&cfg)
}

/// Per-store ceilings (§6.3).
///
/// The pooling slot bounds the same numbers from above, but it bounds them at
/// *instantiation* time. This is what turns a breach into a guest-visible
/// `memory.grow` → `-1` instead of a failed instantiation.
pub fn store_limits() -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(MAX_MEMORY_BYTES)
        .memories(1)
        .instances(1)
        .tables(1)
        .table_elements(MAX_TABLE_ELEMENTS)
        .build()
}

/// Drives `Engine::increment_epoch` so epoch deadlines actually fire.
///
/// Without this thread running, `set_epoch_deadline` never trips and an
/// infinite-loop guest hangs forever — the ticker is load-bearing, not
/// optional. Holds a weak reference so the thread exits once the last `Engine`
/// clone is dropped.
pub fn spawn_epoch_ticker(engine: &Engine) -> JoinHandle<()> {
    let weak = engine.weak();
    thread::spawn(move || loop {
        thread::sleep(EPOCH_TICK);
        match weak.upgrade() {
            Some(engine) => engine.increment_epoch(),
            None => return,
        }
    })
}
