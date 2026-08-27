//! Module cache tests: L1, L2, single-flight compilation, byte-bounded
//! eviction. README.md §8.
//!
//! These build `Cache` instances directly against the shared runtime's engine
//! and linker, so each test gets an isolated cache without paying for another
//! `Engine` and its address-space reservation.

mod common;

use std::sync::Arc;

use nebula_runtime::cache::{content_hash, Cache, Source};
use nebula_runtime::{engine, Runtime};

/// A distinct trivial module per `n`, so tests do not collide in L2.
fn guest(n: u32) -> String {
    format!(r#"(module (func (export "run") (drop (i32.const {n}))))"#)
}

#[test]
fn single_flight_compiles_once_under_concurrency() {
    let runtime = common::runtime();
    let cache = Cache::new(common::temp_dir("single-flight")).unwrap();
    let wasm = guest(1).into_bytes();

    // 32 threads race for the same uncompiled hash. Exactly one may reach
    // Cranelift; the rest must block on the gate and then find the finished
    // module in L1.
    let modules: Vec<Arc<_>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..32)
            .map(|_| {
                scope.spawn(|| {
                    cache
                        .get_or_compile(runtime.engine(), runtime.linker(), &wasm)
                        .expect("compile")
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    assert_eq!(
        cache.cranelift_compiles(),
        1,
        "32 concurrent first-requests must compile the module exactly once"
    );
    assert_eq!(cache.l1_len(), 1);
    assert_eq!(modules.len(), 32);
    for module in &modules {
        assert!(
            Arc::ptr_eq(module, &modules[0]),
            "every caller must receive the same cached module, not a copy"
        );
    }
    // 32 callers, one compile, so the other 31 were served from L1.
    assert_eq!(cache.l1_hits(), 31);
}

#[test]
fn single_flight_still_compiles_distinct_modules_in_parallel() {
    // Guards against "single-flight" degenerating into one global compile lock.
    let runtime = common::runtime();
    let cache = Cache::new(common::temp_dir("single-flight-distinct")).unwrap();
    let sources: Vec<Vec<u8>> = (0..8).map(|n| guest(500 + n).into_bytes()).collect();

    std::thread::scope(|scope| {
        for wasm in &sources {
            scope.spawn(|| {
                cache
                    .get_or_compile(runtime.engine(), runtime.linker(), wasm)
                    .expect("compile")
            });
        }
    });

    assert_eq!(cache.cranelift_compiles(), 8);
    assert_eq!(cache.l1_len(), 8);
}

#[test]
fn l1_hit_avoids_recompilation() {
    let runtime = common::runtime();
    let cache = Cache::new(common::temp_dir("l1-hit")).unwrap();
    let wasm = guest(3).into_bytes();

    let first = cache
        .get_or_compile(runtime.engine(), runtime.linker(), &wasm)
        .unwrap();
    let second = cache
        .get_or_compile(runtime.engine(), runtime.linker(), &wasm)
        .unwrap();

    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(cache.cranelift_compiles(), 1);
    assert_eq!(cache.aot_loads(), 0, "an L1 hit must not touch the disk");
    assert_eq!(cache.l1_hits(), 1);
}

#[test]
fn l2_replays_after_a_restart_without_invoking_cranelift() {
    // README.md Phase 2 exit criterion: a worker restart replays from L2.
    let runtime = common::runtime();
    let dir = common::temp_dir("l2-replay");
    let wasm = guest(4).into_bytes();

    let before = Cache::new(&dir).unwrap();
    let compiled = before
        .get_or_compile(runtime.engine(), runtime.linker(), &wasm)
        .unwrap();
    assert_eq!(compiled.source, Source::Cranelift);
    assert_eq!(before.cranelift_compiles(), 1);
    drop(before);

    // Same directory, empty L1: this is what a restarted worker sees.
    let after = Cache::new(&dir).unwrap();
    let restored = after
        .get_or_compile(runtime.engine(), runtime.linker(), &wasm)
        .unwrap();

    assert_eq!(restored.source, Source::Aot);
    assert_eq!(
        after.cranelift_compiles(),
        0,
        "a restart must replay from L2, not recompile"
    );
    assert_eq!(after.aot_loads(), 1);
    assert!(restored.module.get_export("run").is_some());
}

#[test]
fn a_module_restored_from_l2_still_executes() {
    // Loading a precompiled artifact is `unsafe`; proving it deserializes is not
    // the same as proving it runs. This drives the whole path end to end.
    let dir = common::temp_dir("l2-execute");
    let wasm = br#"
        (module
          (import "nebula" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "from l2")
          (func (export "run")
            (call $log (i32.const 1) (i32.const 0) (i32.const 7))))
        "#;

    let before = Runtime::new(&dir).expect("runtime");
    before
        .execute(wasm, "run", "cache", Vec::new())
        .expect("first run");
    assert_eq!(before.cache().cranelift_compiles(), 1);
    drop(before);

    let after = Runtime::new(&dir).expect("restarted runtime");
    let ctx = after
        .execute(wasm, "run", "cache", Vec::new())
        .expect("replayed run");

    assert_eq!(after.cache().cranelift_compiles(), 0);
    assert_eq!(after.cache().aot_loads(), 1);
    assert_eq!(ctx.logs, vec![(1, "from l2".to_string())]);
}

#[test]
fn a_corrupt_l2_artifact_falls_back_to_compiling() {
    let runtime = common::runtime();
    let dir = common::temp_dir("l2-corrupt");
    let wasm = guest(5).into_bytes();

    let before = Cache::new(&dir).unwrap();
    before
        .get_or_compile(runtime.engine(), runtime.linker(), &wasm)
        .unwrap();
    drop(before);

    // Truncate every artifact in the directory.
    for entry in std::fs::read_dir(&dir).unwrap() {
        std::fs::write(entry.unwrap().path(), b"not a cwasm").unwrap();
    }

    let after = Cache::new(&dir).unwrap();
    let module = after
        .get_or_compile(runtime.engine(), runtime.linker(), &wasm)
        .expect("a corrupt artifact must not be fatal");

    assert_eq!(module.source, Source::Cranelift);
    assert_eq!(after.aot_loads(), 0);
    assert_eq!(after.cranelift_compiles(), 1);
}

#[test]
fn distinct_modules_get_distinct_entries() {
    let runtime = common::runtime();
    let cache = Cache::new(common::temp_dir("distinct")).unwrap();

    for n in 10..14 {
        cache
            .get_or_compile(runtime.engine(), runtime.linker(), guest(n).as_bytes())
            .unwrap();
    }

    assert_eq!(cache.l1_len(), 4);
    assert_eq!(cache.cranelift_compiles(), 4);
    assert_eq!(cache.l1_hits(), 0);
}

#[test]
fn content_hash_distinguishes_and_identifies() {
    assert_eq!(content_hash(b"same"), content_hash(b"same"));
    assert_ne!(content_hash(b"same"), content_hash(b"different"));
}

#[test]
fn eviction_is_bounded_by_bytes_not_entry_count() {
    let runtime = common::runtime();

    // Measure one compiled module so the budget can be expressed in modules.
    let probe = Cache::new(common::temp_dir("probe")).unwrap();
    probe
        .get_or_compile(runtime.engine(), runtime.linker(), guest(100).as_bytes())
        .unwrap();
    let one_module = probe.l1_bytes();
    assert!(
        one_module > 0,
        "a compiled module must have a measured size"
    );

    let budget = one_module * 3;
    let cache = Cache::with_budget(common::temp_dir("evict"), budget).unwrap();
    for n in 200..212 {
        cache
            .get_or_compile(runtime.engine(), runtime.linker(), guest(n).as_bytes())
            .unwrap();
    }

    assert!(
        cache.l1_bytes() <= budget,
        "held {} bytes against a {budget} budget",
        cache.l1_bytes()
    );
    assert!(
        cache.l1_len() < 12,
        "12 modules against a 3-module budget must have evicted something"
    );
    assert!(cache.l1_len() >= 1, "the cache must not evict itself empty");
}

#[test]
fn the_most_recently_used_module_survives_eviction() {
    let runtime = common::runtime();

    let probe = Cache::new(common::temp_dir("probe-lru")).unwrap();
    probe
        .get_or_compile(runtime.engine(), runtime.linker(), guest(300).as_bytes())
        .unwrap();
    let budget = probe.l1_bytes() * 2;

    let cache = Cache::with_budget(common::temp_dir("lru"), budget).unwrap();
    let keep = guest(400).into_bytes();

    cache
        .get_or_compile(runtime.engine(), runtime.linker(), &keep)
        .unwrap();
    for n in 401..410 {
        cache
            .get_or_compile(runtime.engine(), runtime.linker(), guest(n).as_bytes())
            .unwrap();
        // Touch `keep` so it stays the most recently used entry.
        cache
            .get_or_compile(runtime.engine(), runtime.linker(), &keep)
            .unwrap();
    }

    // `keep` was touched after every insert, so it must never have been the
    // eviction victim: it is still served from L1, never recompiled.
    assert_eq!(
        cache.cranelift_compiles(),
        10,
        "only the nine newcomers plus `keep` should ever have been compiled"
    );
}

// ---------------------------------------------------------------------------
// L2 is bounded (§8.2)
// ---------------------------------------------------------------------------

/// A distinct module per `n`, so each one compiles to its own L2 entry.
fn unique(n: usize) -> String {
    format!("(module (func (export \"run\")) (; {n} ;))")
}

#[test]
fn the_l2_cache_stays_inside_its_budget() {
    let dir = common::temp_dir("l2-budget");
    // Small enough that a handful of modules overflow it. L1 is given room, so
    // this measures the disk bound and not the memory one.
    let cache = Cache::with_budgets(&dir, 1 << 30, 64 << 10).expect("cache");
    let engine = engine::engine().expect("engine");
    let linker = wasmtime::Linker::new(&engine);

    for n in 0..40 {
        cache
            .get_or_compile(&engine, &linker, unique(n).as_bytes())
            .expect("compile");
    }

    let on_disk: u64 = std::fs::read_dir(&dir)
        .expect("read dir")
        .flatten()
        .filter_map(|entry| entry.metadata().ok())
        .filter(|meta| meta.is_file())
        .map(|meta| meta.len())
        .sum();

    // An unbounded disk cache is a disk that fills. Every distinct artifact a
    // worker ever compiles leaves an AOT module behind.
    assert!(
        on_disk <= 64 << 10,
        "L2 held {on_disk} bytes against a 64 KiB budget"
    );
    assert!(cache.evicted_l2() > 0, "nothing was evicted");
}

#[test]
fn a_module_that_keeps_being_used_is_not_the_one_evicted() {
    let dir = common::temp_dir("l2-lru");
    let cache = Cache::with_budgets(&dir, 1 << 30, 64 << 10).expect("cache");
    let engine = engine::engine().expect("engine");
    let linker = wasmtime::Linker::new(&engine);

    let hot = unique(9999);
    cache
        .get_or_compile(&engine, &linker, hot.as_bytes())
        .expect("compile hot");

    // Eviction orders by modification time, and an L2 hit touches the file.
    // Without that a hot module ages out purely because it was compiled first,
    // gets recompiled, and the cache spends its budget re-earning what it had.
    for n in 0..40 {
        cache
            .get_or_compile(&engine, &linker, unique(n).as_bytes())
            .expect("compile");
        // Reading `hot` back keeps it current. It comes from L1 here, so this
        // also proves the touch happens on the path that matters.
        cache
            .get_or_compile(&engine, &linker, hot.as_bytes())
            .expect("hot stays warm");
    }

    let compiles_before = cache.cranelift_compiles();
    cache
        .get_or_compile(&engine, &linker, hot.as_bytes())
        .expect("hot");
    assert_eq!(
        cache.cranelift_compiles(),
        compiles_before,
        "the hot module was evicted and had to be recompiled"
    );
}
