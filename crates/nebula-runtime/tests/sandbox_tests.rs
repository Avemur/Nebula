//! Sandbox tests: memory safety and resource ceilings.
//!
//! Covers `engine.rs` (epoch deadline, memory ceiling), `host.rs`
//! (`checked_range`, `guest_slice`, `nebula.log`), and `lib.rs` (store
//! freshness).
//!
//! The guest-facing tests assert a *specific* outcome, not merely "did not
//! crash" — README.md §15.

mod common;

use nebula_runtime::host::{checked_range, MAX_LOG_BYTES};
use nebula_runtime::HostCtx;
use wasmtime::{Error, Result, Trap};

fn run(wat: &str) -> Result<HostCtx> {
    common::runtime().execute(wat.as_bytes(), "run", "sandbox", Vec::new())
}

#[track_caller]
fn assert_trap(err: Error, want: Trap) {
    match err.downcast_ref::<Trap>() {
        Some(got) => assert_eq!(*got, want, "wrong trap kind; full error: {err:?}"),
        None => panic!("expected trap {want:?}, got non-trap error: {err:?}"),
    }
}

// ---------------------------------------------------------------------------
// host.rs — checked_range
//
// The arithmetic that has to be right, tested directly. `guest_slice` cannot be
// called without a live `Caller`, which is why this is a separate function.
// ---------------------------------------------------------------------------

#[test]
fn checked_range_accepts_in_bounds() {
    assert_eq!(checked_range(100, 10, 20).unwrap(), 10..30);
}

#[test]
fn checked_range_accepts_exact_end() {
    assert_eq!(checked_range(100, 90, 10).unwrap(), 90..100);
}

#[test]
fn checked_range_accepts_zero_length_at_boundary() {
    // ptr == mem_len with len == 0 is an empty slice at the very end, not an
    // overrun. Rejecting it would break well-behaved guests logging "".
    assert_eq!(checked_range(100, 100, 0).unwrap(), 100..100);
}

#[test]
fn checked_range_rejects_ptr_past_end() {
    assert!(checked_range(100, 101, 0).is_err());
}

#[test]
fn checked_range_rejects_len_past_end() {
    assert!(checked_range(100, 90, 11).is_err());
}

#[test]
fn checked_range_rejects_ptr_plus_len_overflow() {
    // The case that disappears if the addition is widened to usize before being
    // checked: u32::MAX + 16 wraps in u32 but is comfortably in range as usize.
    assert!(checked_range(usize::MAX, u32::MAX, 16).is_err());
    assert!(checked_range(usize::MAX, 1, u32::MAX).is_err());
}

#[test]
fn checked_range_rejects_everything_against_empty_memory() {
    assert!(checked_range(0, 0, 1).is_err());
    assert_eq!(checked_range(0, 0, 0).unwrap(), 0..0);
}

// ---------------------------------------------------------------------------
// host.rs — nebula.log
// ---------------------------------------------------------------------------

#[test]
fn host_receives_logged_string() {
    let ctx = run(r#"
        (module
          (import "nebula" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 16) "hello from guest")
          (func (export "run")
            (call $log (i32.const 2) (i32.const 16) (i32.const 16))))
        "#)
    .expect("guest should run cleanly");

    assert_eq!(ctx.logs, vec![(2, "hello from guest".to_string())]);
}

#[test]
fn host_receives_empty_log_at_memory_boundary() {
    // ptr == memory size, len == 0. In bounds by exactly nothing.
    let ctx = run(r#"
        (module
          (import "nebula" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (func (export "run")
            (call $log (i32.const 2) (i32.const 65536) (i32.const 0))))
        "#)
    .expect("zero-length read at the boundary is legal");

    assert_eq!(ctx.logs, vec![(2, String::new())]);
}

#[test]
fn log_payload_is_truncated_not_trapped() {
    // 5000 bytes of 'A' from a fully in-bounds range: the range is legal, so the
    // cap truncates rather than traps.
    let ctx = run(r#"
        (module
          (import "nebula" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (func (export "run")
            (memory.fill (i32.const 0) (i32.const 65) (i32.const 5000))
            (call $log (i32.const 1) (i32.const 0) (i32.const 5000))))
        "#)
    .expect("in-bounds oversized log should truncate");

    let (level, message) = &ctx.logs[0];
    assert_eq!(*level, 1);
    assert_eq!(message.len(), MAX_LOG_BYTES as usize);
    assert!(message.bytes().all(|byte| byte == b'A'));
}

// ---------------------------------------------------------------------------
// host.rs — guest_slice traps
//
// Each of these reaches guest_slice through a real host call with
// attacker-controlled arguments.
// ---------------------------------------------------------------------------

#[test]
fn guest_slice_traps_on_ptr_past_end_of_memory() {
    let err = run(r#"
        (module
          (import "nebula" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (func (export "run")
            (call $log (i32.const 2) (i32.const 65536) (i32.const 1))))
        "#)
    .expect_err("one byte past a one-page memory must trap");

    assert_trap(err, Trap::MemoryOutOfBounds);
}

#[test]
fn guest_slice_traps_on_ptr_plus_len_overflow() {
    // ptr = 0xFFFFFFFF, len = 16. Overflows u32 before it can be compared
    // against the memory size.
    let err = run(r#"
        (module
          (import "nebula" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (func (export "run")
            (call $log (i32.const 2) (i32.const -1) (i32.const 16))))
        "#)
    .expect_err("u32 pointer overflow must trap");

    assert_trap(err, Trap::MemoryOutOfBounds);
}

#[test]
fn guest_slice_traps_on_len_past_end_of_memory() {
    // ptr = 0, len = 0xFFFFFFFF. No overflow, but far past the one page.
    let err = run(r#"
        (module
          (import "nebula" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (func (export "run")
            (call $log (i32.const 2) (i32.const 0) (i32.const -1))))
        "#)
    .expect_err("length past the end of memory must trap");

    assert_trap(err, Trap::MemoryOutOfBounds);
}

#[test]
fn guest_slice_traps_when_guest_exports_no_memory() {
    let err = run(r#"
        (module
          (import "nebula" "log" (func $log (param i32 i32 i32)))
          (func (export "run")
            (call $log (i32.const 2) (i32.const 0) (i32.const 0))))
        "#)
    .expect_err("a guest with no exported memory must not reach host memory");

    assert_trap(err, Trap::MemoryOutOfBounds);
}

// ---------------------------------------------------------------------------
// engine.rs — resource ceilings
// ---------------------------------------------------------------------------

#[test]
fn infinite_loop_hits_the_epoch_deadline() {
    let err = run(r#"(module (func (export "run") (loop (br 0))))"#)
        .expect_err("an infinite loop must be interrupted, not hang the host");

    assert_trap(err, Trap::Interrupt);
}

#[test]
fn store_limiter_refuses_growth_the_pooling_slot_would_allow() {
    // 3200 pages is 200 MiB: above the 128 MiB `StoreLimits` ceiling but below
    // the 256 MiB pooling slot. Only the per-store limiter can refuse this, so
    // this test fails if `store.limiter(..)` is ever dropped from `new_store`.
    //
    // Verified by experiment: with the limiter commented out, this test fails
    // while the 6.25 GiB case below still passes.
    run(r#"
        (module
          (memory (export "memory") 1)
          (func (export "run")
            (if (i32.ne (memory.grow (i32.const 3200)) (i32.const -1))
              (then (unreachable)))))
        "#)
    .expect("200 MiB is past the 128 MiB per-store ceiling and must return -1");
}

#[test]
fn memory_growth_beyond_the_pooling_slot_is_refused() {
    // 100 000 pages is 6.25 GiB — past both ceilings. This is the backstop, and
    // it passes with or without the limiter; the test above is the one that
    // isolates `StoreLimits`. The guest traps itself if the grow unexpectedly
    // succeeds, so a clean run is the assertion.
    run(r#"
        (module
          (memory (export "memory") 1)
          (func (export "run")
            (if (i32.ne (memory.grow (i32.const 100000)) (i32.const -1))
              (then (unreachable)))))
        "#)
    .expect("grow past every ceiling must return -1, not succeed and not abort");
}

#[test]
fn memory_growth_within_the_ceiling_succeeds() {
    // Guards against the ceiling being enforced by simply refusing all growth.
    run(r#"
        (module
          (memory (export "memory") 1)
          (func (export "run")
            (if (i32.eq (memory.grow (i32.const 16)) (i32.const -1))
              (then (unreachable)))))
        "#)
    .expect("1 MiB of growth is well inside the ceiling");
}

// ---------------------------------------------------------------------------
// lib.rs — store lifecycle
// ---------------------------------------------------------------------------

#[test]
fn each_run_gets_a_fresh_host_context() {
    // README.md §13, invariant 2. If state ever leaks between runs, the second
    // context sees two entries.
    let guest = r#"
        (module
          (import "nebula" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "once")
          (func (export "run")
            (call $log (i32.const 0) (i32.const 0) (i32.const 4))))
        "#;

    let first = run(guest).unwrap();
    let second = run(guest).unwrap();

    assert_eq!(first.logs.len(), 1);
    assert_eq!(second.logs.len(), 1);
    assert_eq!(second.logs[0].1, "once");
}

#[test]
fn guest_memory_does_not_carry_over_between_runs() {
    // The CoW mapping is discarded on teardown, so a second instance must see
    // zeroed memory rather than whatever the first one wrote (§4.2).
    let guest = r#"
        (module
          (import "nebula" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (func (export "run")
            (if (i32.ne (i32.load (i32.const 2048)) (i32.const 0))
              (then (unreachable)))
            (i32.store (i32.const 2048) (i32.const 12345))))
        "#;

    run(guest).expect("first run sees zeroed memory");
    run(guest).expect("second run must also see zeroed memory");
}

#[test]
fn missing_entry_point_is_an_error_not_a_panic() {
    let err = common::runtime()
        .execute(
            br#"(module (func (export "other")))"#,
            "run",
            "sandbox",
            Vec::new(),
        )
        .expect_err("a missing export must surface as an error");

    assert!(err.downcast_ref::<Trap>().is_none(), "not a guest trap");
}
