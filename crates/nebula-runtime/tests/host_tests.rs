//! Host interface tests: WASI lockdown, request/response, and the KV shim.
//!
//! README.md §7. Tests share one `Runtime`, so each uses its own tenant name to
//! stay independent of the others running in parallel.

mod common;

use nebula_runtime::host::MAX_RESPONSE_BYTES;
use nebula_runtime::kv::{self, Kv, Rejected};
use nebula_runtime::{HostCtx, Runtime};
use wasmtime::Result;

fn run_as(tenant: &str, wat: &str, request: Vec<u8>) -> Result<HostCtx> {
    common::runtime().execute(wat.as_bytes(), "run", tenant, request)
}

// ---------------------------------------------------------------------------
// WASI: present, but with nothing attached to it (§7.1)
// ---------------------------------------------------------------------------

#[test]
fn wasi_stdout_is_captured_not_inherited() {
    let ctx = run_as(
        "wasi-stdout",
        r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 100) "wasi stdout")
          (func (export "run")
            (i32.store (i32.const 0) (i32.const 100))   ;; iovec.buf
            (i32.store (i32.const 4) (i32.const 11))    ;; iovec.buf_len
            (drop (call $fd_write
              (i32.const 1)        ;; fd 1 = stdout
              (i32.const 0)        ;; iovs
              (i32.const 1)        ;; iovs_len
              (i32.const 8)))))    ;; nwritten
        "#,
        Vec::new(),
    )
    .expect("writing to stdout is allowed");

    assert_eq!(String::from_utf8(ctx.stdout()).unwrap(), "wasi stdout");
    assert!(ctx.stderr().is_empty());
}

/// stdin carries the request body (§7.1).
///
/// This is the channel the interpreter guests of §22.1 depend on: a guest that
/// must survive Wizer imports nothing but WASI, so it cannot call
/// `nebula.request_read` and reads its source from here instead.
#[test]
fn wasi_stdin_carries_the_request_body() {
    let ctx = run_as(
        "wasi-stdin",
        r#"
        (module
          (import "wasi_snapshot_preview1" "fd_read"
            (func $fd_read (param i32 i32 i32 i32) (result i32)))
          (import "nebula" "response_write"
            (func $response_write (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "run")
            (i32.store (i32.const 0) (i32.const 64))    ;; iovec.buf
            (i32.store (i32.const 4) (i32.const 64))    ;; iovec.buf_len
            (drop (call $fd_read
              (i32.const 0)        ;; fd 0 = stdin
              (i32.const 0)        ;; iovs
              (i32.const 1)        ;; iovs_len
              (i32.const 8)))      ;; nread
            (drop (call $response_write
              (i32.const 64)
              (i32.load (i32.const 8))))))
        "#,
        b"source from stdin".to_vec(),
    )
    .expect("reading stdin is allowed");

    assert_eq!(ctx.response, b"source from stdin");
}

/// A guest that answers on stdout gets stdout as its body; one that uses
/// `response_write` gets that instead. Same reason as the test above — the
/// wizenable guests have no `nebula.response_write` to call.
#[test]
fn the_response_body_falls_back_to_stdout_only_when_nothing_was_written() {
    const PRINTER: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "nebula" "response_write"
            (func $response_write (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 100) "on stdout")
          (data (i32.const 200) "explicit")
          (func $say (param $ptr i32) (param $len i32)
            (i32.store (i32.const 0) (local.get $ptr))
            (i32.store (i32.const 4) (local.get $len))
            (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8))))
          (func (export "run")
            (call $say (i32.const 100) (i32.const 9)))
          (func (export "both")
            (call $say (i32.const 100) (i32.const 9))
            (drop (call $response_write (i32.const 200) (i32.const 8)))))
        "#;

    let ctx = run_as("output-stdout", PRINTER, Vec::new()).expect("guest runs");
    assert_eq!(ctx.output(), b"on stdout");

    let ctx = common::runtime()
        .execute(PRINTER.as_bytes(), "both", "output-explicit", Vec::new())
        .expect("guest runs");
    assert_eq!(
        ctx.output(),
        b"explicit",
        "an explicit response must win; merging two channels would interleave \
         by flush order, which is not a contract a caller can rely on"
    );
}

#[test]
fn wasi_exposes_no_preopened_directories() {
    // fd 3 is the first preopen slot. With no preopens configured,
    // `fd_prestat_get` must report an error; a zero errno would mean the guest
    // holds a directory handle and the filesystem is reachable.
    run_as(
        "wasi-fs",
        r#"
        (module
          (import "wasi_snapshot_preview1" "fd_prestat_get"
            (func $prestat (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "run")
            (if (i32.eqz (call $prestat (i32.const 3) (i32.const 64)))
              (then (unreachable)))))
        "#,
        Vec::new(),
    )
    .expect("guest must observe no preopens");
}

// ---------------------------------------------------------------------------
// request_read / response_write
// ---------------------------------------------------------------------------

const ECHO: &str = r#"
    (module
      (import "nebula" "request_len" (func $len (result i32)))
      (import "nebula" "request_read" (func $read (param i32 i32) (result i32)))
      (import "nebula" "response_write" (func $write (param i32 i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "run")
        (local $n i32)
        (local.set $n (call $len))
        (drop (call $read (i32.const 0) (local.get $n)))
        (drop (call $write (i32.const 0) (local.get $n)))))
    "#;

#[test]
fn request_body_round_trips_through_the_guest() {
    let body = b"the quick brown fox".to_vec();
    let ctx = run_as("echo", ECHO, body.clone()).expect("echo guest");
    assert_eq!(ctx.response, body);
}

#[test]
fn empty_request_body_round_trips() {
    let ctx = run_as("echo-empty", ECHO, Vec::new()).expect("echo guest");
    assert!(ctx.response.is_empty());
}

#[test]
fn response_write_caps_and_reports_the_short_write() {
    // 20 x 64 KiB is 1.25 MiB against a 1 MiB cap. Once full, a further write
    // must report 0 accepted rather than trapping or silently claiming success.
    let ctx = run_as(
        "response-cap",
        r#"
        (module
          (import "nebula" "response_write" (func $write (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "run")
            (local $i i32)
            (loop $l
              (drop (call $write (i32.const 0) (i32.const 65536)))
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br_if $l (i32.lt_u (local.get $i) (i32.const 20))))
            (if (i32.ne (call $write (i32.const 0) (i32.const 16)) (i32.const 0))
              (then (unreachable)))))
        "#,
        Vec::new(),
    )
    .expect("hitting the response cap is not a trap");

    assert_eq!(ctx.response.len(), MAX_RESPONSE_BYTES);
}

// ---------------------------------------------------------------------------
// KV shim through the host functions
// ---------------------------------------------------------------------------

#[test]
fn kv_set_then_get_round_trips() {
    let ctx = run_as(
        "kv-roundtrip",
        r#"
        (module
          (import "nebula" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
          (import "nebula" "kv_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (import "nebula" "response_write" (func $write (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "greeting")
          (data (i32.const 16) "hello kv")
          (func (export "run")
            (if (i32.ne (call $set (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 8))
                        (i32.const 0))
              (then (unreachable)))
            ;; kv_get returns the value's full length, here 8
            (if (i32.ne (call $get (i32.const 0) (i32.const 8) (i32.const 256) (i32.const 64))
                        (i32.const 8))
              (then (unreachable)))
            (drop (call $write (i32.const 256) (i32.const 8)))))
        "#,
        Vec::new(),
    )
    .expect("kv round trip");

    assert_eq!(ctx.response, b"hello kv");
}

#[test]
fn kv_get_reports_full_length_when_the_guest_buffer_is_short() {
    // The guest asks for 4 bytes of an 8-byte value: it gets 4, and a return of
    // 8 tells it the value was longer. Truncation the guest cannot detect would
    // be the bug here.
    let ctx = run_as(
        "kv-short-buffer",
        r#"
        (module
          (import "nebula" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
          (import "nebula" "kv_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (import "nebula" "response_write" (func $write (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "k")
          (data (i32.const 16) "abcdefgh")
          (func (export "run")
            (drop (call $set (i32.const 0) (i32.const 1) (i32.const 16) (i32.const 8)))
            (if (i32.ne (call $get (i32.const 0) (i32.const 1) (i32.const 256) (i32.const 4))
                        (i32.const 8))
              (then (unreachable)))
            (drop (call $write (i32.const 256) (i32.const 4)))))
        "#,
        Vec::new(),
    )
    .expect("short-buffer get");

    assert_eq!(ctx.response, b"abcd");
}

#[test]
fn kv_missing_key_returns_minus_one() {
    run_as(
        "kv-missing",
        r#"
        (module
          (import "nebula" "kv_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "nope")
          (func (export "run")
            (if (i32.ne (call $get (i32.const 0) (i32.const 4) (i32.const 256) (i32.const 64))
                        (i32.const -1))
              (then (unreachable)))))
        "#,
        Vec::new(),
    )
    .expect("absent key reports -1");
}

#[test]
fn kv_rejects_an_oversized_value_without_storing_anything() {
    // 65537 bytes is one past MAX_VALUE_BYTES. The write must be refused
    // outright — storing a truncated value would be silent data corruption.
    run_as(
        "kv-big-value",
        r#"
        (module
          (import "nebula" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 3)
          (data (i32.const 0) "k")
          (func (export "run")
            (if (i32.ne (call $set (i32.const 0) (i32.const 1) (i32.const 16) (i32.const 65537))
                        (i32.const -1))
              (then (unreachable)))))
        "#,
        Vec::new(),
    )
    .expect("oversized value is refused, not trapped");

    assert!(
        common::runtime().kv().get("kv-big-value", b"k").is_none(),
        "a refused write must leave nothing behind, not a truncated value"
    );
}

#[test]
fn kv_rejects_an_oversized_key() {
    run_as(
        "kv-big-key",
        r#"
        (module
          (import "nebula" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 2)
          (func (export "run")
            ;; klen 1025 is one past MAX_KEY_BYTES
            (if (i32.ne (call $set (i32.const 0) (i32.const 1025) (i32.const 2048) (i32.const 4))
                        (i32.const -1))
              (then (unreachable)))))
        "#,
        Vec::new(),
    )
    .expect("oversized key is refused");
}

#[test]
fn kv_oob_pointer_traps_even_though_capacity_failures_do_not() {
    // The distinction the whole error convention rests on: a refused write is a
    // return code, an invalid pointer is a trap.
    let err = run_as(
        "kv-oob",
        r#"
        (module
          (import "nebula" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "run")
            (drop (call $set (i32.const 65530) (i32.const 32) (i32.const 0) (i32.const 4)))))
        "#,
        Vec::new(),
    )
    .expect_err("a key pointer past the end of memory must trap");

    assert!(err.downcast_ref::<wasmtime::Trap>().is_some());
}

#[test]
fn kv_is_isolated_between_tenants() {
    let setter = r#"
        (module
          (import "nebula" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "shared")
          (data (i32.const 16) "secret")
          (func (export "run")
            (if (i32.ne (call $set (i32.const 0) (i32.const 6) (i32.const 16) (i32.const 6))
                        (i32.const 0))
              (then (unreachable)))))
        "#;
    let expect_miss = r#"
        (module
          (import "nebula" "kv_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "shared")
          (func (export "run")
            (if (i32.ne (call $get (i32.const 0) (i32.const 6) (i32.const 256) (i32.const 64))
                        (i32.const -1))
              (then (unreachable)))))
        "#;

    run_as("tenant-alpha", setter, Vec::new()).expect("alpha writes");
    run_as("tenant-beta", expect_miss, Vec::new())
        .expect("beta must not see alpha's key at the same name");

    let kv = common::runtime().kv();
    assert_eq!(
        kv.get("tenant-alpha", b"shared").as_deref(),
        Some(&b"secret"[..])
    );
    assert!(kv.get("tenant-beta", b"shared").is_none());
}

// ---------------------------------------------------------------------------
// KV caps, tested directly against a fresh store
//
// These fill the store to capacity, so they use their own `Kv` rather than the
// shared runtime's — otherwise they would starve every other test in this
// binary.
// ---------------------------------------------------------------------------

#[test]
fn kv_byte_cap_is_enforced_exactly() {
    let kv = Kv::new();
    let value = vec![0u8; kv::MAX_VALUE_BYTES];

    let mut stored = 0usize;
    for i in 0..1000 {
        let key = format!("k{i}");
        match kv.set("t", key.as_bytes(), &value) {
            Ok(()) => stored += 1,
            Err(Rejected) => break,
        }
    }

    assert!(stored > 0, "the store must accept something");
    assert!(stored < 1000, "the store must refuse before 1000 x 64 KiB");
    assert!(
        kv.bytes() <= kv::MAX_BYTES,
        "held {} bytes against a {} cap",
        kv.bytes(),
        kv::MAX_BYTES
    );
    // Nothing more fits, and a refusal leaves the accounting untouched.
    let before = kv.bytes();
    assert_eq!(kv.set("t", b"one-more", &value), Err(Rejected));
    assert_eq!(kv.bytes(), before);
}

#[test]
fn kv_entry_cap_is_enforced() {
    let kv = Kv::new();
    // One-byte values, so the entry cap binds well before the byte cap.
    for i in 0..kv::MAX_ENTRIES {
        kv.set("t", format!("k{i}").as_bytes(), b"v")
            .expect("within the entry cap");
    }
    assert_eq!(kv.len(), kv::MAX_ENTRIES);
    assert_eq!(kv.set("t", b"one-too-many", b"v"), Err(Rejected));

    // An overwrite is not a new entry, so it must still be accepted at the cap.
    assert_eq!(kv.set("t", b"k0", b"w"), Ok(()));
    assert_eq!(kv.get("t", b"k0").as_deref(), Some(&b"w"[..]));
}

#[test]
fn overwriting_releases_the_previous_value_bytes() {
    let kv = Kv::new();
    kv.set("t", b"k", &vec![0u8; kv::MAX_VALUE_BYTES]).unwrap();
    let full = kv.bytes();
    kv.set("t", b"k", b"tiny").unwrap();

    assert!(
        kv.bytes() < full,
        "replacing a large value must return its bytes to the budget"
    );
    assert_eq!(kv.len(), 1, "an overwrite is not a new entry");
}

#[test]
fn kv_byte_cap_holds_under_concurrent_writers() {
    // Establishes that the cap holds while eight writers hammer the store, and
    // that the accounting does not drift or underflow under contention.
    //
    // It does *not* isolate the compare-and-swap in `reserve`: swapping that for
    // a load/check/store still passes this test, because the race window is a
    // few nanoseconds wide and does not reproduce. The CAS is there because the
    // race is real, not because this test caught it. Treat the cap as verified
    // and the atomicity as reasoned.
    let kv = Kv::new();
    let value = vec![7u8; kv::MAX_VALUE_BYTES];

    std::thread::scope(|scope| {
        for thread in 0..8 {
            let kv = &kv;
            let value = &value;
            scope.spawn(move || {
                for i in 0..100 {
                    let _ = kv.set("t", format!("t{thread}-k{i}").as_bytes(), value);
                }
            });
        }
    });

    assert!(
        kv.bytes() <= kv::MAX_BYTES,
        "overshot the cap: {} > {}",
        kv.bytes(),
        kv::MAX_BYTES
    );
    assert!(
        kv.bytes() > kv::MAX_BYTES / 2,
        "the store should be near full"
    );
}

// ---------------------------------------------------------------------------
// The KV shim is node-local, and that is observable
// ---------------------------------------------------------------------------

#[test]
fn kv_state_is_shared_across_requests_on_one_node() {
    // Unlike `HostCtx`, the KV handle deliberately outlives a request. Two
    // separate executions for the same tenant see the same store.
    let runtime = Runtime::new(common::temp_dir("kv-node")).expect("runtime");
    let write = r#"
        (module
          (import "nebula" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "carried")
          (data (i32.const 16) "over")
          (func (export "run")
            (drop (call $set (i32.const 0) (i32.const 7) (i32.const 16) (i32.const 4)))))
        "#;

    runtime
        .execute(write.as_bytes(), "run", "node", Vec::new())
        .unwrap();
    assert_eq!(
        runtime.kv().get("node", b"carried").as_deref(),
        Some(&b"over"[..])
    );
}
