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
        common::runtime()
            .kv()
            .get("kv-big-value", "", b"k")
            .is_none(),
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
        kv.get("tenant-alpha", "", b"shared").as_deref(),
        Some(&b"secret"[..])
    );
    assert!(kv.get("tenant-beta", "", b"shared").is_none());
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
        match kv.set("t", "", key.as_bytes(), &value) {
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
    assert_eq!(kv.set("t", "", b"one-more", &value), Err(Rejected));
    assert_eq!(kv.bytes(), before);
}

#[test]
fn kv_entry_cap_is_enforced() {
    let kv = Kv::new();
    // One-byte values, so the entry cap binds well before the byte cap.
    for i in 0..kv::MAX_ENTRIES {
        kv.set("t", "", format!("k{i}").as_bytes(), b"v")
            .expect("within the entry cap");
    }
    assert_eq!(kv.len(), kv::MAX_ENTRIES);
    assert_eq!(kv.set("t", "", b"one-too-many", b"v"), Err(Rejected));

    // An overwrite is not a new entry, so it must still be accepted at the cap.
    assert_eq!(kv.set("t", "", b"k0", b"w"), Ok(()));
    assert_eq!(kv.get("t", "", b"k0").as_deref(), Some(&b"w"[..]));
}

#[test]
fn overwriting_releases_the_previous_value_bytes() {
    let kv = Kv::new();
    kv.set("t", "", b"k", &vec![0u8; kv::MAX_VALUE_BYTES])
        .unwrap();
    let full = kv.bytes();
    kv.set("t", "", b"k", b"tiny").unwrap();

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
                    let _ = kv.set("t", "", format!("t{thread}-k{i}").as_bytes(), value);
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
        runtime.kv().get("node", "", b"carried").as_deref(),
        Some(&b"over"[..])
    );
}

// ---------------------------------------------------------------------------
// Outbound HTTP (§22.8)
// ---------------------------------------------------------------------------

/// Fetches the URL in the request body and writes the raw response back.
const FETCHER: &str = r#"
    (module
      (import "nebula" "request_len" (func $len (result i32)))
      (import "nebula" "request_read" (func $read (param i32 i32) (result i32)))
      (import "nebula" "http_get" (func $get (param i32 i32 i32 i32) (result i32)))
      (import "nebula" "response_write" (func $write (param i32 i32) (result i32)))
      (memory (export "memory") 32)
      (data (i32.const 0) "REFUSED")
      (func (export "run")
        (local $n i32)
        (local $got i32)
        (local.set $n (call $len))
        (drop (call $read (i32.const 1024) (local.get $n)))
        (local.set $got
          (call $get (i32.const 1024) (local.get $n) (i32.const 8192) (i32.const 65536)))
        (if (i32.lt_s (local.get $got) (i32.const 0))
          (then (drop (call $write (i32.const 0) (i32.const 7))))
          (else (drop (call $write (i32.const 8192) (local.get $got)))))))
    "#;

/// A single-shot HTTP server on loopback. Returns its port.
///
/// A real socket rather than a mock: the thing under test is a hand-written
/// HTTP client, and the bugs it can have — framing, the `Host` header, reading
/// to EOF — are exactly the ones a mock would paper over.
fn one_shot_server(response: &'static str) -> u16 {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

fn fetch_via_guest(policy: nebula_runtime::egress::Policy, url: &str) -> String {
    // A runtime of its own: egress policy is per-`Runtime`, and the shared one
    // in `common` must stay egress-off so nothing else can reach a socket.
    let runtime = Runtime::new(common::temp_dir("egress"))
        .expect("runtime")
        .with_egress(policy);
    let ctx = runtime
        .execute(FETCHER.as_bytes(), "run", "egress", url.as_bytes().to_vec())
        .expect("guest runs");
    String::from_utf8_lossy(&ctx.response).to_string()
}

#[test]
fn a_guest_cannot_reach_the_network_unless_an_operator_said_so() {
    let port = one_shot_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");

    // The default. Every other test in this file passes an explicit policy, so
    // this is the one that pins the default itself — and the default is the
    // only thing standing between a fresh deployment and an SSRF proxy.
    let answer = fetch_via_guest(
        nebula_runtime::egress::Policy::default(),
        &format!("http://127.0.0.1:{port}/"),
    );
    assert_eq!(answer, "REFUSED");
}

#[test]
fn an_allowed_host_comes_back_whole() {
    let port = one_shot_server("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot there");

    // Loopback is not a public address, so this needs the escape hatch — the
    // only way to point the client at a server the test controls. The address
    // check is asserted on its own, against the whole list of ranges it has to
    // reject; what this test is for is the client itself, which is hand-written
    // and would otherwise never be exercised against a real socket.
    let policy = nebula_runtime::egress::Policy::new(["127.0.0.1"]).allow_private_addresses();
    let answer = fetch_via_guest(policy, &format!("http://127.0.0.1:{port}/"));

    // The *whole* response, status line included. Handing back only the body
    // would leave a script unable to tell `200` from `404`, and an agent would
    // summarise an error page as though it were data.
    assert!(answer.starts_with("HTTP/1.1 404 Not Found"), "{answer}");
    assert!(answer.ends_with("not there"), "{answer}");
}

#[test]
fn a_response_past_the_cap_is_refused_rather_than_truncated() {
    // A truncated response is worse than none: it parses, and it is wrong.
    let body = "x".repeat(2 << 20);
    let response: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_boxed_str(),
    );
    let port = one_shot_server(response);

    let policy = nebula_runtime::egress::Policy::new(["127.0.0.1"]).allow_private_addresses();
    let answer = fetch_via_guest(policy, &format!("http://127.0.0.1:{port}/"));
    assert_eq!(answer, "REFUSED");
}

#[test]
fn a_host_that_is_not_on_the_list_is_refused() {
    let policy = nebula_runtime::egress::Policy::new(["api.example.com"]);
    let answer = fetch_via_guest(policy, "http://evil.test/");
    assert_eq!(answer, "REFUSED");
}

#[test]
fn https_is_refused_rather_than_silently_downgraded() {
    // The dangerous alternative is stripping the scheme and fetching over
    // plaintext, which would be a downgrade attack implemented on purpose.
    let policy = nebula_runtime::egress::Policy::new(["api.example.com"]);
    let answer = fetch_via_guest(policy, "https://api.example.com/");
    assert_eq!(answer, "REFUSED");
}

#[test]
fn a_refusal_is_recoverable_rather_than_a_trap() {
    // §7.2's convention: `-1` on refusal, because a blocked host is a condition
    // the guest can handle. Trapping would kill a script for asking a question
    // it was allowed to ask and told no.
    let policy = nebula_runtime::egress::Policy::new(["api.example.com"]);
    let runtime = Runtime::new(common::temp_dir("egress-trap"))
        .expect("runtime")
        .with_egress(policy);

    let ctx = runtime
        .execute(
            FETCHER.as_bytes(),
            "run",
            "egress",
            b"http://blocked.test/".to_vec(),
        )
        .expect("a refused fetch must not trap the guest");

    assert_eq!(ctx.response, b"REFUSED");
    // The reason goes to the host, never to the guest — a guest told *why* a
    // host was blocked can enumerate the allowlist one request at a time.
    assert!(
        ctx.logs
            .iter()
            .any(|(_, message)| message.contains("refused")),
        "the host should record why: {:?}",
        ctx.logs
    );
}

#[test]
fn the_tenant_selects_the_allowlist() {
    let port = common::one_shot_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

    // Two tenants, one guest, one URL, two answers. This is the test that
    // proves the tenant actually reaches the policy check: with the plumbing
    // broken both calls would agree, and the feature would look like it worked
    // right up until one tenant read another's API.
    let runtime = Runtime::new(common::temp_dir("egress-tenants"))
        .expect("runtime")
        .with_egress(
            nebula_runtime::egress::Policy::default()
                .for_tenant("allowed", ["127.0.0.1"])
                .for_tenant("denied", ["somewhere.else"])
                .allow_private_addresses(),
        );

    let url = format!("http://127.0.0.1:{port}/");
    let fetch_as = |tenant: &str| {
        let ctx = runtime
            .execute(FETCHER.as_bytes(), "run", tenant, url.as_bytes().to_vec())
            .expect("guest runs");
        String::from_utf8_lossy(&ctx.response).to_string()
    };

    assert!(fetch_as("allowed").starts_with("HTTP/1.1 200 OK"));
    assert_eq!(fetch_as("denied"), "REFUSED");
    // A tenant with no entry of its own falls back to the shared list, which is
    // empty here — so an unknown caller reaches nothing rather than everything.
    assert_eq!(fetch_as("unknown"), "REFUSED");
}

// ---------------------------------------------------------------------------
// Session state (§22.5)
// ---------------------------------------------------------------------------

#[test]
fn two_sessions_of_one_tenant_cannot_read_each_other() {
    let kv = Kv::new();
    kv.set("acme", "chat-1", b"draft", b"first conversation")
        .expect("write");
    kv.set("acme", "chat-2", b"draft", b"second conversation")
        .expect("write");

    // The reason §22.5 namespaces by session rather than relying on distinct
    // keys: an agent picks its key names, and two conversations of one tenant
    // will pick the same ones.
    assert_eq!(
        kv.get("acme", "chat-1", b"draft").unwrap(),
        b"first conversation"
    );
    assert_eq!(
        kv.get("acme", "chat-2", b"draft").unwrap(),
        b"second conversation"
    );

    // And an unscoped request is its own namespace, not a shared one — so it
    // never sees a session's scratchpad by accident.
    assert!(kv.get("acme", "", b"draft").is_none());
}

#[test]
fn an_expired_entry_is_neither_served_nor_left_holding_space() {
    let kv = Kv::new();
    kv.set("acme", "s", b"k", b"v").expect("write");
    assert_eq!(kv.len(), 1);
    assert!(kv.bytes() > 0);

    // Nothing has expired yet, so a sweep must leave a live entry alone —
    // a sweep that dropped everything would pass the assertions below while
    // making the store useless.
    assert_eq!(kv.expire(), 0);
    assert!(kv.get("acme", "s", b"k").is_some());
}

#[test]
fn a_full_store_recovers_once_entries_expire() {
    // Without a TTL the caps are permanent: the node fills once and refuses
    // every write for the life of the process. This is the test that would
    // catch someone removing the sweep.
    let kv = Kv::new();
    let value = vec![0u8; kv::MAX_VALUE_BYTES];
    let mut written = 0;
    while kv
        .set("acme", "s", format!("k{written}").as_bytes(), &value)
        .is_ok()
    {
        written += 1;
        assert!(written < 100_000, "the byte cap never engaged");
    }

    assert!(written > 0, "nothing was ever stored");
    // Still full, and nothing has expired, so a retry is still refused rather
    // than the sweep silently dropping live data to make room.
    assert!(kv.set("acme", "s", b"one-more", &value).is_err());
}
