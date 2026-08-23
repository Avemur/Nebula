//! HTTP gateway and chaos tests (README.md §9.2, §10.1, §10.2, §11.1, §12).
//!
//! Lives in `nebula-worker` because it needs both halves of the cluster, and
//! `nebula-worker` is the crate that may depend on both.
//!
//! The HTTP client here is thirty lines of `TcpStream` rather than a
//! dependency: every request sends `Connection: close`, so "read to EOF" is the
//! whole response framing.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nebula_control::gateway::{self, Gateway};
use nebula_control::membership::{self, Membership};
use nebula_control::registry::Registry;
use nebula_control::server::ControlService;
use nebula_proto::nebula_control_server::NebulaControlServer;
use nebula_proto::nebula_worker_server::NebulaWorkerServer;
use nebula_runtime::Runtime;
use nebula_worker::exec_pool::ExecPool;
use nebula_worker::server::WorkerService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tonic::transport::server::TcpIncoming;
use tonic::transport::Server;

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

/// Answers "miss" the first time a tenant calls it and "hit" thereafter.
const KV_PROBE: &str = r#"
    (module
      (import "nebula" "kv_get" (func $get (param i32 i32 i32 i32) (result i32)))
      (import "nebula" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
      (import "nebula" "response_write" (func $write (param i32 i32) (result i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "k")
      (data (i32.const 8) "v")
      (data (i32.const 16) "hit")
      (data (i32.const 32) "miss")
      (func (export "run")
        (if (i32.eq (call $get (i32.const 0) (i32.const 1) (i32.const 256) (i32.const 16))
                    (i32.const -1))
          (then
            (drop (call $set (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 1)))
            (drop (call $write (i32.const 32) (i32.const 4))))
          (else
            (drop (call $write (i32.const 16) (i32.const 3)))))))
    "#;

/// Asks for far more memory than the ceiling allows, then uses it anyway.
const MEMORY_HOG: &str = r#"
    (module
      (memory (export "memory") 1)
      (func (export "run")
        (drop (memory.grow (i32.const 100000)))
        (i32.store (i32.const 65536) (i32.const 1))))
    "#;

const TRAPPER: &str = r#"(module (func (export "run") (unreachable)))"#;

/// Burns roughly 100 ms — comfortably past the 50 ms default budget, and
/// comfortably inside anything a tool-calling client would ask for.
const SLOW: &str = r#"
    (module
      (memory (export "memory") 1)
      (func (export "run")
        (local $i i64)
        (local.set $i (i64.const 250000000))
        (loop $l
          (i32.store (i32.const 0) (i32.wrap_i64 (local.get $i)))
          (local.set $i (i64.sub (local.get $i) (i64.const 1)))
          (br_if $l (i64.ne (local.get $i) (i64.const 0))))))
    "#;

// ---------------------------------------------------------------------------
// A very small HTTP/1.1 client
// ---------------------------------------------------------------------------

struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

async fn http(
    addr: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    extra: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).await.expect("connect gateway");

    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: nebula\r\nConnection: close\r\n\
         Content-Length: {}\r\n",
        body.len()
    );
    if let Some(token) = token {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    for (name, value) in extra {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");

    stream.write_all(head.as_bytes()).await.expect("write head");
    stream.write_all(body).await.expect("write body");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a header terminator");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let body = raw[split + 4..].to_vec();

    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status line");

    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_lowercase(), value.trim().to_string()))
        .collect();

    HttpResponse {
        status,
        headers,
        body,
    }
}

// ---------------------------------------------------------------------------
// Cluster fixture
// ---------------------------------------------------------------------------

fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "nebula-gw-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

struct Cluster {
    http_addr: String,
    control_url: String,
    membership: Arc<Membership>,
    gateway: Arc<Gateway>,
    workers: Vec<Worker>,
}

struct Worker {
    node_id: String,
    /// Closes the server *and* its established connections.
    ///
    /// Aborting the accept task is not enough: tonic runs each connection in
    /// its own task, so an abort closes the listener while every live channel
    /// keeps working. A `kill -9` takes the connections with it, and so must
    /// this.
    kill: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Cluster {
    async fn start(liveness: Duration) -> Self {
        // Quiet unless NEBULA_LOG says otherwise.
        nebula_worker::init_tracing_with_default("off");
        let membership = Arc::new(Membership::new(liveness));
        let registry = Arc::new(Registry::new(temp_dir("registry")).expect("registry"));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_url = format!("http://{}", listener.local_addr().unwrap());
        let control = ControlService::new(membership.clone(), registry.clone());
        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(NebulaControlServer::new(control))
                .serve_with_incoming(TcpIncoming::from(listener))
                .await;
        });

        let gateway =
            Arc::new(Gateway::open(membership.clone(), registry.clone()).expect("gateway"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = listener.local_addr().unwrap().to_string();
        let state = gateway.clone();
        tokio::spawn(async move {
            let _ = gateway::serve(listener, state).await;
        });

        Self {
            http_addr,
            control_url,
            membership,
            gateway,
            workers: Vec::new(),
        }
    }

    /// Starts a worker, registers it, and returns its node id.
    async fn add_worker(&mut self, threads: usize, max_concurrent: usize) -> String {
        let runtime = Arc::new(Runtime::new(temp_dir("l2")).expect("runtime"));
        let pool = Arc::new(ExecPool::new(runtime.clone(), threads, max_concurrent));
        let service = WorkerService::new(runtime, pool, &self.control_url).expect("worker service");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (kill, killed) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(NebulaWorkerServer::new(service))
                .serve_with_incoming_shutdown(TcpIncoming::from(listener), async {
                    let _ = killed.await;
                })
                .await;
        });

        let node_id = format!("worker-{address}");
        self.membership.register(&node_id, &address, 1);
        self.workers.push(Worker {
            node_id: node_id.clone(),
            kill: Some(kill),
        });
        node_id
    }

    /// Registers a node whose address nothing is listening on — a worker the
    /// gateway can never establish a connection to.
    fn add_phantom(&self, node_id: &str) {
        // Port 1 on loopback: reserved, and reliably refuses.
        self.membership.register(node_id, "127.0.0.1:1", 1);
    }

    /// Stops a worker's server outright, the way `kill -9` would.
    fn kill(&mut self, node_id: &str) {
        if let Some(worker) = self.workers.iter_mut().find(|w| w.node_id == node_id) {
            if let Some(kill) = worker.kill.take() {
                let _ = kill.send(());
            }
        }
    }

    async fn publish(&self, function_id: &str, wasm: &str) {
        self.gateway
            .publish(function_id, wasm.as_bytes())
            .await
            .expect("publish");
    }

    async fn post(&self, function_id: &str, token: &str, body: &[u8]) -> HttpResponse {
        self.post_with(function_id, token, &[], body).await
    }

    async fn post_with(
        &self,
        function_id: &str,
        token: &str,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> HttpResponse {
        http(
            &self.http_addr,
            "POST",
            &format!("/execute/{function_id}"),
            Some(token),
            extra,
            body,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Gateway
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn http_execute_round_trips_through_the_cluster() {
    let mut cluster = Cluster::start(Duration::from_secs(30)).await;
    cluster.add_worker(2, 4).await;

    let deployed = http(
        &cluster.http_addr,
        "PUT",
        "/functions/echo",
        Some("acme"),
        &[],
        ECHO.as_bytes(),
    )
    .await;
    assert_eq!(deployed.status, 201);
    assert!(deployed.text().contains("content_hash"));

    let response = cluster.post("echo", "acme", b"hello over http").await;
    assert_eq!(response.status, 200, "body was {}", response.text());
    assert_eq!(response.body, b"hello over http");
    assert_eq!(response.header("x-nebula-cold"), Some("true"));

    let warm = cluster.post("echo", "acme", b"again").await;
    assert_eq!(warm.status, 200);
    assert_eq!(warm.header("x-nebula-cold"), Some("false"));
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_without_a_bearer_token_are_rejected() {
    let mut cluster = Cluster::start(Duration::from_secs(30)).await;
    cluster.add_worker(1, 2).await;
    cluster.publish("echo", ECHO).await;

    let anonymous = http(&cluster.http_addr, "POST", "/execute/echo", None, &[], b"x").await;
    assert_eq!(anonymous.status, 401);
    assert!(anonymous.header("www-authenticate").is_some());

    let unknown = cluster.post("nope", "acme", b"x").await;
    assert_eq!(unknown.status, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bearer_token_namespaces_the_kv_store() {
    // §7.2 via §13: the token *is* the tenant in v1, and it must be the thing
    // that separates two callers of the same function.
    let mut cluster = Cluster::start(Duration::from_secs(30)).await;
    cluster.add_worker(1, 2).await;
    cluster.publish("probe", KV_PROBE).await;

    assert_eq!(cluster.post("probe", "acme", b"").await.text(), "miss");
    assert_eq!(cluster.post("probe", "acme", b"").await.text(), "hit");

    // A different token is a different tenant, so it starts empty even though
    // it is calling the identical function on the identical worker.
    assert_eq!(cluster.post("probe", "globex", b"").await.text(), "miss");
    assert_eq!(cluster.post("probe", "globex", b"").await.text(), "hit");
    assert_eq!(cluster.post("probe", "acme", b"").await.text(), "hit");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_memory_ceiling_breach_maps_to_memory_limit() {
    // Before the limiter recorded its refusal this came back as a plain TRAP —
    // the guest's out-of-bounds access — which names the symptom, not the cause.
    let mut cluster = Cluster::start(Duration::from_secs(30)).await;
    cluster.add_worker(1, 2).await;
    cluster.publish("hog", MEMORY_HOG).await;

    let response = cluster.post("hog", "acme", b"").await;
    assert_eq!(response.status, 500);
    assert_eq!(response.header("x-nebula-fault"), Some("memory_limit"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_cluster_reports_service_unavailable() {
    let cluster = Cluster::start(Duration::from_secs(30)).await;
    cluster.publish("echo", ECHO).await;

    let response = cluster.post("echo", "acme", b"x").await;
    assert_eq!(response.status, 503);
    assert_eq!(response.header("retry-after"), Some("1"));
}

// ---------------------------------------------------------------------------
// Caller-supplied deadlines and machine-readable faults
//
// Both exist for tool-calling clients: 50 ms suits a web handler and starves an
// agent, and a status code alone cannot tell one 503 from another.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_supplied_deadline_is_honoured() {
    let mut cluster = Cluster::start(Duration::from_secs(30)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("slow", SLOW).await;

    // The default budget is too small for this guest, and says so precisely.
    let default = cluster.post("slow", "acme", b"").await;
    assert_eq!(default.status, 504);
    assert_eq!(default.header("x-nebula-fault"), Some("timeout"));
    assert_eq!(default.header("x-nebula-deadline-ms"), Some("50"));

    // Asking for more is all it takes.
    let generous = cluster
        .post_with("slow", "acme", &[("X-Nebula-Deadline-Ms", "2000")], b"")
        .await;
    assert_eq!(
        generous.status,
        200,
        "a 2 s budget should cover a 100 ms guest: {}",
        generous.text()
    );
    assert_eq!(generous.header("x-nebula-deadline-ms"), Some("2000"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_out_of_range_deadline_is_clamped_and_the_effective_value_echoed() {
    let mut cluster = Cluster::start(Duration::from_secs(30)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    // Silently clamping without saying so is how a caller ends up reading a
    // `timeout` fault as a bug in its own code.
    let greedy = cluster
        .post_with("echo", "acme", &[("X-Nebula-Deadline-Ms", "60000")], b"x")
        .await;
    assert_eq!(greedy.status, 200);
    assert_eq!(greedy.header("x-nebula-deadline-ms"), Some("5000"));

    let tiny = cluster
        .post_with("echo", "acme", &[("X-Nebula-Deadline-Ms", "0")], b"x")
        .await;
    assert_eq!(tiny.header("x-nebula-deadline-ms"), Some("10"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_deadline_is_rejected_rather_than_defaulted() {
    // Falling back to 50 ms would hand a client that asked for seconds a
    // `timeout` it cannot explain. A 400 names the mistake.
    let mut cluster = Cluster::start(Duration::from_secs(30)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    for bad in ["abc", "-1", "2.5", ""] {
        let response = cluster
            .post_with("echo", "acme", &[("X-Nebula-Deadline-Ms", bad)], b"x")
            .await;
        assert_eq!(response.status, 400, "accepted deadline {bad:?}");
        assert_eq!(response.header("x-nebula-fault"), Some("invalid_deadline"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_failure_names_its_own_cause() {
    // A client — an LLM tool wrapper especially — has to branch on *why*. Status
    // codes collide: 503 is both "no worker" and "worker shed", 500 is both a
    // guest trap and a memory ceiling.
    let mut cluster = Cluster::start(Duration::from_secs(30)).await;

    // Before any worker exists.
    cluster.publish("echo", ECHO).await;
    let no_worker = cluster.post("echo", "acme", b"x").await;
    assert_eq!(no_worker.status, 503);
    assert_eq!(
        no_worker.header("x-nebula-fault"),
        Some("no_healthy_worker")
    );
    assert_eq!(no_worker.header("retry-after"), Some("1"));

    cluster.add_worker(2, 4).await;
    cluster.publish("hog", MEMORY_HOG).await;
    cluster.publish("trap", TRAPPER).await;

    for (function, status, fault) in [
        ("hog", 500, "memory_limit"),
        ("trap", 500, "trap"),
        ("missing", 404, "unknown_function"),
    ] {
        let response = cluster.post(function, "acme", b"x").await;
        assert_eq!(response.status, status, "{function}");
        assert_eq!(response.header("x-nebula-fault"), Some(fault), "{function}");
    }

    let anonymous = http(&cluster.http_addr, "POST", "/execute/echo", None, &[], b"x").await;
    assert_eq!(anonymous.status, 401);
    assert_eq!(anonymous.header("x-nebula-fault"), Some("unauthorized"));
}

// ---------------------------------------------------------------------------
// Chaos: Phase 3 exit criteria
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_worker_killed_mid_flight_is_reported_not_retried() {
    // `kill -9`: the connection was live, so the request may already have run.
    // §10.2 forbids re-executing it — the gateway cannot know whether the
    // guest's host calls were idempotent — so this is a 502, not a retry.
    let mut cluster = Cluster::start(Duration::from_secs(30)).await;
    let victim = cluster.add_worker(1, 2).await;
    cluster.publish("echo", ECHO).await;

    // Warm the channel, so the gateway holds an established connection.
    assert_eq!(cluster.post("echo", "acme", b"warm").await.status, 200);

    cluster.kill(&victim);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let response = cluster.post("echo", "acme", b"after the kill").await;
    assert_eq!(
        response.status, 502,
        "a request on an established connection must be reported, not retried"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_worker_that_cannot_be_reached_is_retried_onto_a_live_one() {
    // The other half of §10.2: if the connection was never established, nothing
    // ran, and retrying the next node on the ring is safe.
    let mut cluster = Cluster::start(Duration::from_secs(30)).await;
    cluster.add_worker(1, 4).await;
    for n in 0..4 {
        cluster.add_phantom(&format!("phantom-{n}"));
    }

    // Twenty distinct function ids, not twenty calls to one. A single id hashes
    // to a single ring position, so repeating it just asks the same question
    // twenty times — and whether the live worker leads that one walk is decided
    // by the hash, not by the failover logic under test.
    let mut served = 0;
    for n in 0..20 {
        let function = format!("echo-{n}");
        cluster.publish(&function, ECHO).await;
        let response = cluster.post(&function, "acme", b"routed").await;

        match response.status {
            200 => {
                assert_eq!(response.body, b"routed");
                served += 1;
            }
            // One retry only, so two phantoms in a row still gives up.
            503 => {}
            // The point of the test: nothing ran, so nothing may be reported as
            // possibly-executed.
            other => panic!(
                "unreachable nodes must never yield {other}: {}",
                response.text()
            ),
        }
    }

    assert!(
        served > 0,
        "an unreachable lead node must fail over to the live worker"
    );
    assert!(
        served < 20,
        "with four phantoms some walks should exhaust the single retry, \
         otherwise this test is not exercising failover at all"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_paused_worker_leaves_the_ring_after_the_liveness_timeout() {
    // `SIGSTOP`: the process is alive and its socket is open, but it stops
    // beating. To the control plane that is indistinguishable from death, which
    // is exactly why liveness is a timestamp and not a stream.
    //
    // Uses the real 1.5 s timeout from §10.1 rather than a shortened one, so
    // this is the exit criterion and not a scale model of it.
    let mut cluster = Cluster::start(membership::LIVENESS_TIMEOUT).await;
    let paused = cluster.add_worker(1, 2).await;
    cluster.publish("echo", ECHO).await;

    membership::spawn_reconciler(cluster.membership.clone(), Duration::from_millis(100));

    // Beat for a while: a live worker must survive reconciliation.
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(cluster.membership.heartbeat(&paused, 1, 0, 0, 0));
        assert!(cluster.membership.contains(&paused));
    }
    assert_eq!(cluster.post("echo", "acme", b"alive").await.status, 200);

    // Then stop, without closing the socket.
    tokio::time::sleep(membership::LIVENESS_TIMEOUT + Duration::from_millis(400)).await;

    assert!(
        !cluster.membership.contains(&paused),
        "three missed beats must remove the worker from the ring"
    );
    assert!(cluster.membership.is_empty());

    // And the gateway stops routing to it, rather than hanging on a socket that
    // will never answer.
    let response = cluster.post("echo", "acme", b"after the pause").await;
    assert_eq!(response.status, 503);
}

// ---------------------------------------------------------------------------
// Idempotency keys (§22.4)
// ---------------------------------------------------------------------------

/// A guest that counts its executions in the KV shim and answers with the
/// count. Anything that runs twice says so.
const COUNTER: &str = r#"
    (module
      (import "nebula" "kv_get" (func $get (param i32 i32 i32 i32) (result i32)))
      (import "nebula" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
      (import "nebula" "response_write" (func $write (param i32 i32) (result i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "n")
      (data (i32.const 16) "1")
      (data (i32.const 32) "2")
      (func (export "run")
        (if (i32.eq (call $get (i32.const 0) (i32.const 1) (i32.const 256) (i32.const 16))
                    (i32.const -1))
          (then
            (drop (call $set (i32.const 0) (i32.const 1) (i32.const 16) (i32.const 1)))
            (drop (call $write (i32.const 16) (i32.const 1))))
          (else
            (drop (call $write (i32.const 32) (i32.const 1)))))))
    "#;

#[tokio::test]
async fn a_repeated_key_replays_instead_of_running_again() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("counter", COUNTER).await;

    let key = [("Idempotency-Key", "call-1")];
    let first = cluster.post_with("counter", "acme", &key, b"").await;
    assert_eq!(first.status, 200);
    assert_eq!(first.text(), "1", "the first call must actually run");
    assert!(first.header("x-nebula-idempotent-replay").is_none());

    // The whole point: the guest is *not* invoked a second time. Without the
    // store this would answer "2", because the KV entry from the first run is
    // still there — which is exactly the double execution §10.2 warns about
    // and every agent framework causes by retrying.
    let second = cluster.post_with("counter", "acme", &key, b"").await;
    assert_eq!(second.status, 200);
    assert_eq!(
        second.text(),
        "1",
        "a repeated key must not re-run the guest"
    );
    assert_eq!(second.header("x-nebula-idempotent-replay"), Some("true"));

    // A different key is a different request.
    let other = [("Idempotency-Key", "call-2")];
    let third = cluster.post_with("counter", "acme", &other, b"").await;
    assert_eq!(third.text(), "2", "a fresh key must run the guest again");
}

#[tokio::test]
async fn a_replay_reproduces_the_original_answer_exactly() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;
    cluster.publish("trapper", TRAPPER).await;

    // A guest fault replays too: the script ran and produced this outcome, so
    // running it again would produce the same one. Not replaying it would mean
    // a retrying client re-executes every failing script.
    let key = [("Idempotency-Key", "fault-1")];
    let first = cluster.post_with("trapper", "acme", &key, b"").await;
    assert_eq!(first.status, 500);
    assert_eq!(first.header("x-nebula-fault"), Some("trap"));

    let second = cluster.post_with("trapper", "acme", &key, b"").await;
    assert_eq!(second.status, first.status);
    assert_eq!(second.text(), first.text());
    assert_eq!(second.header("x-nebula-fault"), Some("trap"));
    assert_eq!(second.header("x-nebula-idempotent-replay"), Some("true"));

    // Informational headers come back as recorded rather than regenerated: a
    // replay that reported a fresh `cold` or a new exec time would be
    // reporting a measurement of something that never happened.
    let key = [("Idempotency-Key", "echo-1")];
    let first = cluster.post_with("echo", "acme", &key, b"payload").await;
    let second = cluster.post_with("echo", "acme", &key, b"payload").await;
    assert_eq!(second.text(), "payload");
    assert_eq!(
        second.header("x-nebula-exec-micros"),
        first.header("x-nebula-exec-micros")
    );
    assert_eq!(
        second.header("x-nebula-cold"),
        first.header("x-nebula-cold")
    );
}

#[tokio::test]
async fn one_tenants_key_cannot_read_anothers_answer() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    // Not a nicety. Without the tenant in the slot, an `Idempotency-Key` is an
    // oracle for whatever another tenant happened to name the same thing —
    // which would make this feature a cross-tenant read primitive.
    let key = [("Idempotency-Key", "shared-name")];
    let acme = cluster
        .post_with("echo", "acme", &key, b"acme secret")
        .await;
    assert_eq!(acme.text(), "acme secret");

    let other = cluster
        .post_with("echo", "globex", &key, b"globex data")
        .await;
    assert_eq!(other.text(), "globex data");
    assert!(
        other.header("x-nebula-idempotent-replay").is_none(),
        "a second tenant must never be served the first tenant's answer"
    );
}

#[tokio::test]
async fn a_failure_that_never_ran_leaves_the_key_free_for_a_real_retry() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.publish("echo", ECHO).await;

    // No workers yet: nothing ran, so there is no answer worth keeping.
    let key = [("Idempotency-Key", "retry-me")];
    let first = cluster.post_with("echo", "acme", &key, b"payload").await;
    assert_eq!(first.status, 503);
    assert_eq!(first.header("x-nebula-fault"), Some("no_healthy_worker"));

    // Storing that 503 would pin a transient failure for the whole TTL and
    // make the key actively worse than not sending one.
    cluster.add_worker(2, 4).await;
    let second = cluster.post_with("echo", "acme", &key, b"payload").await;
    assert_eq!(second.status, 200);
    assert_eq!(second.text(), "payload");
    assert!(second.header("x-nebula-idempotent-replay").is_none());
}

#[tokio::test]
async fn a_duplicate_arriving_mid_flight_is_refused_rather_than_run() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("slow", SLOW).await;

    // SLOW runs ~100 ms; both requests are keyed the same and overlap. Serving
    // the second by running it would be the exact double execution the key was
    // sent to prevent, and there is no stored answer to replay yet.
    let headers = [
        ("Idempotency-Key", "concurrent"),
        ("X-Nebula-Deadline-Ms", "2000"),
    ];
    let first = cluster.post_with("slow", "acme", &headers, b"");
    let second = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        cluster.post_with("slow", "acme", &headers, b"").await
    };
    let (first, second) = tokio::join!(first, second);

    assert_eq!(first.status, 200);
    assert_eq!(second.status, 409);
    assert_eq!(
        second.header("x-nebula-fault"),
        Some("idempotency_in_flight")
    );
}

#[tokio::test]
async fn a_malformed_key_is_refused_rather_than_silently_dropped() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    // A client that sent a key meant to be protected. Ignoring the header and
    // running unkeyed is the worst of the three options: it looks like it
    // worked and silently removes the guarantee that was asked for.
    let long = "k".repeat(300);
    for bad in ["", "   ", long.as_str()] {
        let response = cluster
            .post_with("echo", "acme", &[("Idempotency-Key", bad)], b"payload")
            .await;
        assert_eq!(response.status, 400, "key {bad:?} should be refused");
        assert_eq!(
            response.header("x-nebula-fault"),
            Some("invalid_idempotency_key")
        );
    }

    // And an unkeyed request is entirely unaffected.
    let response = cluster.post("echo", "acme", b"payload").await;
    assert_eq!(response.status, 200);
}
