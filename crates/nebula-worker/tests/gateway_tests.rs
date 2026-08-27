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
use nebula_control::ratelimit::Limit;
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

/// Burns roughly 100 ms: comfortably past the 50 ms default budget, and
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
    registry: Arc<Registry>,
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
        // Existing tests predate the limiter and are not about it; leaving them
        // subject to the real defaults would make an unrelated failure look
        // like a routing bug.
        Self::with_limits(liveness, Limit::NONE, Limit::NONE).await
    }

    /// A cluster that requires signed bearer tokens (§13).
    async fn authenticated(secret: &[u8]) -> Self {
        let mut cluster = Self::start(Duration::from_secs(5)).await;
        cluster
            .restart_gateway_with(nebula_control::auth::Auth::signed(secret))
            .await;
        cluster
    }

    /// A cluster with real rate limits, for the tests that are about them.
    async fn with_limits(liveness: Duration, execute: Limit, deploy: Limit) -> Self {
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

        let gateway = Arc::new(
            Gateway::open(membership.clone(), registry.clone())
                .expect("gateway")
                .with_limits(execute, deploy),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = listener.local_addr().unwrap().to_string();
        let state = gateway.clone();
        tokio::spawn(async move {
            let _ = gateway::serve(listener, state).await;
        });

        Self {
            http_addr,
            registry,
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

    /// Replaces the gateway with one that authenticates, on a new port.
    async fn restart_gateway_with(&mut self, auth: nebula_control::auth::Auth) {
        let gateway = Arc::new(
            Gateway::open(self.membership.clone(), self.registry.clone())
                .expect("gateway")
                .with_auth(auth),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        self.http_addr = listener.local_addr().unwrap().to_string();
        self.gateway = gateway.clone();
        tokio::spawn(async move {
            let _ = gateway::serve(listener, gateway).await;
        });
    }

    /// Registers a node whose address nothing is listening on: a worker the
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

    // Deployed before any worker exists, so nothing precompiles it (§19) and
    // the first request is genuinely cold. With a worker already up this would
    // report warm, which is the point of precompilation and would make the
    // assertion below untrue for a reason unrelated to what this test is for.
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

    cluster.add_worker(2, 4).await;
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
    // Before the limiter recorded its refusal this came back as a plain TRAP,
    // the guest's out-of-bounds access, which names the symptom, not the cause.
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
    // A client, an LLM tool wrapper especially, has to branch on *why*. Status
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
    // §10.2 forbids re-executing it (the gateway cannot know whether the
    // guest's host calls were idempotent), so this is a 502, not a retry.
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
    // twenty times, and whether the live worker leads that one walk is decided
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
    // still there, which is exactly the double execution §10.2 warns about
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
    // oracle for whatever another tenant happened to name the same thing,
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

#[tokio::test]
async fn a_client_that_disconnects_does_not_wedge_its_own_key() {
    use tokio::io::AsyncWriteExt;

    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("slow", SLOW).await;

    // Send a keyed request and hang up before it can answer. This is the exact
    // scenario the key exists for: the client lost the answer and will retry.
    {
        let mut stream = TcpStream::connect(&cluster.http_addr).await.unwrap();
        let head = "POST /execute/slow HTTP/1.1\r\nHost: nebula\r\nConnection: close\r\n\
                    Authorization: Bearer acme\r\nIdempotency-Key: dropped\r\n\
                    X-Nebula-Deadline-Ms: 2000\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(head.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let _ = stream.shutdown().await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The retry must run. A slot left claimed by a request nobody is waiting
    // for would answer 409 for the whole TTL, which would make the key a
    // liability in precisely the case it was added to serve.
    let headers = [
        ("Idempotency-Key", "dropped"),
        ("X-Nebula-Deadline-Ms", "2000"),
    ];
    let retry = cluster.post_with("slow", "acme", &headers, b"").await;
    assert_eq!(
        retry.status, 200,
        "a retry after a disconnect must run, not hit a wedged slot"
    );
}

// ---------------------------------------------------------------------------
// Trace context (§22.6)
// ---------------------------------------------------------------------------

/// A well-formed W3C `traceparent`, from the spec's own example.
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const CALLER_TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

#[tokio::test]
async fn a_callers_trace_id_is_adopted_and_reported_back() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    let response = cluster
        .post_with("echo", "acme", &[("traceparent", TRACEPARENT)], b"hi")
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("x-nebula-trace-id"),
        Some(CALLER_TRACE_ID),
        "the tool call must appear inside the caller's trace, not a new one"
    );
}

#[tokio::test]
async fn a_request_without_a_traceparent_still_gets_an_id_it_can_be_told() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    let first = cluster.post("echo", "acme", b"hi").await;
    let second = cluster.post("echo", "acme", b"hi").await;

    let (Some(a), Some(b)) = (
        first.header("x-nebula-trace-id"),
        second.header("x-nebula-trace-id"),
    ) else {
        panic!("a minted trace id is useless if the caller is never told it");
    };
    assert_eq!(a.len(), 32);
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b, "two requests must not share a trace id");
}

#[tokio::test]
async fn broken_caller_instrumentation_does_not_break_the_call() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    // W3C says a malformed header starts a new trace. Refusing the request
    // would mean a caller's tracing bug takes down its tool calls, which is a
    // spectacularly bad trade.
    for bad in ["garbage", "00-tooshort-00f067aa0ba902b7-01", ""] {
        let response = cluster
            .post_with("echo", "acme", &[("traceparent", bad)], b"hi")
            .await;
        assert_eq!(
            response.status, 200,
            "traceparent {bad:?} broke the request"
        );

        let id = response
            .header("x-nebula-trace-id")
            .expect("a fresh trace should still be reported");
        assert_eq!(id.len(), 32, "{bad:?} produced {id}");
        assert_ne!(id, CALLER_TRACE_ID);
    }
}

#[tokio::test]
async fn a_rejected_request_is_still_findable_in_the_callers_trace() {
    let cluster = Cluster::start(Duration::from_secs(5)).await;

    // The failures are the ones a caller most wants to find. A trace id
    // stamped only on success is a trace id that is missing exactly when it is
    // needed, so every exit gets one, including the ones that never reach a
    // worker at all.
    let unauthorized = http(
        &cluster.http_addr,
        "POST",
        "/execute/echo",
        None,
        &[("traceparent", TRACEPARENT)],
        b"hi",
    )
    .await;
    assert_eq!(unauthorized.status, 401);
    assert_eq!(
        unauthorized.header("x-nebula-trace-id"),
        Some(CALLER_TRACE_ID)
    );

    let unknown = cluster
        .post_with("nothing-here", "acme", &[("traceparent", TRACEPARENT)], b"")
        .await;
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.header("x-nebula-trace-id"), Some(CALLER_TRACE_ID));

    cluster.publish("echo", ECHO).await;
    let no_worker = cluster
        .post_with("echo", "acme", &[("traceparent", TRACEPARENT)], b"")
        .await;
    assert_eq!(no_worker.status, 503);
    assert_eq!(no_worker.header("x-nebula-trace-id"), Some(CALLER_TRACE_ID));
}

#[tokio::test]
async fn a_replayed_answer_reports_the_trace_that_asked_for_it() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    let key = ("Idempotency-Key", "traced");
    let first = cluster
        .post_with("echo", "acme", &[key, ("traceparent", TRACEPARENT)], b"hi")
        .await;
    assert_eq!(first.header("x-nebula-trace-id"), Some(CALLER_TRACE_ID));

    // The body is replayed; the trace id is not. It belongs to *this* request,
    // and reporting the original one would point a caller at a trace it was
    // never part of.
    let second = cluster.post_with("echo", "acme", &[key], b"hi").await;
    assert_eq!(second.header("x-nebula-idempotent-replay"), Some("true"));
    let replayed = second
        .header("x-nebula-trace-id")
        .expect("a replay is still a request");
    assert_ne!(replayed, CALLER_TRACE_ID);
}

// ---------------------------------------------------------------------------
// Per-tenant rate limiting (§22.7)
// ---------------------------------------------------------------------------

/// Two requests up front, then one every ten seconds, so within a test, the
/// third request is refused and stays refused.
const TWO_THEN_NOTHING: Limit = Limit {
    per_second: 0.1,
    burst: 2.0,
};

#[tokio::test]
async fn a_tenant_over_its_budget_is_told_so_and_told_when_to_return() {
    let mut cluster = Cluster::with_limits(
        Duration::from_secs(5),
        TWO_THEN_NOTHING,
        nebula_control::ratelimit::Limit::NONE,
    )
    .await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    assert_eq!(cluster.post("echo", "acme", b"a").await.status, 200);
    assert_eq!(cluster.post("echo", "acme", b"b").await.status, 200);

    let refused = cluster.post("echo", "acme", b"c").await;
    // A 429 rather than a 503: the cluster is fine, this caller is ahead of its
    // own budget, and "service unavailable" would send it looking at the wrong
    // problem entirely.
    assert_eq!(refused.status, 429);
    assert_eq!(refused.header("x-nebula-fault"), Some("rate_limited"));
    assert!(
        refused.header("retry-after").is_some(),
        "a refusal with no advice on when to come back invites a hot loop"
    );
}

#[tokio::test]
async fn a_noisy_tenant_does_not_spend_a_quiet_ones_budget() {
    let mut cluster = Cluster::with_limits(
        Duration::from_secs(5),
        TWO_THEN_NOTHING,
        nebula_control::ratelimit::Limit::NONE,
    )
    .await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    // This is the whole reason the limiter is per-tenant rather than global.
    // §10.3 sheds when the *cluster* is busy and cannot tell a noisy neighbour
    // from a busy day; a global limiter would make every tenant pay for one.
    for _ in 0..4 {
        cluster.post("echo", "noisy", b"x").await;
    }
    assert_eq!(cluster.post("echo", "noisy", b"x").await.status, 429);

    let quiet = cluster.post("echo", "polite", b"x").await;
    assert_eq!(quiet.status, 200);
    assert_eq!(quiet.text(), "x");
}

#[tokio::test]
async fn a_refused_request_never_reaches_a_worker() {
    let mut cluster = Cluster::with_limits(
        Duration::from_secs(5),
        TWO_THEN_NOTHING,
        nebula_control::ratelimit::Limit::NONE,
    )
    .await;
    cluster.add_worker(2, 4).await;

    // Deliberately *not* deployed. A refused request must be rejected before
    // the deployment lookup and the ring walk, so a limiter under attack costs
    // a hash rather than becoming its own load amplifier. If the check moved
    // below the lookup, these would be 404 and the ordering bug would be
    // invisible.
    for _ in 0..2 {
        assert_eq!(
            cluster.post("never-deployed", "acme", b"x").await.status,
            404
        );
    }
    let refused = cluster.post("never-deployed", "acme", b"x").await;
    assert_eq!(refused.status, 429);
    assert_eq!(refused.header("x-nebula-fault"), Some("rate_limited"));
}

#[tokio::test]
async fn deploys_are_limited_far_harder_than_executions() {
    let mut cluster = Cluster::with_limits(
        Duration::from_secs(5),
        nebula_control::ratelimit::Limit::NONE,
        Limit {
            per_second: 0.01,
            burst: 2.0,
        },
    )
    .await;
    cluster.add_worker(2, 4).await;

    // `PUT /functions/{id}` runs Wizer, which spawns a subprocess and executes
    // the caller's guest code on the control plane (§11.1). An unlimited deploy
    // endpoint is a far cheaper way to hurt this process than an unlimited
    // execute endpoint, which at least has §10.3 behind it.
    for n in 0..2 {
        let response = http(
            &cluster.http_addr,
            "PUT",
            &format!("/functions/deploy-{n}"),
            Some("acme"),
            &[],
            ECHO.as_bytes(),
        )
        .await;
        assert_eq!(response.status, 201);
    }

    let refused = http(
        &cluster.http_addr,
        "PUT",
        "/functions/deploy-3",
        Some("acme"),
        &[],
        ECHO.as_bytes(),
    )
    .await;
    assert_eq!(refused.status, 429);
    assert_eq!(refused.header("x-nebula-fault"), Some("rate_limited"));

    // Executions are untouched by the deploy bucket: two limits, two budgets.
    cluster.publish("echo", ECHO).await;
    assert_eq!(cluster.post("echo", "acme", b"x").await.status, 200);
}

#[tokio::test]
async fn a_rate_limited_request_still_reports_its_trace() {
    let mut cluster = Cluster::with_limits(
        Duration::from_secs(5),
        Limit {
            per_second: 0.1,
            burst: 1.0,
        },
        nebula_control::ratelimit::Limit::NONE,
    )
    .await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    cluster.post("echo", "acme", b"x").await;
    let refused = cluster
        .post_with("echo", "acme", &[("traceparent", TRACEPARENT)], b"x")
        .await;

    // §22.6: a throttled call is one an agent very much wants to find in its
    // own trace, because it explains a latency spike that has nothing to do
    // with the code it ran.
    assert_eq!(refused.status, 429);
    assert_eq!(refused.header("x-nebula-trace-id"), Some(CALLER_TRACE_ID));
}

// ---------------------------------------------------------------------------
// Session continuity (§22.5)
// ---------------------------------------------------------------------------

/// Appends the request body to a session-scoped key and answers with the whole
/// accumulated value. A guest with no memory of its own would only ever say
/// what it was just sent.
const NOTEPAD: &str = r#"
    (module
      (import "nebula" "request_len" (func $len (result i32)))
      (import "nebula" "request_read" (func $read (param i32 i32) (result i32)))
      (import "nebula" "kv_get" (func $get (param i32 i32 i32 i32) (result i32)))
      (import "nebula" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
      (import "nebula" "response_write" (func $write (param i32 i32) (result i32)))
      (memory (export "memory") 4)
      (data (i32.const 0) "notes")
      (func (export "run")
        (local $held i32)
        (local $added i32)
        ;; Existing value into 1024, its length into $held (-1 becomes 0).
        (local.set $held
          (call $get (i32.const 0) (i32.const 5) (i32.const 1024) (i32.const 4096)))
        (if (i32.lt_s (local.get $held) (i32.const 0))
          (then (local.set $held (i32.const 0))))
        ;; Request body appended straight after it.
        (local.set $added (call $len))
        (drop (call $read (i32.add (i32.const 1024) (local.get $held)) (local.get $added)))
        (local.set $held (i32.add (local.get $held) (local.get $added)))
        (drop (call $set (i32.const 0) (i32.const 5) (i32.const 1024) (local.get $held)))
        (drop (call $write (i32.const 1024) (local.get $held)))))
    "#;

#[tokio::test]
async fn a_session_carries_state_from_one_request_to_the_next() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    // Several workers, so sticky routing has something to get wrong: without
    // it the second request lands wherever the ring sends it and the notepad
    // is empty.
    for _ in 0..3 {
        cluster.add_worker(2, 4).await;
    }
    cluster.publish("notepad", NOTEPAD).await;

    let session = [("X-Nebula-Partition-Key", "chat-1")];
    assert_eq!(
        cluster
            .post_with("notepad", "acme", &session, b"a")
            .await
            .text(),
        "a"
    );
    assert_eq!(
        cluster
            .post_with("notepad", "acme", &session, b"b")
            .await
            .text(),
        "ab"
    );
    assert_eq!(
        cluster
            .post_with("notepad", "acme", &session, b"c")
            .await
            .text(),
        "abc"
    );
}

#[tokio::test]
async fn a_second_session_starts_from_nothing() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    for _ in 0..3 {
        cluster.add_worker(2, 4).await;
    }
    cluster.publish("notepad", NOTEPAD).await;

    cluster
        .post_with(
            "notepad",
            "acme",
            &[("X-Nebula-Partition-Key", "chat-1")],
            b"private",
        )
        .await;

    // Two conversations of one tenant will pick the same key names, so the
    // separation has to come from the session rather than from the guest being
    // careful.
    let other = cluster
        .post_with(
            "notepad",
            "acme",
            &[("X-Nebula-Partition-Key", "chat-2")],
            b"fresh",
        )
        .await;
    assert_eq!(other.text(), "fresh");

    // And a request with no partition key is its own namespace, not a window
    // into someone's conversation.
    let unscoped = cluster.post("notepad", "acme", b"anon").await;
    assert_eq!(unscoped.text(), "anon");
}

#[tokio::test]
async fn a_malformed_partition_key_is_refused_rather_than_ignored() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("notepad", NOTEPAD).await;

    // A caller that sent a key is expecting its state back. Quietly dropping
    // the header would route the request somewhere else and look, from the
    // outside, exactly like the state vanishing.
    let long = "s".repeat(200);
    for bad in ["", "   ", long.as_str()] {
        let response = cluster
            .post_with("notepad", "acme", &[("X-Nebula-Partition-Key", bad)], b"x")
            .await;
        assert_eq!(response.status, 400, "key {bad:?} should be refused");
        assert_eq!(
            response.header("x-nebula-fault"),
            Some("invalid_partition_key")
        );
    }
}

#[tokio::test]
async fn sessions_of_one_function_spread_across_workers() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;

    // Deployed first, so deploy-time compilation (§19) reaches nobody and every
    // worker starts genuinely cold. Precompilation warms the two ring
    // candidates, which would leave exactly one worker able to report a cold
    // start and quietly turn the count below into a constant.
    cluster.publish("notepad", NOTEPAD).await;
    for _ in 0..3 {
        cluster.add_worker(2, 4).await;
    }

    // The test the two above cannot be: consistent hashing already pins one
    // *function* to one worker, so a notepad accumulates correctly even if the
    // partition key is ignored for routing entirely. What only partition
    // routing produces is *spread*: different sessions of one function landing
    // on different nodes.
    //
    // `X-Nebula-Cold` makes that observable: a worker reports cold the first
    // time it has to fetch a module. Route by function id and exactly one
    // worker ever sees this module, so exactly one response is cold.
    let mut cold = 0;
    for n in 0..12 {
        let key = format!("chat-{n}");
        let response = cluster
            .post_with("notepad", "acme", &[("X-Nebula-Partition-Key", &key)], b"x")
            .await;
        assert_eq!(response.status, 200);
        if response.header("x-nebula-cold") == Some("true") {
            cold += 1;
        }
    }

    assert!(
        cold > 1,
        "every session landed on one worker, so the partition key is not \
         reaching the ring: {cold} cold start(s) across 3 workers"
    );

    // And the cost of that spread, stated rather than hidden: each worker pays
    // its own compile. That is the trade §22.5 makes: state affinity instead
    // of cache affinity, and it is only paid by callers who ask for it.
    assert!(cold <= 3, "more cold starts than workers: {cold}");
}

// ---------------------------------------------------------------------------
// Tool metadata (§22.2)
// ---------------------------------------------------------------------------

const SCHEMA: &str = r#"{"description":"Echoes its input back.","input_schema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}"#;

async fn deploy_with(cluster: &Cluster, id: &str, schema: Option<&str>) -> HttpResponse {
    let extra: Vec<(&str, &str)> = schema
        .map(|s| vec![("X-Nebula-Tool-Schema", s)])
        .unwrap_or_default();
    http(
        &cluster.http_addr,
        "PUT",
        &format!("/functions/{id}"),
        Some("acme"),
        &extra,
        ECHO.as_bytes(),
    )
    .await
}

#[tokio::test]
async fn a_described_function_is_listed_for_agents() {
    let cluster = Cluster::start(Duration::from_secs(5)).await;

    let deployed = deploy_with(&cluster, "echo", Some(SCHEMA)).await;
    assert_eq!(deployed.status, 201);
    assert!(
        deployed.text().contains("\"described\":true"),
        "{}",
        deployed.text()
    );

    let listed = http(&cluster.http_addr, "GET", "/tools", None, &[], b"").await;
    assert_eq!(listed.status, 200);

    let tools: serde_json::Value = serde_json::from_slice(&listed.body).expect("json");
    let tools = tools.as_array().expect("an array");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "echo");
    assert_eq!(tools[0]["description"], "Echoes its input back.");
    // The schema is passed through untouched. A gateway that rewrote it would
    // be a gateway with an opinion about the guest's ABI.
    assert_eq!(tools[0]["input_schema"]["required"][0], "text");
}

#[tokio::test]
async fn an_undescribed_function_is_deployed_but_not_advertised() {
    let cluster = Cluster::start(Duration::from_secs(5)).await;

    let deployed = deploy_with(&cluster, "internal", None).await;
    assert_eq!(deployed.status, 201);
    assert!(deployed.text().contains("\"described\":false"));

    // A tool a model cannot understand is worse than one it cannot see: it will
    // call the first and guess at the arguments.
    let listed = http(&cluster.http_addr, "GET", "/tools", None, &[], b"").await;
    assert_eq!(listed.text(), "[]");
}

#[tokio::test]
async fn redeploying_without_a_descriptor_clears_the_old_one() {
    let cluster = Cluster::start(Duration::from_secs(5)).await;

    deploy_with(&cluster, "echo", Some(SCHEMA)).await;
    deploy_with(&cluster, "echo", None).await;

    // A stale description of a function that has changed is how a model gets
    // told confidently wrong things about what it is calling.
    let listed = http(&cluster.http_addr, "GET", "/tools", None, &[], b"").await;
    assert_eq!(listed.text(), "[]");
}

#[tokio::test]
async fn an_unusable_descriptor_is_refused_rather_than_dropped() {
    let cluster = Cluster::start(Duration::from_secs(5)).await;

    // A caller that sent a descriptor expects an agent to be able to find the
    // function. Deploying it undescribed would look like success and produce a
    // tool nobody can call.
    let long = format!(
        r#"{{"description":"{}","input_schema":{{}}}}"#,
        "x".repeat(20_000)
    );
    for bad in [
        "not json",
        r#"{"input_schema":{}}"#,
        r#"{"description":"   ","input_schema":{}}"#,
        long.as_str(),
    ] {
        let response = deploy_with(&cluster, "echo", Some(bad)).await;
        assert_eq!(response.status, 400, "descriptor {bad:.40} was accepted");
    }

    // And nothing was deployed under a refused descriptor.
    let response = cluster.post("echo", "acme", b"x").await;
    assert_eq!(response.status, 404);
}

#[tokio::test]
async fn a_deployment_table_written_before_tools_existed_still_loads() {
    // The whole reason descriptors went in a second map instead of a richer
    // value type: an unrecognised version stops startup by design (§11.1), so
    // a bump would have refused every table already on disk.
    let dir = temp_dir("legacy-registry");
    std::fs::write(
        dir.join("deployments.json"),
        br#"{"version":1,"functions":{"legacy":"abc"}}"#,
    )
    .expect("write");

    let registry = Registry::new(&dir).expect("registry");
    let loaded = registry
        .load_deployments()
        .expect("a v1 table must still load");
    assert_eq!(
        loaded.functions.get("legacy").map(String::as_str),
        Some("abc")
    );
    assert!(loaded.tools.is_empty());
}

// ---------------------------------------------------------------------------
// Authentication (§13)
// ---------------------------------------------------------------------------

const SECRET: &[u8] = b"a shared secret";

#[tokio::test]
async fn a_signed_token_names_its_tenant_and_a_bare_one_does_not() {
    let mut cluster = Cluster::authenticated(SECRET).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    let token = nebula_control::auth::Auth::signed(SECRET)
        .mint("acme")
        .expect("mint");
    assert_eq!(cluster.post("echo", &token, b"hello").await.status, 200);

    // Under v1 auth this was a valid credential for `acme`. That it is not any
    // more is the entire point of the change.
    let bare = cluster.post("echo", "acme", b"hello").await;
    assert_eq!(bare.status, 401);
    assert_eq!(bare.header("x-nebula-fault"), Some("unauthorized"));
}

#[tokio::test]
async fn one_tenants_token_cannot_be_edited_into_another() {
    let mut cluster = Cluster::authenticated(SECRET).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    let token = nebula_control::auth::Auth::signed(SECRET)
        .mint("acme")
        .expect("mint");
    let signature = token.split_once('.').unwrap().1;

    // Everything §22 isolates is keyed on the tenant: the session scratchpad
    // (§22.5), the replay store (§22.4), the egress allowlist (§22.8). Moving
    // the name in front of a valid signature is the cheapest possible attack on
    // all three at once.
    let forged = cluster
        .post("echo", &format!("globex.{signature}"), b"hello")
        .await;
    assert_eq!(forged.status, 401);

    // And a token minted under a different secret is refused, which is what
    // makes rotating the secret a revocation.
    let other = nebula_control::auth::Auth::signed(b"rotated")
        .mint("acme")
        .expect("mint");
    assert_eq!(cluster.post("echo", &other, b"hello").await.status, 401);
}

#[tokio::test]
async fn deploys_are_authenticated_too() {
    let cluster = Cluster::authenticated(SECRET).await;

    // `PUT` runs Wizer, which executes the caller's guest code on the control
    // plane (§11.1). An unauthenticated deploy endpoint would be the cheapest
    // way in.
    let refused = http(
        &cluster.http_addr,
        "PUT",
        "/functions/echo",
        Some("acme"),
        &[],
        ECHO.as_bytes(),
    )
    .await;
    assert_eq!(refused.status, 401);

    let token = nebula_control::auth::Auth::signed(SECRET)
        .mint("acme")
        .expect("mint");
    let accepted = http(
        &cluster.http_addr,
        "PUT",
        "/functions/echo",
        Some(&token),
        &[],
        ECHO.as_bytes(),
    )
    .await;
    assert_eq!(accepted.status, 201);
}

#[tokio::test]
async fn a_malformed_tenant_id_is_refused_even_without_signing() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;
    cluster.publish("echo", ECHO).await;

    // The charset guards four different stores, and that is true whether or not
    // anybody checked a signature: a tenant id is the first element of the KV
    // key, the idempotency slot, and the egress lookup.
    for bad in ["has a space", "has.a.dot", &"t".repeat(100)] {
        let response = cluster.post("echo", bad, b"x").await;
        assert_eq!(response.status, 401, "tenant {bad:?} was accepted");
    }
    assert_eq!(cluster.post("echo", "acme-prod_2", b"x").await.status, 200);
}

// ---------------------------------------------------------------------------
// Deploy-time precompilation (§19)
// ---------------------------------------------------------------------------

/// Enough functions that Cranelift takes a measurable amount of time, which is
/// the whole point: a trivial module compiles too fast to tell the difference.
fn sized_module(seed: usize, target: usize) -> String {
    let mut wat = String::with_capacity(target + 4096);
    wat.push_str(
        ECHO.trim_end()
            .trim_end_matches(|c: char| c.is_whitespace()),
    );
    // ECHO closes the module on its last line; reopen by trimming that paren.
    wat.pop();
    let mut n = 0;
    while wat.len() < target {
        wat.push_str(&format!(
            "\n  (func $f{seed}_{n} (param i32) (result i32) (i32.add (local.get 0) (i32.const {n})))"
        ));
        n += 1;
    }
    wat.push_str("\n)");
    wat
}

#[tokio::test]
async fn a_deployed_function_is_already_compiled_before_its_first_request() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;

    let wat = sized_module(1, 512 << 10);
    let deployed = http(
        &cluster.http_addr,
        "PUT",
        "/functions/sized",
        Some("acme"),
        &[],
        wat.as_bytes(),
    )
    .await;
    assert_eq!(deployed.status, 201);

    // The first request must not be the one that pays for Cranelift. §19
    // measured cold start as compilation and almost nothing else, so a request
    // that still had to compile would report itself cold.
    let first = cluster
        .post_with("sized", "acme", &[("X-Nebula-Deadline-Ms", "5000")], b"x")
        .await;
    assert_eq!(first.status, 200);
    assert_eq!(
        first.header("x-nebula-cold"),
        Some("false"),
        "the first request compiled the module, so precompilation did not happen"
    );
}

#[tokio::test]
async fn a_module_that_cannot_compile_is_refused_at_deploy() {
    let mut cluster = Cluster::start(Duration::from_secs(5)).await;
    cluster.add_worker(2, 4).await;

    // Valid enough to pass the shape checks on the control plane, which has no
    // compiler (§11.1), and rejected by the one place that does.
    let broken = r#"(module (func (export "run") (i32.const 1)))"#;
    let response = http(
        &cluster.http_addr,
        "PUT",
        "/functions/broken",
        Some("acme"),
        &[],
        broken.as_bytes(),
    )
    .await;

    assert_eq!(response.status, 400, "{}", response.text());
    assert!(
        response.text().contains("does not compile"),
        "{}",
        response.text()
    );

    // And nothing was registered: a refused deploy must not leave the id
    // pointing at an artifact nothing can run.
    assert_eq!(cluster.post("broken", "acme", b"x").await.status, 404);
}

#[tokio::test]
async fn a_deploy_still_succeeds_when_no_worker_can_precompile() {
    let cluster = Cluster::start(Duration::from_secs(5)).await;

    // No workers at all. Precompilation is an optimisation, and refusing to
    // deploy because an optimisation could not run would trade a slow first
    // request for no service.
    let response = http(
        &cluster.http_addr,
        "PUT",
        "/functions/echo",
        Some("acme"),
        &[],
        ECHO.as_bytes(),
    )
    .await;
    assert_eq!(response.status, 201);
    assert_eq!(cluster.gateway.deployed(), 1);
}
