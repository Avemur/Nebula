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
            .expect("publish");
    }

    async fn post(&self, function_id: &str, token: &str, body: &[u8]) -> HttpResponse {
        http(
            &self.http_addr,
            "POST",
            &format!("/execute/{function_id}"),
            Some(token),
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

    let anonymous = http(&cluster.http_addr, "POST", "/execute/echo", None, b"x").await;
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
