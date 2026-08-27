//! End-to-end mesh tests (README.md §10, §11.2, §12).
//!
//! A real control plane and a real worker on ephemeral ports, talking over real
//! gRPC. Nothing here is mocked: the worker cold-starts by streaming the
//! artifact back from the control plane's registry, exactly as §4.1 describes.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nebula_control::membership::{self, Membership};
use nebula_control::registry::Registry;
use nebula_control::server::ControlService;
use nebula_proto::nebula_control_client::NebulaControlClient;
use nebula_proto::nebula_control_server::NebulaControlServer;
use nebula_proto::nebula_worker_client::NebulaWorkerClient;
use nebula_proto::nebula_worker_server::NebulaWorkerServer;
use nebula_proto::{DrainRequest, ExecuteRequest, HeartbeatRequest, Outcome, RegisterRequest};
use nebula_runtime::Runtime;
use nebula_worker::exec_pool::ExecPool;
use nebula_worker::server::WorkerService;
use tonic::transport::server::TcpIncoming;
use tonic::transport::Server;
use tonic::Code;

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

const TRAPPER: &str = r#"(module (func (export "run") (unreachable)))"#;
const SPINNER: &str = r#"(module (func (export "run") (loop (br 0))))"#;

fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "nebula-mesh-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

struct Mesh {
    control_url: String,
    worker_url: String,
    membership: Arc<Membership>,
    registry: Arc<Registry>,
}

impl Mesh {
    async fn control(&self) -> NebulaControlClient<tonic::transport::Channel> {
        NebulaControlClient::connect(self.control_url.clone())
            .await
            .expect("dial control plane")
    }

    async fn worker(&self) -> NebulaWorkerClient<tonic::transport::Channel> {
        NebulaWorkerClient::connect(self.worker_url.clone())
            .await
            .expect("dial worker")
    }
}

/// Binds both servers on port 0 and serves them.
///
/// `TcpListener::bind` is already listening by the time this returns, so a
/// client can connect immediately: no sleeping and hoping the server came up.
async fn start_mesh(threads: usize, max_concurrent: usize, liveness: Duration) -> Mesh {
    let membership = Arc::new(Membership::new(liveness));
    let registry = Arc::new(Registry::new(temp_dir("registry")).expect("registry"));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind control");
    let control_url = format!("http://{}", listener.local_addr().unwrap());
    let control = ControlService::new(membership.clone(), registry.clone());
    tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(NebulaControlServer::new(control))
            .serve_with_incoming(TcpIncoming::from(listener))
            .await;
    });

    let runtime = Arc::new(Runtime::new(temp_dir("l2")).expect("runtime"));
    let pool = Arc::new(ExecPool::new(runtime.clone(), threads, max_concurrent));
    let worker = WorkerService::new(runtime, pool, &control_url).expect("worker service");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind worker");
    let worker_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(NebulaWorkerServer::new(worker))
            .serve_with_incoming(TcpIncoming::from(listener))
            .await;
    });

    Mesh {
        control_url,
        worker_url,
        membership,
        registry,
    }
}

fn execute(function_id: &str, content_hash: &str, body: &[u8]) -> ExecuteRequest {
    ExecuteRequest {
        function_id: function_id.to_string(),
        content_hash: content_hash.to_string(),
        body: body.to_vec(),
        request_id: "req".to_string(),
        deadline_ms: 50,
        tenant: "mesh-tenant".to_string(),
        partition_key: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn register_heartbeat_and_execute_over_grpc() {
    let mesh = start_mesh(2, 4, Duration::from_secs(5)).await;
    let hash = mesh
        .registry
        .put(ECHO.as_bytes())
        .expect("publish artifact");

    // --- Register -----------------------------------------------------------
    let mut control = mesh.control().await;
    let registered = control
        .register(RegisterRequest {
            node_id: "worker-1".to_string(),
            address: "127.0.0.1:9999".to_string(),
            generation: 42,
        })
        .await
        .expect("register")
        .into_inner();

    assert!(registered.heartbeat_interval_ms > 0);
    assert!(mesh.membership.contains("worker-1"));
    assert_eq!(
        mesh.membership.route("some-fn").as_deref(),
        Some("worker-1")
    );

    // --- Heartbeat ----------------------------------------------------------
    let beat = control
        .heartbeat(HeartbeatRequest {
            node_id: "worker-1".to_string(),
            generation: 42,
            in_flight: 1,
            queue_depth: 0,
            cache_bytes: 4096,
        })
        .await
        .expect("heartbeat")
        .into_inner();
    assert!(
        !beat.re_register,
        "a known node must not be asked to re-register"
    );

    let stale = control
        .heartbeat(HeartbeatRequest {
            node_id: "worker-1".to_string(),
            generation: 7, // a different process under the same id
            ..Default::default()
        })
        .await
        .expect("heartbeat")
        .into_inner();
    assert!(
        stale.re_register,
        "a restarted worker must be told to register again"
    );

    // --- Execute (cold) -----------------------------------------------------
    let mut worker = mesh.worker().await;
    let cold = worker
        .execute(execute("echo", &hash, b"over the wire"))
        .await
        .expect("execute")
        .into_inner();

    assert_eq!(cold.outcome, Outcome::Ok as i32);
    assert_eq!(cold.body, b"over the wire");
    assert!(cold.fault_detail.is_empty());
    assert!(
        cold.cold,
        "the first request had to stream the artifact from the control plane"
    );

    // --- Execute (warm) -----------------------------------------------------
    let warm = worker
        .execute(execute("echo", &hash, b"again"))
        .await
        .expect("execute")
        .into_inner();

    assert_eq!(warm.outcome, Outcome::Ok as i32);
    assert_eq!(warm.body, b"again");
    assert!(!warm.cold, "the artifact is local now");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_worker_is_reconciled_out_of_the_ring() {
    let mesh = start_mesh(1, 2, Duration::from_millis(150)).await;
    let mut control = mesh.control().await;

    control
        .register(RegisterRequest {
            node_id: "worker-1".to_string(),
            address: "127.0.0.1:9999".to_string(),
            generation: 1,
        })
        .await
        .expect("register");

    membership::spawn_reconciler(mesh.membership.clone(), Duration::from_millis(30));
    assert!(mesh.membership.contains("worker-1"));

    // Beat once, so this is a node that was alive and then went quiet.
    tokio::time::sleep(Duration::from_millis(50)).await;
    control
        .heartbeat(HeartbeatRequest {
            node_id: "worker-1".to_string(),
            generation: 1,
            ..Default::default()
        })
        .await
        .expect("heartbeat");
    assert!(mesh.membership.contains("worker-1"));

    // Then stop. Past the liveness timeout it must leave the ring on its own.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !mesh.membership.contains("worker-1"),
        "a silent worker must be reconciled away without operator action"
    );
    assert!(mesh.membership.route("any-key").is_none());
    assert!(mesh.membership.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_overloaded_worker_sheds_with_resource_exhausted() {
    // One thread, one permit: the second concurrent request has nowhere to go.
    let mesh = start_mesh(1, 1, Duration::from_secs(5)).await;
    let hash = mesh.registry.put(SPINNER.as_bytes()).expect("publish");

    let mut first = mesh.worker().await;
    let mut second = mesh.worker().await;

    let occupied = {
        let request = execute("spin", &hash, b"");
        tokio::spawn(async move { first.execute(request).await })
    };

    // Let the spinner take the permit and start burning its epoch budget.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let shed = second
        .execute(execute("spin", &hash, b""))
        .await
        .expect_err("a full worker must shed, not queue");
    assert_eq!(
        shed.code(),
        Code::ResourceExhausted,
        "§10.3 sheds with RESOURCE_EXHAUSTED"
    );

    // And the request that did get in still finishes, as a timeout, since it
    // spins until the epoch deadline.
    let finished = occupied.await.expect("task").expect("execute").into_inner();
    assert_eq!(finished.outcome, Outcome::Timeout as i32);

    // Capacity comes back.
    let after = second
        .execute(execute("spin", &hash, b""))
        .await
        .expect("execute")
        .into_inner();
    assert_eq!(after.outcome, Outcome::Timeout as i32);
}

#[tokio::test(flavor = "multi_thread")]
async fn guest_faults_map_to_outcomes_not_grpc_errors() {
    // §11.2: a tenant's fault is a value inside a successful RPC. If these came
    // back as gRPC statuses they would pollute transport error rates and look
    // like a worker crash.
    let mesh = start_mesh(2, 4, Duration::from_secs(5)).await;
    let trapper = mesh.registry.put(TRAPPER.as_bytes()).expect("publish");
    let spinner = mesh.registry.put(SPINNER.as_bytes()).expect("publish");
    let mut worker = mesh.worker().await;

    let trapped = worker
        .execute(execute("trap", &trapper, b""))
        .await
        .expect("the RPC itself must succeed")
        .into_inner();
    assert_eq!(trapped.outcome, Outcome::Trap as i32);
    assert!(
        !trapped.fault_detail.is_empty(),
        "guest fault detail goes back to the caller: it is their code"
    );

    let timed_out = worker
        .execute(execute("spin", &spinner, b""))
        .await
        .expect("the RPC itself must succeed")
        .into_inner();
    assert_eq!(timed_out.outcome, Outcome::Timeout as i32);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_module_maps_to_module_not_found() {
    let mesh = start_mesh(1, 2, Duration::from_secs(5)).await;
    let mut worker = mesh.worker().await;

    let response = worker
        .execute(execute("missing", &"0".repeat(64), b""))
        .await
        .expect("the RPC itself must succeed")
        .into_inner();

    assert_eq!(response.outcome, Outcome::ModuleNotFound as i32);
    assert!(response.body.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_traversal_content_hash_is_refused_end_to_end() {
    // The registry validates the *shape* of a content hash before it touches
    // the filesystem, so this never becomes a file read on the control plane.
    let mesh = start_mesh(1, 2, Duration::from_secs(5)).await;
    let mut worker = mesh.worker().await;

    for attempt in ["../../etc/passwd", "..", "/etc/passwd", ""] {
        let response = worker
            .execute(execute("evil", attempt, b""))
            .await
            .expect("the RPC itself must succeed")
            .into_inner();
        assert_eq!(
            response.outcome,
            Outcome::ModuleNotFound as i32,
            "registry served something for {attempt:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn draining_stops_admitting_new_work() {
    let mesh = start_mesh(1, 2, Duration::from_secs(5)).await;
    let hash = mesh.registry.put(ECHO.as_bytes()).expect("publish");
    let mut worker = mesh.worker().await;

    let before = worker
        .execute(execute("echo", &hash, b"still open"))
        .await
        .expect("execute")
        .into_inner();
    assert_eq!(before.outcome, Outcome::Ok as i32);

    let drained = worker
        .drain(DrainRequest {})
        .await
        .expect("drain")
        .into_inner();
    assert_eq!(drained.in_flight, 0);

    let after = worker
        .execute(execute("echo", &hash, b"too late"))
        .await
        .expect_err("a draining worker must not admit new work");
    assert_eq!(after.code(), Code::ResourceExhausted);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chunked_artifact_reassembles_exactly() {
    // Bigger than one 256 KiB chunk, so FetchModule actually streams more than
    // one message and the worker's hash check has something to verify.
    let mesh = start_mesh(2, 4, Duration::from_secs(5)).await;
    let padding = " ".repeat(400 * 1024);
    let padded = format!("{ECHO}\n(; {padding} ;)");
    let hash = mesh.registry.put(padded.as_bytes()).expect("publish");
    assert!(padded.len() > 256 * 1024);

    let mut worker = mesh.worker().await;
    let response = worker
        .execute(execute("echo", &hash, b"chunked"))
        .await
        .expect("execute")
        .into_inner();

    assert_eq!(response.outcome, Outcome::Ok as i32);
    assert_eq!(response.body, b"chunked");
    assert!(response.cold);
}
