//! The Phase 3 scale exit criteria (README.md §5.2, §9.1, §10.1, §10.3, §18).
//!
//! Two proofs the mesh tests could not give:
//!
//! * a worker held at five times its capacity still heartbeats, because guest
//!   execution never touches the async reactor;
//! * fifty functions across three workers each land on exactly one worker and
//!   stay there.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nebula_control::gateway::{self, Gateway};
use nebula_control::membership::{self, Membership};
use nebula_control::registry::Registry;
use nebula_control::server::ControlService;
use nebula_proto::nebula_control_client::NebulaControlClient;
use nebula_proto::nebula_control_server::NebulaControlServer;
use nebula_proto::nebula_worker_client::NebulaWorkerClient;
use nebula_proto::nebula_worker_server::NebulaWorkerServer;
use nebula_proto::ExecuteRequest;
use nebula_runtime::Runtime;
use nebula_worker::exec_pool::ExecPool;
use nebula_worker::heartbeat::{self, Identity};
use nebula_worker::server::WorkerService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint, Server};
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

/// Burns roughly 100 ms of CPU.
///
/// Stores to memory on every iteration so Cranelift cannot decide the loop is
/// unobservable and delete it. A load-test guest that optimises away to nothing
/// is the classic way to "prove" a thread pool is fast.
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
// Fixture
// ---------------------------------------------------------------------------

fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "nebula-scale-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

struct Worker {
    node_id: String,
    address: String,
    runtime: Arc<Runtime>,
    pool: Arc<ExecPool>,
    /// Closes the server and its established connections. Aborting the accept
    /// task is not enough — tonic runs each connection in its own task.
    kill: Option<tokio::sync::oneshot::Sender<()>>,
}

struct Cluster {
    http_addr: String,
    control_url: String,
    membership: Arc<Membership>,
    gateway: Arc<Gateway>,
    workers: Vec<Worker>,
}

impl Cluster {
    async fn start(liveness: Duration) -> Self {
        // Quiet unless NEBULA_LOG says otherwise; see the span-tree test.
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
                // These tests fire a thousand requests as one tenant, which
                // is precisely what §22.7 exists to refuse. Opting out is
                // stated rather than sidestepped with a generous default: a
                // load test that silently measures the rate limiter is
                // measuring the wrong thing, and one tuned to stay under it
                // is worse.
                .with_limits(
                    nebula_control::ratelimit::Limit::NONE,
                    nebula_control::ratelimit::Limit::NONE,
                ),
        );
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

    async fn add_worker(&mut self, threads: usize, max_concurrent: usize) -> String {
        let runtime = Arc::new(Runtime::new(temp_dir("l2")).expect("runtime"));
        let pool = Arc::new(ExecPool::new(runtime.clone(), threads, max_concurrent));
        let service = WorkerService::new(runtime.clone(), pool.clone(), &self.control_url)
            .expect("worker service");

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
            address,
            runtime,
            pool,
            kill: Some(kill),
        });
        node_id
    }

    fn kill(&mut self, node_id: &str) {
        if let Some(worker) = self.workers.iter_mut().find(|w| w.node_id == node_id) {
            if let Some(kill) = worker.kill.take() {
                let _ = kill.send(());
            }
        }
    }

    /// Beats for every worker except `silent`, so the reconciler evicts exactly
    /// one node rather than the whole cluster.
    fn beat_all_except(&self, silent: &str) {
        for worker in &self.workers {
            if worker.node_id != silent {
                self.membership.heartbeat(&worker.node_id, 1, 0, 0, 0);
            }
        }
    }

    fn compiles(&self, nodes: &[String]) -> usize {
        nodes
            .iter()
            .map(|node| self.worker(node).runtime.cache().cranelift_compiles())
            .sum()
    }

    fn lookups(&self, nodes: &[String]) -> usize {
        nodes
            .iter()
            .map(|node| {
                let cache = self.worker(node).runtime.cache();
                cache.cranelift_compiles() + cache.l1_hits()
            })
            .sum()
    }

    fn worker(&self, node_id: &str) -> &Worker {
        self.workers
            .iter()
            .find(|worker| worker.node_id == node_id)
            .expect("known worker")
    }

    async fn post(&self, function_id: &str, token: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let mut stream = TcpStream::connect(&self.http_addr)
            .await
            .expect("connect gateway");
        let head = format!(
            "POST /execute/{function_id} HTTP/1.1\r\nHost: nebula\r\nConnection: close\r\n\
             Authorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("head");
        let status = String::from_utf8_lossy(&raw[..split])
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .expect("status");
        (status, raw[split + 4..].to_vec())
    }
}

/// Sends `rounds` passes over `functions` distinct function ids.
async fn drive(cluster: &Cluster, functions: usize, rounds: usize) {
    for _ in 0..rounds {
        for n in 0..functions {
            let (status, body) = cluster.post(&format!("fn-{n}"), "acme", b"x").await;
            assert_eq!(status, 200, "fn-{n}");
            assert_eq!(body, b"x");
        }
    }
}

/// Fires `count` requests at once over one multiplexed HTTP/2 connection.
///
/// One connection, cloned: dialling per request would stagger arrivals by more
/// than the guest runs for, and the test would be measuring the dialling rather
/// than the admission control.
async fn wave(
    client: &NebulaWorkerClient<Channel>,
    template: &ExecuteRequest,
    count: usize,
) -> (usize, usize) {
    let mut tasks = Vec::with_capacity(count);
    for _ in 0..count {
        let mut client = client.clone();
        let request = template.clone();
        tasks.push(tokio::spawn(async move { client.execute(request).await }));
    }

    let (mut admitted, mut shed) = (0, 0);
    for task in tasks {
        match task.await.expect("task") {
            Ok(_) => admitted += 1,
            Err(status) if status.code() == Code::ResourceExhausted => shed += 1,
            Err(other) => panic!("unexpected dispatch failure: {other}"),
        }
    }
    (admitted, shed)
}

// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn deployments_survive_a_control_plane_restart() {
    // Artifacts were always on disk; the *names* pointing at them were not, so a
    // restart used to answer 404 for every function that had been working.
    let dir = temp_dir("persist");
    let membership = Arc::new(Membership::new(Duration::from_secs(60)));
    let registry = Arc::new(Registry::new(&dir).expect("registry"));

    let before = Gateway::open(membership.clone(), registry.clone()).expect("gateway");
    let hash = before
        .publish("echo", ECHO.as_bytes())
        .await
        .expect("publish")
        .content_hash;
    assert_eq!(before.deployed(), 1);
    drop(before);

    // A second gateway over the same directory is what a restart looks like.
    let registry = Arc::new(Registry::new(&dir).expect("registry"));
    let after = Gateway::open(membership, registry).expect("gateway reopens");

    assert_eq!(after.deployed(), 1);
    assert_eq!(
        after.content_hash_of("echo").as_deref(),
        Some(hash.as_str())
    );
    assert!(dir.join("deployments.json").is_file());
}

#[tokio::test(flavor = "multi_thread")]
async fn deploying_a_guest_with_an_initializer_pre_initializes_it() {
    // §4.3 moved into the deploy path: the artifact the cluster stores is
    // already booted, so no worker ever pays that cost at request time.
    let raw = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../guests/examples/heavy_init/dist/heavy_init.wasm"),
    );
    let Ok(raw) = raw else {
        eprintln!("SKIPPED: guest artifacts missing; see `bash guests/build.sh`.");
        return;
    };

    let dir = temp_dir("wizer-deploy");
    let membership = Arc::new(Membership::new(Duration::from_secs(60)));
    let registry = Arc::new(Registry::new(&dir).expect("registry"));
    let gateway = Gateway::open(membership, registry.clone()).expect("gateway");

    let published = gateway.publish("heavy", &raw).await.expect("deploy");
    if !published.wizened {
        eprintln!("SKIPPED: wizer is not on PATH; deploy fell back to the raw artifact.");
        return;
    }

    let stored = registry
        .read(&published.content_hash)
        .expect("stored artifact");
    assert!(
        !nebula_control::wizer::should_wizen(&stored),
        "the stored artifact must have had its initializer consumed, or every \
         worker would still boot it on instantiation"
    );
    assert!(
        stored.len() > raw.len(),
        "the pre-initialized artifact carries the booted heap: {} vs {} bytes",
        stored.len(),
        raw.len()
    );
    assert_ne!(
        published.content_hash,
        nebula_control::registry::content_hash_hex(&raw),
        "wizening happens before hashing, so the stored hash is the snapshot's"
    );
    eprintln!(
        "wizened at deploy: {} bytes -> {} bytes",
        raw.len(),
        stored.len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn losing_a_worker_reshuffles_only_its_share_of_the_keyspace() {
    // The property consistent hashing exists for. Losing one of three nodes must
    // move that node's ~1/3 of the functions and leave the rest untouched; under
    // `hash % n` the modulus changes and roughly 2/3 of keys would move, so the
    // whole cluster would cold-start at once.
    //
    // A recompile on a surviving worker is the observable: it means a function
    // arrived somewhere it had never been.
    const FUNCTIONS: usize = 100;
    const ROUNDS: usize = 10;
    let liveness = Duration::from_millis(300);

    let mut cluster = Cluster::start(liveness).await;
    let mut nodes = Vec::new();
    for _ in 0..3 {
        nodes.push(cluster.add_worker(4, 16).await);
    }
    for n in 0..FUNCTIONS {
        let distinct = format!("{ECHO}\n(; churn {n} ;)");
        cluster
            .gateway
            .publish(&format!("fn-{n}"), distinct.as_bytes())
            .await
            .expect("publish");
    }

    // Phase 1: steady state across three workers.
    drive(&cluster, FUNCTIONS, ROUNDS).await;
    let victim = nodes[1].clone();
    let survivors: Vec<String> = nodes.iter().filter(|n| **n != victim).cloned().collect();
    let compiles_before = cluster.compiles(&survivors);
    let lookups_before = cluster.lookups(&survivors);

    // Where each function is served from, taken from the ring itself.
    //
    // This used to be inferred from new compiles on the survivors, which worked
    // while a moved function had to be recompiled where it landed. Deploy-time
    // compilation (§19) warms the failover candidate too, so a move now leaves
    // no trace in the compile counter. Asking the ring is immune to that and is
    // a more direct test of the claim, which is about consistent hashing rather
    // than about caches.
    let owner_before: Vec<String> = (0..FUNCTIONS)
        .map(|n| {
            cluster.membership.route_plan(&format!("fn-{n}"))[0]
                .0
                .clone()
        })
        .collect();
    // Deploying compiles on the ring candidates ahead of any request (§19), so
    // the steady-state count is that fanout and nothing more. A function served
    // by a worker outside its candidates would add a compile, which is still
    // exactly what this is watching for.
    let expected = FUNCTIONS * nebula_control::gateway::PRECOMPILE_FANOUT;
    let cluster_compiles = cluster.compiles(&nodes);
    assert_eq!(
        cluster_compiles, expected,
        "steady state should compile each function once per ring candidate"
    );

    // Kill one worker and let the reconciler notice, by beating only the others.
    cluster.kill(&victim);
    tokio::time::sleep(liveness + Duration::from_millis(150)).await;
    cluster.beat_all_except(&victim);
    let removed = cluster.membership.reconcile();
    assert_eq!(removed, vec![victim.clone()], "exactly one node should go");
    assert_eq!(cluster.membership.len(), 2);

    // Phase 2: the same traffic against two workers.
    drive(&cluster, FUNCTIONS, ROUNDS).await;

    let moved = (0..FUNCTIONS)
        .filter(|n| cluster.membership.route_plan(&format!("fn-{n}"))[0].0 != owner_before[*n])
        .count();
    let recompiles = cluster.compiles(&survivors) - compiles_before;
    let lookups = cluster.lookups(&survivors) - lookups_before;
    let hit_ratio = (lookups - recompiles) as f64 / lookups as f64;
    eprintln!(
        "after losing 1 of 3: {moved} of {FUNCTIONS} functions moved          ({:.0}% of the keyspace), {recompiles} recompiles,          phase-2 hit ratio {:.1}%",
        100.0 * moved as f64 / FUNCTIONS as f64,
        hit_ratio * 100.0
    );

    // Failover is warm. A function moves to a node that was one of its
    // deploy-time candidates (§19), so it already holds the compiled module and
    // the move costs a route change and nothing else.
    assert_eq!(
        recompiles, 0,
        "a moved function had to be recompiled, so precompilation missed its          failover candidate"
    );

    // A third of the keyspace, give or take the sampling noise of 100 keys over
    // 3 nodes (about 1/sqrt(33), ~17%). The upper bound is what matters: it is
    // far below the ~2/3 that modulo hashing would have moved.
    assert!(
        (15..=55).contains(&moved),
        "{moved} functions moved; consistent hashing should shift about a third"
    );
    assert!(
        hit_ratio >= 0.90,
        "phase-2 hit ratio {:.1}% — losing one worker should not cold-start the \
         whole cluster",
        hit_ratio * 100.0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_saturated_worker_sheds_and_keeps_its_heartbeat() {
    // The proof that §5.2 was worth its complexity. Every execution thread is
    // busy for seconds on end. If guest execution ran on the tokio reactor the
    // heartbeats would stop, the reconciler would evict a perfectly healthy
    // worker, and the cluster would shed load off a node that was merely busy —
    // which looks exactly like a crash from the outside.
    let mut cluster = Cluster::start(membership::LIVENESS_TIMEOUT).await;
    let node = cluster.add_worker(2, 2).await;
    let (address, runtime, pool) = {
        let worker = cluster.worker(&node);
        (
            worker.address.clone(),
            worker.runtime.clone(),
            worker.pool.clone(),
        )
    };

    let hash = cluster
        .gateway
        .publish("slow", SLOW.as_bytes())
        .await
        .expect("publish")
        .content_hash;

    // Real heartbeats on the async reactor, and the real reconciler.
    let control = NebulaControlClient::new(
        Endpoint::from_shared(cluster.control_url.clone())
            .unwrap()
            .connect_lazy(),
    );
    tokio::spawn(heartbeat::beat_forever(
        control,
        Identity {
            node_id: node.clone(),
            address: address.clone(),
            generation: 1,
        },
        pool,
        runtime,
        Duration::from_millis(200),
    ));
    membership::spawn_reconciler(cluster.membership.clone(), Duration::from_millis(100));

    let client = NebulaWorkerClient::connect(format!("http://{address}"))
        .await
        .expect("dial worker");
    let template = ExecuteRequest {
        function_id: "slow".to_string(),
        content_hash: hash,
        body: Vec::new(),
        request_id: "load".to_string(),
        // Well above the guest's runtime, and well under MAX_DEADLINE_MS.
        deadline_ms: 1_000,
        partition_key: None,
        tenant: "acme".to_string(),
    };

    // Warm the module, so the first wave measures admission and not compilation.
    let warm = Instant::now();
    let warmed = client
        .clone()
        .execute(template.clone())
        .await
        .expect("warm-up")
        .into_inner();
    eprintln!(
        "guest ran for {:?} (worker reported {} us)",
        warm.elapsed(),
        warmed.exec_micros
    );

    // Assertion 1: ten at once against a capacity of two.
    let (admitted, shed) = wave(&client, &template, 10).await;
    assert_eq!(
        (admitted, shed),
        (2, 8),
        "capacity 2 must admit 2 and shed 8 — queueing them would be the bug"
    );

    // Assertion 2: stay saturated for longer than the liveness timeout, and
    // check membership on every wave rather than only at the end, so a
    // transient eviction cannot heal before anyone looks.
    let until = Instant::now() + membership::LIVENESS_TIMEOUT + Duration::from_millis(900);
    let (mut total_admitted, mut total_shed) = (admitted, shed);
    while Instant::now() < until {
        let (admitted, shed) = wave(&client, &template, 10).await;
        total_admitted += admitted;
        total_shed += shed;
        assert!(
            cluster.membership.contains(&node),
            "the worker left the ring while saturated — heartbeats are not \
             flowing independently of guest execution"
        );
    }

    eprintln!("sustained 5x load: {total_admitted} admitted, {total_shed} shed");
    assert!(
        cluster.membership.contains(&node),
        "a busy worker is not a dead worker"
    );
    assert!(
        total_shed > total_admitted * 3,
        "offered load was not actually 5x capacity: {total_admitted} admitted \
         against {total_shed} shed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fifty_functions_spread_across_three_workers_and_stay_put() {
    const FUNCTIONS: usize = 50;
    const ROUNDS: usize = 20;

    let mut cluster = Cluster::start(Duration::from_secs(60)).await;
    let mut nodes = Vec::new();
    for _ in 0..3 {
        nodes.push(cluster.add_worker(2, 8).await);
    }
    // Each function gets a *distinct* artifact.
    //
    // Publishing the same bytes under fifty names would prove nothing about
    // routing: the module cache is keyed by content hash, so fifty names sharing
    // one artifact compile once per worker no matter where requests land. That
    // deduplication is a real and welcome property of content addressing — it is
    // simply not the property under test here.
    for n in 0..FUNCTIONS {
        let distinct = format!("{ECHO}\n(; unique {n} ;)");
        cluster
            .gateway
            .publish(&format!("fn-{n}"), distinct.as_bytes())
            .await
            .expect("publish");
    }

    for round in 0..ROUNDS {
        for n in 0..FUNCTIONS {
            let function = format!("fn-{n}");
            let (status, body) = cluster.post(&function, "acme", b"x").await;
            assert_eq!(status, 200, "round {round}, {function}");
            assert_eq!(body, b"x");
        }
    }

    let mut compiles = 0usize;
    let mut hits = 0usize;
    let mut per_worker = Vec::new();
    for node in &nodes {
        let cache = cluster.worker(node).runtime.cache();
        compiles += cache.cranelift_compiles();
        hits += cache.l1_hits();
        // L1 hits alone are the request count now. A compile used to be a
        // request that missed; since §19 they happen at deploy, so counting
        // them here would credit a worker with traffic it never served.
        per_worker.push(cache.l1_hits());
    }

    let total = FUNCTIONS * ROUNDS;
    eprintln!(
        "{total} requests over {FUNCTIONS} functions: {compiles} compiles, \
         {hits} L1 hits, per-worker {per_worker:?}"
    );

    // Every function compiled exactly once per ring candidate, and never on a
    // third worker. That is a stronger claim than a hit ratio: it says no
    // function was ever served by a worker outside its candidates, which is
    // precisely what ring affinity means. A ratio alone would still look
    // healthy if a few functions flapped.
    assert_eq!(
        compiles,
        FUNCTIONS * nebula_control::gateway::PRECOMPILE_FANOUT,
        "a function compiled more often than its ring candidates means it moved"
    );
    // Deploy-time compilation means the requests themselves never miss: every
    // function was already in L1 on the worker that serves it.
    assert_eq!(hits, total);

    let hit_ratio = hits as f64 / total as f64;
    assert!(
        hit_ratio >= 0.95,
        "cache hit ratio {:.1}% is below the 95% §18 asks for",
        hit_ratio * 100.0
    );

    // Distribution. Fifty keys is a different regime from the ring test's ten
    // thousand: sampling noise here is about sqrt(50/3)/(50/3), roughly 24%, so
    // §9.1's 10% bound does not apply and asserting it would be wrong. What must
    // hold is that all three workers carry real traffic.
    assert_eq!(per_worker.iter().sum::<usize>(), total);
    for (node, served) in nodes.iter().zip(&per_worker) {
        let share = *served as f64 / total as f64;
        assert!(
            share > 0.10,
            "{node} served only {:.1}% — the ring is not spreading 50 keys",
            share * 100.0
        );
        assert!(
            share < 0.60,
            "{node} served {:.1}% — one worker is carrying the cluster",
            share * 100.0
        );
    }
}
