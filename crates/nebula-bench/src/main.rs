//! The three measurements of README.md §19.
//!
//! Every latency number in this repository was a target until this existed. The
//! point of the section it implements is that a claim is meaningless without
//! saying what is inside the measurement, so each boundary is measured
//! separately and reported separately.
//!
//! | | Boundary |
//! |---|---|
//! | **M1** | In process. Instantiate from a cached `InstancePre`, call, drop the `Store`. |
//! | **M2** | Client socket to client socket, through the gateway and gRPC, module cached. |
//! | **M3** | The same, with a module this worker has never seen: fetch, compile, instantiate, execute. |
//!
//! ```text
//! cargo run --release -p nebula-bench
//! ```
//!
//! ponytail: sorted `Vec<u64>` of microseconds and a nearest-rank percentile,
//! not a histogram library. Percentiles of a few thousand samples are a sort,
//! and a sort is not worth a dependency. The §19 conditions that cost minutes
//! rather than seconds, a 60 second window and three runs, are flags rather
//! than defaults, because a benchmark nobody runs measures nothing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use nebula_control::gateway::{self, Gateway};
use nebula_control::membership::Membership;
use nebula_control::registry::Registry;
use nebula_control::server::ControlService;
use nebula_proto::nebula_control_server::NebulaControlServer;
use nebula_proto::nebula_worker_server::NebulaWorkerServer;
use nebula_runtime::Runtime;
use nebula_worker::exec_pool::ExecPool;
use nebula_worker::server::WorkerService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic::transport::server::TcpIncoming;
use tonic::transport::Server;

/// The trivial tier of §19: smaller than 10 KiB, no allocation, no host calls
/// beyond the request and response.
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

fn interpreter_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../guests/interpreters/js/dist/nebula_js.wasm")
}

fn samples(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct Latencies {
    label: &'static str,
    micros: Vec<u64>,
}

impl Latencies {
    fn new(label: &'static str, mut micros: Vec<u64>) -> Self {
        micros.sort_unstable();
        Self { label, micros }
    }

    /// Nearest-rank: the smallest value at or above the requested rank. No
    /// interpolation, so every number printed is one that actually happened.
    fn p(&self, percentile: f64) -> f64 {
        if self.micros.is_empty() {
            return f64::NAN;
        }
        let rank = (percentile / 100.0 * self.micros.len() as f64).ceil() as usize;
        self.micros[rank.clamp(1, self.micros.len()) - 1] as f64 / 1000.0
    }

    fn max(&self) -> f64 {
        self.micros.last().copied().unwrap_or(0) as f64 / 1000.0
    }

    fn report(&self, target_ms: Option<f64>) {
        let p99 = self.p(99.0);
        let verdict = match target_ms {
            // Reported either way. A benchmark that only prints numbers
            // clearing the bar is marketing (§19).
            Some(target) if p99 < target => format!("  MET (target p99 < {target} ms)"),
            Some(target) => format!("  MISSED (target p99 < {target} ms)"),
            None => String::new(),
        };
        println!(
            "{:<28} n={:<6} p50 {:>8.3}  p99 {:>8.3}  max {:>8.3} ms{}",
            self.label,
            self.micros.len(),
            self.p(50.0),
            p99,
            self.max(),
            verdict
        );
    }
}

// ---------------------------------------------------------------------------
// M1: in process
// ---------------------------------------------------------------------------

fn m1(label: &'static str, wasm: &[u8], count: usize) -> Latencies {
    let dir = std::env::temp_dir().join(format!("nebula-bench-m1-{}", std::process::id()));
    let runtime = Runtime::new(&dir).expect("runtime");

    // Warmup, discarded. The first call compiles, and §19 measures a warm
    // instantiate rather than a Cranelift invocation.
    for _ in 0..count.clamp(1, 200) {
        runtime
            .execute(wasm, "run", "bench", b"x".to_vec())
            .expect("warmup");
    }

    let micros = (0..count)
        .map(|_| {
            let started = Instant::now();
            runtime
                .execute(wasm, "run", "bench", b"x".to_vec())
                .expect("execute");
            started.elapsed().as_micros() as u64
        })
        .collect();

    let _ = std::fs::remove_dir_all(&dir);
    Latencies::new(label, micros)
}

// ---------------------------------------------------------------------------
// M2 and M3: through the cluster
// ---------------------------------------------------------------------------

struct Cluster {
    http_addr: String,
    gateway: Arc<Gateway>,
}

impl Cluster {
    async fn start(workers: usize) -> Self {
        let membership = Arc::new(Membership::with_defaults());
        let dir = std::env::temp_dir().join(format!("nebula-bench-{}", std::process::id()));
        let registry = Arc::new(Registry::new(dir.join("registry")).expect("registry"));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_url = format!("http://{}", listener.local_addr().unwrap());
        let control = ControlService::new(membership.clone(), registry.clone());
        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(NebulaControlServer::new(control))
                .serve_with_incoming(TcpIncoming::from(listener))
                .await;
        });

        for index in 0..workers {
            let runtime = Arc::new(Runtime::new(dir.join(format!("l2-{index}"))).expect("runtime"));
            let pool = Arc::new(ExecPool::with_default_size(runtime.clone()));
            let service = WorkerService::new(runtime, pool, &control_url).expect("worker service");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            tokio::spawn(async move {
                let _ = Server::builder()
                    .add_service(NebulaWorkerServer::new(service))
                    .serve_with_incoming(TcpIncoming::from(listener))
                    .await;
            });
            membership.register(&format!("worker-{address}"), &address, 1);
        }

        let gateway = Arc::new(
            Gateway::open(membership, registry)
                .expect("gateway")
                .with_limits(
                    nebula_control::ratelimit::Limit::NONE,
                    nebula_control::ratelimit::Limit::NONE,
                ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = listener.local_addr().unwrap().to_string();
        let serving = gateway.clone();
        tokio::spawn(async move {
            let _ = gateway::serve(listener, serving).await;
        });

        Self { http_addr, gateway }
    }

    /// One request, socket open to socket closed. That boundary is the point of
    /// M2: it includes connection setup, which a client reusing a pool would
    /// not pay, and saying so is better than quietly excluding it.
    async fn post(&self, function_id: &str) -> Duration {
        let started = Instant::now();
        let mut stream = tokio::net::TcpStream::connect(&self.http_addr)
            .await
            .expect("connect");
        let head = format!(
            "POST /execute/{function_id} HTTP/1.1\r\nHost: nebula\r\n\
             Connection: close\r\nAuthorization: Bearer bench\r\n\
             Content-Length: 1\r\n\r\nx"
        );
        stream.write_all(head.as_bytes()).await.expect("write");

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read");
        let elapsed = started.elapsed();

        let head = String::from_utf8_lossy(&raw[..raw.len().min(32)]).to_string();
        assert!(head.contains("200"), "request failed: {head}");
        elapsed
    }
}

async fn m2(cluster: &Cluster, count: usize) -> Latencies {
    cluster
        .gateway
        .publish("hot", ECHO.as_bytes())
        .await
        .expect("deploy");

    for _ in 0..20 {
        cluster.post("hot").await;
    }

    let mut micros = Vec::with_capacity(count);
    for _ in 0..count {
        micros.push(cluster.post("hot").await.as_micros() as u64);
    }
    Latencies::new("M2 hot end to end", micros)
}

/// A module of roughly `target` bytes, made of filler functions.
///
/// G2 is defined for a module of up to 2 MiB and the trivial tier is half a
/// kilobyte, so without this the bound in the goal is assumed rather than
/// measured. Padding with a data segment would not do: cold start is dominated
/// by compiling *code*, and a large data segment is bytes Cranelift never
/// looks at.
fn sized_module(target: usize, seed: usize) -> String {
    // Written whole rather than spliced onto ECHO: a wat module is a paren
    // tree, and trimming its tail to append into it produced something that
    // parsed as far as the first filler function and then did not.
    let mut wat = String::with_capacity(target + 4096);
    wat.push_str(
        r#"(module
  (import "nebula" "request_len" (func $len (result i32)))
  (import "nebula" "request_read" (func $read (param i32 i32) (result i32)))
  (import "nebula" "response_write" (func $write (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run")
    (local $n i32)
    (local.set $n (call $len))
    (drop (call $read (i32.const 0) (local.get $n)))
    (drop (call $write (i32.const 0) (local.get $n))))"#,
    );

    let mut n = 0;
    while wat.len() < target {
        // Distinct bodies, so nothing folds them together.
        wat.push_str(&format!(
            "
  (func $f{seed}_{n} (param i32) (result i32) (i32.add (local.get 0) (i32.const {n})))"
        ));
        n += 1;
    }
    wat.push_str(
        "
)",
    );
    wat
}

/// Makes `wasm` unique without changing what it does.
///
/// Appending to a `.wat` string is enough for the trivial tier, but a compiled
/// module is a section structure and trailing bytes make it invalid. A custom
/// section is the sanctioned way to carry bytes nothing executes, so the module
/// stays valid and its content hash changes, which is what misses the caches.
fn uniquify(wasm: &[u8], n: usize) -> Vec<u8> {
    const NAME: &[u8] = b"nebula-bench";

    let mut payload = vec![NAME.len() as u8];
    payload.extend_from_slice(NAME);
    payload.extend_from_slice(&(n as u64).to_le_bytes());

    let mut out = wasm.to_vec();
    out.push(0); // custom section
    let mut size = payload.len();
    // LEB128, unsigned.
    loop {
        let mut byte = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if size == 0 {
            break;
        }
    }
    out.extend_from_slice(&payload);
    out
}

/// M3 for a module the size of a real workload.
///
/// The trivial tier's cold start is dominated by nothing much, so comparing it
/// against a microVM boot flatters this system. §19 says M3 is the number that
/// gets compared to Firecracker's 125-200 ms floor, and this is the one that
/// comparison should use.
async fn m3_heavy(cluster: &Cluster, wasm: &[u8], count: usize) -> Latencies {
    let mut ids = Vec::with_capacity(count);
    for n in 0..count {
        let id = format!("cold-heavy-{n}");
        cluster
            .gateway
            .publish(&id, &uniquify(wasm, n))
            .await
            .expect("deploy");
        ids.push(id);
    }

    let mut micros = Vec::with_capacity(count);
    for id in &ids {
        micros.push(cluster.post(id).await.as_micros() as u64);
    }
    Latencies::new("M3 cold (interpreter)", micros)
}

async fn m3(cluster: &Cluster, count: usize) -> Latencies {
    // A distinct module per sample, so no worker has ever seen it: the artifact
    // hash differs, which misses L1 and L2 and forces a fetch and a compile.
    // Deploying is done up front and is not inside the measurement.
    let mut ids = Vec::with_capacity(count);
    for n in 0..count {
        let id = format!("cold-{n}");
        let wasm = format!("{ECHO}\n(; unique {n} ;)");
        cluster
            .gateway
            .publish(&id, wasm.as_bytes())
            .await
            .expect("deploy");
        ids.push(id);
    }

    let mut micros = Vec::with_capacity(count);
    for id in &ids {
        micros.push(cluster.post(id).await.as_micros() as u64);
    }
    Latencies::new("M3 cold end to end", micros)
}

#[tokio::main]
async fn main() {
    let m1_count = samples("NEBULA_BENCH_M1", 5_000);
    let m2_count = samples("NEBULA_BENCH_M2", 1_000);
    let m3_count = samples("NEBULA_BENCH_M3", 200);

    println!("nebula-bench: README.md §19\n");
    println!(
        "host: {} logical cores, {} build\n",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        if cfg!(debug_assertions) {
            "debug (numbers are not comparable to anything)"
        } else {
            "release"
        }
    );

    // On a plain OS thread, not this one. A guest that touches WASI stdio goes
    // through a sync bridge that blocks, and blocking a tokio worker thread
    // panics. §5.2 puts execution on dedicated threads for exactly this reason,
    // so a harness that measured it any other way would be measuring something
    // the runtime never does.
    let interpreter = interpreter_path();
    let in_process = std::thread::spawn(move || {
        let trivial = m1("M1 in process (trivial)", ECHO.as_bytes(), m1_count);
        // The interpreter of §22.1 is the heavy tier, and the one an agent
        // actually calls. Skipped rather than failed when it is not built.
        let heavy = std::fs::read(&interpreter)
            .ok()
            .map(|wasm| m1("M1 in process (interpreter)", &wasm, m1_count.min(300)));
        (trivial, heavy)
    })
    .join()
    .expect("in-process measurement");

    in_process.0.report(Some(1.0));
    match in_process.1 {
        Some(heavy) => heavy.report(None),
        None => println!("M1 in process (interpreter)  skipped, run `bash guests/build.sh`"),
    }

    let cluster = Cluster::start(3).await;
    m2(&cluster, m2_count).await.report(Some(5.0));
    m3(&cluster, m3_count).await.report(Some(50.0));

    // The size G2 actually names.
    let sized_count = samples("NEBULA_BENCH_M3_SIZED", 5);
    let sized: Vec<String> = (0..sized_count)
        .map(|seed| sized_module(2 << 20, seed))
        .collect();
    let mut micros = Vec::with_capacity(sized_count);
    for (seed, wat) in sized.iter().enumerate() {
        let id = format!("cold-2mib-{seed}");
        cluster
            .gateway
            .publish(&id, wat.as_bytes())
            .await
            .expect("deploy");
        micros.push(cluster.post(&id).await.as_micros() as u64);
    }
    Latencies::new("M3 cold (2 MiB)", micros).report(Some(50.0));

    if let Ok(wasm) = std::fs::read(interpreter_path()) {
        let count = samples("NEBULA_BENCH_M3_HEAVY", 3);
        m3_heavy(&cluster, &wasm, count).await.report(Some(50.0));
    }
}
