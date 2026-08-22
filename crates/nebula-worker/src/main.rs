//! Worker node binary (§3.2).

use std::sync::Arc;

use nebula_proto::nebula_control_client::NebulaControlClient;
use nebula_proto::nebula_worker_server::NebulaWorkerServer;
use nebula_runtime::Runtime;
use nebula_worker::exec_pool::ExecPool;
use nebula_worker::heartbeat::{self, Identity};
use nebula_worker::server::WorkerService;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    nebula_worker::init_tracing();
    let addr = std::env::var("NEBULA_WORKER_ADDR").unwrap_or_else(|_| "127.0.0.1:7001".to_string());
    let control =
        std::env::var("NEBULA_CONTROL_URL").unwrap_or_else(|_| "http://127.0.0.1:7000".to_string());
    let cache_dir =
        std::env::var("NEBULA_CACHE_DIR").unwrap_or_else(|_| "/tmp/nebula-l2".to_string());

    // Expensive: reserves the pooling allocator's address space and starts the
    // epoch ticker. One per process, never per request.
    let runtime = Arc::new(Runtime::new(&cache_dir)?);
    let pool = Arc::new(ExecPool::with_default_size(runtime.clone()));
    let service = WorkerService::new(runtime.clone(), pool.clone(), &control)?;

    let identity = Identity::new(format!("worker-{addr}"), &addr);
    let mut client = NebulaControlClient::new(
        tonic::transport::Endpoint::from_shared(control.clone())?.connect_lazy(),
    );

    // A worker that cannot reach the control plane yet still serves; the
    // heartbeat loop keeps trying, and cold starts recover once it is up.
    let interval = match heartbeat::register(&mut client, &identity).await {
        Ok(interval) => interval,
        Err(status) => {
            eprintln!("nebula-worker: initial register failed ({status}), will retry by heartbeat");
            nebula_control_heartbeat_fallback()
        }
    };
    tokio::spawn(heartbeat::beat_forever(
        client,
        identity,
        pool.clone(),
        runtime.clone(),
        interval,
    ));

    println!(
        "nebula-worker: listening on {addr}, control at {control}, \
         {} execution threads, L2 cache at {cache_dir}",
        pool.threads()
    );
    Server::builder()
        .add_service(NebulaWorkerServer::new(service))
        .serve(addr.parse()?)
        .await?;
    Ok(())
}

/// Used only when the very first `Register` fails, so the heartbeat loop has a
/// cadence to start at.
fn nebula_control_heartbeat_fallback() -> std::time::Duration {
    std::time::Duration::from_millis(500)
}
