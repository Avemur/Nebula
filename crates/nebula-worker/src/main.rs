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

    // §22.8. Off unless `NEBULA_EGRESS_ALLOW` names hosts, and enforced here
    // rather than at the gateway because this is the process that opens the
    // socket — a policy checked anywhere else is one something can route
    // around.
    let egress = nebula_runtime::egress::Policy::from_env();

    // Expensive: reserves the pooling allocator's address space and starts the
    // epoch ticker. One per process, never per request.
    // §13. All three variables or none.
    let mesh_tls = nebula_proto::tls::MeshTls::from_env()?;

    let runtime = Arc::new(Runtime::new(&cache_dir)?.with_egress(egress.clone()));
    let pool = Arc::new(ExecPool::with_default_size(runtime.clone()));
    let service =
        WorkerService::with_mesh_tls(runtime.clone(), pool.clone(), &control, mesh_tls.clone())?;

    let identity = Identity::new(format!("worker-{addr}"), &addr);
    let heartbeat_endpoint = tonic::transport::Endpoint::from_shared(nebula_proto::tls::endpoint(
        &control,
        mesh_tls.is_some(),
    ))?;
    let heartbeat_endpoint = match &mesh_tls {
        Some(tls) => heartbeat_endpoint.tls_config(tls.client())?,
        None => heartbeat_endpoint,
    };
    let mut client = NebulaControlClient::new(heartbeat_endpoint.connect_lazy());

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
    // Printed either way. An operator who meant to enable egress and typoed the
    // variable would otherwise find out from a guest's `-1`, and an operator
    // who did *not* mean to enable it should see that it is on.
    if mesh_tls.is_some() {
        println!("nebula-worker: internal gRPC requires mutual TLS");
    } else {
        println!(
            "nebula-worker: WARNING internal gRPC is unauthenticated plaintext. Anyone who can              reach this port can act as any tenant. Set {}, {} and {} to require              mutual TLS.",
            nebula_proto::tls::CA_ENV,
            nebula_proto::tls::CERT_ENV,
            nebula_proto::tls::KEY_ENV
        );
    }
    if egress.is_enabled() {
        println!("nebula-worker: outbound HTTP enabled for {egress:?}");
    } else {
        println!("nebula-worker: outbound HTTP disabled (set NEBULA_EGRESS_ALLOW to enable)");
    }
    let mut server = Server::builder();
    if let Some(tls) = &mesh_tls {
        server = server.tls_config(tls.server())?;
    }
    server
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
