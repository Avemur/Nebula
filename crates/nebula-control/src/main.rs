//! Control plane binary (§3.1).
//!
//! Serves the `NebulaControl` gRPC surface and runs the membership reconciler.
//! The axum API gateway of §11.1 is not wired yet.

use std::sync::Arc;

use nebula_control::gateway::{self, Gateway};
use nebula_control::membership::{self, Membership, RECONCILE_INTERVAL};
use nebula_control::registry::Registry;
use nebula_control::server::ControlService;
use nebula_proto::nebula_control_server::NebulaControlServer;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr =
        std::env::var("NEBULA_CONTROL_ADDR").unwrap_or_else(|_| "127.0.0.1:7000".to_string());
    let registry_dir =
        std::env::var("NEBULA_REGISTRY_DIR").unwrap_or_else(|_| "/tmp/nebula-registry".to_string());

    let membership = Arc::new(Membership::with_defaults());
    let registry = Arc::new(Registry::new(&registry_dir)?);

    membership::spawn_reconciler(membership.clone(), RECONCILE_INTERVAL);

    let http_addr =
        std::env::var("NEBULA_HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let gateway = Arc::new(Gateway::open(membership.clone(), registry.clone())?);
    let listener = tokio::net::TcpListener::bind(&http_addr).await?;
    tokio::spawn(async move {
        let _ = gateway::serve(listener, gateway).await;
    });

    println!("nebula-control: gRPC on {addr}, HTTP on {http_addr}, registry at {registry_dir}");
    Server::builder()
        .add_service(NebulaControlServer::new(ControlService::new(
            membership, registry,
        )))
        .serve(addr.parse()?)
        .await?;
    Ok(())
}
