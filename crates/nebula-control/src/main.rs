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
    let auth = nebula_control::auth::Auth::from_env();

    // `nebula-control mint <tenant>` prints a token and exits. A signing scheme
    // nobody can issue a token for is a signing scheme nobody turns on.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("mint") {
        let Some(tenant) = args.get(2) else {
            eprintln!("usage: nebula-control mint <tenant>");
            std::process::exit(2);
        };
        match auth.mint(tenant) {
            Some(token) => println!("{token}"),
            None => {
                eprintln!(
                    "cannot mint: set {} and use a tenant of [A-Za-z0-9_-]{{1,64}}",
                    nebula_control::auth::SECRET_ENV
                );
                std::process::exit(2);
            }
        }
        return Ok(());
    }

    nebula_control::init_tracing();
    let addr =
        std::env::var("NEBULA_CONTROL_ADDR").unwrap_or_else(|_| "127.0.0.1:7000".to_string());
    let registry_dir =
        std::env::var("NEBULA_REGISTRY_DIR").unwrap_or_else(|_| "/tmp/nebula-registry".to_string());

    let membership = Arc::new(Membership::with_defaults());
    let registry = Arc::new(Registry::new(&registry_dir)?);

    membership::spawn_reconciler(membership.clone(), RECONCILE_INTERVAL);

    let http_addr =
        std::env::var("NEBULA_HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let enforcing = auth.is_enforcing();
    let gateway = Arc::new(Gateway::open(membership.clone(), registry.clone())?.with_auth(auth));
    let listener = tokio::net::TcpListener::bind(&http_addr).await?;
    tokio::spawn(async move {
        let _ = gateway::serve(listener, gateway).await;
    });

    println!("nebula-control: gRPC on {addr}, HTTP on {http_addr}, registry at {registry_dir}");
    // Printed either way, and loudly in the insecure case. An operator who
    // believes they have authentication and does not is worse off than one who
    // knows they have none.
    if enforcing {
        println!("nebula-control: bearer tokens must be signed; mint with `nebula-control mint <tenant>`");
    } else {
        println!(
            "nebula-control: WARNING authentication is OFF -- the bearer token is taken as the              tenant id, so any caller can be any tenant. Set {} to require signed tokens.",
            nebula_control::auth::SECRET_ENV
        );
    }
    Server::builder()
        .add_service(NebulaControlServer::new(ControlService::new(
            membership, registry,
        )))
        .serve(addr.parse()?)
        .await?;
    Ok(())
}
