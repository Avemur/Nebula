//! MCP server binary (§22.3).
//!
//! Runs beside the cluster rather than on it: point it at the HTTP gateway and
//! it speaks Model Context Protocol to anything that already knows how.

use std::sync::Arc;

use nebula_mcp::gateway::Gateway;
use nebula_mcp::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    nebula_mcp::init_tracing_with_default("info");

    let addr = std::env::var("NEBULA_MCP_ADDR").unwrap_or_else(|_| "127.0.0.1:8090".to_string());
    let gateway_addr =
        std::env::var("NEBULA_GATEWAY_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    // v1 auth: the bearer token *is* the tenant (§13), so this doubles as the
    // tenant every script from this MCP server runs as.
    let token = std::env::var("NEBULA_TOKEN").unwrap_or_else(|_| "mcp".to_string());
    let function_id = std::env::var("NEBULA_JS_FUNCTION").unwrap_or_else(|_| "js".to_string());

    let server = Arc::new(Server::new(
        Gateway {
            address: gateway_addr.clone(),
            token,
        },
        &function_id,
    ));

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!(
        "nebula-mcp: POST http://{addr}/mcp -> gateway {gateway_addr}, interpreter `{function_id}`"
    );
    nebula_mcp::serve(listener, server).await?;
    Ok(())
}
