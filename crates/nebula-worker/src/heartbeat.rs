//! Worker-side registration and liveness (README.md §10.1).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nebula_proto::nebula_control_client::NebulaControlClient;
use nebula_proto::{HeartbeatRequest, RegisterRequest};
use nebula_runtime::Runtime;
use tonic::transport::Channel;
use tonic::Status;

use crate::exec_pool::ExecPool;

#[derive(Debug, Clone)]
pub struct Identity {
    pub node_id: String,
    pub address: String,
    /// Random per process start, so the control plane can tell a restarted
    /// worker from a continuing one and drop stale routing state (§10.1).
    pub generation: u64,
}

impl Identity {
    pub fn new(node_id: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            address: address.into(),
            generation: new_generation(),
        }
    }
}

/// A generation only has to differ between process starts on one machine, which
/// the clock and the pid together already guarantee. A `rand` dependency would
/// buy nothing here.
fn new_generation() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos ^ ((std::process::id() as u64) << 32)
}

/// Registers with the control plane, returning the heartbeat interval it asks
/// for.
pub async fn register(
    client: &mut NebulaControlClient<Channel>,
    identity: &Identity,
) -> Result<Duration, Status> {
    let response = client
        .register(RegisterRequest {
            node_id: identity.node_id.clone(),
            address: identity.address.clone(),
            generation: identity.generation,
        })
        .await?
        .into_inner();

    Ok(Duration::from_millis(
        response.heartbeat_interval_ms.max(1) as u64
    ))
}

/// Beats until cancelled.
///
/// Re-registers when the control plane says it does not recognise this node —
/// which is what a control plane restart looks like from here. Transport errors
/// are logged and retried on the next tick rather than ending the loop: the
/// control plane being briefly unreachable is not a reason for a healthy worker
/// to stop announcing itself.
pub async fn beat_forever(
    mut client: NebulaControlClient<Channel>,
    identity: Identity,
    pool: Arc<ExecPool>,
    runtime: Arc<Runtime>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;

        let request = HeartbeatRequest {
            node_id: identity.node_id.clone(),
            generation: identity.generation,
            in_flight: pool.in_flight() as u32,
            queue_depth: pool.queue_depth() as u32,
            cache_bytes: runtime.cache().l1_bytes() as u64,
        };

        match client.heartbeat(request).await {
            Ok(response) => {
                if response.into_inner().re_register {
                    if let Err(status) = register(&mut client, &identity).await {
                        eprintln!("nebula-worker: re-register failed: {status}");
                    }
                }
            }
            Err(status) => eprintln!("nebula-worker: heartbeat failed: {status}"),
        }
    }
}
