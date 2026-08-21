//! The `NebulaWorker` gRPC service (README.md §11.2) and the local artifact
//! mirror that backs the cold-start path of §4.1.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use nebula_proto::nebula_control_client::NebulaControlClient;
use nebula_proto::nebula_worker_server::NebulaWorker;
use nebula_proto::{
    DrainRequest, DrainResponse, ExecuteRequest, ExecuteResponse, FetchModuleRequest, Outcome,
};
use nebula_runtime::wasmtime::Trap;
use nebula_runtime::{wasmtime, HostCtx, MemoryLimitExceeded, Runtime};
use tonic::transport::Channel;
use tonic::{Code, Request, Response, Status};

use crate::exec_pool::{ExecPool, PoolError};

/// §6.4 caps artifacts at 32 MiB, enforced while chunks accumulate so a broken
/// or hostile control plane cannot stream the worker to death.
pub const MAX_ARTIFACT_BYTES: usize = 32 << 20;

/// Ceiling on a caller-supplied `deadline_ms`. The field is a request, not an
/// instruction: without a cap a client could pin an execution thread for as
/// long as it liked, which is the resource exhaustion admission control exists
/// to prevent.
pub const MAX_DEADLINE_MS: u32 = 5_000;

#[derive(Debug, Clone, Copy)]
enum FetchError {
    NotFound,
    Transport,
    Corrupt,
    TooLarge,
}

pub struct WorkerService {
    runtime: Arc<Runtime>,
    pool: Arc<ExecPool>,
    control: NebulaControlClient<Channel>,
    /// Artifacts this worker has fetched, by content hash.
    ///
    /// Separate from the runtime's module cache because `Runtime::execute` takes
    /// bytes: the cache holds *compiled* modules, this holds the source they
    /// were compiled from. Concurrent misses for one hash can fetch twice —
    /// wasteful but harmless, since the compile behind it is single-flighted.
    artifacts: Mutex<HashMap<String, Arc<Vec<u8>>>>,
    draining: AtomicBool,
}

impl std::fmt::Debug for WorkerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerService")
            .field("pool", &self.pool)
            .field("draining", &self.draining.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl WorkerService {
    /// `control_endpoint` is dialled lazily, so a worker can start before the
    /// control plane is listening and still recover on its first cold start.
    pub fn new(
        runtime: Arc<Runtime>,
        pool: Arc<ExecPool>,
        control_endpoint: &str,
    ) -> Result<Self, tonic::transport::Error> {
        let channel =
            tonic::transport::Endpoint::from_shared(control_endpoint.to_string())?.connect_lazy();
        Ok(Self {
            runtime,
            pool,
            control: NebulaControlClient::new(channel),
            artifacts: Mutex::new(HashMap::new()),
            draining: AtomicBool::new(false),
        })
    }

    pub fn pool(&self) -> &Arc<ExecPool> {
        &self.pool
    }

    pub fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    /// Returns the artifact for `hash` and whether this request had to fetch it.
    async fn artifact(&self, hash: &str) -> Result<(Arc<Vec<u8>>, bool), FetchError> {
        if let Some(cached) = self.artifacts.lock().unwrap().get(hash) {
            return Ok((cached.clone(), false));
        }

        let mut client = self.control.clone();
        let mut stream = client
            .fetch_module(FetchModuleRequest {
                content_hash: hash.to_string(),
            })
            .await
            .map_err(|status| match status.code() {
                Code::NotFound => FetchError::NotFound,
                _ => FetchError::Transport,
            })?
            .into_inner();

        let mut artifact: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.message().await.map_err(|_| FetchError::Transport)? {
            if artifact.len() + chunk.data.len() > MAX_ARTIFACT_BYTES {
                return Err(FetchError::TooLarge);
            }
            artifact.extend_from_slice(&chunk.data);
            if chunk.last {
                break;
            }
        }

        // §4.1 step 5. The hash is what was asked for; anything else means the
        // transfer or the registry is wrong, and compiling it would be running
        // code nobody requested.
        if nebula_runtime::cache::content_hash_hex(&artifact) != hash {
            return Err(FetchError::Corrupt);
        }

        let artifact = Arc::new(artifact);
        self.artifacts
            .lock()
            .unwrap()
            .insert(hash.to_string(), artifact.clone());
        Ok((artifact, true))
    }
}

/// Maps an execution result onto the wire outcomes of §12.
///
/// Guest faults are `Outcome` values inside a successful RPC, never gRPC status
/// codes: a tenant's infinite loop must not appear in transport error rates or
/// look like a worker crash.
fn classify(result: wasmtime::Result<HostCtx>) -> ExecuteResponse {
    match result {
        Ok(ctx) => ExecuteResponse {
            outcome: Outcome::Ok as i32,
            body: ctx.response,
            ..Default::default()
        },
        Err(err) => {
            // Checked before the trap: a guest that is refused memory and then
            // touches the pointer anyway traps with `MemoryOutOfBounds`, and
            // reporting *that* would name the symptom instead of the cause.
            let outcome = if err.downcast_ref::<MemoryLimitExceeded>().is_some() {
                Outcome::MemoryLimit
            } else {
                match err.downcast_ref::<Trap>() {
                    Some(Trap::Interrupt) => Outcome::Timeout,
                    Some(Trap::OutOfFuel) => Outcome::FuelExhausted,
                    Some(_) => Outcome::Trap,
                    // No trap means the host failed, not the guest.
                    None => Outcome::Internal,
                }
            };

            // §12: guest fault detail goes back to the caller — it is their
            // code. Host internal detail does not; it is logged here and the
            // caller gets an opaque outcome.
            let fault_detail = if outcome == Outcome::Internal {
                eprintln!("nebula-worker: internal execution failure: {err:?}");
                String::new()
            } else {
                format!("{err}")
            };

            ExecuteResponse {
                outcome: outcome as i32,
                fault_detail,
                ..Default::default()
            }
        }
    }
}

fn fault(outcome: Outcome, detail: &str) -> ExecuteResponse {
    ExecuteResponse {
        outcome: outcome as i32,
        fault_detail: detail.to_string(),
        ..Default::default()
    }
}

#[tonic::async_trait]
impl NebulaWorker for WorkerService {
    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        if self.draining.load(Ordering::Relaxed) {
            return Err(Status::resource_exhausted("worker is draining"));
        }

        // §10.3. Admission first, before any work at all: a shed request costs
        // a permit check and never reaches the engine.
        let Some(admitted) = self.pool.try_admit() else {
            return Err(Status::resource_exhausted("worker at capacity"));
        };

        let request = request.into_inner();
        if request.tenant.is_empty() {
            // Defaulting would pool every caller into one KV namespace, which
            // is exactly the failure this field exists to prevent.
            return Err(Status::invalid_argument("tenant is required"));
        }
        let started = Instant::now();

        // The permit is held across the fetch as well as the execution — a cold
        // start is in-flight work and should count against capacity. Dropping
        // out of this function early releases it either way.
        let (wasm, cold) = match self.artifact(&request.content_hash).await {
            Ok(found) => found,
            Err(FetchError::NotFound) => {
                return Ok(Response::new(fault(
                    Outcome::ModuleNotFound,
                    "unknown content_hash",
                )));
            }
            Err(other) => {
                eprintln!("nebula-worker: module fetch failed: {other:?}");
                return Ok(Response::new(fault(Outcome::Internal, "")));
            }
        };

        // The gateway derived this from the bearer token; the worker trusts it
        // (§13). It namespaces the KV shim per §7.2, so two functions belonging
        // to one tenant share a store and two tenants never can.
        let tenant = request.tenant.clone();

        // §6.4's default when the caller says nothing, and capped so a client
        // cannot ask a worker to hold a thread indefinitely.
        let deadline_ticks = match request.deadline_ms {
            0 => nebula_runtime::engine::DEFAULT_DEADLINE_TICKS,
            requested => requested.min(MAX_DEADLINE_MS) as u64,
        };

        let result = match self
            .pool
            .run(admitted, wasm, tenant, request.body, deadline_ticks)
            .await
        {
            Ok(result) => result,
            Err(PoolError::Full) => {
                return Err(Status::resource_exhausted("execution queue full"));
            }
            Err(PoolError::Stopped) => {
                return Err(Status::internal("execution pool stopped"));
            }
        };

        let mut response = classify(result);
        response.exec_micros = started.elapsed().as_micros() as u64;
        // "Cold" here means this request had to fetch the artifact. A worker
        // that restarted with a warm L2 will report warm, which is the honest
        // answer for the question the gateway asks.
        response.cold = cold;
        Ok(Response::new(response))
    }

    async fn drain(
        &self,
        _request: Request<DrainRequest>,
    ) -> Result<Response<DrainResponse>, Status> {
        self.draining.store(true, Ordering::Relaxed);
        Ok(Response::new(DrainResponse {
            in_flight: self.pool.in_flight() as u32,
        }))
    }
}
