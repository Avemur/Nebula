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

/// W3C trace context, forwarded by the gateway (§22.6).
pub const TRACEPARENT_METADATA: &str = "traceparent";

/// The trace id out of a `traceparent`, if it looks like one.
///
/// The gateway validated the header and re-emitted it, and §13 makes the mesh
/// trusted, so this does not re-parse — it takes the field by position. The
/// length and hex checks are here only so a malformed value produces no
/// `trace_id` rather than a confusing one; there is nothing to defend against.
fn trace_id_of(request: &Request<ExecuteRequest>) -> Option<String> {
    let raw = request
        .metadata()
        .get(TRACEPARENT_METADATA)?
        .to_str()
        .ok()?;
    let id = raw.split('-').nth(1)?;
    (id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_string())
}

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
        self.fetch(hash).await.map(|artifact| (artifact, true))
    }

    /// Split out from [`WorkerService::artifact`] so the span exists only on a
    /// miss. A `fetch_module` span that closes in 200 ns on every warm request
    /// is noise in exactly the trace you are reading to find the cold ones.
    #[tracing::instrument(
        name = "fetch_module",
        skip_all,
        fields(hash = %hash, bytes = tracing::field::Empty)
    )]
    async fn fetch(&self, hash: &str) -> Result<Arc<Vec<u8>>, FetchError> {
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

        tracing::Span::current().record("bytes", artifact.len());

        let artifact = Arc::new(artifact);
        self.artifacts
            .lock()
            .unwrap()
            .insert(hash.to_string(), artifact.clone());
        Ok(artifact)
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
            body: ctx.output(),
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
    #[tracing::instrument(
        name = "grpc_execute",
        skip_all,
        fields(
            // Recorded before anything can fail, so a shed or draining request
            // still lands in the caller's trace (§22.6).
            trace_id = tracing::field::Empty,
            function_id = tracing::field::Empty,
            tenant = tracing::field::Empty,
            cold = tracing::field::Empty,
            outcome = tracing::field::Empty,
        )
    )]
    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        if let Some(trace_id) = trace_id_of(&request) {
            tracing::Span::current().record("trace_id", trace_id.as_str());
        }

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
        let span = tracing::Span::current();
        span.record("function_id", request.function_id.as_str());
        span.record("tenant", request.tenant.as_str());

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
        span.record("cold", cold);
        span.record(
            "outcome",
            tracing::field::debug(Outcome::try_from(response.outcome).unwrap_or(Outcome::Internal)),
        );
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

#[cfg(test)]
mod trace_tests {
    use super::*;
    use nebula_control::trace::TraceContext;

    /// The worker reads what the gateway writes — asserted against the real
    /// producer rather than a string someone typed here.
    ///
    /// This is the whole integration risk in one test. Both sides could be
    /// individually correct about a format they disagree on, and the symptom
    /// would be a `trace_id` field that is silently never populated: nothing
    /// fails, no test goes red, and a trace just quietly stops at the gateway.
    #[test]
    fn the_worker_reads_the_traceparent_the_gateway_writes() {
        let context = TraceContext::adopt(Some(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        ));
        let on_the_wire = context.outgoing("aaaaaaaaaaaaaaaa");

        let mut request = Request::new(ExecuteRequest::default());
        request
            .metadata_mut()
            .insert(TRACEPARENT_METADATA, on_the_wire.parse().unwrap());

        assert_eq!(trace_id_of(&request), Some(context.trace_id));
    }

    #[test]
    fn a_minted_trace_survives_the_hop_too() {
        // A request the caller did not trace still gets an id, and the worker
        // has to pick that one up as well or half the traces stop at the
        // gateway for no visible reason.
        let context = TraceContext::adopt(None);
        let mut request = Request::new(ExecuteRequest::default());
        request.metadata_mut().insert(
            TRACEPARENT_METADATA,
            context.outgoing("bbbbbbbbbbbbbbbb").parse().unwrap(),
        );

        assert_eq!(trace_id_of(&request), Some(context.trace_id));
    }

    #[test]
    fn an_absent_or_unusable_traceparent_is_simply_no_trace_id() {
        // Nothing here is a defence — §13 makes the mesh trusted. It only has
        // to produce *no* id rather than a confusing one.
        assert_eq!(trace_id_of(&Request::new(ExecuteRequest::default())), None);

        for bad in ["", "garbage", "00-short-00f067aa0ba902b7-01"] {
            let mut request = Request::new(ExecuteRequest::default());
            request
                .metadata_mut()
                .insert(TRACEPARENT_METADATA, bad.parse().unwrap());
            assert_eq!(trace_id_of(&request), None, "{bad:?}");
        }
    }
}
