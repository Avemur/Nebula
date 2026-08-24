//! The HTTP API gateway (README.md §11.1).
//!
//! Translates client HTTP into `Execute` RPCs, and is the only place a tenant
//! identity is established: everything behind it trusts the `tenant` field
//! because the mesh is assumed trusted (§13).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use nebula_proto::nebula_worker_client::NebulaWorkerClient;
use nebula_proto::{ExecuteRequest, ExecuteResponse, Outcome};
use tonic::transport::{Channel, Endpoint};
use tonic::Code;

use crate::idempotency;
use crate::membership::Membership;
use crate::ratelimit::{Decision, Limit, Limiter};
use crate::registry::{Deployments, Registry, Tool, MAX_ARTIFACT_BYTES};
use crate::trace;
use crate::wizer;

/// §6.4 caps a request body at 1 MiB.
pub const MAX_REQUEST_BYTES: usize = 1 << 20;

/// Bound on a caller-supplied function id. It is a map key and a ring key, not
/// a path, but an unbounded one is still a free allocation for anyone asking.
pub const MAX_FUNCTION_ID_BYTES: usize = 128;

/// Optional per-request budget in milliseconds.
///
/// Exists for tool-calling clients: §6.4's 50 ms suits a web handler and is far
/// too tight for an agent asking a sandbox to do real work. The effective value
/// is echoed back on the response, so a caller that asked for more than the cap
/// learns what it actually got instead of wondering why it timed out early.
pub const DEADLINE_HEADER: &str = "x-nebula-deadline-ms";

/// Set on **every** non-200 response.
///
/// A status code is shared by several unrelated failures — 503 is both "no
/// worker" and "worker shed", 500 is both a guest trap and a memory ceiling. A
/// client branching on the status cannot tell them apart; this names the reason.
pub const FAULT_HEADER: &str = "x-nebula-fault";

/// Describes a deployed function to an agent (§22.2).
///
/// A header rather than a multipart body or a second endpoint: the artifact is
/// already the body, and a tool descriptor is metadata about the request rather
/// than a second document to negotiate.
pub const TOOL_SCHEMA_HEADER: &str = "x-nebula-tool-schema";

/// Bound on a tool descriptor. Generous — a real JSON Schema with descriptions
/// on every property is a few kilobytes — and still a bound.
pub const MAX_TOOL_SCHEMA_BYTES: usize = 16 << 10;

/// Routes a request to a stable worker and namespaces its scratchpad (§22.5).
///
/// Reserved in §21 for actor pins and used here for the far cheaper half of
/// that idea: state that survives between steps, without a live instance to
/// pin, a lease to hold, or a fencing token to reason about.
pub const PARTITION_HEADER: &str = "x-nebula-partition-key";

/// Bound on a caller-supplied partition key. It is a ring key and a map key,
/// not a path; an unbounded one is a free allocation for anyone asking.
pub const MAX_PARTITION_KEY_BYTES: usize = 128;

/// Opt-in replay of an already-answered request (§22.4).
///
/// Present because agent frameworks retry automatically, which quietly breaks
/// the §10.2 rule against retrying a dispatched request.
pub const IDEMPOTENCY_HEADER: &str = "idempotency-key";

/// Set when a response came from the idempotency store rather than a fresh
/// execution, so a caller can tell "it ran again" from "it did not need to".
pub const REPLAY_HEADER: &str = "x-nebula-idempotent-replay";

/// §6.4's default, used when the caller does not ask.
const DEFAULT_DEADLINE_MS: u32 = 50;

/// Bounds on a caller-supplied deadline.
///
/// The ceiling mirrors the worker's own `MAX_DEADLINE_MS`. It is duplicated
/// rather than shared because the worker clamps independently — a gateway is
/// not a trust boundary the worker gets to rely on, and the worker is the one
/// whose execution thread is at stake.
const MIN_DEADLINE_MS: u32 = 10;
const MAX_DEADLINE_MS: u32 = 5_000;

pub struct Gateway {
    membership: Arc<Membership>,
    registry: Arc<Registry>,
    /// `function_id` to content hash, mirrored to `deployments.json`.
    ///
    /// One file for the whole table rather than a file per function: a
    /// `function_id` comes from a URL, and the surest way not to have to defend
    /// it against path traversal is never to put it in a path.
    functions: Mutex<Deployments>,
    /// Connected channels by worker address.
    ///
    /// Connections are established eagerly and cached. That is what makes §10.2
    /// implementable: a failure from `connect` proves the request was never
    /// sent, while a failure from a live channel proves nothing.
    workers: Mutex<HashMap<String, NebulaWorkerClient<Channel>>>,
    /// Answers to already-served keyed requests (§22.4).
    idempotency: idempotency::Store<Answer>,
    /// Per-tenant fairness (§22.7). Two buckets, because a deploy runs Wizer
    /// and an execution does not.
    execute_limit: Limiter,
    deploy_limit: Limiter,
}

/// The result of a successful deploy.
#[derive(Debug, Clone)]
pub struct Published {
    pub content_hash: String,
    /// Whether Wizer pre-initialized the artifact (§4.3).
    pub wizened: bool,
    /// Whether a tool descriptor came with it (§22.2).
    pub described: bool,
}

#[derive(Debug)]
pub enum PublishError {
    InvalidId,
    /// The caller's module failed its own initializer. A 400.
    Wizer(String),
    /// The `X-Nebula-Tool-Schema` header was not usable. A 400.
    InvalidTool(String),
    Io(std::io::Error),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidId => f.write_str("function id must be 1..=128 bytes"),
            Self::Wizer(detail) => write!(f, "pre-initialization failed: {detail}"),
            Self::InvalidTool(detail) => write!(f, "{TOOL_SCHEMA_HEADER} is unusable: {detail}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

/// What happened to one dispatch attempt.
enum Attempt {
    Answered(ExecuteResponse),
    /// Never sent — the connection could not be established. Safe to retry.
    NotSent,
    /// Sent, and then something went wrong. **Never** retried: the guest may
    /// have run and had effects, and nothing here knows whether its host calls
    /// were idempotent.
    Failed(tonic::Status),
}

impl Gateway {
    /// Opens the gateway, restoring the deployment table from disk.
    ///
    /// Fallible on purpose: a control plane that cannot read its own deployments
    /// should refuse to start rather than come up serving 404 for every function
    /// that was working a minute ago.
    pub fn open(membership: Arc<Membership>, registry: Arc<Registry>) -> std::io::Result<Self> {
        let functions = registry.load_deployments()?;
        Ok(Self {
            membership,
            registry,
            functions: Mutex::new(functions),
            workers: Mutex::new(HashMap::new()),
            idempotency: idempotency::Store::new(),
            execute_limit: Limiter::new(Limit::EXECUTE),
            deploy_limit: Limiter::new(Limit::DEPLOY),
        })
    }

    /// Replaces the default rate limits.
    ///
    /// Exists for tests, which cannot wait out a 50/s bucket without becoming
    /// slow and flaky — and a limiter nobody can test at its edges is a limiter
    /// nobody knows the edges of.
    pub fn with_limits(mut self, execute: Limit, deploy: Limit) -> Self {
        self.execute_limit = Limiter::new(execute);
        self.deploy_limit = Limiter::new(deploy);
        self
    }

    pub fn content_hash_of(&self, function_id: &str) -> Option<String> {
        self.functions
            .lock()
            .unwrap()
            .functions
            .get(function_id)
            .cloned()
    }

    /// Every deployed function that carries a descriptor (§22.2).
    ///
    /// Functions without one are omitted rather than listed with an empty
    /// description: a tool a model cannot understand is worse than a tool it
    /// cannot see, because it will call the first one and guess.
    pub fn tools(&self) -> Vec<(String, Tool)> {
        let functions = self.functions.lock().unwrap();
        functions
            .tools
            .iter()
            .filter(|(id, _)| functions.functions.contains_key(*id))
            .map(|(id, tool)| (id.clone(), tool.clone()))
            .collect()
    }

    pub fn deployed(&self) -> usize {
        self.functions.lock().unwrap().functions.len()
    }

    /// Deploys `wasm` under `function_id`, pre-initializing it if it asks to be.
    ///
    /// This is where §4.3's build-time step actually happens: a module that
    /// exports an initializer is run through Wizer *before* it is hashed, so the
    /// artifact the cluster stores and every worker compiles is already booted.
    #[tracing::instrument(name = "publish", skip_all, fields(function_id = %function_id, bytes = wasm.len(), wizened = tracing::field::Empty))]
    pub async fn publish(&self, function_id: &str, wasm: &[u8]) -> Result<Published, PublishError> {
        self.publish_with_tool(function_id, wasm, None).await
    }

    /// As [`Gateway::publish`], attaching a tool descriptor (§22.2).
    pub async fn publish_with_tool(
        &self,
        function_id: &str,
        wasm: &[u8],
        tool: Option<Tool>,
    ) -> Result<Published, PublishError> {
        if function_id.is_empty() || function_id.len() > MAX_FUNCTION_ID_BYTES {
            return Err(PublishError::InvalidId);
        }

        let (artifact, wizened) = if wizer::should_wizen(wasm) {
            match wizer::wizen(wasm, self.registry.dir()).await {
                Ok(initialized) => (initialized, true),
                Err(wizer::WizerError::Failed(detail)) => {
                    return Err(PublishError::Wizer(detail));
                }
                // Wizer missing is an operator gap, not a bad artifact. The
                // module still runs; it just pays its boot on every request, and
                // saying so beats refusing a deploy the caller cannot fix.
                Err(wizer::WizerError::Unavailable) => {
                    tracing::warn!(
                        "wizer is not installed; {function_id} deployed without \
                         pre-initialization and will boot on every request"
                    );
                    (wasm.to_vec(), false)
                }
                Err(other) => {
                    return Err(PublishError::Io(std::io::Error::other(other.to_string())))
                }
            }
        } else {
            (wasm.to_vec(), false)
        };

        tracing::Span::current().record("wizened", wizened);

        let content_hash = self.registry.put(&artifact).map_err(PublishError::Io)?;
        let described = tool.is_some();
        let mut functions = self.functions.lock().unwrap();
        functions
            .functions
            .insert(function_id.to_string(), content_hash.clone());
        // A redeploy without a descriptor clears the old one rather than
        // leaving it: a stale description of a function that has changed is how
        // a model gets told confidently wrong things about what it is calling.
        match tool {
            Some(tool) => functions.tools.insert(function_id.to_string(), tool),
            None => functions.tools.remove(function_id),
        };

        // Persisted before the caller is told the deployment succeeded. The lock
        // is held across the write so the file can never disagree with the map;
        // deploys are rare, so serialising them costs nothing that matters.
        self.registry
            .save_deployments(&functions)
            .map_err(PublishError::Io)?;

        Ok(Published {
            content_hash,
            wizened,
            described,
        })
    }

    async fn client(&self, address: &str) -> Option<NebulaWorkerClient<Channel>> {
        if let Some(existing) = self.workers.lock().unwrap().get(address) {
            return Some(existing.clone());
        }
        let channel = Endpoint::from_shared(format!("http://{address}"))
            .ok()?
            .connect()
            .await
            .ok()?;
        let client = NebulaWorkerClient::new(channel);
        self.workers
            .lock()
            .unwrap()
            .insert(address.to_string(), client.clone());
        Some(client)
    }

    fn forget(&self, address: &str) {
        self.workers.lock().unwrap().remove(address);
    }

    /// One dispatch attempt. Instrumented per attempt rather than per request,
    /// so a retry shows up as a second span instead of hiding inside the first.
    #[tracing::instrument(name = "route_to_worker", skip_all, fields(worker = %address, outcome = tracing::field::Empty))]
    async fn dispatch(&self, address: &str, request: ExecuteRequest, traceparent: &str) -> Attempt {
        let span = tracing::Span::current();
        let Some(mut client) = self.client(address).await else {
            span.record("outcome", "not_sent");
            return Attempt::NotSent;
        };

        // Trace context rides in gRPC metadata rather than in `ExecuteRequest`,
        // for the same reason it rides in an HTTP header rather than a JSON
        // body: it describes the call, not the work (§22.6).
        let mut request = tonic::Request::new(request);
        if let Ok(value) = traceparent.parse() {
            request
                .metadata_mut()
                .insert(trace::TRACEPARENT_HEADER, value);
        }

        match client.execute(request).await {
            Ok(response) => {
                span.record("outcome", "answered");
                Attempt::Answered(response.into_inner())
            }
            Err(status) => {
                span.record("outcome", status.code().description());
                // The channel is suspect now; drop it so the next request
                // reconnects and gets a clean "never sent" answer instead of
                // failing on a corpse.
                self.forget(address);
                Attempt::Failed(status)
            }
        }
    }
}

/// Serves the gateway on `listener`.
///
/// Exists so axum stays an implementation detail of this crate: callers hand
/// over a listener rather than taking on the dependency themselves.
pub async fn serve(listener: tokio::net::TcpListener, state: Arc<Gateway>) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}

pub fn router(state: Arc<Gateway>) -> Router {
    Router::new()
        .route("/execute/{id}", post(execute))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .route(
            "/functions/{id}",
            put(publish).layer(DefaultBodyLimit::max(MAX_ARTIFACT_BYTES)),
        )
        .route("/healthz", get(healthz))
        .route("/cluster", get(cluster))
        .route("/tools", get(tools))
        .with_state(state)
}

/// v1 authentication: the bearer token *is* the tenant id (§13). Enough to prove
/// the authorization path exists; not a credential system.
fn tenant_of(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Reads [`TOOL_SCHEMA_HEADER`].
///
/// `Ok(None)` is absent. Anything present and unusable is an error rather than
/// a silent drop — a caller that sent a descriptor is expecting its function to
/// be callable by an agent, and quietly deploying it undescribed looks like
/// success and produces a tool nobody can find.
fn tool_of(headers: &HeaderMap) -> Result<Option<Tool>, String> {
    let Some(raw) = headers.get(TOOL_SCHEMA_HEADER) else {
        return Ok(None);
    };
    let raw = raw
        .to_str()
        .map_err(|_| "not printable ASCII".to_string())?;
    if raw.len() > MAX_TOOL_SCHEMA_BYTES {
        return Err(format!("longer than {MAX_TOOL_SCHEMA_BYTES} bytes"));
    }

    let tool: Tool = serde_json::from_str(raw).map_err(|err| err.to_string())?;
    if tool.description.trim().is_empty() {
        // The field that decides whether a model calls the tool correctly, or
        // at all. An empty one is a descriptor that describes nothing.
        return Err("`description` must not be empty".to_string());
    }
    Ok(Some(tool))
}

/// §22.2. The array in the shape the Anthropic and OpenAI tool APIs take, so
/// wiring an agent is a paste rather than a translation layer.
async fn tools(State(gateway): State<Arc<Gateway>>) -> Response {
    let tools: Vec<serde_json::Value> = gateway
        .tools()
        .into_iter()
        .map(|(name, tool)| {
            serde_json::json!({
                "name": name,
                "description": tool.description,
                "input_schema": tool.input_schema,
            })
        })
        .collect();

    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&tools).unwrap_or_else(|_| "[]".to_string()),
    )
        .into_response()
}

async fn healthz() -> &'static str {
    "ok"
}

async fn cluster(State(gateway): State<Arc<Gateway>>) -> String {
    let mut lines = Vec::new();
    for (id, state) in gateway.membership.snapshot() {
        lines.push(format!(
            "{id} {} in_flight={} queue={} cache_bytes={}",
            state.address, state.in_flight, state.queue_depth, state.cache_bytes
        ));
    }
    lines.sort();
    lines.join("\n")
}

async fn publish(
    State(gateway): State<Arc<Gateway>>,
    Path(function_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(tenant) = tenant_of(&headers) else {
        return unauthorized().into_response();
    };
    // Checked before `publish`, which is where Wizer runs the caller's guest
    // code in a subprocess (§11.1) — the single most expensive thing this
    // endpoint can be asked to do.
    if let Decision::Limited { retry_after } = gateway.deploy_limit.check(&tenant) {
        return rate_limited(retry_after).into_response();
    }
    let tool = match tool_of(&headers) {
        Ok(tool) => tool,
        Err(detail) => {
            return (
                StatusCode::BAD_REQUEST,
                PublishError::InvalidTool(detail).to_string(),
            )
                .into_response()
        }
    };

    match gateway.publish_with_tool(&function_id, &body, tool).await {
        Ok(published) => (
            StatusCode::CREATED,
            [(header::CONTENT_TYPE, "application/json")],
            // Hand-built rather than a serde dependency for three fields. The
            // hash is hex and the flags are bools, so there is nothing here to
            // escape.
            format!(
                "{{\"content_hash\":\"{}\",\"wizened\":{},\"described\":{}}}",
                published.content_hash, published.wizened, published.described
            ),
        )
            .into_response(),
        // A module whose own initializer fails is a bad artifact, and the caller
        // is the only one who can fix it.
        Err(
            err @ (PublishError::Wizer(_) | PublishError::InvalidId | PublishError::InvalidTool(_)),
        ) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
        Err(PublishError::Io(err)) => {
            tracing::error!("deploy of {function_id} failed: {err}");
            (StatusCode::INTERNAL_SERVER_ERROR, "deploy failed").into_response()
        }
    }
}

#[tracing::instrument(
    name = "request_received",
    skip_all,
    fields(
        function_id = %function_id,
        bytes = body.len(),
        // Recorded first thing in the body, so every span underneath this one
        // carries the caller's trace id (§22.6).
        trace_id = tracing::field::Empty,
        tenant = tracing::field::Empty,
        deadline_ms = tracing::field::Empty,
    )
)]
async fn execute(
    State(gateway): State<Arc<Gateway>>,
    Path(function_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Before anything that can fail: a rejected request is exactly the one a
    // caller most wants to find in its own trace.
    let trace = trace::TraceContext::adopt(
        headers
            .get(trace::TRACEPARENT_HEADER)
            .and_then(|value| value.to_str().ok()),
    );
    tracing::Span::current().record("trace_id", trace.trace_id.as_str());

    // Answered as an `Answer` throughout so the trace id can be stamped on
    // every exit in one place — including the ones that never reach a worker.
    let answer = answer_for(&gateway, &function_id, &headers, body, &trace).await;
    answer.with_trace(&trace).into_response()
}

async fn answer_for(
    gateway: &Gateway,
    function_id: &str,
    headers: &HeaderMap,
    body: Bytes,
    trace: &trace::TraceContext,
) -> Answer {
    let Some(tenant) = tenant_of(headers) else {
        return unauthorized();
    };
    tracing::Span::current().record("tenant", tenant.as_str());

    let partition = match partition_key_of(headers) {
        Ok(key) => key,
        Err(()) => {
            return fault(
                StatusCode::BAD_REQUEST,
                "invalid_partition_key",
                format!(
                "{PARTITION_HEADER} must be 1..={MAX_PARTITION_KEY_BYTES} printable ASCII bytes"
            ),
            )
        }
    };

    // Before the deployment lookup, the ring walk, and the idempotency claim:
    // a refused request should cost a hash and nothing else, or the limiter
    // becomes its own load amplifier.
    if let Decision::Limited { retry_after } = gateway.execute_limit.check(&tenant) {
        return rate_limited(retry_after);
    }

    let Some(deadline_ms) = deadline_of(headers) else {
        return fault(
            StatusCode::BAD_REQUEST,
            "invalid_deadline",
            format!("{DEADLINE_HEADER} must be a whole number of milliseconds"),
        );
    };
    tracing::Span::current().record("deadline_ms", deadline_ms);

    // Unkeyed is the common path and stays exactly as it was.
    let key = match idempotency_key_of(headers) {
        None => {
            return run(
                gateway,
                function_id,
                tenant,
                partition,
                deadline_ms,
                body,
                trace,
            )
            .await
        }
        Some(Err(())) => {
            return fault(
                StatusCode::BAD_REQUEST,
                "invalid_idempotency_key",
                format!(
                    "{IDEMPOTENCY_HEADER} must be 1..={} printable ASCII bytes",
                    idempotency::MAX_KEY_BYTES
                ),
            )
        }
        Some(Ok(key)) => key,
    };

    let slot = idempotency::Slot {
        tenant: tenant.clone(),
        function_id: function_id.to_string(),
        key,
    };

    match gateway.idempotency.claim(&slot) {
        idempotency::Claim::Replay(mut answer) => {
            tracing::info!(status = answer.status.as_u16(), "replayed a keyed request");
            answer.replayed = true;
            answer
        }
        // §22.4: a duplicate arriving while the first is still running is told
        // to wait, not served a second execution. Returning the *original*
        // request's answer is impossible — it does not exist yet — and running
        // the script again is the exact thing the key was sent to prevent.
        idempotency::Claim::InFlight => fault(
            StatusCode::CONFLICT,
            "idempotency_in_flight",
            "a request with this Idempotency-Key is already running",
        ),
        // The claim is a guard: if this future is dropped — a client that hung
        // up mid-request, which is precisely the case the key exists for — the
        // slot is released rather than left answering 409 until the TTL runs
        // out.
        idempotency::Claim::Proceed(claim) => {
            let answer = run(
                gateway,
                function_id,
                tenant,
                partition,
                deadline_ms,
                body,
                trace,
            )
            .await;
            claim.finish(&answer, answer.replayable(), answer.weight());
            answer
        }
    }
}

async fn run(
    gateway: &Gateway,
    function_id: &str,
    tenant: String,
    partition: Option<String>,
    deadline_ms: u32,
    body: Bytes,
    trace: &trace::TraceContext,
) -> Answer {
    let Some(content_hash) = gateway.content_hash_of(function_id) else {
        return fault(
            StatusCode::NOT_FOUND,
            "unknown_function",
            "no function deployed under that id",
        );
    };

    // Bounded-load ordering (§9.2): the ring's owner leads unless it is above
    // 1.25x mean cluster load, in which case the walk starts at the next node.
    // The rest of the plan stays in ring order, so failover is unchanged.
    // §22.5. A partition key routes by *session* rather than by function, which
    // trades cache affinity for state affinity: two sessions of one function
    // land on different workers and each compiles it once. That is the price of
    // reading back what you wrote, and it is paid only by callers who ask.
    let plan = gateway
        .membership
        .route_plan(partition.as_deref().unwrap_or(function_id));
    if plan.is_empty() {
        return fault(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_healthy_worker",
            "no worker is in the ring",
        );
    }

    let request = ExecuteRequest {
        function_id: function_id.to_string(),
        content_hash,
        body: body.to_vec(),
        // The trace id, not a synthesised label: it is unique per request
        // and it is the same id the caller and the worker both log, which is
        // the only property that makes a request id worth having.
        request_id: trace.trace_id.clone(),
        deadline_ms,
        partition_key: partition,
        tenant,
    };

    // A fresh parent per attempt: a retry is a second hop and should appear
    // in the trace as one, not as a mysterious repeat of the first (§22.6).
    let traceparent = trace.outgoing(&trace::current_span_id());

    // §10.2: at most one retry, and only when the first attempt was never sent.
    let mut last_status = None;
    for (index, (_node, address)) in plan.iter().take(2).enumerate() {
        match gateway
            .dispatch(address, request.clone(), &traceparent)
            .await
        {
            Attempt::Answered(response) => return to_http(response, deadline_ms),
            Attempt::NotSent => continue,
            Attempt::Failed(status) => {
                if status.code() == Code::ResourceExhausted && index == 0 {
                    // Shedding is not a failure of the worker, and §10.3 allows
                    // one more ring node before giving up.
                    last_status = Some(status);
                    continue;
                }
                return from_status(&status);
            }
        }
    }

    match last_status {
        Some(status) if status.code() == Code::ResourceExhausted => fault(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster_at_capacity",
            "every candidate worker shed the request",
        ),
        Some(status) => from_status(&status),
        // Every candidate refused the connection: nothing ran anywhere.
        None => fault(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_reachable_worker",
            "no candidate worker accepted a connection",
        ),
    }
}

fn to_http(response: ExecuteResponse, deadline_ms: u32) -> Answer {
    let outcome = Outcome::try_from(response.outcome).unwrap_or(Outcome::Internal);

    // §12. Guest fault detail goes back to the caller — it is their code. The
    // `Internal` arm carries none, because the worker withheld it deliberately.
    let (status, fault, body) = match outcome {
        Outcome::Ok => (StatusCode::OK, None, response.body),
        Outcome::Trap => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("trap"),
            response.fault_detail.into_bytes(),
        ),
        Outcome::Timeout => (
            StatusCode::GATEWAY_TIMEOUT,
            Some("timeout"),
            response.fault_detail.into_bytes(),
        ),
        Outcome::FuelExhausted => (
            StatusCode::GATEWAY_TIMEOUT,
            Some("fuel_exhausted"),
            response.fault_detail.into_bytes(),
        ),
        Outcome::MemoryLimit => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("memory_limit"),
            response.fault_detail.into_bytes(),
        ),
        Outcome::ModuleNotFound => (
            StatusCode::NOT_FOUND,
            Some("module_not_found"),
            response.fault_detail.into_bytes(),
        ),
        Outcome::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("internal"),
            response.fault_detail.into_bytes(),
        ),
    };

    Answer {
        status,
        fault,
        body,
        cold: Some(response.cold),
        exec_micros: Some(response.exec_micros),
        // The *effective* budget, after clamping. A caller that asked for 60 s
        // and silently got 5 s would otherwise read a `timeout` fault as a bug.
        deadline_ms: Some(deadline_ms),
        replayed: false,
        trace_id: None,
        retry_after: None,
    }
}

fn from_status(status: &tonic::Status) -> Answer {
    match status.code() {
        Code::ResourceExhausted => fault(
            StatusCode::SERVICE_UNAVAILABLE,
            "worker_shed",
            "worker at capacity",
        ),
        Code::InvalidArgument => fault(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            status.message().to_string(),
        ),
        // The request reached a worker and then the connection failed. It may
        // have executed, so this is reported, not retried (§10.2).
        Code::Unavailable | Code::Cancelled | Code::DeadlineExceeded => fault(
            StatusCode::BAD_GATEWAY,
            "worker_unreachable",
            "worker became unreachable mid-request; the call may or may not have run",
        ),
        _ => fault(
            StatusCode::INTERNAL_SERVER_ERROR,
            "dispatch_failed",
            "dispatch failed",
        ),
    }
}

/// A finished answer, in a form that can be stored and replayed (§22.4).
///
/// The handler builds one of these rather than a `Response` directly, because
/// an `axum::Response` body is a stream and cannot be cloned into the
/// idempotency store. Everything the caller sees is here, so a replay is
/// byte-identical to the original rather than a reconstruction of it.
#[derive(Clone, Debug)]
pub struct Answer {
    status: StatusCode,
    /// `None` on success; every non-200 names its cause (§11.1).
    fault: Option<&'static str>,
    body: Vec<u8>,
    /// Informational headers, carried so a replay reports the same numbers the
    /// original did rather than a fresh, misleading set.
    cold: Option<bool>,
    exec_micros: Option<u64>,
    deadline_ms: Option<u32>,
    /// Set on a replay so a caller can tell one from a fresh execution.
    replayed: bool,
    /// The trace this request belonged to (§22.6). Stamped on every exit, so a
    /// caller can find a rejected request in its own trace — those are the ones
    /// it most wants to find.
    trace_id: Option<String>,
    /// Whole seconds, when the answer can say something more useful than the
    /// flat `Retry-After: 1` that 503 carries (§22.7).
    retry_after: Option<u64>,
}

impl Answer {
    /// Whether a retry with the same key should receive this verbatim (§22.4).
    ///
    /// A completed execution is replayable whether it succeeded or the guest
    /// faulted — the script ran, and running it again would produce the same
    /// thing. Everything else means "no answer exists", and storing it would
    /// pin a transient failure for the whole TTL.
    fn replayable(&self) -> bool {
        matches!(
            self.fault,
            None | Some("trap") | Some("timeout") | Some("fuel_exhausted") | Some("memory_limit")
        )
    }

    /// Stamps the current trace, overwriting whatever a replayed answer
    /// carried — the id belongs to *this* request, not to the one that
    /// originally produced the body.
    fn with_trace(mut self, trace: &trace::TraceContext) -> Self {
        self.trace_id = Some(trace.trace_id.clone());
        self
    }

    /// What this costs the idempotency store, for its byte budget.
    ///
    /// The body dominates and is capped at 1 MiB (§7.2); the constant is a
    /// nod to the `Slot` strings and the map entry, so a flood of tiny answers
    /// is still charged for something.
    fn weight(&self) -> usize {
        self.body.len() + 128
    }
}

impl IntoResponse for Answer {
    fn into_response(self) -> Response {
        let mut headers = HeaderMap::new();
        if let Some(kind) = self.fault {
            headers.insert(FAULT_HEADER, HeaderValue::from_static(kind));
        }
        // `Retry-After` rides along with 503 and 429 because both statuses
        // *mean* "try again" — not a special case, just the definition. 502
        // still does not get one: §22.4 explains why a key does not make that
        // safe either.
        if self.status == StatusCode::SERVICE_UNAVAILABLE {
            headers.insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        if let Some(value) = self
            .retry_after
            .and_then(|s| HeaderValue::from_str(&s.to_string()).ok())
        {
            headers.insert(header::RETRY_AFTER, value);
        }
        if self.status == StatusCode::UNAUTHORIZED {
            headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        if let Some(cold) = self.cold {
            headers.insert(
                "x-nebula-cold",
                HeaderValue::from_static(if cold { "true" } else { "false" }),
            );
        }
        if let Some(value) = self
            .exec_micros
            .and_then(|n| HeaderValue::from_str(&n.to_string()).ok())
        {
            headers.insert("x-nebula-exec-micros", value);
        }
        if let Some(value) = self
            .deadline_ms
            .and_then(|n| HeaderValue::from_str(&n.to_string()).ok())
        {
            headers.insert(DEADLINE_HEADER, value);
        }
        if self.replayed {
            headers.insert(REPLAY_HEADER, HeaderValue::from_static("true"));
        }
        if let Some(value) = self
            .trace_id
            .as_deref()
            .and_then(|id| HeaderValue::from_str(id).ok())
        {
            headers.insert(trace::TRACE_ID_HEADER, value);
        }

        (self.status, headers, self.body).into_response()
    }
}

/// A non-200 answer that names its own cause.
fn fault(status: StatusCode, kind: &'static str, detail: impl Into<String>) -> Answer {
    Answer {
        status,
        fault: Some(kind),
        body: detail.into().into_bytes(),
        cold: None,
        exec_micros: None,
        deadline_ms: None,
        replayed: false,
        trace_id: None,
        retry_after: None,
    }
}

/// §22.7. A `429` rather than a `503`: the cluster is fine, this caller is
/// simply ahead of its own budget, and telling it "service unavailable" would
/// point it at the wrong problem.
fn rate_limited(retry_after: std::time::Duration) -> Answer {
    Answer {
        retry_after: Some(retry_after.as_secs().max(1)),
        ..fault(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "tenant rate limit exceeded",
        )
    }
}

fn unauthorized() -> Answer {
    fault(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "missing or malformed bearer token",
    )
}

/// Reads [`PARTITION_HEADER`].
///
/// `Ok(None)` is absent. An over-long or non-ASCII key is an error rather than
/// a silent drop: a caller that sent one is expecting its state back, and
/// quietly routing it somewhere else would look like the state vanished.
#[allow(clippy::result_unit_err)]
fn partition_key_of(headers: &HeaderMap) -> Result<Option<String>, ()> {
    let Some(raw) = headers.get(PARTITION_HEADER) else {
        return Ok(None);
    };
    match raw.to_str() {
        Ok(key) if !key.trim().is_empty() && key.len() <= MAX_PARTITION_KEY_BYTES => {
            Ok(Some(key.trim().to_string()))
        }
        _ => Err(()),
    }
}

/// Reads `Idempotency-Key`.
///
/// `None` means absent — the request runs unkeyed. An over-long or non-ASCII
/// key is `Some(Err)`: a client that sent one meant to be protected, and
/// silently dropping the protection is the worst of the three options.
#[allow(clippy::result_unit_err)]
fn idempotency_key_of(headers: &HeaderMap) -> Option<Result<String, ()>> {
    let raw = headers.get(IDEMPOTENCY_HEADER)?;
    Some(match raw.to_str() {
        Ok(key) if !key.trim().is_empty() && key.len() <= idempotency::MAX_KEY_BYTES => {
            Ok(key.trim().to_string())
        }
        _ => Err(()),
    })
}

/// Reads [`DEADLINE_HEADER`], clamped to `[MIN_DEADLINE_MS, MAX_DEADLINE_MS]`.
///
/// A malformed value is a 400 rather than a silent fall back to the default.
/// Defaulting would hand a client asking for 5 s a 50 ms budget and then a
/// `timeout` fault, which is the most confusing failure this endpoint could
/// produce — and the one a tool-calling agent is least able to diagnose.
/// `None` means the header was present and unparseable — an absent header
/// yields the default, so the two cases never blur.
fn deadline_of(headers: &HeaderMap) -> Option<u32> {
    let Some(raw) = headers.get(DEADLINE_HEADER) else {
        return Some(DEFAULT_DEADLINE_MS);
    };
    raw.to_str()
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .map(|ms| ms.clamp(MIN_DEADLINE_MS, MAX_DEADLINE_MS))
}
