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

use crate::membership::Membership;
use crate::registry::{Deployments, Registry, MAX_ARTIFACT_BYTES};
use crate::wizer;

/// §6.4 caps a request body at 1 MiB.
pub const MAX_REQUEST_BYTES: usize = 1 << 20;

/// Bound on a caller-supplied function id. It is a map key and a ring key, not
/// a path, but an unbounded one is still a free allocation for anyone asking.
pub const MAX_FUNCTION_ID_BYTES: usize = 128;

/// The worker's per-request budget, sent so the worker can size its own
/// deadline. §6.4's default.
const DEADLINE_MS: u32 = 50;

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
}

/// The result of a successful deploy.
#[derive(Debug, Clone)]
pub struct Published {
    pub content_hash: String,
    /// Whether Wizer pre-initialized the artifact (§4.3).
    pub wizened: bool,
}

#[derive(Debug)]
pub enum PublishError {
    InvalidId,
    /// The caller's module failed its own initializer. A 400.
    Wizer(String),
    Io(std::io::Error),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidId => f.write_str("function id must be 1..=128 bytes"),
            Self::Wizer(detail) => write!(f, "pre-initialization failed: {detail}"),
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
        })
    }

    pub fn content_hash_of(&self, function_id: &str) -> Option<String> {
        self.functions
            .lock()
            .unwrap()
            .functions
            .get(function_id)
            .cloned()
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
        let mut functions = self.functions.lock().unwrap();
        functions
            .functions
            .insert(function_id.to_string(), content_hash.clone());

        // Persisted before the caller is told the deployment succeeded. The lock
        // is held across the write so the file can never disagree with the map;
        // deploys are rare, so serialising them costs nothing that matters.
        self.registry
            .save_deployments(&functions)
            .map_err(PublishError::Io)?;

        Ok(Published {
            content_hash,
            wizened,
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
    async fn dispatch(&self, address: &str, request: ExecuteRequest) -> Attempt {
        let span = tracing::Span::current();
        let Some(mut client) = self.client(address).await else {
            span.record("outcome", "not_sent");
            return Attempt::NotSent;
        };
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
        .with_state(state)
}

/// v1 authentication: the bearer token *is* the tenant id (§13). Enough to prove
/// the authorization path exists; not a credential system.
fn tenant_of(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    (!token.is_empty()).then(|| token.to_string())
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
    if tenant_of(&headers).is_none() {
        return unauthorized();
    }
    match gateway.publish(&function_id, &body).await {
        Ok(published) => (
            StatusCode::CREATED,
            [(header::CONTENT_TYPE, "application/json")],
            // Hand-built rather than a serde dependency for two fields. The hash
            // is hex and the flag is a bool, so there is nothing here to escape.
            format!(
                "{{\"content_hash\":\"{}\",\"wizened\":{}}}",
                published.content_hash, published.wizened
            ),
        )
            .into_response(),
        // A module whose own initializer fails is a bad artifact, and the caller
        // is the only one who can fix it.
        Err(err @ (PublishError::Wizer(_) | PublishError::InvalidId)) => {
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
        Err(PublishError::Io(err)) => {
            tracing::error!("deploy of {function_id} failed: {err}");
            (StatusCode::INTERNAL_SERVER_ERROR, "deploy failed").into_response()
        }
    }
}

#[tracing::instrument(
    name = "request_received",
    skip_all,
    fields(function_id = %function_id, bytes = body.len(), tenant = tracing::field::Empty)
)]
async fn execute(
    State(gateway): State<Arc<Gateway>>,
    Path(function_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(tenant) = tenant_of(&headers) else {
        return unauthorized();
    };
    tracing::Span::current().record("tenant", tenant.as_str());

    let Some(content_hash) = gateway.content_hash_of(&function_id) else {
        return (StatusCode::NOT_FOUND, "unknown function").into_response();
    };

    // Bounded-load ordering (§9.2): the ring's owner leads unless it is above
    // 1.25x mean cluster load, in which case the walk starts at the next node.
    // The rest of the plan stays in ring order, so failover is unchanged.
    let plan = gateway.membership.route_plan(&function_id);
    if plan.is_empty() {
        return retry_later(StatusCode::SERVICE_UNAVAILABLE, "no healthy worker");
    }

    let request = ExecuteRequest {
        function_id: function_id.clone(),
        content_hash,
        body: body.to_vec(),
        request_id: format!("{function_id}-{}", plan.len()),
        deadline_ms: DEADLINE_MS,
        partition_key: None,
        tenant,
    };

    // §10.2: at most one retry, and only when the first attempt was never sent.
    let mut last_status = None;
    for (index, (_node, address)) in plan.iter().take(2).enumerate() {
        match gateway.dispatch(address, request.clone()).await {
            Attempt::Answered(response) => return to_http(response),
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
        Some(status) if status.code() == Code::ResourceExhausted => {
            retry_later(StatusCode::SERVICE_UNAVAILABLE, "cluster at capacity")
        }
        Some(status) => from_status(&status),
        // Every candidate refused the connection: nothing ran anywhere.
        None => retry_later(StatusCode::SERVICE_UNAVAILABLE, "no reachable worker"),
    }
}

fn to_http(response: ExecuteResponse) -> Response {
    let outcome = Outcome::try_from(response.outcome).unwrap_or(Outcome::Internal);

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-nebula-cold",
        HeaderValue::from_static(if response.cold { "true" } else { "false" }),
    );
    if let Ok(value) = HeaderValue::from_str(&response.exec_micros.to_string()) {
        headers.insert("x-nebula-exec-micros", value);
    }

    // §12. Guest fault detail goes back to the caller — it is their code. The
    // `Internal` arm carries none, because the worker withheld it deliberately.
    let (status, fault) = match outcome {
        Outcome::Ok => {
            return (StatusCode::OK, headers, response.body).into_response();
        }
        Outcome::Trap => (StatusCode::INTERNAL_SERVER_ERROR, "trap"),
        Outcome::Timeout => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
        Outcome::FuelExhausted => (StatusCode::GATEWAY_TIMEOUT, "fuel_exhausted"),
        Outcome::MemoryLimit => (StatusCode::INTERNAL_SERVER_ERROR, "memory_limit"),
        Outcome::ModuleNotFound => (StatusCode::NOT_FOUND, "module_not_found"),
        Outcome::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };

    headers.insert("x-nebula-fault", HeaderValue::from_static(fault));
    (status, headers, response.fault_detail).into_response()
}

fn from_status(status: &tonic::Status) -> Response {
    match status.code() {
        Code::ResourceExhausted => retry_later(StatusCode::SERVICE_UNAVAILABLE, "worker shed"),
        Code::InvalidArgument => {
            (StatusCode::BAD_REQUEST, status.message().to_string()).into_response()
        }
        // The request reached a worker and then the connection failed. It may
        // have executed, so this is reported, not retried (§10.2).
        Code::Unavailable | Code::Cancelled | Code::DeadlineExceeded => (
            StatusCode::BAD_GATEWAY,
            "worker became unreachable mid-request",
        )
            .into_response(),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "dispatch failed").into_response(),
    }
}

fn retry_later(status: StatusCode, message: &'static str) -> Response {
    (status, [("retry-after", "1")], message).into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        "missing or malformed bearer token",
    )
        .into_response()
}
