//! Model Context Protocol server (README.md §22.3).
//!
//! The adapter that turns Nebula from "an HTTP API an agent could be taught to
//! call" into "a tool server any MCP client already knows how to call". It owns
//! no execution and no routing: every method maps onto something §11.1 already
//! does, and the whole crate is a translation layer.
//!
//! | MCP method | Nebula |
//! |---|---|
//! | `initialize` | static capability advertisement |
//! | `tools/list` | the descriptor below |
//! | `tools/call` | `POST /execute/{id}`, script as the body |
//!
//! # Why one tool and not one per function
//!
//! §22.2 scoped a per-function descriptor so `tools/list` would have something
//! to return. §22.1 then landed the interpreter guest, and the agent-facing
//! surface collapsed to a single tool: an agent does not deploy a module per
//! snippet, it sends source. The per-function story is still wanted for
//! purpose-built wasm tools, and it is still §22.2 — it is just no longer on
//! the path to a working MCP server.
//!
//! # Transport
//!
//! Streamable HTTP, `POST /mcp`, JSON responses. The spec permits answering
//! with `application/json` instead of an SSE stream, and without streaming
//! results (§22.9 item 9) there is nothing to stream.
//!
//! ponytail: no session ids, no SSE, no batching. Batching was removed from the
//! protocol in the 2025-06-18 revision, so its absence is compliance rather
//! than a shortcut. Sessions become worth having when §22.5 lands.

pub mod gateway;

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::gateway::Gateway;

/// The revision this server implements.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

pub const TOOL_NAME: &str = "run_javascript";

/// Deadline defaults for a *tool* call, not a web request.
///
/// §11.1's 50 ms default suits a handler and starves an agent asking a sandbox
/// to do real work, so this adapter asks for a second by default. The ceiling
/// is the gateway's own `MAX_DEADLINE_MS`; asking for more is clamped there and
/// the effective value comes back on the response.
pub const DEFAULT_TIMEOUT_MS: u32 = 1_000;
pub const MAX_TIMEOUT_MS: u32 = 5_000;

/// What the MCP client is told it can call.
pub struct Server {
    gateway: Gateway,
    /// The `function_id` the JavaScript interpreter of §22.1 is deployed under.
    function_id: String,
}

impl Server {
    pub fn new(gateway: Gateway, function_id: impl Into<String>) -> Self {
        Self {
            gateway,
            function_id: function_id.into(),
        }
    }

    fn descriptor(&self) -> Value {
        json!({
            "name": TOOL_NAME,
            "description":
                "Run JavaScript in an isolated WebAssembly sandbox and return what it \
                 printed. The script has no filesystem, no network, and no access to \
                 anything outside itself. `console.log` output is returned, followed by \
                 the value of the final expression when it is not undefined. Objects are \
                 rendered as JSON. State does not persist between calls.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "description": "JavaScript source to evaluate."
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": format!(
                            "Milliseconds the script may run for. Defaults to \
                             {DEFAULT_TIMEOUT_MS}, capped at {MAX_TIMEOUT_MS}."
                        ),
                        "minimum": 10,
                        "maximum": MAX_TIMEOUT_MS
                    }
                },
                "required": ["source"]
            }
        })
    }
}

pub fn router(server: Arc<Server>) -> Router {
    Router::new().route("/mcp", post(handle)).with_state(server)
}

pub async fn serve(listener: tokio::net::TcpListener, server: Arc<Server>) -> std::io::Result<()> {
    axum::serve(listener, router(server)).await
}

// ---------------------------------------------------------------------------
// JSON-RPC
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Rpc {
    /// Absent means notification: acknowledge, answer nothing.
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

const PARSE_ERROR: i32 = -32700;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;

fn result(id: Value, result: Value) -> Response {
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

fn error(id: Value, code: i32, message: impl Into<String>) -> Response {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message.into()}
    }))
    .into_response()
}

/// A tool result, which is a *success* at the protocol layer even when
/// `isError` is set.
///
/// This is §11.2's rule one level further out. There, a guest trap is an
/// `Outcome` inside a successful RPC rather than a gRPC status, because a
/// tenant's infinite loop is not a transport failure. Here, a script that threw
/// is content the model can read and correct — a JSON-RPC error would be
/// handled by the client's plumbing and never reach the model at all.
fn tool_result(id: Value, text: String, is_error: bool) -> Response {
    result(
        id,
        json!({
            "content": [{"type": "text", "text": text}],
            "isError": is_error
        }),
    )
}

async fn handle(State(server): State<Arc<Server>>, headers: HeaderMap, body: String) -> Response {
    // Forwarded so the sandbox call lands inside the agent's own trace rather
    // than as an unexplained gap in it (§22.6).
    let traceparent = headers
        .get(crate::gateway::TRACEPARENT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let Ok(rpc) = serde_json::from_str::<Rpc>(&body) else {
        // No id could be parsed, so the spec's null-id form is the only honest
        // answer.
        return error(Value::Null, PARSE_ERROR, "request is not valid JSON-RPC");
    };

    let Some(id) = rpc.id else {
        // A notification — `notifications/initialized` is the one that matters.
        // Nothing to say, and saying it anyway would be a protocol violation.
        return StatusCode::ACCEPTED.into_response();
    };

    match rpc.method.as_str() {
        "initialize" => result(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "nebula", "version": env!("CARGO_PKG_VERSION")}
            }),
        ),
        "ping" => result(id, json!({})),
        "tools/list" => result(id, json!({"tools": [server.descriptor()]})),
        "tools/call" => call_tool(&server, id, rpc.params, traceparent.as_deref()).await,
        other => error(id, METHOD_NOT_FOUND, format!("unknown method `{other}`")),
    }
}

async fn call_tool(
    server: &Server,
    id: Value,
    params: Value,
    traceparent: Option<&str>,
) -> Response {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if name != TOOL_NAME {
        return error(id, INVALID_PARAMS, format!("unknown tool `{name}`"));
    }

    let arguments = params.get("arguments").unwrap_or(&Value::Null);
    let Some(source) = arguments.get("source").and_then(Value::as_str) else {
        return error(
            id,
            INVALID_PARAMS,
            "`source` is required and must be a string",
        );
    };

    // Clamped here as well as at the gateway. Not defensive duplication: a
    // schema the model sees is a suggestion, and clamping before the call keeps
    // the number in the error message the same as the number that was applied.
    let timeout_ms = arguments
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .map(|ms| (ms as u32).clamp(10, MAX_TIMEOUT_MS))
        .unwrap_or(DEFAULT_TIMEOUT_MS);

    let span = tracing::info_span!("tools/call", tool = TOOL_NAME, timeout_ms);
    let _entered = span.enter();

    let reply = match server
        .gateway
        .execute(
            &server.function_id,
            timeout_ms,
            traceparent,
            source.as_bytes(),
        )
        .await
    {
        Ok(reply) => reply,
        Err(err) => {
            // The cluster is unreachable from here, which is this server's
            // problem rather than the script's. Still a tool result: the model
            // can decide to stop calling the tool, which a transport error
            // would never let it do.
            tracing::warn!(%err, "gateway unreachable");
            return tool_result(
                id,
                format!(
                    "Nebula is unreachable from this MCP server: {err}. The script did not run."
                ),
                true,
            );
        }
    };

    if reply.status == 200 {
        let text = reply.text();
        // A script whose output is empty said nothing, and "" reads to a model
        // as a broken tool rather than as a silent success.
        let text = if text.is_empty() {
            "(the script produced no output)".to_string()
        } else {
            text
        };
        return tool_result(id, text, false);
    }

    tracing::info!(
        status = reply.status,
        fault = reply.fault_or_unknown(),
        "tool call failed"
    );
    tool_result(id, explain(&reply, timeout_ms, &server.function_id), true)
}

/// Turns `X-Nebula-Fault` into something a model can act on.
///
/// This is the whole reason the header exists (§11.1). An agent that reads
/// `timeout` can shorten its work; one that reads `memory_limit` can process
/// less at a time; one that reads a bare `500` can only retry forever or give
/// up. The distinction that matters most is *retryable or not*, and the wording
/// says so in each case rather than leaving the model to guess.
fn explain(reply: &crate::gateway::Reply, timeout_ms: u32, function_id: &str) -> String {
    let detail = reply.text();
    match reply.fault_or_unknown() {
        "timeout" | "fuel_exhausted" => format!(
            "The script ran longer than its {timeout_ms} ms budget and was stopped. \
             Do less work, or pass a larger `timeout_ms` (up to {MAX_TIMEOUT_MS})."
        ),
        "memory_limit" => "The script exceeded the sandbox's memory ceiling and was stopped. \
             Process the data in smaller pieces."
            .to_string(),
        "trap" => format!(
            "The sandbox aborted the script: {detail}. This is a fault in the \
             interpreter rather than an ordinary exception — an uncaught JavaScript \
             error would have come back as normal output."
        ),
        "unknown_function" | "module_not_found" => format!(
            "The JavaScript interpreter is not deployed on this Nebula cluster under \
             `{function_id}`. This is a configuration problem on the server side; \
             retrying will not help."
        ),
        "unauthorized" => "This MCP server's credentials were rejected by Nebula. This is a \
             configuration problem on the server side; retrying will not help."
            .to_string(),
        // §10.2: the request was dispatched and then the connection failed, so
        // whether it ran is genuinely unknown. Saying so is the only honest
        // answer, and it is the one an agent needs before it retries.
        "worker_unreachable" => "The connection to the sandbox dropped after the script was sent. \
             It may or may not have run. Retry only if running it twice is safe."
            .to_string(),
        // §22.7. The one fault whose cause is the agent's own behaviour rather
        // than its code, so it is the one where "retry in a moment" and "retry
        // immediately" are opposite instructions.
        "rate_limited" => format!(
            "This tool is being called faster than its rate limit allows. Nothing ran.              Wait {} before calling it again, and avoid retrying in a tight loop.",
            match reply.retry_after {
                Some(1) => "a second".to_string(),
                Some(seconds) => format!("{seconds} seconds"),
                None => "a moment".to_string(),
            }
        ),
        "no_healthy_worker" | "no_reachable_worker" | "cluster_at_capacity" | "worker_shed" => {
            "Nebula has no capacity to run the script right now. Nothing ran. \
             Retrying in a moment is reasonable."
                .to_string()
        }
        other => format!(
            "Nebula refused the call ({other}, HTTP {}){}",
            reply.status,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        ),
    }
}

/// Structured span output on stdout (§14). Idempotent; tests may call it.
pub fn init_tracing_with_default(default: &str) {
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::EnvFilter;

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("NEBULA_LOG").unwrap_or_else(|_| EnvFilter::new(default)),
        )
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .try_init();
}
