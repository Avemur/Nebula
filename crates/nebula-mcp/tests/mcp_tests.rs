//! MCP protocol and fault-translation tests (README.md §22.3).
//!
//! The gateway is a stub rather than a real cluster, for two reasons. It can
//! produce faults a real cluster will not produce on demand — `worker_shed`,
//! `cluster_at_capacity`, a dropped connection — and it can *assert what it was
//! sent*, which is where the integration risk actually lives: a wrong header
//! name or a wrong path would sail past a test that only checked the JSON.
//!
//! What that leaves uncovered is the gateway's own behaviour, which is the
//! subject of `nebula-worker/tests/gateway_tests.rs` and is not retested here.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use nebula_mcp::gateway::{Gateway, DEADLINE_HEADER, FAULT_HEADER, TRACEPARENT_HEADER};
use nebula_mcp::{Server, MAX_TIMEOUT_MS, PROTOCOL_VERSION, TOOL_NAME};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// A stub gateway that records what it was asked for
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct Seen {
    function_id: String,
    token: String,
    deadline_ms: String,
    traceparent: String,
    body: String,
}

/// What the stub should answer with: a status, an optional fault, and a body.
#[derive(Clone)]
struct Canned {
    status: StatusCode,
    fault: Option<&'static str>,
    body: &'static str,
}

#[derive(Clone)]
struct Stub {
    seen: Arc<Mutex<Vec<Seen>>>,
    canned: Arc<Mutex<Canned>>,
}

async fn stub_execute(
    State(stub): State<Stub>,
    Path(function_id): Path<String>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };

    stub.seen.lock().unwrap().push(Seen {
        function_id,
        token: header("authorization"),
        deadline_ms: header(DEADLINE_HEADER),
        traceparent: header(TRACEPARENT_HEADER),
        body,
    });

    let canned = stub.canned.lock().unwrap().clone();
    let mut out = HeaderMap::new();
    if let Some(fault) = canned.fault {
        out.insert(FAULT_HEADER, fault.parse().unwrap());
    }
    (canned.status, out, canned.body).into_response()
}

/// An MCP server wired to a stub gateway, both on ephemeral ports.
struct Harness {
    mcp: String,
    stub: Stub,
}

impl Harness {
    async fn start() -> Self {
        nebula_mcp::init_tracing_with_default("off");

        let stub = Stub {
            seen: Arc::new(Mutex::new(Vec::new())),
            canned: Arc::new(Mutex::new(Canned {
                status: StatusCode::OK,
                fault: None,
                body: "",
            })),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = listener.local_addr().unwrap().to_string();
        let router = Router::new()
            .route("/execute/{id}", post(stub_execute))
            .with_state(stub.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let server = Arc::new(Server::new(
            Gateway {
                address: gateway_addr,
                token: "tenant-a".to_string(),
            },
            "js",
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mcp = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _ = nebula_mcp::serve(listener, server).await;
        });

        Self { mcp, stub }
    }

    /// A gateway that is registered but has nothing listening.
    async fn unreachable() -> Self {
        let mut harness = Self::start().await;
        let server = Arc::new(Server::new(
            Gateway {
                // Port 1 on loopback: reserved, and reliably refuses.
                address: "127.0.0.1:1".to_string(),
                token: "tenant-a".to_string(),
            },
            "js",
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        harness.mcp = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _ = nebula_mcp::serve(listener, server).await;
        });
        harness
    }

    fn answer_with(&self, status: StatusCode, fault: Option<&'static str>, body: &'static str) {
        *self.stub.canned.lock().unwrap() = Canned {
            status,
            fault,
            body,
        };
    }

    fn last_seen(&self) -> Seen {
        self.stub
            .seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("the gateway was never called")
    }

    fn call_count(&self) -> usize {
        self.stub.seen.lock().unwrap().len()
    }

    /// One JSON-RPC round trip. Returns `(status, parsed body)`; the body is
    /// `Null` for the 202 that acknowledges a notification.
    async fn rpc(&self, request: Value) -> (u16, Value) {
        self.rpc_with(request, &[]).await
    }

    async fn rpc_with(&self, request: Value, extra: &[(&str, &str)]) -> (u16, Value) {
        let body = request.to_string();
        let raw = raw_post_with(&self.mcp, "/mcp", &body, extra).await;
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header terminator");
        let head = String::from_utf8_lossy(&raw[..split]).to_string();
        let status: u16 = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .expect("status line");

        let body = &raw[split + 4..];
        let parsed = serde_json::from_slice(body).unwrap_or(Value::Null);
        (status, parsed)
    }

    /// `tools/call` with the given arguments, returning the single text block
    /// and whether it was flagged as an error.
    async fn call(&self, arguments: Value) -> (String, bool) {
        let (_, response) = self
            .rpc(json!({
                "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": {"name": TOOL_NAME, "arguments": arguments}
            }))
            .await;

        let result = response
            .get("result")
            .unwrap_or_else(|| panic!("expected a result, got {response}"));
        let text = result["content"][0]["text"]
            .as_str()
            .expect("a text content block")
            .to_string();
        (text, result["isError"].as_bool().unwrap_or(false))
    }
}

async fn raw_post(addr: &str, path: &str, body: &str) -> Vec<u8> {
    raw_post_with(addr, path, body, &[]).await
}

async fn raw_post_with(addr: &str, path: &str, body: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut head = format!(
        "POST {path} HTTP/1.1\r\nHost: mcp\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in extra {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    raw
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_client_can_handshake_and_discover_the_tool() {
    let harness = Harness::start().await;

    let (_, response) = harness
        .rpc(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
        .await;
    assert_eq!(response["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert!(
        response["result"]["capabilities"]["tools"].is_object(),
        "a client that sees no tools capability will never call tools/list: {response}"
    );

    let (_, response) = harness
        .rpc(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .await;
    let tools = response["result"]["tools"]
        .as_array()
        .expect("a tools array");
    assert_eq!(tools.len(), 1, "§22.1 collapsed the surface to one tool");

    let tool = &tools[0];
    assert_eq!(tool["name"], TOOL_NAME);
    // The schema is what the model reads before it writes a call. If `source`
    // stops being required, every malformed call becomes a runtime error the
    // model has to discover by trying.
    assert_eq!(tool["inputSchema"]["required"][0], "source");
    assert_eq!(
        tool["inputSchema"]["properties"]["source"]["type"],
        "string"
    );
    assert_eq!(
        tool["inputSchema"]["properties"]["timeout_ms"]["maximum"],
        MAX_TIMEOUT_MS
    );
}

#[tokio::test]
async fn a_notification_is_acknowledged_without_a_reply() {
    let harness = Harness::start().await;

    // `notifications/initialized` has no id. Answering it at all is a protocol
    // violation, so the only correct response is an empty acknowledgement.
    let (status, body) = harness
        .rpc(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    assert_eq!(status, 202);
    assert_eq!(body, Value::Null, "a notification must not be answered");
}

#[tokio::test]
async fn protocol_level_mistakes_are_json_rpc_errors() {
    let harness = Harness::start().await;

    let (_, response) = harness
        .rpc(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/nope"}))
        .await;
    assert_eq!(response["error"]["code"], -32601);

    let (_, response) = harness
        .rpc(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "run_python", "arguments": {"source": "1"}}
        }))
        .await;
    assert_eq!(response["error"]["code"], -32602);

    let (_, response) = harness
        .rpc(json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": TOOL_NAME, "arguments": {"src": "1"}}
        }))
        .await;
    assert_eq!(
        response["error"]["code"], -32602,
        "a missing `source` is the client's mistake, not a failed script"
    );

    // Unparseable JSON cannot yield an id, so the spec's null-id form is the
    // only honest answer.
    let raw = raw_post(&harness.mcp, "/mcp", "{not json").await;
    let body = String::from_utf8_lossy(&raw);
    assert!(body.contains("-32700"), "expected a parse error: {body}");

    assert_eq!(
        harness.call_count(),
        0,
        "nothing malformed should have reached the cluster"
    );
}

// ---------------------------------------------------------------------------
// Translation to the gateway
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_tool_call_becomes_an_execute_request_for_the_interpreter() {
    let harness = Harness::start().await;
    harness.answer_with(StatusCode::OK, None, "6");

    let (text, is_error) = harness
        .call(json!({"source": "[1,2,3].reduce((a,b) => a+b)"}))
        .await;
    assert_eq!(text, "6");
    assert!(!is_error);

    let seen = harness.last_seen();
    assert_eq!(seen.function_id, "js");
    assert_eq!(seen.body, "[1,2,3].reduce((a,b) => a+b)");
    assert_eq!(seen.token, "Bearer tenant-a");
    assert_eq!(
        seen.deadline_ms, "1000",
        "an agent tool call needs the §11.1 deadline header, not the 50 ms default"
    );
}

#[tokio::test]
async fn a_requested_timeout_is_passed_through_and_clamped() {
    let harness = Harness::start().await;
    harness.answer_with(StatusCode::OK, None, "ok");

    harness
        .call(json!({"source": "1", "timeout_ms": 2500}))
        .await;
    assert_eq!(harness.last_seen().deadline_ms, "2500");

    // The schema says 5000 is the maximum, but a schema is a suggestion to a
    // model. Clamping here keeps the number in any error message equal to the
    // number that was actually applied.
    harness
        .call(json!({"source": "1", "timeout_ms": 999_999}))
        .await;
    assert_eq!(harness.last_seen().deadline_ms, MAX_TIMEOUT_MS.to_string());
}

#[tokio::test]
async fn a_silent_script_does_not_look_like_a_broken_tool() {
    let harness = Harness::start().await;
    harness.answer_with(StatusCode::OK, None, "");

    let (text, is_error) = harness.call(json!({"source": "let x = 1;"})).await;
    assert!(!is_error);
    assert!(
        !text.is_empty(),
        "an empty string reads to a model as a failure rather than a silent success"
    );
}

// ---------------------------------------------------------------------------
// Faults become something a model can act on
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_fault_is_explained_rather_than_passed_through_as_a_status_code() {
    let harness = Harness::start().await;

    // (fault, gateway status, a word the explanation must contain)
    let cases: &[(&'static str, StatusCode, &str)] = &[
        ("timeout", StatusCode::GATEWAY_TIMEOUT, "timeout_ms"),
        ("fuel_exhausted", StatusCode::GATEWAY_TIMEOUT, "budget"),
        (
            "memory_limit",
            StatusCode::INTERNAL_SERVER_ERROR,
            "smaller pieces",
        ),
        ("unknown_function", StatusCode::NOT_FOUND, "not deployed"),
        ("unauthorized", StatusCode::UNAUTHORIZED, "credentials"),
        (
            "worker_shed",
            StatusCode::SERVICE_UNAVAILABLE,
            "Retrying in a moment",
        ),
        (
            "worker_unreachable",
            StatusCode::BAD_GATEWAY,
            "may or may not have run",
        ),
    ];

    for (fault, status, expected) in cases {
        harness.answer_with(*status, Some(fault), "");
        let (text, is_error) = harness.call(json!({"source": "1"})).await;
        assert!(is_error, "`{fault}` must be flagged as an error");
        assert!(
            text.contains(expected),
            "`{fault}` must tell the model what to do; expected `{expected}` in: {text}"
        );
    }

    // The two that decide whether an agent should retry at all must never read
    // the same way. §10.2 is the reason: one request definitely did not run,
    // the other may have.
    harness.answer_with(StatusCode::SERVICE_UNAVAILABLE, Some("worker_shed"), "");
    let (shed, _) = harness.call(json!({"source": "1"})).await;
    harness.answer_with(StatusCode::BAD_GATEWAY, Some("worker_unreachable"), "");
    let (unreachable, _) = harness.call(json!({"source": "1"})).await;
    assert_ne!(shed, unreachable);
    assert!(shed.contains("Nothing ran"));
}

#[tokio::test]
async fn an_unrecognised_fault_still_names_itself() {
    let harness = Harness::start().await;
    // A fault this adapter has never heard of must not become a shrug. The
    // taxonomy will grow, and an MCP server one version behind should still
    // pass the name through rather than inventing a diagnosis.
    harness.answer_with(
        StatusCode::IM_A_TEAPOT,
        Some("something_new"),
        "detail here",
    );

    let (text, is_error) = harness.call(json!({"source": "1"})).await;
    assert!(is_error);
    assert!(text.contains("something_new"), "{text}");
    assert!(text.contains("detail here"), "{text}");
}

#[tokio::test]
async fn an_unreachable_cluster_is_a_tool_error_not_a_transport_error() {
    let harness = Harness::unreachable().await;

    // A JSON-RPC error would be handled by the client's plumbing and never
    // reach the model, which would then have no way to learn that calling the
    // tool again is pointless.
    let (text, is_error) = harness.call(json!({"source": "1"})).await;
    assert!(is_error);
    assert!(
        text.contains("did not run"),
        "the model must be told the script never ran: {text}"
    );
}

// ---------------------------------------------------------------------------
// The one coupling to the control plane
// ---------------------------------------------------------------------------

/// The header names are duplicated rather than imported, so that this crate
/// carries no production dependency on the control plane (§22.3). Duplication
/// without a check is just a bug with a delay on it.
#[test]
fn the_header_names_still_match_the_gateways() {
    assert_eq!(FAULT_HEADER, nebula_control::gateway::FAULT_HEADER);
    assert_eq!(DEADLINE_HEADER, nebula_control::gateway::DEADLINE_HEADER);
    assert_eq!(
        TRACEPARENT_HEADER,
        nebula_control::trace::TRACEPARENT_HEADER
    );
}

// ---------------------------------------------------------------------------
// Trace context (§22.6)
// ---------------------------------------------------------------------------

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

#[tokio::test]
async fn an_agents_trace_is_carried_into_the_sandbox_call() {
    let harness = Harness::start().await;
    harness.answer_with(StatusCode::OK, None, "ok");

    // Without this the tool call is an unexplained gap in the agent's trace,
    // which is the exact complaint §22.6 opens with.
    harness
        .rpc_with(
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": TOOL_NAME, "arguments": {"source": "1"}}
            }),
            &[("traceparent", TRACEPARENT)],
        )
        .await;

    assert_eq!(harness.last_seen().traceparent, TRACEPARENT);
}

#[tokio::test]
async fn an_untraced_call_forwards_nothing_and_a_dangerous_one_is_dropped() {
    let harness = Harness::start().await;
    harness.answer_with(StatusCode::OK, None, "ok");

    harness.call(json!({"source": "1"})).await;
    assert_eq!(
        harness.last_seen().traceparent,
        "",
        "nothing to forward means forward nothing; the gateway mints an id"
    );

    // A forwarded header is attacker-influenced text going into a request this
    // server writes by hand. A CR in it would be a second header, so anything
    // that is not the shape of a traceparent never reaches the wire.
    harness
        .rpc_with(
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": TOOL_NAME, "arguments": {"source": "1"}}
            }),
            &[("traceparent", "00-abc-def-01 evil")],
        )
        .await;
    assert_eq!(harness.last_seen().traceparent, "");
}
