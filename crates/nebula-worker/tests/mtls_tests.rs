//! Mutual TLS on the internal mesh (README.md §13).
//!
//! The claim under test is narrow and is the only one that matters: **a client
//! without a mesh certificate cannot call `Execute`.** Everything §22 isolates
//! keys on the `tenant` field of that request, and the worker trusts it, so an
//! open gRPC port makes the HMAC on the gateway decorative.
//!
//! Certificates are generated per run rather than checked in. They expire, and
//! a private key in a repository is a private key in a repository even when it
//! is only for tests.

use std::sync::Arc;

use nebula_proto::nebula_worker_client::NebulaWorkerClient;
use nebula_proto::nebula_worker_server::NebulaWorkerServer;
use nebula_proto::tls::{MeshTls, MESH_NAME};
use nebula_proto::ExecuteRequest;
use nebula_runtime::Runtime;
use nebula_worker::exec_pool::ExecPool;
use nebula_worker::server::WorkerService;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint, Server};

const ECHO: &str = r#"
    (module
      (import "nebula" "request_len" (func $len (result i32)))
      (import "nebula" "request_read" (func $read (param i32 i32) (result i32)))
      (import "nebula" "response_write" (func $write (param i32 i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "run")
        (local $n i32)
        (local.set $n (call $len))
        (drop (call $read (i32.const 0) (local.get $n)))
        (drop (call $write (i32.const 0) (local.get $n)))))
    "#;

/// A throwaway CA plus one node certificate signed by it.
///
/// Returns `(ca_pem, cert_pem, key_pem)`.
fn issue(name: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(vec![name.to_string()]).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("ca");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let node_key = rcgen::KeyPair::generate().expect("node key");
    let node_params = rcgen::CertificateParams::new(vec![name.to_string()]).expect("node params");
    let node = node_params.signed_by(&node_key, &issuer).expect("node");

    (
        ca.pem().into_bytes(),
        node.pem().into_bytes(),
        node_key.serialize_pem().into_bytes(),
    )
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "nebula-mtls-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// A worker serving on loopback, with mesh TLS required.
async fn worker(tls: &MeshTls) -> String {
    let runtime = Arc::new(Runtime::new(temp_dir("l2")).expect("runtime"));
    let pool = Arc::new(ExecPool::new(runtime.clone(), 2, 4));
    // No control plane: these tests never fetch, they deploy by hash locally.
    let service = WorkerService::new(runtime, pool, "http://127.0.0.1:1").expect("service");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = tls.server();
    tokio::spawn(async move {
        let _ = Server::builder()
            .tls_config(server)
            .expect("server tls")
            .add_service(NebulaWorkerServer::new(service))
            .serve_with_incoming(TcpIncoming::from(listener))
            .await;
    });
    address
}

fn request() -> ExecuteRequest {
    ExecuteRequest {
        function_id: "echo".to_string(),
        content_hash: "0".repeat(64),
        body: b"hello".to_vec(),
        request_id: "mtls".to_string(),
        deadline_ms: 1_000,
        partition_key: None,
        tenant: "acme".to_string(),
    }
}

async fn channel(address: &str, tls: Option<&MeshTls>) -> Result<Channel, tonic::transport::Error> {
    let endpoint =
        Endpoint::from_shared(nebula_proto::tls::endpoint(address, tls.is_some())).expect("uri");
    match tls {
        Some(tls) => endpoint.tls_config(tls.client())?.connect().await,
        None => endpoint.connect().await,
    }
}

/// Connects *and* calls `Execute`, returning the outcome or nothing.
///
/// Connecting is not admission: a plaintext client opens a TCP socket to a TLS
/// port perfectly happily, and some stacks complete a handshake and only fail
/// at the first request. Asserting on a connection alone would pass while the
/// port was wide open.
async fn served(address: &str, tls: Option<&MeshTls>) -> Result<i32, ()> {
    let channel = channel(address, tls).await.map_err(|_| ())?;
    NebulaWorkerClient::new(channel)
        .execute(request())
        .await
        .map(|response| response.into_inner().outcome)
        .map_err(|_| ())
}

/// What a served request answers here.
///
/// These workers have no control plane to fetch from, so the artifact lookup
/// fails at the transport and §12 maps that to `INTERNAL`. The value is not the
/// point; reaching the guest path at all is.
fn reached_the_guest_path(outcome: i32) -> bool {
    outcome == nebula_proto::Outcome::Internal as i32
        || outcome == nebula_proto::Outcome::ModuleNotFound as i32
}

#[tokio::test]
async fn a_client_holding_a_mesh_certificate_is_served() {
    let (ca, cert, key) = issue(MESH_NAME);
    let tls = MeshTls::from_pem(ca, cert, key);
    let address = worker(&tls).await;

    let outcome = served(&address, Some(&tls))
        .await
        .expect("a mesh member should be served");
    assert!(reached_the_guest_path(outcome), "outcome {outcome}");
    let _ = ECHO;
}

#[tokio::test]
async fn a_client_without_a_certificate_cannot_call_execute() {
    let (ca, cert, key) = issue(MESH_NAME);
    let tls = MeshTls::from_pem(ca, cert, key);
    let address = worker(&tls).await;

    // Plaintext against a TLS port. This is the attacker who can route a packet
    // to a worker and would otherwise set `tenant` to anything they liked.
    assert!(
        served(&address, None).await.is_err(),
        "a plaintext client was served by a mutual-TLS worker"
    );
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_refused() {
    let (mesh_ca, cert, key) = issue(MESH_NAME);
    let mesh = MeshTls::from_pem(mesh_ca.clone(), cert, key);
    let address = worker(&mesh).await;

    // A well-formed certificate for the right name, signed by the wrong CA,
    // presented by a client that *does* trust the mesh CA.
    //
    // That combination is what isolates the check under test. An outsider that
    // also distrusted the server would be turned away by its own verification,
    // and this test would pass without the worker ever having looked at the
    // client certificate. Trusting the server puts the whole burden on
    // `client_ca_root`, which is the one line separating a port that is
    // encrypted from a port that is authenticated.
    let (_, other_cert, other_key) = issue(MESH_NAME);
    let outsider = MeshTls::from_pem(mesh_ca.clone(), other_cert, other_key);

    assert!(
        served(&address, Some(&outsider)).await.is_err(),
        "a foreign certificate was admitted"
    );
}

#[tokio::test]
async fn the_mesh_still_works_without_tls_configured() {
    // The documented default (§13). Turning this off must not be the only way
    // to run the thing, or nobody will run it.
    let runtime = Arc::new(Runtime::new(temp_dir("plain")).expect("runtime"));
    let pool = Arc::new(ExecPool::new(runtime.clone(), 2, 4));
    let service = WorkerService::new(runtime, pool, "http://127.0.0.1:1").expect("service");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(NebulaWorkerServer::new(service))
            .serve_with_incoming(TcpIncoming::from(listener))
            .await;
    });

    let outcome = served(&address, None).await.expect("plaintext is served");
    assert!(reached_the_guest_path(outcome), "outcome {outcome}");
}
