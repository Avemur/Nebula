//! Mutual TLS for the internal mesh (README.md §13).
//!
//! §13 assumed a trusted network and said so. That assumption is the last thing
//! standing between the HMAC on the gateway and an attacker who can route a
//! packet to a worker: `Execute` carries a `tenant` field the worker trusts,
//! and an unauthenticated gRPC port lets anyone set it to anything. Every
//! isolation guarantee in §22 keys on that field.
//!
//! ```text
//! NEBULA_TLS_CA=ca.pem NEBULA_TLS_CERT=node.pem NEBULA_TLS_KEY=node.key
//! ```
//!
//! All three, or none. A half-configured mesh is the failure mode worth
//! designing out: a worker that presents a certificate and does not demand one
//! is a worker with encryption and no authentication, which reads as secure and
//! is not.
//!
//! # Nodes are identified by their certificate, not by their address
//!
//! Every node presents a certificate for the same name, and clients verify
//! against that name rather than against the address they dialled. That is
//! deliberate. A mesh member is whoever holds a key signed by the mesh CA;
//! binding identity to a hostname would mean reissuing certificates when a
//! worker moves, and would make the ring's addresses part of the trust model.
//! Issuing a certificate is the act that admits a node.
//!
//! ponytail: one CA, one name, no revocation, no rotation story beyond
//! reissuing and restarting. A CRL needs somewhere to publish it and something
//! to poll it, which is infrastructure rather than a question. Short-lived
//! certificates are the answer when this stops being enough.

use std::path::PathBuf;

use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

/// The name every mesh certificate is issued for, and the name every client
/// verifies against.
pub const MESH_NAME: &str = "nebula-mesh";

pub const CA_ENV: &str = "NEBULA_TLS_CA";
pub const CERT_ENV: &str = "NEBULA_TLS_CERT";
pub const KEY_ENV: &str = "NEBULA_TLS_KEY";

/// PEM material for one node, or nothing.
#[derive(Clone)]
pub struct MeshTls {
    ca: Vec<u8>,
    cert: Vec<u8>,
    key: Vec<u8>,
}

#[derive(Debug)]
pub enum TlsError {
    /// Some of the three variables were set and some were not.
    Partial(&'static str),
    Io(PathBuf, std::io::Error),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Partial(missing) => write!(
                f,
                "mesh TLS is half configured: {missing} is not set. Set {CA_ENV}, \
                 {CERT_ENV} and {KEY_ENV} together, or none of them"
            ),
            Self::Io(path, err) => write!(f, "reading {}: {err}", path.display()),
        }
    }
}

impl std::error::Error for TlsError {}

impl MeshTls {
    /// Reads the three environment variables.
    ///
    /// `Ok(None)` means none were set, which leaves the mesh in the plaintext
    /// mode §13 documented. Setting some but not all is an error rather than a
    /// silent downgrade: the operator who set two of three meant to set three.
    pub fn from_env() -> Result<Option<Self>, TlsError> {
        let Some(paths) = mesh_paths(
            std::env::var_os(CA_ENV),
            std::env::var_os(CERT_ENV),
            std::env::var_os(KEY_ENV),
        )?
        else {
            return Ok(None);
        };

        let read = |value: std::ffi::OsString| {
            let path = PathBuf::from(value);
            std::fs::read(&path).map_err(|err| TlsError::Io(path, err))
        };
        Ok(Some(Self {
            ca: read(paths.0)?,
            cert: read(paths.1)?,
            key: read(paths.2)?,
        }))
    }

    /// PEM bytes directly, for tests and for callers with their own loader.
    pub fn from_pem(ca: Vec<u8>, cert: Vec<u8>, key: Vec<u8>) -> Self {
        Self { ca, cert, key }
    }

    /// Server side: present this node's certificate, and **require** one back.
    ///
    /// `client_ca_root` is what makes this mutual. Without it the port is
    /// encrypted and open, which is the shape of security rather than security.
    pub fn server(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(&self.cert, &self.key))
            .client_ca_root(Certificate::from_pem(&self.ca))
    }

    /// Client side: present this node's certificate, and verify the peer
    /// against the mesh CA rather than against the address dialled.
    pub fn client(&self) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&self.ca))
            .identity(Identity::from_pem(&self.cert, &self.key))
            .domain_name(MESH_NAME)
    }
}

/// All three paths, or none.
///
/// Separated from [`MeshTls::from_env`] so it can be tested without mutating
/// process-wide environment state from a test running in parallel with others.
type MeshPaths = (std::ffi::OsString, std::ffi::OsString, std::ffi::OsString);

fn mesh_paths(
    ca: Option<std::ffi::OsString>,
    cert: Option<std::ffi::OsString>,
    key: Option<std::ffi::OsString>,
) -> Result<Option<MeshPaths>, TlsError> {
    match (ca, cert, key) {
        (None, None, None) => Ok(None),
        (Some(ca), Some(cert), Some(key)) => Ok(Some((ca, cert, key))),
        (None, _, _) => Err(TlsError::Partial(CA_ENV)),
        (_, None, _) => Err(TlsError::Partial(CERT_ENV)),
        (_, _, None) => Err(TlsError::Partial(KEY_ENV)),
    }
}

/// `https://` when the mesh is encrypted, `http://` when it is not.
///
/// Centralised because getting it wrong fails at connect time with a message
/// about the scheme rather than about TLS, which is a confusing way to find out
/// that half the cluster is configured differently from the other half.
pub fn endpoint(address: &str, tls: bool) -> String {
    let scheme = if tls { "https" } else { "http" };
    match address.split_once("://") {
        Some((_, rest)) => format!("{scheme}://{rest}"),
        None => format!("{scheme}://{address}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_endpoint_takes_the_scheme_the_mesh_is_using() {
        assert_eq!(endpoint("127.0.0.1:7001", false), "http://127.0.0.1:7001");
        assert_eq!(endpoint("127.0.0.1:7001", true), "https://127.0.0.1:7001");

        // An address that already carries a scheme is rewritten rather than
        // doubled: the control plane URL arrives from configuration and will
        // have one.
        assert_eq!(
            endpoint("http://control:7000", true),
            "https://control:7000"
        );
        assert_eq!(
            endpoint("https://control:7000", false),
            "http://control:7000"
        );
    }

    /// Setting two of the three variables must not quietly leave the mesh in
    /// plaintext. That is the mistake this whole module exists to prevent, and
    /// it is the one an operator is most likely to make.
    #[test]
    fn a_half_configured_mesh_is_an_error_not_a_downgrade() {
        let path = |value: &str| Some(std::ffi::OsString::from(value));

        for (ca, cert, key, missing) in [
            (None, path("c"), path("k"), CA_ENV),
            (path("a"), None, path("k"), CERT_ENV),
            (path("a"), path("c"), None, KEY_ENV),
        ] {
            match mesh_paths(ca, cert, key) {
                Err(TlsError::Partial(named)) => assert_eq!(named, missing),
                _ => panic!("{missing} missing should have been refused"),
            }
        }

        // All three, or none. Both are configurations somebody meant.
        assert!(mesh_paths(None, None, None)
            .expect("none is fine")
            .is_none());
        assert!(mesh_paths(path("a"), path("c"), path("k"))
            .expect("all three is fine")
            .is_some());
    }

    #[test]
    fn a_generated_mesh_certificate_builds_both_configs() {
        let (ca, cert, key) = super::test_certs::issue();
        let tls = MeshTls::from_pem(ca, cert, key);

        // Cheap, and it catches the failure that is otherwise only visible as a
        // handshake error at runtime: PEM that parses as a file but not as a
        // certificate.
        let _ = tls.server();
        let _ = tls.client();
    }
}

/// Issues a throwaway mesh CA and node certificate.
///
/// Test-only and compiled out otherwise. Certificates cannot be checked in: they
/// expire, and a private key in a repository is a private key in a repository
/// even when it is only for tests.
#[cfg(test)]
pub(crate) mod test_certs {
    use super::MESH_NAME;

    /// Returns `(ca_pem, cert_pem, key_pem)`.
    pub fn issue() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let mut ca_params =
            rcgen::CertificateParams::new(vec![MESH_NAME.to_string()]).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_params_for_issuer = ca_params.clone();
        let ca = ca_params.self_signed(&ca_key).expect("ca");
        let issuer = rcgen::Issuer::new(ca_params_for_issuer, ca_key);

        let node_key = rcgen::KeyPair::generate().expect("node key");
        let node_params =
            rcgen::CertificateParams::new(vec![MESH_NAME.to_string()]).expect("node params");
        let node = node_params
            .signed_by(&node_key, &issuer)
            .expect("node cert");

        (
            ca.pem().into_bytes(),
            node.pem().into_bytes(),
            node_key.serialize_pem().into_bytes(),
        )
    }
}
