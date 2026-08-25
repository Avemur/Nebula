//! Generated gRPC contracts for Nebula (README.md §11.2).
//!
//! Almost nothing is hand-written here. The source of truth is
//! `proto/nebula.proto`, and this crate exists so codegen and `protoc` are a
//! dependency of one crate rather than of every crate that speaks gRPC.
//!
//! The exception is [`tls`], which configures the transport the generated
//! clients and servers run on. It lives here because both halves of the mesh
//! need identical settings and a mesh whose two sides disagree about TLS is a
//! mesh that fails at connect time with a message about a URL scheme.

pub mod tls;

tonic::include_proto!("nebula.v1");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_discriminants_are_pinned() {
        // These are wire values, not an internal enum. Renumbering one silently
        // re-labels every response already in flight, and the failure looks
        // like a worker returning nonsense rather than like a schema change.
        assert_eq!(Outcome::Ok as i32, 0);
        assert_eq!(Outcome::Trap as i32, 1);
        assert_eq!(Outcome::Timeout as i32, 2);
        assert_eq!(Outcome::FuelExhausted as i32, 3);
        assert_eq!(Outcome::MemoryLimit as i32, 4);
        assert_eq!(Outcome::ModuleNotFound as i32, 5);
        assert_eq!(Outcome::Internal as i32, 6);
    }

    #[test]
    fn partition_key_is_optional_and_absent_by_default() {
        // §21 reserved it so stateful actors can be added without a wire break.
        // If this ever defaults to `Some`, the reservation has become a feature
        // by accident.
        let request = ExecuteRequest::default();
        assert_eq!(request.partition_key, None);
    }

    #[test]
    fn both_service_clients_and_servers_are_generated() {
        // Cheap proof that build.rs ran with server and client codegen on: these
        // paths do not exist otherwise, so this is a compile-time assertion that
        // happens to be written as a test.
        let _ = nebula_worker_client::NebulaWorkerClient::<tonic::transport::Channel>::new;
        let _ = nebula_control_client::NebulaControlClient::<tonic::transport::Channel>::new;
        assert!(nebula_worker_server::SERVICE_NAME.contains("NebulaWorker"));
        assert!(nebula_control_server::SERVICE_NAME.contains("NebulaControl"));
    }
}
