//! Worker node: the gRPC receiver wrapped around `nebula-runtime` (§3.2).
//!
//! Library plus binary so the pool, the service, and the heartbeat loop are
//! testable without launching a process.

pub mod exec_pool;
pub mod heartbeat;
pub mod server;
