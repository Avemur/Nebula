//! Control plane: scheduler, module registry, membership (§3.1).
//!
//! Library plus binary rather than a bare binary so the scheduler and the
//! membership tracker are testable on their own — and so `pub` means something
//! instead of every method tripping `dead_code` until `main` happens to call it.
//!
//! Serves two surfaces: the `NebulaControl` gRPC mesh that workers speak, and
//! the HTTP gateway of §11.1 that clients speak.

pub mod gateway;
pub mod membership;
pub mod registry;
pub mod ring;
pub mod server;
