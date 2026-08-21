//! Control plane: scheduler, module registry, membership (§3.1).
//!
//! Library plus binary rather than a bare binary so the scheduler and the
//! membership tracker are testable on their own — and so `pub` means something
//! instead of every method tripping `dead_code` until `main` happens to call it.
//!
//! The axum API gateway of §11.1 is still outstanding; today this serves the
//! `NebulaControl` gRPC surface only.

pub mod membership;
pub mod registry;
pub mod ring;
pub mod server;
