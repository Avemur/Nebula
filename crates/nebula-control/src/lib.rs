//! Control plane: API gateway, scheduler, module registry, membership (§3.1).
//!
//! Library plus binary rather than a bare binary so the scheduler is testable on
//! its own — and so `pub` means something, instead of every ring method
//! tripping `dead_code` until `main` happens to call it.
//!
//! Today this is the ring alone. The gateway, registry, and membership tracker
//! land with the gRPC mesh.

pub mod ring;
