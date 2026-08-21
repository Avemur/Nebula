//! Worker node binary (§3.2).
//!
//! Placeholder. The tonic server, the admission semaphore, and the dedicated
//! blocking execution pool (§5.2) replace this body entirely; it exists so the
//! crate has a binary target and so the execution core can be started by hand.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let cache_dir =
        std::env::var("NEBULA_CACHE_DIR").unwrap_or_else(|_| "/tmp/nebula-l2".to_string());

    // Expensive: reserves the pooling allocator's address space and starts the
    // epoch ticker. One per process, never per request.
    let runtime = nebula_runtime::Runtime::new(&cache_dir)?;

    println!(
        "nebula-worker: execution core ready. L2 cache at {cache_dir}, \
         {} module(s) in L1. gRPC not wired yet.",
        runtime.cache().l1_len()
    );
    Ok(())
}
