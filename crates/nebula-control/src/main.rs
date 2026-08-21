//! Control plane binary (§3.1).
//!
//! Placeholder. The axum gateway, the tonic server, and the membership
//! reconciler replace this body entirely; it exists so the crate has a binary
//! target and so the ring can be exercised by hand.
//!
//! `nebula-control worker-a worker-b worker-c`

use nebula_control::ring::Ring;

fn main() {
    let mut ring = Ring::new();
    for node in std::env::args().skip(1) {
        ring.insert(&node);
    }

    println!(
        "nebula-control: {} worker(s), {} ring points. gRPC and HTTP not wired yet.",
        ring.len(),
        ring.virtual_nodes()
    );
    for node in ring.members() {
        println!("  {node}");
    }
}
