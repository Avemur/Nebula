//! Cluster membership and liveness (README.md §10.1).
//!
//! Workers send a unary heartbeat; the control plane records `last_seen` and a
//! background task removes anything that has gone quiet. A stale timestamp
//! catches process death, network partition, and a wedged process identically,
//! which is why this is not a stream.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::ring::Ring;

/// How often workers beat.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(500);

/// How often the reconciler wakes.
pub const RECONCILE_INTERVAL: Duration = Duration::from_millis(500);

/// Three missed beats, per §10.1.
pub const LIVENESS_TIMEOUT: Duration = Duration::from_millis(1500);

/// A node above this multiple of mean cluster load loses the lead (§9.2).
pub const BOUNDED_LOAD_FACTOR: f64 = 1.25;

#[derive(Debug, Clone)]
pub struct NodeState {
    pub address: String,
    pub generation: u64,
    pub last_seen: Instant,
    pub in_flight: u32,
    pub queue_depth: u32,
    pub cache_bytes: u64,
}

#[derive(Debug)]
pub struct Membership {
    inner: Mutex<Inner>,
    liveness_timeout: Duration,
}

#[derive(Debug, Default)]
struct Inner {
    ring: Ring,
    nodes: HashMap<String, NodeState>,
}

impl Membership {
    pub fn new(liveness_timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            liveness_timeout,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(LIVENESS_TIMEOUT)
    }

    /// Adds a worker to the ring, or refreshes one that re-registered.
    pub fn register(&self, node_id: &str, address: &str, generation: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.nodes.insert(
            node_id.to_string(),
            NodeState {
                address: address.to_string(),
                generation,
                last_seen: Instant::now(),
                in_flight: 0,
                queue_depth: 0,
                cache_bytes: 0,
            },
        );
        inner.ring.insert(node_id);
    }

    /// Records a beat. Returns `false` when this node and generation are not
    /// recognised, which tells the worker to register again.
    ///
    /// A *different* generation under a known id means the worker died and
    /// restarted between beats. Adopting the new process under the old entry
    /// would keep stale routing state alive, so it is treated as unknown.
    pub fn heartbeat(
        &self,
        node_id: &str,
        generation: u64,
        in_flight: u32,
        queue_depth: u32,
        cache_bytes: u64,
    ) -> bool {
        let mut inner = self.inner.lock().unwrap();
        match inner.nodes.get_mut(node_id) {
            Some(state) if state.generation == generation => {
                state.last_seen = Instant::now();
                state.in_flight = in_flight;
                state.queue_depth = queue_depth;
                state.cache_bytes = cache_bytes;
                true
            }
            _ => false,
        }
    }

    /// Drops nodes that have gone quiet, returning the ids removed.
    pub fn reconcile(&self) -> Vec<String> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();

        let dead: Vec<String> = inner
            .nodes
            .iter()
            .filter(|(_, state)| now.duration_since(state.last_seen) > self.liveness_timeout)
            .map(|(id, _)| id.clone())
            .collect();

        for id in &dead {
            inner.nodes.remove(id);
            inner.ring.remove(id);
        }
        dead
    }

    /// The worker that owns `key`, if the ring is not empty.
    pub fn route(&self, key: &str) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .ring
            .route(key)
            .map(str::to_string)
    }

    /// Ordered dispatch plan of `(node_id, address)` for `key`.
    ///
    /// The ring's owner leads, unless it is carrying more than
    /// [`BOUNDED_LOAD_FACTOR`] times the mean cluster load, then the walk
    /// starts at the next node instead (§9.2). Everything after the lead stays
    /// in ring order, so failover is unaffected by the load check.
    ///
    /// Computed under one lock: sampling the ring and the load separately would
    /// let a rebalance land between them.
    pub fn route_plan(&self, key: &str) -> Vec<(String, String)> {
        let inner = self.inner.lock().unwrap();
        if inner.nodes.is_empty() {
            return Vec::new();
        }

        let total: u32 = inner.nodes.values().map(|state| state.in_flight).sum();
        let limit = BOUNDED_LOAD_FACTOR * (total as f64 / inner.nodes.len() as f64);
        let load = |node: &str| {
            inner
                .nodes
                .get(node)
                .map(|state| state.in_flight as f64)
                .unwrap_or(0.0)
        };

        let walk: Vec<&str> = inner.ring.candidates(key).collect();
        // If every node is hot, keep cache affinity rather than thrash: fall
        // back to the owner and let admission control do the shedding.
        let lead = walk
            .iter()
            .position(|node| load(node) <= limit)
            .unwrap_or(0);

        (0..walk.len())
            .filter_map(|offset| {
                let node = walk[(lead + offset) % walk.len()];
                inner
                    .nodes
                    .get(node)
                    .map(|state| (node.to_string(), state.address.clone()))
            })
            .collect()
    }

    /// Owner first, then the failover walk (§9.1).
    pub fn candidates(&self, key: &str) -> Vec<String> {
        self.inner
            .lock()
            .unwrap()
            .ring
            .candidates(key)
            .map(str::to_string)
            .collect()
    }

    pub fn contains(&self, node_id: &str) -> bool {
        self.inner.lock().unwrap().nodes.contains_key(node_id)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn address_of(&self, node_id: &str) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .nodes
            .get(node_id)
            .map(|state| state.address.clone())
    }

    pub fn snapshot(&self) -> Vec<(String, NodeState)> {
        self.inner
            .lock()
            .unwrap()
            .nodes
            .iter()
            .map(|(id, state)| (id.clone(), state.clone()))
            .collect()
    }
}

/// The asynchronous reconciler of §10.1. Removal is automatic and so is
/// recovery: a node whose heartbeats resume simply registers again.
pub fn spawn_reconciler(
    membership: Arc<Membership>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            for node in membership.reconcile() {
                eprintln!("nebula-control: {node} missed its heartbeats, removed from the ring");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Duration = Duration::from_millis(60);

    fn beat(membership: &Membership, node: &str, generation: u64) -> bool {
        membership.heartbeat(node, generation, 0, 0, 0)
    }

    #[test]
    fn registering_puts_a_worker_on_the_ring() {
        let membership = Membership::new(FAST);
        membership.register("worker-a", "127.0.0.1:1", 7);

        assert_eq!(membership.len(), 1);
        assert!(membership.contains("worker-a"));
        assert_eq!(
            membership.route("some-function").as_deref(),
            Some("worker-a")
        );
        assert_eq!(
            membership.address_of("worker-a").as_deref(),
            Some("127.0.0.1:1")
        );
    }

    #[test]
    fn a_beating_worker_survives_reconciliation() {
        let membership = Membership::new(FAST);
        membership.register("worker-a", "127.0.0.1:1", 7);

        for _ in 0..4 {
            std::thread::sleep(FAST / 2);
            assert!(beat(&membership, "worker-a", 7));
            assert!(membership.reconcile().is_empty());
        }
        assert!(membership.contains("worker-a"));
    }

    #[test]
    fn a_silent_worker_is_removed_from_the_ring() {
        let membership = Membership::new(FAST);
        membership.register("worker-a", "127.0.0.1:1", 7);
        membership.register("worker-b", "127.0.0.1:2", 8);

        std::thread::sleep(FAST * 2);
        beat(&membership, "worker-b", 8);

        let removed = membership.reconcile();
        assert_eq!(removed, vec!["worker-a".to_string()]);
        assert!(!membership.contains("worker-a"));
        assert_eq!(membership.len(), 1);
        // And the ring no longer routes to it.
        for key in ["a", "b", "c", "d", "e"] {
            assert_eq!(membership.route(key).as_deref(), Some("worker-b"));
        }
    }

    #[test]
    fn a_restarted_worker_is_told_to_register_again() {
        let membership = Membership::new(FAST);
        membership.register("worker-a", "127.0.0.1:1", 7);

        // Same id, new generation: the process died and came back.
        assert!(!beat(&membership, "worker-a", 999));
        // The old entry is untouched until it either re-registers or ages out:
        // a beat from an unknown generation must not refresh someone else's
        // liveness.
        assert!(membership.contains("worker-a"));

        membership.register("worker-a", "127.0.0.1:1", 999);
        assert!(beat(&membership, "worker-a", 999));
    }

    #[test]
    fn an_unknown_worker_is_told_to_register() {
        let membership = Membership::new(FAST);
        assert!(!beat(&membership, "never-seen", 1));
        assert!(membership.is_empty());
    }

    #[test]
    fn re_registering_does_not_duplicate_the_node() {
        let membership = Membership::new(FAST);
        membership.register("worker-a", "127.0.0.1:1", 7);
        membership.register("worker-a", "127.0.0.1:1", 7);
        assert_eq!(membership.len(), 1);
    }
}
