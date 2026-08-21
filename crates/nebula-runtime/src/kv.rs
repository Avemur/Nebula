//! Node-local key-value shim (README.md §7.2).
//!
//! Not a database. It exists to exercise host-call plumbing and memory
//! translation. Values are per-node, non-durable, and lost on restart — guests
//! must not assume a write on one request is visible on the next.

use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

/// Node-wide caps (§6.4).
pub const MAX_ENTRIES: usize = 10_000;
pub const MAX_BYTES: usize = 16 << 20; // 16 MiB

/// Per-item caps.
///
/// Not in §6.4's original table. Without them a single guest can consume the
/// entire node budget in one call, and the entry-count overshoot below would be
/// unbounded rather than bounded by the number of concurrent writers.
pub const MAX_KEY_BYTES: usize = 1024;
pub const MAX_VALUE_BYTES: usize = 64 << 10; // 64 KiB

/// Keys are `(tenant, key)` tuples rather than a concatenated string, so no
/// choice of key bytes can land a guest in another tenant's namespace. A
/// delimiter scheme would need an argument about escaping; a tuple needs none.
type Key = (String, Vec<u8>);

/// The store refused the write: the item is oversized, or the node is at
/// capacity.
///
/// Rejection is deliberately *not* a trap and *not* a silent truncation.
/// Truncating a value is data corruption the guest cannot detect; trapping
/// kills a request over a recoverable condition. Returning a refusal follows
/// the precedent WebAssembly itself sets with `memory.grow` returning `-1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejected;

#[derive(Debug, Default)]
pub struct Kv {
    map: DashMap<Key, Vec<u8>>,
    bytes: AtomicUsize,
    entries: AtomicUsize,
}

impl Kv {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, tenant: &str, key: &[u8]) -> Option<Vec<u8>> {
        self.map
            .get(&(tenant.to_string(), key.to_vec()))
            .map(|value| value.clone())
    }

    pub fn set(&self, tenant: &str, key: &[u8], value: &[u8]) -> Result<(), Rejected> {
        if key.len() > MAX_KEY_BYTES || value.len() > MAX_VALUE_BYTES {
            return Err(Rejected);
        }
        let cost = key.len() + value.len();

        // `entry` holds this key's shard lock for the whole read-modify-write.
        // Nothing inside may call a `DashMap` method that touches all shards
        // (`len`, `iter`, `clear`) — that would deadlock against the lock we are
        // already holding. Hence the separate `entries` counter below.
        match self.map.entry((tenant.to_string(), key.to_vec())) {
            Entry::Occupied(mut slot) => {
                let previous = key.len() + slot.get().len();
                self.reserve(cost, previous)?;
                slot.insert(value.to_vec());
            }
            Entry::Vacant(slot) => {
                // ponytail: the entry-count check is a load-then-insert, not a
                // CAS, so N concurrent writers can overshoot MAX_ENTRIES by at
                // most N (itself bounded by the execution pool). The byte cap
                // is exact and is the one that actually bounds memory. Make
                // this a CAS pair only if an exact entry count ever matters.
                if self.entries.load(Ordering::Relaxed) >= MAX_ENTRIES {
                    return Err(Rejected);
                }
                self.reserve(cost, 0)?;
                self.entries.fetch_add(1, Ordering::Relaxed);
                slot.insert(value.to_vec());
            }
        }
        Ok(())
    }

    /// Atomically trade `removed` bytes of budget for `added`.
    ///
    /// Exact, not approximate: the compare-and-swap loop means two writers
    /// cannot both observe headroom that only one of them can have.
    fn reserve(&self, added: usize, removed: usize) -> Result<(), Rejected> {
        self.bytes
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                let next = current.saturating_sub(removed).saturating_add(added);
                (next <= MAX_BYTES).then_some(next)
            })
            .map(|_| ())
            .map_err(|_| Rejected)
    }

    pub fn len(&self) -> usize {
        self.entries.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total key + value bytes currently held.
    pub fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }
}
