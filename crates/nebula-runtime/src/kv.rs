//! Node-local key-value shim (README.md §7.2), and the session store of §22.5.
//!
//! Not a database. Values are per-node, non-durable, and lost on restart.
//!
//! With a session (§22.5) a guest *may* expect to read back what it wrote,
//! because the gateway routes a session to one worker and this is that worker's
//! memory. "May" is the strongest word available: a ring rebalance sends the
//! next request elsewhere and the session starts empty. That is a recoverable
//! outcome rather than a correctness bug, which is exactly why §22.5 is cheap
//! and §21's actor pins are not.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

/// Node-wide caps (§6.4).
pub const MAX_ENTRIES: usize = 10_000;
pub const MAX_BYTES: usize = 16 << 20; // 16 MiB

/// How long an entry survives without being written again.
///
/// Long enough for an agent to think between steps; short enough that abandoned
/// sessions cannot hold the node's budget forever. Without it the store fills
/// once and then refuses every write for the life of the process: a cap with
/// no expiry is a cap that becomes permanent.
pub const TTL: Duration = Duration::from_secs(600);

/// Per-item caps.
///
/// Not in §6.4's original table. Without them a single guest can consume the
/// entire node budget in one call, and the entry-count overshoot below would be
/// unbounded rather than bounded by the number of concurrent writers.
pub const MAX_KEY_BYTES: usize = 1024;
pub const MAX_VALUE_BYTES: usize = 64 << 10; // 64 KiB

/// Keys are `(tenant, session, key)` tuples rather than a concatenated string,
/// so no choice of key bytes can land a guest in another tenant's namespace, or
/// another session's. A delimiter scheme would need an argument about escaping;
/// a tuple needs none.
///
/// The session is `""` when the caller sent no partition key, which makes
/// unscoped state its own namespace rather than a shared one.
type Key = (String, String, Vec<u8>);

struct Slot {
    value: Vec<u8>,
    expires: Instant,
}

/// The store refused the write: the item is oversized, or the node is at
/// capacity.
///
/// Rejection is deliberately *not* a trap and *not* a silent truncation.
/// Truncating a value is data corruption the guest cannot detect; trapping
/// kills a request over a recoverable condition. Returning a refusal follows
/// the precedent WebAssembly itself sets with `memory.grow` returning `-1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejected;

#[derive(Default)]
pub struct Kv {
    map: DashMap<Key, Slot>,
    bytes: AtomicUsize,
    entries: AtomicUsize,
}

impl std::fmt::Debug for Kv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kv")
            .field("entries", &self.len())
            .field("bytes", &self.bytes())
            .finish()
    }
}

impl Kv {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, tenant: &str, session: &str, key: &[u8]) -> Option<Vec<u8>> {
        let slot = self
            .map
            .get(&(tenant.to_string(), session.to_string(), key.to_vec()))?;
        // Checked on read as well as on the sweep: an expired value must not be
        // served just because nothing has needed its space yet.
        (slot.expires > Instant::now()).then(|| slot.value.clone())
    }

    /// Writes, sweeping expired entries and retrying once if the node is full.
    ///
    /// The sweep happens here rather than on a timer or on every write: it costs
    /// a full scan, and the common path should not pay for the rare one. It also
    /// cannot happen inside `try_set`: `retain` touches every shard and would
    /// deadlock against the `entry` lock that function holds.
    pub fn set(
        &self,
        tenant: &str,
        session: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), Rejected> {
        match self.try_set(tenant, session, key, value) {
            Ok(()) => Ok(()),
            // Nothing expired means the node is genuinely full, and a second
            // attempt would fail the same way.
            Err(Rejected) if self.expire() == 0 => Err(Rejected),
            Err(Rejected) => self.try_set(tenant, session, key, value),
        }
    }

    fn try_set(
        &self,
        tenant: &str,
        session: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), Rejected> {
        if key.len() > MAX_KEY_BYTES || value.len() > MAX_VALUE_BYTES {
            return Err(Rejected);
        }
        let cost = key.len() + value.len();
        let expires = Instant::now() + TTL;

        // `entry` holds this key's shard lock for the whole read-modify-write.
        // Nothing inside may call a `DashMap` method that touches all shards
        // (`len`, `iter`, `clear`): that would deadlock against the lock we are
        // already holding. Hence the separate `entries` counter below.
        match self
            .map
            .entry((tenant.to_string(), session.to_string(), key.to_vec()))
        {
            Entry::Occupied(mut slot) => {
                let previous = key.len() + slot.get().value.len();
                self.reserve(cost, previous)?;
                slot.insert(Slot {
                    value: value.to_vec(),
                    expires,
                });
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
                slot.insert(Slot {
                    value: value.to_vec(),
                    expires,
                });
            }
        }
        Ok(())
    }

    /// Drops everything past its deadline, returning what was freed.
    ///
    /// Called when a write is refused rather than on a timer: a sweep costs a
    /// full scan, and doing it on every write would make the common path pay
    /// for the rare one. `retain` touches every shard, so this must never be
    /// called while an `entry` lock is held: it would deadlock against it.
    pub fn expire(&self) -> usize {
        let now = Instant::now();
        let mut freed = 0;
        let mut dropped = 0;
        self.map.retain(|(_, _, key), slot| {
            let live = slot.expires > now;
            if !live {
                freed += key.len() + slot.value.len();
                dropped += 1;
            }
            live
        });
        self.bytes.fetch_sub(freed, Ordering::SeqCst);
        self.entries.fetch_sub(dropped, Ordering::Relaxed);
        dropped
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
