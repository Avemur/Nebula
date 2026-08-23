//! Replay of already-answered requests (README.md §22.4).
//!
//! §10.2 refuses to retry a request that has already been dispatched, because
//! the worker may have run it. That is correct, and it is also a trap: agent
//! frameworks retry failed tool calls automatically, so the guarantee holds
//! inside Nebula and is then broken by the caller one layer up.
//!
//! An `Idempotency-Key` closes the half of that gap the gateway can see. What
//! it covers and what it does not is stated precisely in §22.4 and is not
//! guesswork — see [`Store::finish`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long an answer stays replayable.
///
/// Long enough for a client to notice a dead connection and retry; short enough
/// that the map is bounded by the request rate rather than by the key space.
pub const TTL: Duration = Duration::from_secs(60);

/// Bound on a caller-supplied key. It is a map key, and an unbounded one is a
/// free allocation for anyone asking.
pub const MAX_KEY_BYTES: usize = 255;

/// Ceiling on stored entries, enforced by evicting expired ones and then
/// refusing to grow.
///
/// ponytail: a flat cap with an O(n) expiry sweep. At this size the sweep is
/// microseconds and runs only when the map is full. If keyed traffic ever makes
/// that show up, the upgrade is a min-heap keyed by deadline.
pub const MAX_ENTRIES: usize = 10_000;

/// Scoped so one tenant can never read another's answer by guessing a key.
///
/// The tenant is not a convenience here, it is the boundary: without it, an
/// `Idempotency-Key` would be an oracle for any key another tenant happened to
/// pick. The function id is included so an agent reusing one key across two
/// tools gets two entries rather than one wrong answer.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Slot {
    pub tenant: String,
    pub function_id: String,
    pub key: String,
}

enum Entry<T> {
    /// Claimed by a request that has not answered yet.
    InFlight {
        since: Instant,
    },
    Done {
        answer: T,
        until: Instant,
    },
}

/// What a caller should do with a keyed request.
pub enum Claim<T> {
    /// This request is the first: run it, then call [`Store::finish`].
    Proceed,
    /// An identical request already answered. Return this instead of running.
    Replay(T),
    /// An identical request is running right now. Neither replay nor run.
    InFlight,
}

pub struct Store<T> {
    entries: Mutex<HashMap<Slot, Entry<T>>>,
}

impl<T: Clone> Default for Store<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> Store<T> {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Claims a slot, or reports what already holds it.
    ///
    /// The in-flight marker is written *before* the request is dispatched, and
    /// that ordering is the point. Without it two concurrent retries would both
    /// miss, both execute, and both store — an idempotency key that permits
    /// double execution under exactly the concurrency it exists to handle.
    pub fn claim(&self, slot: &Slot) -> Claim<T> {
        let mut entries = self.entries.lock().expect("idempotency store");
        let now = Instant::now();

        match entries.get(slot) {
            Some(Entry::Done { answer, until }) if *until > now => {
                return Claim::Replay(answer.clone());
            }
            // An in-flight marker older than the TTL means the request that
            // claimed it died without finishing. Reclaiming beats leaving a
            // slot poisoned until it expires.
            Some(Entry::InFlight { since }) if now.duration_since(*since) < TTL => {
                return Claim::InFlight;
            }
            _ => {}
        }

        if entries.len() >= MAX_ENTRIES {
            entries.retain(|_, entry| match entry {
                Entry::Done { until, .. } => *until > now,
                Entry::InFlight { since } => now.duration_since(*since) < TTL,
            });
            if entries.len() >= MAX_ENTRIES {
                // Refusing the claim means the request runs unkeyed rather than
                // being rejected. Losing replay protection under pressure is
                // bad; refusing to run the caller's code is worse.
                return Claim::Proceed;
            }
        }

        entries.insert(slot.clone(), Entry::InFlight { since: now });
        Claim::Proceed
    }

    /// Records an answer, or releases the slot when there is nothing to replay.
    ///
    /// **`replayable` is the whole design.** Only an answer that a retry should
    /// receive verbatim gets stored:
    ///
    /// * A completed execution — success or guest fault — is stored. The script
    ///   ran and produced this; running it again would produce it again.
    /// * "Nothing ran" (`503`, no worker, shed) releases the slot, because a
    ///   retry *should* actually retry.
    /// * `502 worker_unreachable` also releases the slot, and that is the
    ///   honest limit of a gateway-side key: there is no answer to store,
    ///   because the gateway never got one. §22.4 says so out loud.
    pub fn finish(&self, slot: &Slot, answer: &T, replayable: bool) {
        let mut entries = self.entries.lock().expect("idempotency store");
        if replayable {
            entries.insert(
                slot.clone(),
                Entry::Done {
                    answer: answer.clone(),
                    until: Instant::now() + TTL,
                },
            );
        } else {
            entries.remove(slot);
        }
    }

    /// Releases a slot without storing anything. Used when a request is
    /// abandoned before it produced an answer at all.
    pub fn release(&self, slot: &Slot) {
        self.entries.lock().expect("idempotency store").remove(slot);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(tenant: &str, key: &str) -> Slot {
        Slot {
            tenant: tenant.to_string(),
            function_id: "js".to_string(),
            key: key.to_string(),
        }
    }

    fn claimed<T: Clone>(store: &Store<T>, slot: &Slot) -> &'static str {
        match store.claim(slot) {
            Claim::Proceed => "proceed",
            Claim::Replay(_) => "replay",
            Claim::InFlight => "in-flight",
        }
    }

    #[test]
    fn a_finished_answer_replays() {
        let store = Store::new();
        let slot = slot("a", "k1");

        assert_eq!(claimed(&store, &slot), "proceed");
        store.finish(&slot, &"result".to_string(), true);

        match store.claim(&slot) {
            Claim::Replay(answer) => assert_eq!(answer, "result"),
            _ => panic!("an identical keyed request must replay, not re-run"),
        }
    }

    #[test]
    fn a_claim_blocks_a_concurrent_duplicate() {
        let store: Store<String> = Store::new();
        let slot = slot("a", "k1");

        assert_eq!(claimed(&store, &slot), "proceed");
        // The marker goes in before dispatch precisely so this second caller
        // cannot also proceed. Without it, the key would permit exactly the
        // double execution it exists to prevent.
        assert_eq!(claimed(&store, &slot), "in-flight");
    }

    #[test]
    fn an_unreplayable_answer_frees_the_slot_for_a_real_retry() {
        let store = Store::new();
        let slot = slot("a", "k1");

        assert_eq!(claimed(&store, &slot), "proceed");
        // Nothing ran, so there is nothing to replay. Storing this would pin a
        // transient failure for a minute and make the key actively harmful.
        store.finish(&slot, &"shed".to_string(), false);
        assert_eq!(claimed(&store, &slot), "proceed");
    }

    #[test]
    fn one_tenants_key_is_invisible_to_another() {
        let store = Store::new();
        store.finish(&slot("a", "shared"), &"tenant a data".to_string(), true);

        // Not a nicety: without the tenant in the slot, a key is an oracle for
        // whatever another tenant happened to name the same thing.
        assert_eq!(claimed(&store, &slot("b", "shared")), "proceed");
    }

    #[test]
    fn the_same_key_on_a_different_function_is_a_different_slot() {
        let store = Store::new();
        let mut other = slot("a", "k1");
        other.function_id = "python".to_string();

        store.finish(&slot("a", "k1"), &"js answer".to_string(), true);
        assert_eq!(claimed(&store, &other), "proceed");
    }

    #[test]
    fn a_full_store_lets_requests_through_unkeyed() {
        let store: Store<String> = Store::new();
        for n in 0..MAX_ENTRIES {
            let slot = slot("a", &format!("k{n}"));
            store.finish(&slot, &"x".to_string(), true);
        }
        assert_eq!(store.len(), MAX_ENTRIES);

        // Nothing here has expired, so the sweep frees nothing and the store is
        // genuinely full. The caller still gets to run: losing replay
        // protection is bad, refusing to run their code is worse.
        assert_eq!(claimed(&store, &slot("a", "overflow")), "proceed");
        assert_eq!(store.len(), MAX_ENTRIES, "a full store must not grow");
    }
}
