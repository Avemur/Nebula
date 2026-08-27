//! Replay of already-answered requests (README.md §22.4).
//!
//! §10.2 refuses to retry a request that has already been dispatched, because
//! the worker may have run it. That is correct, and it is also a trap: agent
//! frameworks retry failed tool calls automatically, so the guarantee holds
//! inside Nebula and is then broken by the caller one layer up.
//!
//! An `Idempotency-Key` closes the half of that gap the gateway can see. What
//! it covers and what it does not is stated precisely in §22.4 and is not
//! guesswork: see [`Store::finish`].

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

/// Ceiling on stored entries.
///
/// ponytail: a flat cap with an O(n) expiry sweep that runs only when a cap is
/// reached. At this size the sweep is microseconds. If keyed traffic ever makes
/// it show up, the upgrade is a min-heap keyed by deadline.
pub const MAX_ENTRIES: usize = 10_000;

/// Ceiling on stored answer bytes.
///
/// A count cap alone is not a bound. A response body is capped at 1 MiB, so
/// [`MAX_ENTRIES`] of them is ten gigabytes of gateway memory, held for a
/// minute, by any client willing to send keys. Both caps are needed: one bounds
/// the map, the other bounds what the map holds.
pub const MAX_BYTES: usize = 64 << 20;

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
    InFlight { since: Instant },
    Done {
        answer: T,
        until: Instant,
        bytes: usize,
    },
}

/// What a caller should do with a keyed request.
pub enum Claim<'a, T> {
    /// This request is the first. Run it, then [`Claimed::finish`].
    Proceed(Claimed<'a, T>),
    /// An identical request already answered. Return this instead of running.
    Replay(T),
    /// An identical request is running right now. Neither replay nor run.
    InFlight,
}

/// A held claim, released on drop if it is never finished.
///
/// The guard is the whole reason this is not a bare `claim`/`finish` pair. A
/// client that hangs up mid-request has its handler future dropped, so `finish`
/// never runs, and a slot left claimed answers `409` for the entire TTL. That
/// would make the key a liability in exactly the case it exists to serve: the
/// client lost the answer and is about to retry.
pub struct Claimed<'a, T> {
    store: &'a Store<T>,
    slot: Slot,
    /// False when the store was full and the request runs unkeyed, so neither
    /// finishing nor dropping should touch the map.
    tracked: bool,
    settled: bool,
}

impl<T: Clone> Claimed<'_, T> {
    /// Records the answer, or releases the slot when there is nothing worth
    /// replaying. See [`Store::finish`] for which is which.
    pub fn finish(mut self, answer: &T, replayable: bool, bytes: usize) {
        self.settled = true;
        if self.tracked {
            self.store.finish(&self.slot, answer, replayable, bytes);
        }
    }
}

impl<T> Drop for Claimed<'_, T> {
    fn drop(&mut self) {
        if self.tracked && !self.settled {
            self.store.remove(&self.slot);
        }
    }
}

pub struct Store<T> {
    entries: Mutex<State<T>>,
}

struct State<T> {
    map: HashMap<Slot, Entry<T>>,
    /// Sum of the stored answers' sizes, maintained on insert and removal
    /// rather than recomputed: walking the map on the request path is the kind
    /// of thing that is fine right up until it is not.
    bytes: usize,
}

impl<T: Clone> Default for Store<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Store<T> {
    /// Drops a slot, whatever state it is in.
    fn remove(&self, slot: &Slot) {
        let mut state = self.entries.lock().expect("idempotency store");
        if let Some(Entry::Done { bytes, .. }) = state.map.remove(slot) {
            state.bytes = state.bytes.saturating_sub(bytes);
        }
    }
}

impl<T: Clone> Store<T> {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(State {
                map: HashMap::new(),
                bytes: 0,
            }),
        }
    }

    /// Claims a slot, or reports what already holds it.
    ///
    /// The in-flight marker is written *before* the request is dispatched, and
    /// that ordering is the point. Without it two concurrent retries would both
    /// miss, both execute, and both store: an idempotency key that permits
    /// double execution under exactly the concurrency it exists to handle.
    pub fn claim(&self, slot: &Slot) -> Claim<'_, T> {
        let mut state = self.entries.lock().expect("idempotency store");
        let now = Instant::now();

        match state.map.get(slot) {
            Some(Entry::Done { answer, until, .. }) if *until > now => {
                return Claim::Replay(answer.clone());
            }
            // An in-flight marker older than the TTL means the request that
            // claimed it died without finishing. The drop guard makes that
            // nearly impossible, but a process that was SIGKILLed between the
            // claim and the answer leaves no guard to run.
            Some(Entry::InFlight { since }) if now.duration_since(*since) < TTL => {
                return Claim::InFlight;
            }
            _ => {}
        }

        if state.map.len() >= MAX_ENTRIES || state.bytes >= MAX_BYTES {
            state.expire(now);
        }
        if state.map.len() >= MAX_ENTRIES || state.bytes >= MAX_BYTES {
            // Refusing to *track* means the request runs unkeyed rather than
            // being rejected. Losing replay protection under pressure is bad;
            // refusing to run the caller's code is worse.
            return Claim::Proceed(Claimed {
                store: self,
                slot: slot.clone(),
                tracked: false,
                settled: false,
            });
        }

        state
            .map
            .insert(slot.clone(), Entry::InFlight { since: now });
        Claim::Proceed(Claimed {
            store: self,
            slot: slot.clone(),
            tracked: true,
            settled: false,
        })
    }

    /// Records an answer, or releases the slot when there is nothing to replay.
    ///
    /// **`replayable` is the whole design.** Only an answer that a retry should
    /// receive verbatim gets stored:
    ///
    /// * A completed execution, success or guest fault, is stored. The script
    ///   ran and produced this; running it again would produce it again.
    /// * "Nothing ran" (`503`, no worker, shed) releases the slot, because a
    ///   retry *should* actually retry.
    /// * `502 worker_unreachable` also releases the slot, and that is the
    ///   honest limit of a gateway-side key: there is no answer to store,
    ///   because the gateway never got one. §22.4 says so out loud.
    ///
    /// An answer too large for the remaining budget is not stored either. A
    /// retry then re-runs, which is the guarantee that existed before the key:
    /// the alternative is letting one caller's 1 MiB responses evict everyone
    /// else's.
    fn finish(&self, slot: &Slot, answer: &T, replayable: bool, bytes: usize) {
        let mut state = self.entries.lock().expect("idempotency store");
        // Whatever happens next, the in-flight marker goes.
        state.map.remove(slot);
        if !replayable {
            return;
        }

        let now = Instant::now();
        if state.bytes + bytes > MAX_BYTES {
            state.expire(now);
        }
        if state.bytes + bytes > MAX_BYTES || state.map.len() >= MAX_ENTRIES {
            return;
        }

        state.bytes += bytes;
        state.map.insert(
            slot.clone(),
            Entry::Done {
                answer: answer.clone(),
                until: now + TTL,
                bytes,
            },
        );
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap().map.len()
    }

    #[cfg(test)]
    fn bytes(&self) -> usize {
        self.entries.lock().unwrap().bytes
    }
}

impl<T> State<T> {
    /// Drops everything past its deadline, keeping `bytes` in step.
    fn expire(&mut self, now: Instant) {
        let mut freed = 0;
        self.map.retain(|_, entry| match entry {
            Entry::Done { until, bytes, .. } => {
                let live = *until > now;
                if !live {
                    freed += *bytes;
                }
                live
            }
            Entry::InFlight { since } => now.duration_since(*since) < TTL,
        });
        self.bytes = self.bytes.saturating_sub(freed);
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
            // Dropping the guard here releases the claim, which is exactly what
            // a probe should do: it is not going to answer.
            Claim::Proceed(_) => "proceed",
            Claim::Replay(_) => "replay",
            Claim::InFlight => "in-flight",
        }
    }

    /// Claim and answer in one step, the way a completed request does.
    fn served(store: &Store<String>, slot: &Slot, answer: &str, replayable: bool) {
        match store.claim(slot) {
            Claim::Proceed(claim) => claim.finish(&answer.to_string(), replayable, answer.len()),
            _ => panic!("expected a free slot"),
        }
    }

    #[test]
    fn a_finished_answer_replays() {
        let store = Store::new();
        let slot = slot("a", "k1");

        served(&store, &slot, "result", true);
        match store.claim(&slot) {
            Claim::Replay(answer) => assert_eq!(answer, "result"),
            _ => panic!("an identical keyed request must replay, not re-run"),
        };
    }

    #[test]
    fn a_claim_blocks_a_concurrent_duplicate() {
        let store: Store<String> = Store::new();
        let slot = slot("a", "k1");

        let held = match store.claim(&slot) {
            Claim::Proceed(claim) => claim,
            _ => panic!("expected a free slot"),
        };
        // The marker goes in before dispatch precisely so this second caller
        // cannot also proceed. Without it, the key would permit exactly the
        // double execution it exists to prevent.
        assert_eq!(claimed(&store, &slot), "in-flight");
        drop(held);
    }

    #[test]
    fn an_abandoned_claim_is_released_rather_than_left_holding_the_slot() {
        let store: Store<String> = Store::new();
        let slot = slot("a", "k1");

        // A client that hangs up has its handler future dropped, so the answer
        // never arrives. Without the guard the slot would answer 409 for the
        // whole TTL: to the very retry the key exists to serve.
        match store.claim(&slot) {
            Claim::Proceed(claim) => drop(claim),
            _ => panic!("expected a free slot"),
        }
        assert_eq!(claimed(&store, &slot), "proceed");
    }

    #[test]
    fn an_unreplayable_answer_frees_the_slot_for_a_real_retry() {
        let store = Store::new();
        let slot = slot("a", "k1");

        // Nothing ran, so there is nothing to replay. Storing this would pin a
        // transient failure for a minute and make the key actively harmful.
        served(&store, &slot, "shed", false);
        assert_eq!(claimed(&store, &slot), "proceed");
    }

    #[test]
    fn one_tenants_key_is_invisible_to_another() {
        let store = Store::new();
        served(&store, &slot("a", "shared"), "tenant a data", true);

        // Not a nicety: without the tenant in the slot, a key is an oracle for
        // whatever another tenant happened to name the same thing.
        assert_eq!(claimed(&store, &slot("b", "shared")), "proceed");
    }

    #[test]
    fn the_same_key_on_a_different_function_is_a_different_slot() {
        let store = Store::new();
        let mut other = slot("a", "k1");
        other.function_id = "python".to_string();

        served(&store, &slot("a", "k1"), "js answer", true);
        assert_eq!(claimed(&store, &other), "proceed");
    }

    #[test]
    fn a_full_store_lets_requests_through_unkeyed() {
        let store: Store<String> = Store::new();
        for n in 0..MAX_ENTRIES {
            served(&store, &slot("a", &format!("k{n}")), "x", true);
        }
        assert_eq!(store.len(), MAX_ENTRIES);

        // Nothing has expired, so the sweep frees nothing and the store is
        // genuinely full. The caller still gets to run: losing replay
        // protection is bad, refusing to run their code is worse.
        assert_eq!(claimed(&store, &slot("a", "overflow")), "proceed");
        assert_eq!(store.len(), MAX_ENTRIES, "a full store must not grow");
    }

    #[test]
    fn the_store_is_bounded_by_bytes_and_not_only_by_count() {
        let store: Store<String> = Store::new();
        let big = "x".repeat(1 << 20); // one response body at the §7.2 cap

        // Far fewer than MAX_ENTRIES, so a count cap alone would let every one
        // of these in, which at 1 MiB each is how a keyed client turns the
        // gateway into ten gigabytes of held memory.
        for n in 0..200 {
            served(&store, &slot("a", &format!("big{n}")), &big, true);
        }

        assert!(
            store.bytes() <= MAX_BYTES,
            "stored {} bytes, over the {MAX_BYTES} budget",
            store.bytes()
        );
        assert!(
            store.len() < 200,
            "the byte budget must refuse entries the count cap would allow"
        );
    }

    #[test]
    fn evicting_an_entry_returns_its_bytes_to_the_budget() {
        let store: Store<String> = Store::new();
        let slot = slot("a", "k1");

        served(&store, &slot, "some answer", true);
        assert_eq!(store.bytes(), "some answer".len());

        // A miscounted budget leaks: the store would refuse new answers while
        // holding nothing, and no test of the cap itself would notice.
        store.remove(&slot);
        assert_eq!(store.bytes(), 0);
    }
}
