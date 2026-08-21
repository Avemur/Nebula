//! A guest with an expensive boot, used to demonstrate DESIGN.md §4.3.
//!
//! This stands in for a framework or language runtime that spends tens of
//! milliseconds building its heap before it can serve anything. The point is
//! that the cost is paid *once*, at build time, by Wizer — and that the runtime
//! needs no special path to benefit from it.
//!
//! Two exports:
//!
//! * `_initialize` — does the expensive work and parks the result in a static.
//!   Wizer runs this ahead of time and snapshots the resulting linear memory
//!   back into the module's data segments, then drops the export.
//! * `run` — the handler. Reads the precomputed result and prints a summary.
//!   It never recomputes: if the static is empty it says so loudly, so a
//!   benchmark can never mistake an uninitialized module for a fast one.
//!
//! Deliberately imports nothing but WASI. Wizer must instantiate the module to
//! run the initializer, so every import has to be satisfiable at build time,
//! and `--allow-wasi` covers exactly this set.

use std::sync::OnceLock;

/// Sieve bound. Kept modest because everything it touches lands in the
/// snapshot, and the snapshot is a checked-in artifact.
const SIEVE_LIMIT: usize = 200_000;

/// Hash rounds. This is the tuning knob for boot cost — it burns CPU without
/// growing the heap, so the boot can be made slow without making the wizened
/// artifact large.
///
/// Tuned to roughly 22 ms of boot — a little under half the 50 ms epoch
/// deadline (DESIGN.md §6.4). Enough to show that boot eats a serious share of
/// the request budget, with enough headroom left that a loaded machine does not
/// trip the deadline and turn the benchmark into a flaky trap.
const HASH_ROUNDS: u64 = 15_000_000;

struct Boot {
    primes: Vec<u32>,
    checksum: u64,
}

static BOOT: OnceLock<Boot> = OnceLock::new();

/// The expensive boot: a sieve whose output is kept on the heap, then a hash
/// chain over it. Both halves matter — the `Vec` proves heap state survives
/// snapshotting, the hash chain provides the wall-clock cost.
fn boot() -> Boot {
    let mut composite = vec![false; SIEVE_LIMIT];
    let mut primes = Vec::new();
    for n in 2..SIEVE_LIMIT {
        if composite[n] {
            continue;
        }
        primes.push(n as u32);
        let mut multiple = n * n;
        while multiple < SIEVE_LIMIT {
            composite[multiple] = true;
            multiple += n;
        }
    }

    // FNV-1a over the primes, repeated. `wrapping_*` keeps this defined and
    // deterministic, so the checksum is a stable identity for the boot result.
    let mut checksum: u64 = 0xcbf2_9ce4_8422_2325;
    for round in 0..HASH_ROUNDS {
        let prime = primes[(round as usize) % primes.len()];
        checksum ^= prime as u64;
        checksum = checksum.wrapping_mul(0x0000_0100_0000_01b3);
    }

    Boot { primes, checksum }
}

/// Run by Wizer at build time; run by the host at request time when the module
/// has *not* been wizened.
#[export_name = "_initialize"]
pub extern "C" fn initialize() {
    // `set` rather than `get_or_init`: calling this twice is a bug worth
    // ignoring quietly, not worth doing the work twice for.
    let _ = BOOT.set(boot());
}

/// The handler. Pure lookup — no fallback to recomputing.
#[export_name = "run"]
pub extern "C" fn run() {
    match BOOT.get() {
        Some(boot) => println!("{} {}", boot.primes.len(), boot.checksum),
        // A benchmark that compared this against a wizened module would
        // otherwise be measuring "did no work" and calling it "fast".
        None => println!("UNINITIALIZED"),
    }
}
