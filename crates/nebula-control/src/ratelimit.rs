//! Per-tenant token buckets at the gateway (README.md §22.7).
//!
//! §10.3 sheds load at the *worker* when the cluster is saturated, which
//! protects the cluster and says nothing about who caused the saturation. A
//! single tenant in a retry loop can consume every admission slot and every
//! other tenant sees `503`. That is not a capacity problem, it is a fairness
//! problem, and shedding cannot tell the two apart.
//!
//! An MCP endpoint (§22.3) is by construction the thing you hand to something
//! that loops, so this stopped being optional the moment that landed.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Ceiling on tracked tenants.
///
/// v1 auth makes the bearer token *be* the tenant (§13), so a caller can invent
/// tenants for free — an unbounded map here would be a memory-exhaustion vector
/// created by the very thing meant to prevent one.
pub const MAX_TENANTS: usize = 10_000;

/// A refill rate and a burst size.
#[derive(Clone, Copy, Debug)]
pub struct Limit {
    /// Sustained requests per second.
    pub per_second: f64,
    /// Tokens the bucket holds when full — how far ahead a caller may run.
    pub burst: f64,
}

impl Limit {
    /// Executions. Generous on purpose: the point is to stop one tenant
    /// monopolising the cluster, not to meter normal use. §19 targets a 5 ms
    /// hot p99, so a legitimate client can drive hundreds per second and a
    /// tight limit would make Nebula look slow rather than fair. A runaway
    /// retry loop does thousands, which this still stops. §10.3 handles real
    /// saturation either way.
    pub const EXECUTE: Self = Self {
        per_second: 200.0,
        burst: 400.0,
    };

    /// Deploys. Two orders of magnitude tighter, because `PUT /functions/{id}`
    /// runs **Wizer**, which spawns a subprocess and executes the caller's
    /// guest code (§11.1). It is the most expensive thing an unauthenticated-ish
    /// caller can ask this process to do, and leaving it at the execute rate
    /// would make the limiter's job easy and the box's job impossible.
    pub const DEPLOY: Self = Self {
        per_second: 0.2,
        burst: 5.0,
    };

    /// Effectively no limit, for callers that have their own reason to be
    /// exempt — a load test that would otherwise be measuring this module
    /// instead of the thing it claims to measure.
    ///
    /// A large finite number rather than infinity: `0.0 * f64::INFINITY` is
    /// `NaN`, and a limiter that can produce one is a limiter with a bug
    /// waiting for the first request that arrives in the same instant as the
    /// last.
    pub const NONE: Self = Self {
        per_second: 1e9,
        burst: 1e9,
    };
}

/// The deploy bucket must stay far tighter than the execute bucket.
///
/// A compile-time assertion rather than a test, because clippy is right that a
/// comparison between two constants is not something a test run discovers — and
/// an invariant that fails the build is strictly better than one that fails an
/// afternoon later. `PUT /functions/{id}` runs Wizer, which executes the
/// caller's guest code in a subprocess on the control plane (§11.1). If these
/// two ever converge, that is the bug.
const _: () = {
    assert!(Limit::DEPLOY.per_second * 100.0 < Limit::EXECUTE.per_second);
    assert!(Limit::DEPLOY.burst < Limit::EXECUTE.burst);
};

#[derive(Debug, PartialEq)]
pub enum Decision {
    Allowed,
    /// Refused, with how long until a token is available.
    Limited {
        retry_after: Duration,
    },
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct Limiter {
    limit: Limit,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl Limiter {
    pub fn new(limit: Limit) -> Self {
        Self {
            limit,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Spends one token for `tenant`, or reports how long until there is one.
    ///
    /// Refill is lazy — computed from the elapsed time on access rather than by
    /// a background task. A timer per tenant would be a scheduler's worth of
    /// machinery for arithmetic that fits on one line.
    pub fn check(&self, tenant: &str) -> Decision {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate limiter");

        if let Some(bucket) = buckets.get_mut(tenant) {
            let elapsed = now.duration_since(bucket.last).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * self.limit.per_second).min(self.limit.burst);
            bucket.last = now;

            if bucket.tokens < 1.0 {
                return Decision::Limited {
                    retry_after: self.wait_for_one(bucket.tokens),
                };
            }
            bucket.tokens -= 1.0;
            return Decision::Allowed;
        }

        if buckets.len() >= MAX_TENANTS {
            // A bucket at full capacity carries no debt, so forgetting it
            // changes nothing.
            buckets.retain(|_, bucket| {
                let elapsed = now.duration_since(bucket.last).as_secs_f64();
                bucket.tokens + elapsed * self.limit.per_second < self.limit.burst
            });
        }

        if buckets.len() >= MAX_TENANTS {
            // **Fail closed, and only for newcomers.** Admitting an untracked
            // tenant would hand unlimited capacity to exactly the caller that
            // filled the map — minting fresh bearer tokens is free. Tenants
            // already in the map are unaffected, so the cost of being wrong
            // here is one new tenant waiting while an operator looks at why
            // ten thousand of them are active.
            return Decision::Limited {
                retry_after: Duration::from_secs(1),
            };
        }

        buckets.insert(
            tenant.to_string(),
            Bucket {
                // The request being checked is the first one spent.
                tokens: self.limit.burst - 1.0,
                last: now,
            },
        );
        Decision::Allowed
    }

    /// Rounded up to whole seconds, and never zero: `Retry-After` is expressed
    /// in seconds, and `Retry-After: 0` invites a caller to retry immediately
    /// into another refusal.
    fn wait_for_one(&self, tokens: f64) -> Duration {
        let seconds = ((1.0 - tokens) / self.limit.per_second).ceil().max(1.0);
        Duration::from_secs(seconds as u64)
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(limiter: &Limiter, tenant: &str) -> bool {
        limiter.check(tenant) == Decision::Allowed
    }

    /// Spends `n` requests, returning how many were allowed.
    fn spend(limiter: &Limiter, tenant: &str, n: usize) -> usize {
        (0..n).filter(|_| allowed(limiter, tenant)).count()
    }

    #[test]
    fn a_burst_is_allowed_and_then_the_rate_applies() {
        let limiter = Limiter::new(Limit {
            per_second: 10.0,
            burst: 5.0,
        });

        // The burst is the whole point: an agent that fires five tool calls at
        // once is normal, not abusive.
        assert_eq!(spend(&limiter, "acme", 5), 5);
        assert!(!allowed(&limiter, "acme"), "the sixth exceeds the burst");
    }

    #[test]
    fn tokens_come_back_with_time() {
        let limiter = Limiter::new(Limit {
            per_second: 100.0,
            burst: 2.0,
        });
        assert_eq!(spend(&limiter, "acme", 2), 2);
        assert!(!allowed(&limiter, "acme"));

        // 100/s means a token every 10 ms. Without lazy refill this stays
        // refused forever, which is a limiter that only ever says no.
        std::thread::sleep(Duration::from_millis(50));
        assert!(allowed(&limiter, "acme"), "tokens must refill over time");
    }

    #[test]
    fn refill_never_exceeds_the_burst() {
        let limiter = Limiter::new(Limit {
            per_second: 1000.0,
            burst: 3.0,
        });
        assert!(allowed(&limiter, "acme"));

        // A tenant idle for a long time must not bank credit. Without the
        // clamp, going quiet for a minute would buy a minute's worth of
        // requests to spend at once — the opposite of a rate limit.
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(spend(&limiter, "acme", 10), 3, "banked more than the burst");
    }

    #[test]
    fn one_tenant_cannot_spend_anothers_budget() {
        let limiter = Limiter::new(Limit {
            per_second: 1.0,
            burst: 2.0,
        });

        // This is the entire reason the limiter exists rather than a global
        // one: §10.3 sheds when the cluster is busy and cannot tell a noisy
        // neighbour from a busy day.
        assert_eq!(spend(&limiter, "noisy", 5), 2);
        assert!(!allowed(&limiter, "noisy"));
        assert!(
            allowed(&limiter, "quiet"),
            "a well-behaved tenant must not pay for a loud one"
        );
    }

    #[test]
    fn a_refusal_says_when_to_come_back() {
        let limiter = Limiter::new(Limit {
            per_second: 0.5,
            burst: 1.0,
        });
        assert!(allowed(&limiter, "acme"));

        match limiter.check("acme") {
            // Rounded up and never zero: `Retry-After` is whole seconds, and a
            // zero would invite an immediate retry into another refusal.
            Decision::Limited { retry_after } => {
                assert!(retry_after >= Duration::from_secs(1), "{retry_after:?}");
                assert!(retry_after <= Duration::from_secs(3), "{retry_after:?}");
            }
            Decision::Allowed => panic!("expected a refusal"),
        }
    }

    #[test]
    fn a_flood_of_invented_tenants_cannot_grow_the_map_without_bound() {
        let limiter = Limiter::new(Limit {
            per_second: 0.001,
            burst: 1.0,
        });

        // The bearer token *is* the tenant (§13), so minting new ones is free.
        // A limiter whose own state grows per attacker-chosen string is a
        // memory-exhaustion vector wearing a hard hat.
        for n in 0..(MAX_TENANTS + 500) {
            limiter.check(&format!("tenant-{n}"));
        }
        assert!(limiter.tracked() <= MAX_TENANTS, "{}", limiter.tracked());
    }

    #[test]
    fn a_full_map_refuses_newcomers_rather_than_waving_them_through() {
        let limiter = Limiter::new(Limit {
            per_second: 0.001,
            burst: 1.0,
        });
        for n in 0..MAX_TENANTS {
            assert!(allowed(&limiter, &format!("tenant-{n}")));
        }

        // The refill rate here is so slow that nothing has refilled, so the
        // sweep frees nothing and the map is genuinely full. Admitting an
        // untracked tenant would hand unlimited capacity to whoever filled it.
        assert!(
            !allowed(&limiter, "brand-new"),
            "a full map must fail closed for newcomers"
        );

        // And an already-tracked tenant is unaffected by the crowd.
        std::thread::sleep(Duration::from_millis(10));
        let known = limiter.check("tenant-0");
        assert!(
            matches!(known, Decision::Limited { .. }),
            "tenant-0 has spent its budget; it should be limited on its own terms"
        );
    }
}
