//! W3C trace context, ingested and propagated (README.md §22.6).
//!
//! §14 produces a real span tree and it is an island. An agent run is already
//! traced end to end by LangSmith, Langfuse, or a plain OTel collector, and the
//! interesting question is always "which step was slow" — which nobody can
//! answer if the tool call is an opaque gap in the parent trace.
//!
//! This is the smallest thing that closes that gap: adopt the caller's
//! `traceparent` if it sent one, mint a trace id if it did not, hang it on
//! every span as a field, and pass it down the mesh so the worker's spans carry
//! the same id.
//!
//! ponytail: no OpenTelemetry exporter and no collector — §14's position is
//! that `tracing` alone answers "where did the time go", and a collector is
//! infrastructure to run rather than a question to answer. A `trace_id` field
//! is enough to join Nebula's spans to someone else's trace in whatever they
//! already use. An exporter earns itself when someone wants the spans *inside*
//! their UI rather than joined by id.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The W3C header. Lower-case because `HeaderMap` lookups are.
pub const TRACEPARENT_HEADER: &str = "traceparent";

/// Returned so a caller learns the id of a trace it did not name.
///
/// Without this a generated id is invisible: the caller cannot correlate its
/// own logs with the cluster's, which is the entire point of having one.
pub const TRACE_ID_HEADER: &str = "x-nebula-trace-id";

/// The only version this understands. A future version still carries a 32-hex
/// trace id in the same position, but this does not assume that.
const VERSION: &str = "00";

/// One request's place in a distributed trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceContext {
    /// 32 lower-case hex characters, stable across the whole request.
    pub trace_id: String,
    /// 16 lower-case hex characters: the span that sent this request.
    pub parent_id: String,
    /// 2 hex characters. Carried verbatim — the sampling decision belongs to
    /// whoever started the trace, not to us.
    pub flags: String,
}

impl TraceContext {
    /// Adopts an incoming `traceparent`, or starts a fresh trace.
    ///
    /// **A malformed header starts a new trace rather than failing the
    /// request.** That is what the W3C spec requires, and it is also the only
    /// sane behaviour: a caller's broken instrumentation is not a reason to
    /// refuse to run their code.
    pub fn adopt(header: Option<&str>) -> Self {
        match header.and_then(parse) {
            Some(context) => context,
            None => Self {
                trace_id: mint(32),
                parent_id: mint(16),
                flags: "01".to_string(),
            },
        }
    }

    /// The `traceparent` to send onward, naming `span_id` as the parent.
    ///
    /// The outgoing parent is *this* hop, not the one that called us — that is
    /// what makes the receiving side a child rather than a sibling.
    pub fn outgoing(&self, span_id: &str) -> String {
        format!("{VERSION}-{}-{span_id}-{}", self.trace_id, self.flags)
    }
}

/// `00-{32 hex}-{16 hex}-{2 hex}`, and nothing else.
fn parse(raw: &str) -> Option<TraceContext> {
    let raw = raw.trim();
    let mut parts = raw.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let parent_id = parts.next()?;
    let flags = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    if version != VERSION
        || !is_hex(trace_id, 32)
        || !is_hex(parent_id, 16)
        || !is_hex(flags, 2)
        // All-zero ids are the spec's explicit "invalid" encoding, and treating
        // them as real would produce a trace every request joins.
        || trace_id.bytes().all(|b| b == b'0')
        || parent_id.bytes().all(|b| b == b'0')
    {
        return None;
    }

    Some(TraceContext {
        trace_id: trace_id.to_ascii_lowercase(),
        parent_id: parent_id.to_ascii_lowercase(),
        flags: flags.to_ascii_lowercase(),
    })
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A `len`-character hex id.
///
/// ponytail: a hashed counter and clock, not a CSPRNG. A trace id is a
/// correlation handle, not a secret or a capability — nothing authorizes on it,
/// and a collision costs two requests sharing a line in a log viewer. The
/// counter is what makes it unique within a process; the clock is what keeps
/// two processes started at the same moment apart. If trace ids ever become
/// something an outsider should not be able to guess, this needs a real RNG.
fn mint(len: usize) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut hex = String::with_capacity(len);
    let mut seed = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    while hex.len() < len {
        let mut hasher = DefaultHasher::new();
        (seed, nanos, std::process::id()).hash(&mut hasher);
        let block = format!("{:016x}", hasher.finish());
        hex.push_str(&block[..block.len().min(len - hex.len())]);
        seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    }
    hex
}

/// This hop's span id, for the outgoing `traceparent`.
///
/// `tracing` hands out a `span::Id` only when a subscriber is installed, so the
/// fallback is not hypothetical — it is what happens in a test binary that
/// never calls `init_tracing`.
pub fn current_span_id() -> String {
    match tracing::Span::current().id() {
        Some(id) => format!("{:016x}", id.into_u64()),
        None => mint(16),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn a_well_formed_header_is_adopted_whole() {
        let context = TraceContext::adopt(Some(VALID));
        assert_eq!(context.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(context.parent_id, "00f067aa0ba902b7");
        // The sampling decision belongs to whoever started the trace. Rewriting
        // it here would silently drop a caller out of its own sample.
        assert_eq!(context.flags, "01");
    }

    #[test]
    fn an_unsampled_flag_survives() {
        let context = TraceContext::adopt(Some(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
        ));
        assert_eq!(context.flags, "00");
    }

    #[test]
    fn a_malformed_header_starts_a_new_trace_rather_than_failing() {
        // Every one of these is a real thing broken instrumentation emits. The
        // W3C spec requires starting a fresh trace, and refusing the request
        // would mean a caller's tracing bug takes down their tool calls.
        let broken = [
            "",
            "not-a-traceparent",
            // Wrong version.
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            // Trace id one character short.
            "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
            // Non-hex.
            "00-4bf92f3577b34da6a3ce929d0e0e473z-00f067aa0ba902b7-01",
            // The spec's explicit invalid encodings.
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            // Trailing field.
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
        ];

        for raw in broken {
            let context = TraceContext::adopt(Some(raw));
            assert_eq!(context.trace_id.len(), 32, "{raw:?}");
            assert_ne!(
                context.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736",
                "a rejected header must not leak into the new trace: {raw:?}"
            );
        }
    }

    #[test]
    fn an_absent_header_mints_a_usable_id() {
        let context = TraceContext::adopt(None);
        assert_eq!(context.trace_id.len(), 32);
        assert_eq!(context.parent_id.len(), 16);
        assert!(context.trace_id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(context.trace_id.bytes().any(|b| b != b'0'));
    }

    #[test]
    fn minted_ids_do_not_repeat() {
        // The clock has millisecond-ish resolution in practice, so ids minted in
        // one tight loop would collide without the counter — which is exactly
        // the pattern a burst of requests produces.
        let ids: std::collections::HashSet<String> = (0..1000).map(|_| mint(32)).collect();
        assert_eq!(ids.len(), 1000, "minted trace ids collided");
    }

    #[test]
    fn what_goes_out_is_what_a_receiver_can_parse() {
        let context = TraceContext::adopt(Some(VALID));
        let outgoing = context.outgoing("aaaaaaaaaaaaaaaa");

        // Round-tripping is the actual contract: the next hop runs the same
        // parser, so anything this emits and that cannot parse is a broken
        // trace nobody notices until they go looking for a span.
        let received = parse(&outgoing).expect("our own output must parse");
        assert_eq!(received.trace_id, context.trace_id);
        assert_eq!(
            received.parent_id, "aaaaaaaaaaaaaaaa",
            "the outgoing parent must be this hop, or the next span is a sibling"
        );
        assert_eq!(received.flags, context.flags);
    }

    #[test]
    fn a_minted_context_also_round_trips() {
        let context = TraceContext::adopt(None);
        let outgoing = context.outgoing(&current_span_id());
        assert_eq!(
            parse(&outgoing).map(|c| c.trace_id),
            Some(context.trace_id),
            "a generated id must be as valid on the wire as an adopted one"
        );
    }
}
