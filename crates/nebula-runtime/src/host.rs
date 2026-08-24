//! Host functions and the single guest-memory access path.
//!
//! See README.md §7. The set of imports registered here *is* the security
//! policy — a guest can reach nothing the linker did not hand it.

use std::ops::Range;

use wasmtime::{Caller, Extern, Linker, Result, Trap};

use crate::kv;
use crate::{egress, HostCtx};

/// Cap on one `nebula.log` payload (§6.4). An unbounded copy out of guest
/// memory is a trust-boundary hole, not a nicety: without this, one guest can
/// make the host allocate until it dies.
pub const MAX_LOG_BYTES: u32 = 4096;

/// Cap on the response a guest may accumulate (§6.4).
pub const MAX_RESPONSE_BYTES: usize = 1 << 20; // 1 MiB

/// Cap on captured stdout/stderr per request. WASI writes past this trap
/// inside the pipe rather than growing the host buffer.
pub const MAX_STDIO_BYTES: usize = 64 << 10; // 64 KiB

/// Bounds check for a guest `(ptr, len)` pair.
///
/// This is the only place a guest pointer is validated (§13, invariant 1);
/// everything else routes through it. It is split out from [`guest_slice`] so
/// it is directly testable — a `Caller` cannot be fabricated outside a live host
/// call, and this is the arithmetic that actually has to be right.
///
/// The addition is checked in `u32`, the width a guest can express. Widening to
/// `usize` first would make the overflow case unreachable on 64-bit hosts and
/// silently delete half of this check.
pub fn checked_range(mem_len: usize, ptr: u32, len: u32) -> Result<Range<usize>, Trap> {
    let end = ptr.checked_add(len).ok_or(Trap::MemoryOutOfBounds)?;
    if end as usize > mem_len {
        return Err(Trap::MemoryOutOfBounds);
    }
    Ok(ptr as usize..end as usize)
}

/// A validated slice of guest memory together with `&mut HostCtx`.
///
/// Host functions that move bytes between host state and guest memory need both
/// at once; without this they would have to clone the host side just to satisfy
/// the borrow checker. Bounds checking still goes through [`checked_range`].
///
/// Never hold the returned borrow across a guest re-entry: `memory.grow` may
/// reallocate the backing store and invalidate it.
pub fn guest_slice_and_ctx<'a>(
    caller: &'a mut Caller<'_, HostCtx>,
    ptr: u32,
    len: u32,
) -> Result<(&'a mut [u8], &'a mut HostCtx), Trap> {
    let memory = caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or(Trap::MemoryOutOfBounds)?;
    let range = checked_range(memory.data_size(&*caller), ptr, len)?;
    let (data, ctx) = memory.data_and_store_mut(caller);
    Ok((&mut data[range], ctx))
}

/// The path from a guest pointer to host-readable bytes (§7.3), for host
/// functions that do not also need the context.
pub fn guest_slice<'a>(
    caller: &'a mut Caller<'_, HostCtx>,
    ptr: u32,
    len: u32,
) -> Result<&'a mut [u8], Trap> {
    guest_slice_and_ctx(caller, ptr, len).map(|(slice, _)| slice)
}

/// Registers the `nebula` namespace on `linker` (§7.2).
///
/// Integer returns follow one convention throughout: a non-negative count on
/// success, `-1` on refusal. Refusals are recoverable conditions the guest can
/// handle — the precedent is WebAssembly's own `memory.grow`. Traps are reserved
/// for a guest that hands the host an invalid pointer, which is not recoverable.
pub fn add_to_linker(linker: &mut Linker<HostCtx>) -> Result<()> {
    linker.func_wrap(
        "nebula",
        "log",
        |mut caller: Caller<'_, HostCtx>, level: i32, ptr: u32, len: u32| -> Result<()> {
            // Bounds-check the range the guest actually claimed, *then* truncate
            // what we copy. Truncating first would let an out-of-bounds request
            // slip through as an in-bounds short read.
            let message = {
                let bytes = guest_slice(&mut caller, ptr, len)?;
                let take = len.min(MAX_LOG_BYTES) as usize;
                // Guest-controlled bytes. Malformed UTF-8 is a guest bug, not
                // something the host should trap on.
                String::from_utf8_lossy(&bytes[..take]).into_owned()
            };
            caller.data_mut().logs.push((level, message));
            Ok(())
        },
    )?;

    linker.func_wrap(
        "nebula",
        "request_len",
        |caller: Caller<'_, HostCtx>| -> i32 { caller.data().request.len() as i32 },
    )?;

    // One-shot copy from the start of the body, not a cursor: the contract is
    // `request_len` then a single `request_read` into a buffer of that size.
    // Returns the number of bytes written.
    linker.func_wrap(
        "nebula",
        "request_read",
        |mut caller: Caller<'_, HostCtx>, ptr: u32, len: u32| -> Result<i32> {
            let (dst, ctx) = guest_slice_and_ctx(&mut caller, ptr, len)?;
            let n = dst.len().min(ctx.request.len());
            dst[..n].copy_from_slice(&ctx.request[..n]);
            Ok(n as i32)
        },
    )?;

    // Appends and returns the number of bytes accepted. A short return means the
    // response cap was reached; the guest can detect that, which silent
    // truncation would not allow.
    linker.func_wrap(
        "nebula",
        "response_write",
        |mut caller: Caller<'_, HostCtx>, ptr: u32, len: u32| -> Result<i32> {
            let (src, ctx) = guest_slice_and_ctx(&mut caller, ptr, len)?;
            let room = MAX_RESPONSE_BYTES.saturating_sub(ctx.response.len());
            let n = src.len().min(room);
            ctx.response.extend_from_slice(&src[..n]);
            Ok(n as i32)
        },
    )?;

    // Returns the value's full length so the guest can detect truncation, or
    // `-1` if the key is absent. At most `vlen` bytes are written.
    linker.func_wrap(
        "nebula",
        "kv_get",
        |mut caller: Caller<'_, HostCtx>,
         kptr: u32,
         klen: u32,
         vptr: u32,
         vlen: u32|
         -> Result<i32> {
            if klen as usize > kv::MAX_KEY_BYTES {
                return Ok(-1);
            }
            let key = guest_slice(&mut caller, kptr, klen)?.to_vec();
            let ctx = caller.data();
            let Some(value) = ctx.kv().get(&ctx.tenant, &key) else {
                return Ok(-1);
            };
            let dst = guest_slice(&mut caller, vptr, vlen)?;
            let n = dst.len().min(value.len());
            dst[..n].copy_from_slice(&value[..n]);
            Ok(value.len() as i32)
        },
    )?;

    // `0` on success, `-1` if the item is oversized or the node is at capacity.
    // The size checks happen before any copy, so an oversized request costs a
    // comparison rather than an allocation.
    linker.func_wrap(
        "nebula",
        "kv_set",
        |mut caller: Caller<'_, HostCtx>,
         kptr: u32,
         klen: u32,
         vptr: u32,
         vlen: u32|
         -> Result<i32> {
            if klen as usize > kv::MAX_KEY_BYTES || vlen as usize > kv::MAX_VALUE_BYTES {
                return Ok(-1);
            }
            let key = guest_slice(&mut caller, kptr, klen)?.to_vec();
            let value = guest_slice(&mut caller, vptr, vlen)?.to_vec();
            let ctx = caller.data();
            Ok(match ctx.kv().set(&ctx.tenant, &key, &value) {
                Ok(()) => 0,
                Err(kv::Rejected) => -1,
            })
        },
    )?;

    // §22.8. Writes the raw HTTP response — status line, headers, blank line,
    // body — into the guest buffer and returns its full length, or `-1` on any
    // refusal. The full length rather than the written length so a guest can
    // detect truncation, which is the `kv_get` convention.
    //
    // The whole response rather than just the body: a script that cannot tell
    // `200` from `404` will parse an error page as data.
    linker.func_wrap(
        "nebula",
        "http_get",
        |mut caller: Caller<'_, HostCtx>,
         url_ptr: u32,
         url_len: u32,
         out_ptr: u32,
         out_len: u32|
         -> Result<i32> {
            // The URL is read and copied out before anything else touches guest
            // memory: the fetch re-enters nothing, but holding a borrow across
            // a call that can take seconds is a habit worth not having.
            let url = {
                let bytes = guest_slice(&mut caller, url_ptr, url_len)?;
                String::from_utf8_lossy(bytes).into_owned()
            };

            let (policy, budget) = {
                let ctx = caller.data();
                (ctx.egress.clone(), ctx.remaining_budget())
            };

            let response = match egress::fetch(&policy, &url, budget) {
                Ok(response) => response,
                Err(refusal) => {
                    // The reason goes to the host's logs and the guest gets a
                    // `-1` (§7.2). Telling a guest *why* a host is blocked
                    // turns the allowlist into an oracle it can enumerate.
                    tracing::info!(%refusal, "egress refused");
                    caller
                        .data_mut()
                        .logs
                        .push((3, format!("http_get refused: {refusal}")));
                    return Ok(-1);
                }
            };

            let dst = guest_slice(&mut caller, out_ptr, out_len)?;
            let written = dst.len().min(response.len());
            dst[..written].copy_from_slice(&response[..written]);
            Ok(response.len() as i32)
        },
    )?;

    Ok(())
}
