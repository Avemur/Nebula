//! Host functions and the single guest-memory access path.
//!
//! See DESIGN.md §7. The set of imports registered here *is* the security
//! policy — a guest can reach nothing the linker did not hand it.

use std::ops::Range;

use wasmtime::{Caller, Extern, Linker, Result, Trap};

use crate::HostCtx;

/// Cap on one `nebula.log` payload (§6.4). An unbounded copy out of guest
/// memory is a trust-boundary hole, not a nicety: without this, one guest can
/// make the host allocate until it dies.
pub const MAX_LOG_BYTES: u32 = 4096;

/// Bounds check for a guest `(ptr, len)` pair.
///
/// Split out of [`guest_slice`] purely so it is directly testable — a `Caller`
/// cannot be fabricated outside a live host call, and this is the arithmetic
/// that actually has to be right.
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

/// The only path from a guest pointer to host-readable bytes (§7.3).
///
/// Every host function touching guest memory goes through here. No exceptions —
/// see DESIGN.md §13, invariant 1.
///
/// Never hold the returned borrow across a guest re-entry: `memory.grow` may
/// reallocate the backing store and invalidate it.
pub fn guest_slice<'a>(
    caller: &'a mut Caller<'_, HostCtx>,
    ptr: u32,
    len: u32,
) -> Result<&'a mut [u8], Trap> {
    let mem = caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or(Trap::MemoryOutOfBounds)?;
    let range = checked_range(mem.data_size(&*caller), ptr, len)?;
    Ok(&mut mem.data_mut(caller)[range])
}

/// Registers the `nebula` namespace on `linker` (§7.2).
///
/// Only `log` exists so far; request/response and the KV shim land next.
pub fn add_to_linker(linker: &mut Linker<HostCtx>) -> Result<()> {
    linker.func_wrap(
        "nebula",
        "log",
        |mut caller: Caller<'_, HostCtx>, level: i32, ptr: u32, len: u32| -> Result<()> {
            // Bounds-check the range the guest actually claimed, *then* truncate
            // what we copy. Truncating first would let an out-of-bounds request
            // slip through as an in-bounds short read.
            let msg = {
                let bytes = guest_slice(&mut caller, ptr, len)?;
                let take = len.min(MAX_LOG_BYTES) as usize;
                // Guest-controlled bytes. Malformed UTF-8 is a guest bug, not
                // something the host should trap on.
                String::from_utf8_lossy(&bytes[..take]).into_owned()
            };
            caller.data_mut().logs.push((level, msg));
            Ok(())
        },
    )?;
    Ok(())
}
