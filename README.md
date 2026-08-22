# Nebula — Design Document

**Project:** Distributed WebAssembly Serverless Runtime
**Author:** Anirudh Vemuri

---

## Table of Contents

1. [Motivation & Goals](#1-motivation--goals)
2. [Non-Goals](#2-non-goals)
3. [Architecture Overview](#3-architecture-overview)
4. [Request Lifecycle](#4-request-lifecycle)
5. [The Execution Core](#5-the-execution-core)
6. [Sandboxing & Resource Limits](#6-sandboxing--resource-limits)
7. [The Host Interface](#7-the-host-interface)
8. [Module Lifecycle & Caching](#8-module-lifecycle--caching)
9. [Distribution: Scheduling & Routing](#9-distribution-scheduling--routing)
10. [Fault Tolerance & Load Management](#10-fault-tolerance--load-management)
11. [Interfaces](#11-interfaces)
12. [Error Taxonomy](#12-error-taxonomy)
13. [Threat Model](#13-threat-model)
14. [Observability](#14-observability)
15. [Testing Strategy](#15-testing-strategy)
16. [Technology Stack](#16-technology-stack)
17. [Repository Layout](#17-repository-layout)
18. [Implementation Phases](#18-implementation-phases)
19. [Benchmark Methodology & Success Criteria](#19-benchmark-methodology--success-criteria)
20. [Risks & Open Questions](#20-risks--open-questions)
21. [Deferred Work](#21-deferred-work)

---

## 1. Motivation & Goals

Serverless platforms built on microVMs (Firecracker) or containers pay a
process-creation tax on every cold start: 200 ms to 1 s+. That tax exists
because the isolation boundary is the operating system, and constructing an OS
boundary is expensive.

WebAssembly moves the isolation boundary into the compiler. A WASM module is
memory-safe by construction, has no ambient authority, and instantiates in
microseconds rather than milliseconds. Nebula is a distributed, multi-tenant
compute engine that uses this to reach hot-start latencies three orders of
magnitude below a microVM platform.

### Goals

| # | Goal | Measured by |
|---|------|-------------|
| G1 | Sub-millisecond hot-start execution | p99 instantiate+execute of a trivial handler, in-process, < 1 ms |
| G2 | Cold start an order of magnitude below microVMs | p99 end-to-end cold start < 50 ms for a ≤ 2 MiB module |
| G3 | Safe execution of untrusted multi-tenant code | Adversarial guest corpus (§15) cannot crash, hang, or starve a worker |
| G4 | Deterministic, enforced resource ceilings | Every limit in §6 has a test that proves the trap fires |
| G5 | Survive node loss without operator action | Killing a worker under load reroutes traffic within 3 s, zero 5xx after reconvergence |
| G6 | Survive overload without cascading failure | At 5× capacity, the cluster sheds cleanly rather than OOMs |

### Design principles

- **Lean on the engine.** Wasmtime already solves AOT caching, CoW memory
  images, pooling allocation, and deterministic traps. Nebula's job is the
  distributed system around it, not a second-rate reimplementation of it.
- **Guest faults are data, not errors.** A trap is the expected outcome of
  running untrusted code. It flows back as a typed result, never as a
  transport-layer error.
- **Every phase ships something runnable.** Vertical slices, not horizontal
  layers.

---

## 2. Non-Goals

Explicitly out of scope. Each of these is a legitimate feature that Nebula
deliberately does not build, because building it would trade away the schedule
without teaching anything the project is about.

- **Not a container replacement.** No arbitrary syscalls, no `fork`/`exec`, no
  subprocess spawning, no raw sockets. Guests get the host interface in §7 and
  nothing else.
- **No side-channel resistance.** Wasmtime's sandbox enforces memory safety, not
  timing isolation. Spectre-class cross-tenant leakage is an accepted risk (§13).
- **No autoscaling or node provisioning.** The worker set is fixed and started
  manually. The control plane reacts to nodes joining and leaving; it does not
  create them.
- **No multi-region, no geo-routing, no edge PoPs.** Single cluster, single
  region.
- **No billing, quota accounting, or per-tenant cost metering.**
- **No guest-visible persistent storage** beyond the host key-value shim (§7),
  which is per-node and non-durable.
- **No WASM threads or SIMD-dependent guest features in v1.** Single-threaded
  guests only.
- **No production identity system.** v1 uses a static bearer token per tenant
  (§13); real authentication is a deployment concern, not a runtime one.

---

## 3. Architecture Overview

Two binaries, one gRPC mesh.

```mermaid
flowchart TB
    Client([HTTP Client])

    subgraph CP["Control Plane (nebula-control)"]
        GW["API Gateway<br/>axum"]
        SCH["Scheduler<br/>consistent hash ring"]
        REG["Module Registry<br/>local disk"]
        MEM["Membership<br/>heartbeat tracker"]
    end

    subgraph W1["Worker Node (nebula-worker)"]
        RX1["gRPC Receiver<br/>tonic"]
        ADM1["Admission Semaphore"]
        POOL1["Blocking Exec Pool"]
        CACHE1["Module Cache (LRU)<br/>Module + InstancePre"]
        WT1["wasmtime Engine<br/>pooling allocator"]
    end

    subgraph W2["Worker Node (nebula-worker)"]
        RX2["..."]
    end

    Client -->|"POST /execute/:id"| GW
    GW --> SCH
    SCH -->|"Execute RPC"| RX1
    SCH -->|"Execute RPC"| RX2
    RX1 --> ADM1 --> POOL1 --> WT1
    CACHE1 <--> WT1
    RX1 -.->|"FetchModule (cold only)"| REG
    RX1 -.->|"Heartbeat every 500ms"| MEM
    MEM --> SCH
```

**Control Plane** — stateless with respect to execution; holds cluster
membership and the module registry. Horizontally replicable later, single
instance in v1.

**Worker Node** — owns a wasmtime `Engine`, a module cache, and a bounded
execution pool. Workers are interchangeable; the ring decides which one gets a
given function, and any worker can serve any function after a cold start.

The two components share nothing but the proto definitions. A worker never
talks to another worker.

---

## 4. Request Lifecycle

Three paths, distinguished by what the worker already has in memory.

### 4.1 Cold start — worker has never seen this module

1. **Ingress.** Gateway receives `POST /execute/{function_id}`, validates the
   bearer token and body size cap, assigns a request ID.
2. **Scheduling.** Scheduler hashes `function_id` onto the ring, selects the
   owning worker. Falls through to the next node on the ring if the owner is
   unhealthy.
3. **Dispatch.** `Execute` RPC to the worker with the function ID, a module
   content hash, and the request body.
4. **Cache miss.** Worker has no module for that hash. It issues a
   `FetchModule` server-streaming RPC back to the control plane's registry.
5. **Transfer.** Registry streams the artifact in 256 KiB chunks. Worker
   verifies the SHA-256 against the requested hash.
6. **Compile.** Worker checks its on-disk AOT cache
   (`Module::deserialize_file`). On miss, `Module::new` compiles, and the
   result is serialized to disk for next time. The `Module` is inserted into
   the LRU cache alongside a pre-resolved `InstancePre`.
7. **Execute.** Falls into the hot path below.

**Design note — why the worker pulls through the control plane rather than
from object storage.** In v1 the registry *is* local disk on the control plane
node, so there is nowhere else to pull from. This does put the control plane
on the data path for cold starts. It is acceptable because cold starts are
rare by construction (the ring pins functions to nodes) and the transfer is
one-shot per module per worker. When the registry moves to S3, workers pull
directly and the control plane leaves the data path entirely.

### 4.2 Hot start — module compiled and cached

1. Ingress and scheduling as above; the ring routes to the same worker.
2. **Cache hit.** LRU lookup by content hash returns the `InstancePre<HostCtx>`.
3. **Admission.** Acquire a permit from the concurrency semaphore. No permit
   available → shed immediately (§10.3).
4. **Instantiate.** A fresh `Store` is created and `InstancePre::instantiate`
   allocates an instance from the pooling allocator. Imports are already
   resolved; linear memory comes from a CoW mapping of the module's memory
   image. No compilation, no import resolution, no page zeroing.
5. **Execute.** The call runs on the blocking execution pool (§5.2) under an
   epoch deadline. Result is copied out of guest memory.
6. **Teardown.** `Store` is dropped, the instance slot returns to the pool, and
   the CoW mapping is discarded — dirtied pages are dropped, not scrubbed, so
   no cross-request state can survive.

**Every request gets a fresh `Store` and a fresh instance.** The cached object
is the compiled `Module`/`InstancePre`, which is immutable and `Send + Sync`.
Instances are never reused across requests in v1; this is what makes tenant
isolation trivially correct.

### 4.3 Pre-initialized start — heavy guest runtimes

Compiling is fast; *booting* is not. A guest embedding a language runtime or a
framework may spend tens of milliseconds in `_initialize` allocating its heap
before it ever sees a request. Paying that on every instantiation defeats the
point.

**This is solved at build time, not at run time.**
[Wizer](https://github.com/bytecodealliance/wizer) runs the module's
`_initialize` ahead of time and snapshots the resulting linear memory *back
into the module's own data segments*, emitting a new `.wasm`. Wasmtime then
does the rest for free: with `memory_init_cow` enabled (the default), the
module's memory image is mmap'd copy-on-write into every new instance.

So the "zero-boot-time path" is:

- **Deploy time:** `wizer input.wasm -o initialized.wasm`, store the
  pre-initialized artifact in the registry.
- **Run time:** nothing. It is the hot path from §4.2, and the boot cost is
  already paid.

**The runtime needs no flag for this, and does not have one.** Wizer drops the
init export after consuming it, so the runtime rule is simply the WASI reactor
convention: *call `_initialize` if the module exports it, then call the
handler*. A raw module still exports it and pays the boot on every request; a
wizened module does not export it and there is nothing to call. One code path,
and the export's absence is the entire signal.

**Measured** (`crates/nebula-runtime/tests/wizer_bench.rs`, `heavy_init` guest —
a 200k sieve kept on the heap plus a hash chain, ~22 ms of boot):

| | Median execution | Share of the 50 ms deadline |
|---|---|---|
| Raw | 20.5 ms | 41% |
| Wizened | 0.25 ms | 0.5% |
| | **~80× faster** | |

Both emit an identical result, which the test asserts — a module that skipped
the work would otherwise look like a win. The share-of-budget column is the
operationally interesting half: the raw guest burns two fifths of its request
budget before the handler starts, and roughly 2.4× this boot cost would exceed
the deadline outright and fail the request.

> **Superseded:** the original spec proposed freezing and `mmap`-ing linear
> memory snapshots inside the worker. That is a reimplementation of
> `memory_init_cow`, and the hard part — capturing post-`_initialize` state as
> something a fresh instance can start from — is exactly what Wizer does. Cut.

---

## 5. The Execution Core

`nebula-runtime` is a standalone library crate with no networking. It owns the
wasmtime embedding and knows nothing about gRPC, HTTP, or clustering. The
worker binary is a thin shell around it. This is what makes the sandbox
testable and benchmarkable without a cluster.

### 5.1 Engine configuration

One `Engine` per process, shared across all tenants. Engine construction is
expensive; instance creation is not.

```rust
let mut cfg = Config::new();
cfg.epoch_interruption(true);           // wall-clock deadlines (§6.1)
cfg.consume_fuel(false);                // opt-in per function (§6.2)
cfg.memory_init_cow(true);              // CoW memory images (§4.3)
cfg.max_wasm_stack(512 * 1024);         // bound guest stack depth
cfg.wasm_threads(false);                // single-threaded guests only
cfg.cranelift_opt_level(OptLevel::Speed);
cfg.allocation_strategy(InstanceAllocationStrategy::Pooling(pooling_cfg()));
```

The **pooling allocator** is what makes G1 reachable. It pre-reserves instance
slots, linear memory regions, and tables at startup, so instantiation is a slot
handoff plus an mmap rather than a set of fresh allocations. It also gives a
hard ceiling on concurrent instances, which is a resource limit in its own
right (§6.4).

> **API versions.** Names above track the wasmtime 2x series. Pin one exact
> version in `Cargo.toml` at the start of Phase 1 and verify each call against
> that version's docs — this API surface moves between releases (`add_fuel` →
> `set_fuel`, WASI p1 → p2 bindings). Do not upgrade mid-phase.

### 5.2 Execution is blocking work, not async work

**This is the single most important structural decision in the runtime.**

A WASM call is synchronous, CPU-bound, and may run for the full epoch deadline.
Calling it directly from a tokio task pins an async worker thread for the whole
duration. With a default multi-threaded runtime of N threads, N concurrent
executions stall the reactor: heartbeats stop, health checks time out, the
control plane declares a healthy node dead, and load sheds off a node that is
merely busy. Under sustained load this is indistinguishable from a crash.

Nebula therefore keeps two thread populations:

- **The async runtime** (`tokio`, default worker count) handles gRPC framing,
  registry streaming, heartbeats, and admission control. It never blocks.
- **The execution pool**, a dedicated fixed-size pool sized to available cores,
  runs `Store` creation, instantiation, and the guest call. Work is handed to
  it over a bounded channel; the async side awaits a `oneshot` for the result.

A bounded channel is deliberate: a full channel is the backpressure signal that
feeds admission control (§10.3). Queue depth is itself an SLI.

The `Store<HostCtx>` never crosses an `.await`. It is created, used, and
dropped entirely inside one pool task.

> `tokio::task::spawn_blocking` is the obvious first implementation and is
> correct. It is rejected as the *final* design only because its pool is
> unbounded by default and shared with other blocking work, which erases the
> backpressure signal. Phase 1 uses `spawn_blocking`; Phase 3 replaces it with
> the dedicated bounded pool when load shedding lands.

### 5.3 Async host functions

Host functions that perform I/O (the KV shim, future outbound HTTP) present a
mismatch: the guest call is synchronous, but the host work is async. Two
options:

1. **Block inside the host function** on a channel round-trip to the async
   runtime. Simple, correct, and the executing thread is a pool thread that is
   *supposed* to block — it costs nothing that matters.
2. **`Config::async_support(true)`** with `call_async`, which requires guest
   execution on the async runtime and reintroduces §5.2's problem.

**Decision: option 1.** Synchronous engine; host functions block on a channel
round-trip to the async side when they need I/O. Revisit only if host I/O
becomes a measured bottleneck.

---

## 6. Sandboxing & Resource Limits

The guest is assumed hostile. Every dimension along which it could consume
unbounded resources has an explicit ceiling and a test that proves the ceiling
fires (§15).

### 6.1 CPU time: epoch interruption (default)

A background ticker thread calls `Engine::increment_epoch()` on a fixed
interval. Each `Store` is given a deadline in ticks via
`Store::set_epoch_deadline`. Wasmtime emits a cheap counter check at loop
back-edges and function entries; exceeding the deadline raises a trap that
unwinds the guest without touching the host.

- **Tick interval:** 1 ms. This is also the deadline granularity — a 50 ms
  budget is enforced to within ±1 ms.
- **Overhead:** a relaxed atomic load and compare on back-edges. Negligible.
- **Not deterministic:** the same input can consume different wall-clock time
  across runs. Accepted for the default path.

### 6.2 CPU instructions: fuel (opt-in)

`Config::consume_fuel(true)` plus `Store::set_fuel(n)` charges every instruction
against a budget, trapping deterministically at zero. Identical input always
traps at the identical instruction.

Fuel costs 1.3–2× throughput on compute-bound code, because metering is
instrumented into the compiled output. That is too expensive to impose on every
tenant for a guarantee most do not need.

**Decision: epochs are the default; fuel is a per-function opt-in** for
workloads that need reproducibility (replay, deterministic simulation,
instruction-count billing, and the stateful actors of §21 if they land).
Enabling fuel requires a separate `Engine` — `consume_fuel` is engine-level
config baked into compiled code — so the worker holds two engines and routes by
function metadata.

> **Superseded:** the original spec made fuel the sole CPU mechanism. Fuel
> answers "how many instructions did this execute," which is not the question a
> request timeout asks.

### 6.3 Memory

Linear memory grows in 64 KiB pages. Growth requests are intercepted by a
`ResourceLimiter` installed on the `Store`:

```rust
let limits = StoreLimitsBuilder::new()
    .memory_size(128 << 20)   // 128 MiB hard ceiling
    .memories(1)
    .instances(1)
    .tables(1)
    .table_elements(10_000)
    .build();
store.limiter(|ctx| &mut ctx.limits);
```

A `memory.grow` beyond the ceiling returns `-1` to the guest per the WASM spec.
A well-written guest handles this; a naive one traps on the subsequent access.
Both are contained.

Under the pooling allocator, per-slot memory reservation is configured on
`PoolingAllocationConfig` and must be ≥ the `StoreLimits` ceiling, or
instantiation fails before the limiter ever runs.

**The two numbers are deliberately different, not one constant used twice.** The
pooling slot (`POOL_MAX_MEMORY_BYTES`, 256 MiB) is the largest ceiling any
function may ever be granted, because the slot is a fixed reservation made at
startup. `StoreLimits` (`MAX_MEMORY_BYTES`, 128 MiB default) is *this function's*
policy, and is what per-function registry overrides will vary. Setting them equal
has a specific failure mode: the pool silently enforces the same number, so
dropping the per-store limiter changes nothing observable and no test catches it.
Keeping the slot strictly above the default ceiling makes the limiter the binding
constraint and the pool the backstop — see
`store_limiter_refuses_growth_the_pooling_slot_would_allow`, which fails if the
limiter is ever removed.

### 6.4 Full limit table

| Dimension | Mechanism | v1 default |
|---|---|---|
| Wall-clock CPU | epoch deadline | 50 ms |
| Instructions (opt-in) | fuel | 1 × 10⁹ |
| Linear memory (per function) | `StoreLimits` | 128 MiB |
| Linear memory (pooling slot reservation) | `PoolingAllocationConfig` | 256 MiB |
| Guest stack | `Config::max_wasm_stack` | 512 KiB |
| Table elements | `StoreLimits` | 10 000 |
| Instances per `Store` | `StoreLimits` | 1 |
| Concurrent instances per worker | pooling `total_memories` | 64 |
| Concurrent executions per worker | admission semaphore | = pool size |
| Request body | axum `DefaultBodyLimit` | 1 MiB |
| Response body | host-side cap on guest write | 1 MiB |
| Module artifact size | registry validation at deploy | 32 MiB |
| Total request incl. host I/O | tokio `timeout` at gateway | 100 ms |
| KV entries / bytes per node | host shim caps | 10 000 / 16 MiB |
| KV key / value size | host shim caps | 1 KiB / 64 KiB |
| Captured stdout+stderr per request | `MemoryOutputPipe` capacity | 64 KiB each |

Every default is a named constant in one config module, overridable per
function through registry metadata. No magic numbers at call sites.

---

## 7. The Host Interface

A WASM guest has no ambient authority. It can compute, and it can call imports
the host chose to provide. The set of imports *is* the security policy.

### 7.1 WASI

WASI preview 1 via `wasmtime-wasi`, with a deliberately minimal `WasiCtx`:

- **stdout / stderr:** captured to per-request in-memory buffers, surfaced as
  structured log fields. Never inherited from the host.
- **stdin:** empty.
- **Filesystem:** no preopened directories. Every path operation fails.
- **Clocks:** coarse monotonic and wall clock. See §13 on timing.
- **Random:** host CSPRNG.
- **Environment / args:** only what the registry entry declares, never the
  host's real environment.
- **Sockets:** absent.

WASI preview 2 / the component model is the eventual destination and gives a
much better story for typed host interfaces. It is not v1: preview 1 is what
every current guest toolchain reliably emits.

### 7.2 Nebula host functions

Registered on the `Linker` under the `nebula` module namespace:

| Import | Signature | Purpose |
|---|---|---|
| `nebula.request_len` | `() -> i32` | Size of the pending request body |
| `nebula.request_read` | `(ptr: i32, len: i32) -> i32` | Copy request body into guest memory |
| `nebula.response_write` | `(ptr: i32, len: i32) -> i32` | Append to the response buffer (capped) |
| `nebula.kv_get` | `(kptr, klen, vptr, vlen) -> i32` | Read from the node-local KV shim |
| `nebula.kv_set` | `(kptr, klen, vptr, vlen) -> i32` | Write to the node-local KV shim |
| `nebula.log` | `(level: i32, ptr, len)` | Emit a structured log line |

The KV shim is **node-local and non-durable** — a `DashMap` keyed by
`(tenant, key)` *tuples*, not by a concatenated prefix, and bounded per §6.4.
The tuple matters: a delimiter scheme needs an argument about escaping before
you can believe one tenant cannot spell its way into another's namespace, and a
tuple needs none. It exists to exercise host-call plumbing and memory
translation, not to be a database. Guests must not assume a value written on one
request is visible on the next.

Integer returns across the `nebula` namespace follow one convention: a
non-negative count on success, `-1` on refusal. A refusal (store full, item
oversized) is a recoverable condition the guest can handle — the precedent is
WebAssembly's own `memory.grow` returning `-1`. Traps are reserved for a guest
that hands the host an invalid pointer, which is not recoverable. Silent
truncation is used only where the guest can detect it: `kv_get` returns the
value's full length even when it wrote fewer bytes, and `response_write` returns
the count it accepted.

### 7.3 Memory translation

Guest pointers are `u32` offsets into the guest's own linear memory. They are
attacker-controlled and mean nothing to the host until validated.

Every host function that touches guest memory goes through one helper:

```rust
fn guest_slice<'a>(caller: &'a mut Caller<'_, HostCtx>, ptr: u32, len: u32)
    -> Result<&'a mut [u8], Trap>
{
    let mem = caller.get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or(Trap::MemoryOutOfBounds)?;
    let data = mem.data_mut(caller);
    let end = (ptr as usize).checked_add(len as usize)   // overflow -> trap
        .ok_or(Trap::MemoryOutOfBounds)?;
    data.get_mut(ptr as usize..end).ok_or(Trap::MemoryOutOfBounds)
}
```

**One function. Every host call routes through it. No exceptions.** Checked
arithmetic on the bound, a slice index that cannot reach outside the memory,
and a trap on any failure. Borrows are never held across a guest re-entry —
`memory.grow` may reallocate the backing store and invalidate them.

This is a trust boundary and is not subject to simplification. It gets direct
unit tests for `ptr + len` overflow, `ptr` past the end, `len` past the end,
zero-length at the boundary, and a post-`grow` re-borrow.

---

## 8. Module Lifecycle & Caching

### 8.1 Identity

Modules are addressed by **SHA-256 of the artifact bytes**, not by
`function_id`. `function_id` is a mutable pointer to a content hash held in the
registry. This makes the cache trivially correct across deploys: a new version
is a new hash and a new cache entry; the old one ages out. No invalidation
protocol, no staleness window, no cache-busting RPC.

### 8.2 Three cache tiers

| Tier | Contents | Scope | Populated by |
|---|---|---|---|
| L1 — memory | `Module` + `InstancePre<HostCtx>` | Per worker process | Compile or AOT load |
| L2 — disk | `Module::serialize()` bytes | Per worker node, survives restart | First compile |
| L3 — registry | Original `.wasm` artifact | Cluster | Deploy |

A cold start walks L1 → L2 → L3, populating on the way back down. A worker
restart replays from L2 and skips Cranelift entirely.

`Module::deserialize` is `unsafe` — it maps precompiled machine code and trusts
its provenance. The L2 cache is keyed by
`sha256(artifact) + wasmtime_version + engine_config_hash + target_triple`, and
a mismatch on any component is a miss, not a load. Nothing outside the worker
can write to it.

### 8.3 The LRU cache

`Module` is `Send + Sync` and internally reference-counted, so the cache holds
`Arc<CachedModule>` and clones are cheap. A `Mutex<LruCache<Hash, Arc<..>>>`
guards the map; the lock is held only for lookup and insert, never across
compilation or execution.

**Eviction is bounded by memory, not entry count.** A count-based cache holding
sixty 30 MiB modules is an OOM. Each entry's cost is estimated from its
serialized size; the cache evicts LRU-first until the total is under a
configured budget (default 1 GiB).

Concurrent cold starts for the same hash must not compile the same module N
times. A per-hash in-flight map lets the first request compile while the rest
await a broadcast — the standard single-flight pattern, roughly twenty lines.

`InstancePre` is built once at insert. It resolves and type-checks every import
ahead of time, so per-request instantiation skips the entire linking step. This
is a meaningful fraction of the hot-path budget and is free to adopt.

---

## 9. Distribution: Scheduling & Routing

### 9.1 Consistent hashing

The scheduler maps `function_id` onto a hash ring so that repeated requests for
a function reach the same worker, converting what would be a cluster-wide cold
start into a single one.

```
ring: BTreeMap<u64, NodeId>          // virtual node hash -> physical node

insert(node):  for i in 0..V { ring.insert(hash(node.id, i), node) }
lookup(key):   ring.range(hash(key)..).next()
                   .or_else(|| ring.iter().next())   // wrap the ring
                   .map(|(_, n)| n)
```

Stdlib `BTreeMap::range` is the whole algorithm. No crate, no sorted-vec
maintenance, no binary search to write.

**Virtual nodes (V = 160 per physical node) are mandatory, not an
optimization.** With one point per node, a 4-node cluster produces arc lengths
that differ by 3–4×, and one worker takes the majority of traffic. The original
spec's "hash the `function_id` to a node" is only balanced with virtual nodes
present.

**What V = 160 actually buys, measured.** Consistent hashing's load imbalance
falls off as roughly `1/√V`, so V = 160 gives about 8% — not "a few percent",
as an earlier draft of this document claimed. Over 200 key sets of 10 000 keys
on a 3-worker ring:

| median | p90 | max | over 10% |
|---|---|---|---|
| 8.0% | 9.9% | 11.6% | 17 of 200 |

So a 10% spread is the **typical** case at V = 160, not a guarantee, and a test
asserting 10% against a single key set is a coin flip that lands right about
11 times in 12. `crates/nebula-control/src/ring.rs` therefore keeps the
single-key-set assertion the requirement asks for *and* a sweep that asserts the
median, so a genuine regression is distinguishable from an unlucky draw.

Raising V is the lever if a hard worst-case bound is ever needed: the error
shrinks as `1/√V`, so a 10% worst case wants V ≈ 640. That is a deliberate
trade — 640 points per node makes ring rebuilds and memory four times heavier —
and §9.2's bounded-load check is the cheaper answer to the same problem, since
it corrects hotspots at request time rather than trying to eliminate them
structurally.

**Hashing.** The ring uses stdlib `DefaultHasher`. That is sound only while the
control plane is a single process (§2): the ring is rebuilt in memory from live
membership, never persisted and never compared across processes, so the hash
only has to be stable within one run — and `DefaultHasher` is explicitly not
stable across Rust releases. Replacing it with a fixed hash (§16 names xxhash)
is a prerequisite for replicating the control plane, not an optimization;
without it two instances on different toolchains would disagree about routing
and silently split the keyspace.

**Failover:** if the owning node is unhealthy, walk the ring to the next
*distinct* physical node. This is deliberately not replication — the second
node cold-starts. Correct, slower, and one line. Pre-warming replicas is
deferred (§21).

**Rebalance cost:** adding or removing a node remaps only ~1/N of the keyspace,
which is the entire reason for consistent hashing over `hash % N`.

### 9.2 Scheduling with load awareness

Pure consistent hashing routes by identity alone and will happily hammer a
saturated node while its neighbour idles. The scheduler therefore tracks each
worker's reported in-flight count (piggybacked on heartbeats) and applies
**bounded load**: if the ring's chosen node is above `c ×` mean cluster load
(`c = 1.25`), advance to the next node on the ring. This preserves cache
affinity in the common case and bleeds off hotspots at the tail.

---

## 10. Fault Tolerance & Load Management

### 10.1 Membership and liveness

Workers register with the control plane at startup, then send a **unary
`Heartbeat` RPC every 500 ms** carrying in-flight count, queue depth, cache
occupancy, and their generation ID.

The control plane records `last_seen: Instant` per node. A reconciliation task
runs every 500 ms and marks any node whose `last_seen` exceeds 1.5 s (three
missed beats) as unhealthy, removing its virtual nodes from the ring.

> **Superseded:** the original spec called for bidirectional gRPC streaming. A
> unary beat plus a timestamp is strictly simpler and detects *more* failure
> modes — a stream stays open through a wedged process or a stop-the-world
> pause, and reconnect logic is a whole state machine to get wrong. A stale
> timestamp catches process death, network partition, and livelock identically.

A **generation ID** (random per process start) lets the control plane detect a
worker that died and restarted between beats, so it can drop stale routing
state rather than assume continuity.

Recovery is symmetric: heartbeats resuming re-adds the node to the ring. No
operator action, no manual drain.

### 10.2 Failure handling on the request path

| Failure | Handling |
|---|---|
| Connection refused / DNS failure | Retry once on the next ring node. Safe: the request was never sent. |
| Timeout after send | **No retry.** The guest may have run and had effects. Return 502. |
| `RESOURCE_EXHAUSTED` (shed) | Try one more ring node, then 503 + `Retry-After`. |
| Guest trap / timeout / OOM | Not a failure of Nebula. Typed outcome, mapped per §12. |

**Retrying only on connection-establishment failure is a correctness decision,
not a tuning knob.** Nebula cannot know whether a guest's host calls were
idempotent, so it must not re-execute anything that may already have run.

### 10.3 Load shedding and backpressure

Little's Law: `L = λW`. Latency `W` grows without bound only if concurrency `L`
is unbounded at a given arrival rate `λ`. Bounding `L` bounds `W`. So the
control is a **concurrency limit, not a latency threshold**:

- **Worker admission.** A `tokio::sync::Semaphore` sized to the execution pool.
  `try_acquire` fails → return `RESOURCE_EXHAUSTED` immediately. Shedding is
  *fast*; a shed request costs microseconds and never touches the engine.
- **Queue bound.** The channel into the execution pool is bounded. A full
  channel is a second, earlier shed signal.
- **Gateway.** Translates `RESOURCE_EXHAUSTED` into `503` with `Retry-After`,
  after one attempt at the next ring node. It does not queue and does not
  retry-storm.

A p99-latency trigger measures the symptom after the queue has already filled;
the semaphore prevents the queue from filling. It is also fewer moving parts —
no histogram, no windowing, no controller to tune.

> `ponytail:` static concurrency limit. If measurement shows the right limit
> varies with workload mix, upgrade to an AIMD/Vegas-style adaptive limiter
> (the `tower` ecosystem has one). Not before.

### 10.4 What is deliberately not built

Circuit breakers, hedged requests, priority request queues, and speculative
retries are all absent. Each adds failure modes of its own, and none of them is
on the path to any goal in §1.

---

## 11. Interfaces

### 11.1 HTTP (client-facing)

```
POST /execute/{function_id}
  Authorization: Bearer <tenant-token>
  Content-Type: application/octet-stream
  X-Nebula-Partition-Key: <opt, reserved for §21>
  Body: <= 1 MiB
  ->  200 <response body>
      X-Nebula-Request-Id, X-Nebula-Worker, X-Nebula-Cold: true|false
      X-Nebula-Exec-Micros: <n>

PUT  /functions/{function_id}      # deploy: body is the .wasm artifact
     -> 201 { "content_hash": "...", "wizened": bool, "compile_micros": n }
GET  /functions/{function_id}      # metadata
GET  /healthz                      # gateway liveness
GET  /cluster                      # node list, ring occupancy, per-node load
GET  /metrics                      # Prometheus exposition
```

Deploy-time work happens on `PUT`: size validation, `Module::validate`, an
optional Wizer pass, hashing, and registry write. **Compilation errors surface
at deploy, not on a user's first request.**

**Deployment persistence.** The `function_id` → content-hash table lives in
`deployments.json` in the registry directory, written via a temporary and a
rename before the `PUT` is acknowledged — a client told its function is
deployed must not lose it to a restart a moment later. It is one file for the
whole table rather than a file per function, deliberately: a `function_id`
arrives from a URL, and the surest way not to have to defend it against path
traversal is never to put it in a path. A corrupt or unknown-version table is
an error that stops startup, not something to shrug off into an empty map —
silently starting empty would look like every function vanishing for no reason.

### 11.2 gRPC (internal)

```proto
service NebulaWorker {
  rpc Execute(ExecuteRequest) returns (ExecuteResponse);
  rpc Drain(DrainRequest) returns (DrainResponse);   // graceful shutdown
}

service NebulaControl {
  rpc Register(RegisterRequest) returns (RegisterResponse);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc FetchModule(FetchModuleRequest) returns (stream ModuleChunk);
}

message ExecuteRequest {
  string function_id   = 1;
  string content_hash  = 2;   // worker fetches if not cached
  bytes  body          = 3;
  string request_id    = 4;
  uint32 deadline_ms   = 5;
  optional string partition_key = 6;   // reserved, §21
}

message ExecuteResponse {
  Outcome outcome      = 1;
  bytes   body         = 2;
  string  fault_detail = 3;   // trap reason, empty on OK
  uint64  exec_micros  = 4;
  bool    cold         = 5;
  uint64  fuel_used    = 6;   // 0 when fuel disabled
}

enum Outcome {
  OK = 0; TRAP = 1; TIMEOUT = 2; FUEL_EXHAUSTED = 3;
  MEMORY_LIMIT = 4; MODULE_NOT_FOUND = 5; INTERNAL = 6;
}

message ModuleChunk { bytes data = 1; uint64 offset = 2; bool last = 3; }
```

**Guest faults are `Outcome` values inside a successful RPC, never gRPC status
codes.** A tenant's infinite loop is a normal Tuesday; it must not appear in
transport error rates, must not trip retry logic, and must not be
indistinguishable from a worker crash on a dashboard. gRPC error statuses are
reserved for things that are genuinely Nebula's fault.

---

## 12. Error Taxonomy

| Condition | `Outcome` / gRPC status | HTTP | Notes |
|---|---|---|---|
| Success | `OK` | 200 | |
| Guest trap (unreachable, OOB, div-by-zero) | `TRAP` | 500 + `X-Nebula-Fault: trap` | Detail in body |
| Epoch deadline exceeded | `TIMEOUT` | 504 | |
| Fuel exhausted | `FUEL_EXHAUSTED` | 504 | Only when opted in |
| Memory ceiling hit | `MEMORY_LIMIT` | 500 + `X-Nebula-Fault: memory_limit` | Guest's own fault; 5xx by convention |
| — | — | — | *The limiter records its refusal on the store (`engine::Limits`), and a failed execution after one is tagged `MemoryLimitExceeded`. Without that, a guest refused memory and then dereferencing the pointer reports `TRAP` — the symptom, not the cause.* |
| Unknown `function_id` | `MODULE_NOT_FOUND` | 404 | |
| Artifact fails validation at deploy | `INVALID_ARGUMENT` | 400 | Deploy path only |
| Artifact > 32 MiB / body > 1 MiB | — | 413 | Gateway-enforced |
| Missing or bad bearer token | — | 401 | |
| Worker sheds | `RESOURCE_EXHAUSTED` | 503 + `Retry-After` | After one ring retry |
| No healthy worker in ring | `UNAVAILABLE` | 503 | |
| Worker died mid-request | `UNAVAILABLE` | 502 | Never retried |
| Host-side bug | `INTERNAL` | 500 | Alerts; should be zero |

Guest fault detail is returned to the caller — it is their code. Host internal
error detail is **not**; it logs with the request ID and the client gets an
opaque 500.

---

## 13. Threat Model

**Adversary:** a tenant who fully controls the `.wasm` artifact and the request
body, and who wants to crash the worker, deny service to co-tenants, read
another tenant's data, or escape to the host.

### Defended

| Attack | Defense |
|---|---|
| Read/write outside guest memory | WASM linear-memory bounds checks; guest pointers are offsets, not addresses |
| Escape to host memory | No raw pointers cross the boundary; §7.3 is the only path and it is bounds-checked |
| Infinite loop / CPU hog | Epoch deadline (§6.1); traps without host involvement |
| Memory exhaustion | `ResourceLimiter` ceiling + pooling slot cap (§6.3) |
| Stack overflow | `max_wasm_stack`; guest stack is a bounded region, host stack untouched |
| Instance-count exhaustion | Pooling allocator hard cap + admission semaphore |
| Filesystem access | No WASI preopens; every path call fails |
| Network access | No socket imports exist |
| Reading host environment | `WasiCtx` env is explicitly constructed, never inherited |
| Cross-request state leakage | Fresh `Store` and fresh CoW memory per request; instances never reused |
| Cross-tenant KV access | Keys are `(tenant, key)` tuples supplied host-side; no choice of key bytes reaches another tenant |
| Poisoned AOT cache | L2 keyed by artifact hash + engine config + wasmtime version; worker-writable only |
| Compile bombs | Size cap and compile timeout at deploy time, not request time |

### Accepted risks

- **Timing side channels (Spectre class).** Wasmtime mitigates some variants
  (heap access masking, indirect-call guards) but co-tenancy on shared hardware
  is not side-channel-free. Mitigation is deployment-level — separate hardware
  for hostile-adjacent tenants — not runtime-level. Explicitly out of scope
  (§2).
- **Wall-clock timing observation.** Guests can read a clock and observe
  neighbours. Not addressed in v1; coarsening the clock is the known lever if it
  matters later.
- **Control-plane DoS.** The gateway is a single instance in v1 with no
  per-tenant rate limiting. Deployment concern.
- **v1 authentication is a static bearer token per tenant**, compared in
  constant time. Sufficient to prove the authorization *path* exists; not a
  credential system.
- **Internal gRPC is unauthenticated plaintext** on a trusted network. mTLS is a
  known, deferred hardening step.

### Invariants for review

Any change touching these gets scrutiny, regardless of how small the diff is:

1. Guest pointers are validated by §7.3 and nowhere else.
2. A `Store` is never shared or reused between requests.
3. Every `Store` has both a limiter and an epoch deadline before the guest runs.
4. No host function returns host-internal error detail to the guest.
5. `Module::deserialize` is called only on bytes from the worker's own L2 cache.

---

## 14. Observability

`tracing` throughout, with `tracing-opentelemetry` for spans and a Prometheus
exporter for metrics.

### Spans

```
request_received     { function_id, bytes, tenant }              [gateway]
└── route_to_worker  { worker, outcome }                          one per attempt

grpc_execute         { function_id, tenant, cold, outcome }       [worker]
├── fetch_module     { hash, bytes }                              cold only
└── wasm_execute     { tenant, deadline_ms, bytes }
    └── compile_l1   { bytes, source: aot|cranelift, compiled_bytes }   L1 miss only
```

`tracing-subscriber` with `FmtSpan::CLOSE` is the whole configuration: it prints
each span's duration as it closes, which is what turns the tree into a latency
breakdown rather than a log. No collector — `tracing` alone answers "where did
the time go", and a collector is infrastructure to run, not a question to
answer. `NEBULA_LOG` sets the filter; it defaults to `off` under test so a
normal `cargo test` stays quiet.

**Measured**, one cold request then one warm, against the echo guest:

```
grpc_execute{function_id=echo tenant=acme}:fetch_module{bytes=482}:               close time.busy=169µs
grpc_execute:wasm_execute:compile_l1{source="cranelift" compiled_bytes=14024}:    close time.busy=2.53ms
grpc_execute:wasm_execute{deadline_ms=50 bytes=482}:                              close time.busy=2.76ms
grpc_execute{cold=true outcome=Ok}:                                               close time.busy=2.95ms

grpc_execute:wasm_execute{deadline_ms=50 bytes=482}:                              close time.busy=77.9µs
grpc_execute{cold=false outcome=Ok}:                                              close time.busy=178µs
```

Cold is 2.95 ms, of which Cranelift is 2.53 ms — compilation dominates, and the
fetch is noise beside it. Warm is **78 µs of guest inside 178 µs of worker**,
the rest being instantiation and the gRPC frame.

Two deliberate shapes here. `route_to_worker` is one span *per attempt*, so a
§10.2 retry shows as a second span instead of hiding inside the first. And
`compile_l1` nests *inside* `wasm_execute` rather than beside it, because
compilation is lazy — it happens during the execute call, not before it. That
nesting is what lets you read actual execution as the difference: 2.76 − 2.53 ≈
0.23 ms on the cold path.

`wasm_execute` runs on a pool thread, not the reactor, so nothing propagates
the request context to it automatically. The job carries its parent `Span`
explicitly (§5.2); without that the guest's span would appear at the root of the
trace rather than under the request that caused it.

### SLIs

| Metric | Type | Why |
|---|---|---|
| `nebula_request_duration_seconds{outcome,cold}` | histogram | Primary SLI; the cold/hot split is the headline |
| `nebula_instantiate_micros` | histogram | G1, isolated from guest work |
| `nebula_guest_exec_micros{outcome}` | histogram | Tenant code cost |
| `nebula_cache_lookups_total{tier,hit}` | counter | Ring affinity is working iff hit ratio is high |
| `nebula_shed_total{reason}` | counter | Overload behaviour |
| `nebula_exec_queue_depth` | gauge | Leading indicator of shed |
| `nebula_inflight_executions` | gauge | Semaphore occupancy |
| `nebula_guest_faults_total{outcome}` | counter | Tenant health; must not page |
| `nebula_ring_nodes` / `nebula_heartbeat_misses_total` | gauge / counter | Membership churn |
| `nebula_module_cache_bytes` | gauge | Eviction pressure |

Histograms record microseconds. A millisecond-resolution histogram cannot
measure a sub-millisecond target.

---

## 15. Testing Strategy

### Adversarial guest corpus

A directory of hand-written hostile `.wasm` modules is checked in and run
against the sandbox in CI **from Phase 1 onward**. Each asserts a specific
`Outcome`, not merely "did not crash":

| Guest | Expected |
|---|---|
| `infinite_loop.wat` | `TIMEOUT` |
| `tight_alloc.wat` — grow until refused | `MEMORY_LIMIT` or graceful `-1` handling |
| `deep_recursion.wat` | `TRAP` (stack exhausted), host stack intact |
| `oob_read.wat` / `oob_write.wat` | `TRAP` |
| `ptr_overflow.wat` — host call with `ptr + len` overflowing `u32` | `TRAP`, no host read |
| `huge_response.wat` — write past the response cap | `TRAP` or truncation, capped |
| `grow_then_write.wat` — `memory.grow` inside a host call sequence | No stale host borrow |
| `kv_flood.wat` | Bounded at the KV cap |
| `unreachable.wat` | `TRAP` |
| `fuel_burn.wat` (fuel engine) | `FUEL_EXHAUSTED` at a deterministic count |

The determinism assertion is real: `fuel_burn.wat` must report the **identical**
`fuel_used` across runs, or fuel is not delivering what it costs.

### Other layers

- **Unit** — ring distribution (chi-square across 10⁶ keys), ring failover and
  wraparound, byte-bounded LRU eviction, single-flight compile, §7.3 bounds
  cases, error mapping table.
- **Integration** — one control plane + N workers in-process over real gRPC on
  ephemeral ports. Cold-then-hot, deploy-new-version, kill-a-worker,
  restart-a-worker, drain.
- **Chaos** — `kill -9` a worker mid-request; assert 502 and no retry. Pause a
  worker with `SIGSTOP`; assert heartbeat timeout and ring removal. Partition
  the control plane; assert workers keep serving in-flight work.
- **Load** — §19.
- **Fuzz** — `cargo-fuzz` on the host-function argument surface. The guest side
  is attacker-controlled by definition, so it is the natural fuzz target.

CI runs unit + adversarial corpus + integration on every commit. Load and chaos
run at phase boundaries.

---

## 16. Technology Stack

| Concern | Choice | Rationale |
|---|---|---|
| Language | Rust | Memory safety at the host boundary is the whole premise |
| WASM engine | `wasmtime` (pinned exact version) | Pooling allocator, CoW images, epochs, fuel, AOT — all upstream |
| Async runtime | `tokio` | Everything below assumes it |
| RPC | `tonic` + `prost` | Typed internal contracts, streaming for module transfer |
| HTTP | `axum` | Thin layer over `hyper`, same tower middleware stack as tonic |
| Pre-initialization | `wizer` (build-time CLI) | Replaces the hand-rolled snapshot subsystem (§4.3) |
| Tracing | `tracing` + `tracing-opentelemetry` | Microsecond spans |
| Metrics | `metrics` + `metrics-exporter-prometheus` | |
| LRU | `lru` crate | Byte-bounded eviction wraps it; the map itself is not worth writing |
| Concurrent map | `dashmap` | KV shim and in-flight compile map |
| Hashing | `sha2` (identity), `xxhash-rust` (ring) | Ring hashing is not a security boundary; speed over crypto |
| Load generation | `oha` (external) + `nebula-bench` | Off-the-shelf for throughput; a small custom bin only for the cold/hot split `oha` cannot express |
| Serialization | `serde` + `serde_json` for registry metadata | Human-readable on disk |

**Consistent hashing has no crate dependency** — `BTreeMap::range` is the
algorithm (§9.1).

---

## 17. Repository Layout

```
nebula/
├── Cargo.toml                  # workspace
├── DESIGN.md
├── proto/
│   └── nebula.proto
├── crates/
│   ├── nebula-proto/           # tonic-build output, isolated for build times
│   ├── nebula-runtime/         # lib: engine, limits, host fns, cache, execute
│   │   ├── src/{engine,limits,host,cache,exec,config}.rs
│   │   └── tests/adversarial.rs
│   ├── nebula-control/         # bin: gateway + scheduler + registry + membership
│   │   └── src/{gateway,scheduler,ring,registry,membership}.rs
│   ├── nebula-worker/          # bin: gRPC server wrapping nebula-runtime
│   └── nebula-bench/           # bin: cold/hot latency harness (Phase 4)
└── guests/
    ├── adversarial/            # hostile .wat corpus (§15)
    └── examples/               # echo, json-transform, heavy-init (wizer target)
```

`nebula-runtime` having no networking dependency is load-bearing: the sandbox
tests and the benchmark harness both link it directly, so G1 and G3 can be
tested without a cluster.

---

## 18. Implementation Phases

Each phase ends with something that runs and a demo you could show someone.
Phase boundaries are commit points.

### Phase 1 — Single-Node Execution Core

**Goal:** `curl` a WASM function on localhost, with hostile code contained.

- Cargo workspace; pin wasmtime; CI (fmt, clippy, test) from day one.
- `nebula-runtime`: `Engine` config per §5.1, pooling allocator, `Store`
  construction, execute-one-function.
- Epoch ticker thread + per-`Store` deadlines. `StoreLimits` for memory, tables,
  stack.
- Execution on `spawn_blocking` (upgraded in Phase 3 per §5.2).
- Minimal `axum` gateway in `nebula-control` calling `nebula-runtime`
  **in-process** — no gRPC yet. This is the vertical slice.
- **Adversarial corpus wired into CI.** All of §15's guests, asserting exact
  outcomes.

**Exit criteria**

- `curl -d 'hi' localhost:8080/execute/echo` returns `hi`.
- Every adversarial guest produces its expected `Outcome`; the worker process
  survives all of them, back to back, without leaking memory across 10 000
  iterations.
- Instantiate + trivial execute p99 measured and recorded as the Phase 1
  baseline. G1 should already be close here — everything after this is about not
  regressing it.

**Not yet:** gRPC, clustering, host functions beyond request/response, caching.

---

### Phase 2 — Host Interface & Module Caching

**Goal:** guests do useful work; hot starts are measurably fast.

- `Linker` + `wasmtime-wasi` with the locked-down `WasiCtx` of §7.1.
- The §7.2 host functions; the §7.3 memory helper with its full unit-test set.
- KV shim with per-tenant prefixes and caps.
- L1 cache (`Module` + `InstancePre`) with byte-bounded LRU eviction and
  single-flight compilation.
- L2 on-disk AOT cache with the composite key of §8.2.
- Content-hash addressing; `PUT /functions/{id}` deploy path with validation.
- **Pick and wizen the heavy example guest now, not in Phase 4** (risk R2).
  Done: `guests/examples/heavy_init` plus `guests/build.sh`. Wizer integration
  in the *deploy* path stays in Phase 4; this is the build-time proof that the
  §4.3 mechanism works and is worth wiring up.

**Exit criteria**

- A guest reads its request body, calls `kv_set`/`kv_get`, logs, and writes a
  response.
- Cold vs hot latency differ by the expected order of magnitude; both recorded.
- Worker restart replays from L2 with zero Cranelift compilation (assert on the
  `module.compile{source}` span).
- Fifty concurrent first-requests for one function compile it exactly once.
- Memory-bounded eviction verified: 100 × 20 MiB modules against a 1 GiB budget
  stays under budget.

**Not yet:** distribution.

---

### Phase 3 — The Distributed Mesh

**Goal:** a real cluster that survives node loss and overload.

- ✅ `nebula.proto` and the `nebula-proto` codegen crate; workspace split into
  `nebula-control` and `nebula-worker` binaries. Transport not yet wired.
- ✅ Consistent hash ring with 160 virtual nodes and the failover walk.
  Bounded-load advance (§9.2) waits on live load, which arrives with heartbeats.
- ✅ `tonic` client and server; the two binaries actually speaking.
- ✅ `Register` + unary `Heartbeat` + reconciliation loop (§10.1), generation IDs.
- ✅ Dedicated bounded execution pool, admission semaphore, `FetchModule`
  streaming, HTTP gateway with bounded-load dispatch and the §10.2 retry policy.
- ✅ Chaos: `kill -9` reported as 502 without retry; a paused worker reconciled
  out of the ring after the real 1.5 s timeout.
- ✅ Deployment persistence: `deployments.json` beside the artifacts, written
  before a `PUT` is acknowledged and reloaded on startup.
- ✅ **Scale criteria, measured.** A worker at capacity 2 offered 10 concurrent
  100 ms guests admits exactly 2 and sheds 8, and stays in the ring through
  2.4 s of continuous saturation — the proof that §5.2 was worth its
  complexity, since heartbeats keep flowing while every execution thread is
  busy. Fifty distinct functions over three workers across 1 000 requests:
  **50 compiles, 950 L1 hits (95.0%)**, per-worker split 46 / 22 / 32%.

  The split is wide because fifty keys is a different regime from §9.1's ten
  thousand: sampling noise is about `sqrt(50/3)/(50/3)` ≈ 24%, so the 10% bound
  does not apply at this scale and asserting it would be wrong. The stable-
  routing claim is carried by the compile count instead — 50 compiles for 50
  functions means no function was ever served by two workers, which a hit ratio
  alone would not show.
- `FetchModule` chunked streaming with SHA-256 verification; L3 registry.
- **Replace `spawn_blocking` with the dedicated bounded execution pool (§5.2).**
- Admission semaphore, bounded queue, `RESOURCE_EXHAUSTED` → 503 mapping
  (§10.3).
- Retry policy per §10.2 — connection-establishment failures only.
- Bearer-token auth; graceful `Drain`.

**Exit criteria**

- 3-worker cluster serves traffic; ring hit ratio > 95% in steady state.
- `kill -9` a worker under sustained load → traffic reroutes within 3 s, no 5xx
  after reconvergence, zero duplicate executions.
- `SIGSTOP` a worker → heartbeat timeout removes it from the ring; `SIGCONT`
  re-adds it.
- At 5× capacity the cluster returns 503s with stable p99 on admitted requests
  and no OOM. **This is the test that proves §5.2 was necessary** — heartbeats
  must keep flowing while every execution thread is saturated.
- Key distribution across 3 workers within 10% of even.

---

### Phase 4 — Pre-initialization, Benchmarking, Optimization

**Goal:** numbers that support the claims in §1.

- ✅ Wizer integration in the deploy path; `wizened` flag through the API
  response and the `publish` span. A module exporting `_initialize` is run
  through Wizer *before* hashing, so the artifact the cluster stores is already
  booted. Text `.wat` and modules without an initializer pass through untouched;
  a module whose own initializer fails is a 400, while Wizer being absent is an
  operator gap that logs and deploys un-wizened rather than refusing a deploy
  the caller cannot fix.
- ✅ Full `tracing` span tree with durations (§14).
- ✅ Ring churn: losing 1 of 3 workers moved **31 of 100 functions (31%)** and
  left the phase-2 cache hit ratio at **96.9%**. Under `hash % n` the modulus
  changes and roughly two thirds of the keyspace would have moved, cold-starting
  most of the cluster at once.
- `nebula-bench`: cold/hot/wizened split, percentiles from a microsecond
  histogram, sustained and burst profiles.
- Full `tracing` span tree; flamegraph the hot path; eliminate what shows up.
- Tune pooling allocator sizing, LRU budget, semaphore width, chunk size against
  measurements.
- Final numbers written up against §19.

**Exit criteria**

- Every goal in §1 has a measured number — met, or explicitly not met with an
  explanation.
- A wizened heavy guest's hot-start p50 is within 2× of a trivial guest's.
- Flamegraph shows no single non-guest frame above 15% of hot-path time.

---

## 19. Benchmark Methodology & Success Criteria

**Latency claims are meaningless without stating what is inside the
measurement.** Nebula reports three separate numbers:

| Measurement | Boundary | Target |
|---|---|---|
| **M1 — Instantiate + execute** | In-process, `nebula-runtime` only. No network, no gRPC, no HTTP. Instantiate from cached `InstancePre`, call handler, drop `Store`. | p99 < 1 ms (**G1**) |
| **M2 — Hot end-to-end** | Client socket to client socket, over loopback, through gateway and gRPC, module cached. | p99 < 5 ms |
| **M3 — Cold end-to-end** | Same, but the worker has never seen the module: fetch + compile + instantiate + execute. | p99 < 50 ms (**G2**) |

M1 is the WASM claim. M2 is the system claim. **M3 is what gets compared against
Firecracker's 125–200 ms boot floor**, and that comparison is the honest one for
G2 — not M1 against a microVM cold start, which measures two different things.

### Conditions

- Fixed hardware; core count, CPU model, and OS recorded in the results.
- 30 s warmup discarded; 60 s measurement window.
- Sustained (constant rate) and burst (0 → 5× capacity step) profiles.
- Guest tiers: **trivial** (echo, < 10 KiB), **moderate** (JSON transform,
  ~500 KiB), **heavy** (framework init, ~5 MiB, measured wizened and raw).
- Percentiles from microsecond histograms, never from averages.
- Three runs; median reported; spread published.

### Recorded even when unflattering

Shed rate under overload, cache hit ratio, per-outcome fault rates, recovery
time after node kill, and any goal missed. A design document that only reports
numbers clearing the bar is marketing.

---

## 20. Risks & Open Questions

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | Pooling allocator address-space reservation is large (slots × max memory) | Startup failure or reduced density | 64 slots × 128 MiB = 8 GiB of *virtual* reservation, fine on 64-bit. Validate on the target box before anything depends on it. |
| ~~R2~~ | ~~Wizer does not work on the chosen heavy guest~~ | — | **Closed in Phase 2.** `guests/examples/heavy_init` wizens cleanly and is measured at ~80×. Two constraints found in the doing: Wizer must instantiate the module to run the initializer, so *every* import has to be satisfiable at build time — the guest therefore imports only WASI and reports through stdout rather than through `nebula` host functions. And Wizer's default init export is `wizer.initialize`, so the build passes `--init-func _initialize`. |
| R3 | Wasmtime API drift mid-project | Rework | Pin an exact version; no upgrades inside a phase. |
| R4 | Guest toolchain friction (Rust → `wasm32-wasip1`, TinyGo) | Time sink | The corpus is hand-written `.wat` — no toolchain in the critical path for G3/G4. |
| R5 | Loopback benchmarking hides real network effects | Optimistic M2/M3 | State it. Add a two-machine run in Phase 4 if time allows. |
| R6 | Single control plane is a SPOF | Total outage | Accepted (§2). The design keeps it off the data path for hot requests, so the blast radius is *new* routing, not in-flight work. |
| R7 | Epoch granularity (1 ms) is coarse for a sub-ms target | Imprecise timeouts at the low end | Only matters for functions with sub-ms deadlines; the 50 ms default is 50 ticks. Note it, do not chase it. |
| R8 | Fuel requiring a second `Engine` doubles cache memory if both are used | Memory pressure | Keep fuel strictly opt-in and rare; cache budgets are per-engine. |

### Open questions for review

1. **Are stateful actor pins (§21) in or out?** They are the most distinctive
   idea in the original spec and also the largest scope risk — they invert the
   "fresh instance per request" invariant that makes §13 easy to reason about.
   As written they are deferred. Overrideable.
2. **Is a static bearer token enough for v1 auth**, or should per-function
   signing keys land in Phase 3?
3. **Is loopback-only benchmarking acceptable** for the headline numbers, or is
   a two-machine setup required for M2/M3 to be credible?
4. **WASI preview 1 vs the component model.** p1 is the pragmatic v1 choice.
   Committing to p2 would change §7 substantially and is much better decided
   before Phase 2 than during Phase 3.

---

## 21. Deferred Work

Not cancelled — scoped out of v1, with the reasoning recorded so the
decision can be revisited rather than re-derived.

### Stateful Execution Pins (Actor Model)

The original design proposed an optional `partition_key` routed through the hash
ring to guarantee that all requests for a key reach the same **live instance** on
one worker, giving mutual exclusion and letting guests hold in-memory state
(game sessions, CRDTs) without races.

It is genuinely valuable and genuinely expensive, because it breaks three
invariants the rest of the system rests on:

1. **"Fresh instance per request" (§4.2)** becomes "long-lived instance per
   key." Cross-request isolation stops being structural and starts needing an
   argument.
2. **The LRU cache (§8.3)** currently evicts anything. Pinned instances cannot be
   evicted while live, so it needs a second eviction policy plus an idle reaper —
   and a hostile tenant creating unbounded keys becomes a memory-exhaustion
   vector that §6 does not currently cover.
3. **Resource limits (§6)** are per-request budgets. A long-lived actor needs
   per-actor lifetime budgets, cumulative accounting, and a policy for what
   happens when an actor exhausts its budget mid-conversation.

There is also a distributed-systems problem the original spec does not address:
mutual exclusion holds only while ring membership is stable. During a rebalance,
two workers can briefly both believe they own a key. Correctness requires
ownership leases with fencing tokens — a real consensus-shaped problem, not a
routing tweak.

**Recommendation:** ship the stateless system, prove G1–G6, then take actors as a
follow-on with proper design. The `partition_key` field is reserved in the proto
and the HTTP header so adding it later is additive.

That reserved plumbing is the entire concession. If actors are wanted inside
v1, they replace Phase 4 — they do not fit alongside it.

### Other deferrals

| Item | Trigger to build it |
|---|---|
| S3-backed registry, workers pulling directly | When cold-start rate makes the control plane a measured bottleneck |
| Replicated pre-warming (N nodes per function) | When failover cold starts show up in p99 |
| Adaptive concurrency limiter (AIMD/Vegas) | When a static limit is measurably wrong across workloads |
| mTLS on internal gRPC | Before any deployment on an untrusted network |
| Multi-instance control plane | When the SPOF matters more than the simplicity |
| WASI preview 2 / component model | When guest toolchains emit components as reliably as p1 modules |
| Outbound HTTP host function | When a guest needs it — it is the single largest new attack surface (SSRF, egress policy) and needs its own threat model |
| Per-tenant rate limiting at the gateway | Before multi-tenant exposure to untrusted callers |
