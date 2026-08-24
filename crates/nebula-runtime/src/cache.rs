//! Compiled-module cache: L1 in memory, L2 on disk (README.md §8).
//!
//! Modules are addressed by SHA-256 of the artifact, never by `function_id`
//! (§8.1). A new version is a new hash and a new entry, so there is no
//! invalidation protocol and no staleness window.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::hash::{DefaultHasher, Hash as _, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use wasmtime::{Engine, InstancePre, Linker, Module, Result};

use crate::HostCtx;

/// Default L1 budget (§8.3). Eviction is bounded by bytes, not entry count: a
/// count-bounded cache holding sixty 30 MiB modules is an OOM.
pub const DEFAULT_L1_BYTES: usize = 1 << 30; // 1 GiB

/// Ceiling on the on-disk L2 cache.
///
/// L1 has been byte-bounded since §8.3; L2 was not, and an unbounded disk cache
/// is a disk that fills. Every distinct artifact a worker ever compiles leaves
/// an AOT module behind, and a wasm interpreter weighs several megabytes, so
/// "it is only a cache" stops being reassuring at about a thousand deploys.
pub const DEFAULT_L2_BYTES: u64 = 4 << 30; // 4 GiB

pub type Hash = [u8; 32];

pub fn content_hash(wasm: &[u8]) -> Hash {
    Sha256::digest(wasm).into()
}

/// The same hash as hex — the form that travels on the wire and names files.
pub fn content_hash_hex(wasm: &[u8]) -> String {
    hex(&content_hash(wasm))
}

/// What produced a `Module`.
///
/// The distinction is a Phase 2 exit criterion: a worker restart must replay
/// from L2 without invoking Cranelift, and that has to be observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Cranelift,
    Aot,
}

pub struct CachedModule {
    pub module: Module,
    /// Imports resolved and type-checked once, at insert. Per-request
    /// instantiation then skips linking entirely (§8.3).
    pub pre: InstancePre<HostCtx>,
    pub source: Source,
    /// Serialized size, used for L1 accounting.
    pub size: usize,
}

struct Slot {
    module: Arc<CachedModule>,
    used: u64,
}

struct L1 {
    map: HashMap<Hash, Slot>,
    bytes: usize,
    clock: u64,
    budget: usize,
}

pub struct Cache {
    dir: PathBuf,
    l2_budget: u64,
    l1: Mutex<L1>,
    /// Per-hash compile gates, present only while a compile is in flight.
    in_flight: Mutex<HashMap<Hash, Arc<Mutex<()>>>>,
    cranelift: AtomicUsize,
    aot: AtomicUsize,
    l1_hits: AtomicUsize,
    evicted_l2: AtomicUsize,
}

impl Cache {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        Self::with_budget(dir, DEFAULT_L1_BYTES)
    }

    pub fn with_budget(dir: impl Into<PathBuf>, budget: usize) -> Result<Self> {
        Self::with_budgets(dir, budget, DEFAULT_L2_BYTES)
    }

    pub fn with_budgets(dir: impl Into<PathBuf>, budget: usize, l2_budget: u64) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self {
            l2_budget,
            dir,
            l1: Mutex::new(L1 {
                map: HashMap::new(),
                bytes: 0,
                clock: 0,
                budget,
            }),
            in_flight: Mutex::new(HashMap::new()),
            cranelift: AtomicUsize::new(0),
            aot: AtomicUsize::new(0),
            l1_hits: AtomicUsize::new(0),
            evicted_l2: AtomicUsize::new(0),
        })
    }

    /// Cranelift compilations performed. This is the single-flight assertion:
    /// N concurrent first-requests for one module must leave this at 1.
    pub fn cranelift_compiles(&self) -> usize {
        self.cranelift.load(Ordering::Relaxed)
    }

    /// Modules loaded from the L2 on-disk cache instead of compiled.
    pub fn aot_loads(&self) -> usize {
        self.aot.load(Ordering::Relaxed)
    }

    pub fn l1_hits(&self) -> usize {
        self.l1_hits.load(Ordering::Relaxed)
    }

    pub fn l1_len(&self) -> usize {
        self.l1.lock().unwrap().map.len()
    }

    pub fn l1_bytes(&self) -> usize {
        self.l1.lock().unwrap().bytes
    }

    /// L1 → L2 → compile, populating on the way back down.
    ///
    /// Concurrent callers for the same hash compile it exactly once: the first
    /// takes the gate, the rest block and then find the finished module in L1.
    pub fn get_or_compile(
        &self,
        engine: &Engine,
        linker: &Linker<HostCtx>,
        wasm: &[u8],
    ) -> Result<Arc<CachedModule>> {
        let hash = content_hash(wasm);
        if let Some(hit) = self.l1_get(&hash) {
            self.l1_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(hit);
        }

        let gate = self
            .in_flight
            .lock()
            .unwrap()
            .entry(hash)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _compiling = gate.lock().unwrap();

        // Re-check under the gate: whoever held it before us has finished and
        // published to L1. This double-check is what makes the pattern correct
        // rather than merely serialized.
        if let Some(hit) = self.l1_get(&hash) {
            self.l1_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(hit);
        }

        let cached = match self.load_or_compile(engine, linker, wasm, &hash) {
            Ok(module) => Arc::new(module),
            Err(err) => {
                self.in_flight.lock().unwrap().remove(&hash);
                return Err(err);
            }
        };

        // Publish to L1 *before* releasing the gate, so a caller that arrives
        // after the gate is dropped cannot miss and start a second compile.
        self.l1_insert(hash, cached.clone());
        self.in_flight.lock().unwrap().remove(&hash);
        Ok(cached)
    }

    fn load_or_compile(
        &self,
        engine: &Engine,
        linker: &Linker<HostCtx>,
        wasm: &[u8],
        hash: &Hash,
    ) -> Result<CachedModule> {
        // `source` is recorded rather than logged so one span answers both
        // "how long did this take" and "did L2 save us from Cranelift".
        let span = tracing::info_span!(
            "compile_l1",
            bytes = wasm.len(),
            source = tracing::field::Empty,
            compiled_bytes = tracing::field::Empty,
        );
        let _entered = span.enter();

        let path = self.l2_path(engine, hash);

        let mut loaded = None;
        if path.is_file() {
            // SAFETY: these bytes were written by this worker's own L2 and by
            // nothing else (§13, invariant 5). The filename includes the
            // engine's compatibility hash, and wasmtime independently
            // re-validates the artifact on load, so a mismatch surfaces as
            // `Err` rather than as undefined behaviour.
            match unsafe { Module::deserialize_file(engine, &path) } {
                Ok(module) => {
                    self.aot.fetch_add(1, Ordering::Relaxed);
                    // Touch on read, so the L2 sweep below has a recency signal
                    // without any bookkeeping of its own: the filesystem
                    // already keeps one. Best effort, because a cache whose
                    // reads can fail is worse than one that evicts imperfectly.
                    touch(&path);
                    loaded = Some((module, Source::Aot));
                }
                // Stale or truncated: drop it and fall through to a compile.
                Err(_) => {
                    let _ = fs::remove_file(&path);
                }
            }
        }

        let (module, source) = match loaded {
            Some(hit) => hit,
            None => {
                let module = Module::new(engine, wasm)?;
                self.cranelift.fetch_add(1, Ordering::Relaxed);
                if let Ok(bytes) = module.serialize() {
                    let _ = write_atomic(&path, &bytes);
                    // Only a compile can grow L2, so this is the only place it
                    // needs bounding, and compiles are rare by construction.
                    self.sweep_l2();
                }
                (module, Source::Cranelift)
            }
        };

        let size = fs::metadata(&path)
            .map(|meta| meta.len() as usize)
            .unwrap_or(wasm.len());
        span.record(
            "source",
            match source {
                Source::Aot => "aot",
                Source::Cranelift => "cranelift",
            },
        );
        span.record("compiled_bytes", size);

        let pre = linker.instantiate_pre(&module)?;
        Ok(CachedModule {
            module,
            pre,
            source,
            size,
        })
    }

    /// Evicts the least recently used L2 entries until the directory fits.
    ///
    /// Recency is the file's modification time, which [`touch`] refreshes on
    /// every hit, so this is an LRU with no index to keep in sync. A hot module
    /// that is never recompiled still looks recent.
    ///
    /// ponytail: an O(n) directory scan on every compile. At a few hundred
    /// modules that is microseconds against a Cranelift compile measured in
    /// milliseconds. An index earns itself when the scan shows up in a profile,
    /// and it would then need to survive a restart, which the filesystem's own
    /// metadata already does.
    fn sweep_l2(&self) {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };

        let mut files: Vec<(std::time::SystemTime, u64, PathBuf)> = entries
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                let meta = entry.metadata().ok()?;
                // Directories, and anything a future version of this cache
                // writes alongside the modules, are left alone.
                if !meta.is_file() {
                    return None;
                }
                Some((meta.modified().ok()?, meta.len(), path))
            })
            .collect();

        let mut total: u64 = files.iter().map(|(_, size, _)| size).sum();
        if total <= self.l2_budget {
            return;
        }

        // Oldest first, so the loop removes the least recently used.
        files.sort_by_key(|(modified, _, _)| *modified);
        for (_, size, path) in files {
            if total <= self.l2_budget {
                break;
            }
            if fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(size);
                self.evicted_l2.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Modules dropped from L2 to stay inside the budget.
    pub fn evicted_l2(&self) -> usize {
        self.evicted_l2.load(Ordering::Relaxed)
    }

    /// L2 filename: artifact hash plus the engine's own compatibility hash,
    /// which folds in wasmtime version, target triple, and engine config (§8.2).
    ///
    /// `DefaultHasher` is not guaranteed stable across Rust releases. That is
    /// fine here: a changed hash is a cache *miss* and a recompile, never a
    /// wrong load.
    fn l2_path(&self, engine: &Engine, hash: &Hash) -> PathBuf {
        let mut hasher = DefaultHasher::new();
        engine.precompile_compatibility_hash().hash(&mut hasher);
        self.dir
            .join(format!("{}-{:016x}.cwasm", hex(hash), hasher.finish()))
    }

    fn l1_get(&self, hash: &Hash) -> Option<Arc<CachedModule>> {
        let mut l1 = self.l1.lock().unwrap();
        l1.clock += 1;
        let now = l1.clock;
        let slot = l1.map.get_mut(hash)?;
        slot.used = now;
        Some(slot.module.clone())
    }

    fn l1_insert(&self, hash: Hash, module: Arc<CachedModule>) {
        let mut l1 = self.l1.lock().unwrap();
        l1.clock += 1;
        let used = l1.clock;
        let size = module.size;
        if let Some(previous) = l1.map.insert(hash, Slot { module, used }) {
            l1.bytes -= previous.module.size;
        }
        l1.bytes += size;

        // ponytail: eviction finds the victim by linear scan. The map holds tens
        // of entries (a 1 GiB budget over module-sized artifacts) and this runs
        // only on a cold start, where it is dwarfed by compilation. Swap in an
        // intrusive LRU list if the cache ever holds thousands of modules.
        //
        // The `len() > 1` guard keeps the entry just inserted even if it alone
        // exceeds the budget, so an oversized module cannot make the cache
        // thrash itself empty on every request.
        while l1.bytes > l1.budget && l1.map.len() > 1 {
            let Some(victim) = l1
                .map
                .iter()
                .min_by_key(|(_, slot)| slot.used)
                .map(|(hash, _)| *hash)
            else {
                break;
            };
            if let Some(slot) = l1.map.remove(&victim) {
                l1.bytes -= slot.module.size;
            }
        }
    }
}

/// Write via a temporary and rename, so a concurrent reader never observes a
/// half-written artifact. Single-flight serializes writers within one process;
/// this covers two processes sharing a cache directory.
/// Marks a file as used, for [`Cache::sweep_l2`]'s recency ordering.
///
/// Best effort: a filesystem that refuses this gives a worse eviction order,
/// which is a performance problem, while a read that failed because of it would
/// be a correctness one.
fn touch(path: &Path) {
    if let Ok(file) = fs::File::options().write(true).open(path) {
        let now = std::time::SystemTime::now();
        let _ = file.set_times(fs::FileTimes::new().set_modified(now));
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}
