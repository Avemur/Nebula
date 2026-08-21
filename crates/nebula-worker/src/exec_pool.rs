//! The dedicated blocking execution pool (README.md §5.2).
//!
//! **The most important structural decision in the worker.** A WASM call is
//! synchronous, CPU-bound, and may run for the full epoch deadline. Running it
//! on a tokio worker thread pins that thread for the duration; with N async
//! threads, N concurrent executions stall the reactor, heartbeats stop, and the
//! control plane declares a perfectly healthy node dead. Under sustained load
//! that is indistinguishable from a crash.
//!
//! So there are two thread populations: tokio handles gRPC framing, module
//! fetches, and admission; this pool of plain OS threads runs the guest. Work
//! crosses between them over a bounded channel, and the async side awaits a
//! `oneshot`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;

use nebula_runtime::wasmtime;
use nebula_runtime::{HostCtx, Runtime};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

/// The handler every guest exports.
pub const HANDLER_EXPORT: &str = "run";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolError {
    /// The queue is full — the second, earlier shed signal of §10.3.
    Full,
    /// The pool is gone, or a worker thread died mid-job.
    Stopped,
}

/// Proof that a request was admitted. Holding one reserves a slot; dropping it
/// releases the slot, whether the job ran or not.
#[derive(Debug)]
pub struct Admitted(OwnedSemaphorePermit);

struct Job {
    wasm: Arc<Vec<u8>>,
    tenant: String,
    body: Vec<u8>,
    reply: oneshot::Sender<wasmtime::Result<HostCtx>>,
    permit: OwnedSemaphorePermit,
}

pub struct ExecPool {
    tx: SyncSender<Job>,
    semaphore: Arc<Semaphore>,
    in_flight: Arc<AtomicUsize>,
    queued: Arc<AtomicUsize>,
    threads: usize,
}

impl std::fmt::Debug for ExecPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecPool")
            .field("threads", &self.threads)
            .field("in_flight", &self.in_flight())
            .field("queue_depth", &self.queue_depth())
            .finish()
    }
}

/// One execution thread per core, unless the platform declines to say.
pub fn default_threads() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

impl ExecPool {
    /// `max_concurrent` is the admission limit and bounds the queue: it is what
    /// §10.3 actually controls. Little's Law says `L = λW`, so bounding
    /// concurrency `L` bounds latency `W` — which is why this is a concurrency
    /// limit and not a latency threshold.
    ///
    /// Sizing it above `threads` allows a little queueing; sizing it equal
    /// means every admitted job runs immediately and the queue is decorative.
    pub fn new(runtime: Arc<Runtime>, threads: usize, max_concurrent: usize) -> Self {
        assert!(threads > 0 && max_concurrent > 0);

        let (tx, rx) = sync_channel::<Job>(max_concurrent);
        let rx = Arc::new(Mutex::new(rx));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let queued = Arc::new(AtomicUsize::new(0));

        for _ in 0..threads {
            let rx: Arc<Mutex<Receiver<Job>>> = rx.clone();
            let runtime = runtime.clone();
            let in_flight = in_flight.clone();
            let queued = queued.clone();

            thread::spawn(move || {
                loop {
                    // The lock is held across `recv` and released before the
                    // guest runs: one thread parks in `recv`, the rest wait on
                    // the mutex, and whoever takes a job frees the handoff
                    // immediately. Execution never holds it.
                    let job = {
                        let receiver = rx.lock().expect("execution queue poisoned");
                        receiver.recv()
                    };
                    let Ok(job) = job else {
                        return; // the pool was dropped
                    };

                    let Job {
                        wasm,
                        tenant,
                        body,
                        reply,
                        permit,
                    } = job;

                    queued.fetch_sub(1, Ordering::Relaxed);
                    in_flight.fetch_add(1, Ordering::Relaxed);
                    let result = runtime.execute(&wasm, HANDLER_EXPORT, &tenant, body);
                    in_flight.fetch_sub(1, Ordering::Relaxed);

                    // Send first, then release the slot: a caller that sees its
                    // result must not race a new admission into a thread that
                    // has not finished tidying up.
                    let _ = reply.send(result);
                    drop(permit);
                }
            });
        }

        Self {
            tx,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            in_flight,
            queued,
            threads,
        }
    }

    pub fn with_default_size(runtime: Arc<Runtime>) -> Self {
        let threads = default_threads();
        Self::new(runtime, threads, threads * 2)
    }

    /// Admission control (§10.3). Non-blocking by design: shedding costs a
    /// permit check and never touches the engine, so an overloaded worker sheds
    /// in microseconds instead of queueing its way into a timeout.
    pub fn try_admit(&self) -> Option<Admitted> {
        self.semaphore
            .clone()
            .try_acquire_owned()
            .ok()
            .map(Admitted)
    }

    /// Hands a job to the pool and awaits its result without blocking the
    /// reactor.
    pub async fn run(
        &self,
        admitted: Admitted,
        wasm: Arc<Vec<u8>>,
        tenant: String,
        body: Vec<u8>,
    ) -> Result<wasmtime::Result<HostCtx>, PoolError> {
        let (reply, wait) = oneshot::channel();
        let job = Job {
            wasm,
            tenant,
            body,
            reply,
            permit: admitted.0,
        };

        self.queued.fetch_add(1, Ordering::Relaxed);
        if let Err(err) = self.tx.try_send(job) {
            self.queued.fetch_sub(1, Ordering::Relaxed);
            return Err(match err {
                TrySendError::Full(_) => PoolError::Full,
                TrySendError::Disconnected(_) => PoolError::Stopped,
            });
        }

        wait.await.map_err(|_| PoolError::Stopped)
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Queue depth — a leading indicator of shedding (§14).
    pub fn queue_depth(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ECHO: &str = r#"
        (module
          (import "nebula" "request_len" (func $len (result i32)))
          (import "nebula" "request_read" (func $read (param i32 i32) (result i32)))
          (import "nebula" "response_write" (func $write (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "run")
            (local $n i32)
            (local.set $n (call $len))
            (drop (call $read (i32.const 0) (local.get $n)))
            (drop (call $write (i32.const 0) (local.get $n)))))
        "#;

    const SPIN: &str = r#"(module (func (export "run") (loop (br 0))))"#;

    fn pool(threads: usize, max_concurrent: usize) -> ExecPool {
        let dir = std::env::temp_dir().join(format!(
            "nebula-pool-{}-{}",
            std::process::id(),
            max_concurrent
        ));
        let runtime = Arc::new(Runtime::new(dir).expect("runtime"));
        ExecPool::new(runtime, threads, max_concurrent)
    }

    #[tokio::test]
    async fn a_job_runs_and_reports_its_response() {
        let pool = pool(2, 4);
        let admitted = pool.try_admit().expect("capacity");
        let result = pool
            .run(
                admitted,
                Arc::new(ECHO.as_bytes().to_vec()),
                "tenant".to_string(),
                b"round trip".to_vec(),
            )
            .await
            .expect("pool accepted the job");

        assert_eq!(result.expect("guest ran").response, b"round trip");
    }

    #[tokio::test]
    async fn admission_is_refused_once_the_permits_are_gone() {
        let pool = pool(1, 1);
        let held = pool.try_admit().expect("first request is admitted");

        assert!(
            pool.try_admit().is_none(),
            "a second request must be shed, not queued"
        );
        assert_eq!(pool.available_permits(), 0);

        drop(held);
        assert!(
            pool.try_admit().is_some(),
            "capacity must return when a request finishes"
        );
    }

    #[tokio::test]
    async fn permits_are_returned_after_a_guest_traps() {
        // A guest that burns its epoch deadline still has to give the slot back,
        // or one runaway tenant permanently shrinks the worker.
        let pool = pool(1, 1);
        let admitted = pool.try_admit().expect("capacity");
        let result = pool
            .run(
                admitted,
                Arc::new(SPIN.as_bytes().to_vec()),
                "tenant".to_string(),
                Vec::new(),
            )
            .await
            .expect("pool accepted the job");

        assert!(result.is_err(), "the spinner must hit the epoch deadline");
        assert_eq!(pool.in_flight(), 0);
        assert!(pool.try_admit().is_some(), "the slot must be back");
    }
}
