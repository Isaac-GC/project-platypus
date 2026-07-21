//! Cooperative-thread model for the Dalvik interpreter.
//!
//! Real Android apps spawn worker threads (`new Thread(runnable).start()`,
//! `Executor.execute`, kotlinx coroutines). We approximate that with a
//! lightweight scheduler that runs each spawned method on its own register
//! file + call stack, while the heap (`Memory`) stays shared with the
//! spawning VM — matching the JVM heap-shared / stack-per-thread model.
//!
//! ## v1 semantics — sequential
//!
//! `Vm::spawn_method` runs the spawned method **synchronously** to
//! completion before returning the handle. The handle's status flips
//! straight from `Pending` to `Completed`/`Failed`. From the caller's
//! perspective this looks like a recorded `call_method` invocation;
//! the value is making it inspectable as a labelled "thread" with a
//! result the host UI can poll and display.
//!
//! Real parallel execution would require splitting `Memory` into an
//! `Arc<Mutex<…>>` shared heap + a per-thread `Frame` — tractable but
//! out of scope here; the API is designed so v2 can swap in async/
//! preemptive scheduling without breaking callers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::value::Value;

/// Monotonically-increasing thread id source. Process-wide so test runs
/// that create multiple VMs still get unique ids — useful when the host
/// UI persists thread references across reloads.
static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);

/// Opaque handle returned by [`crate::vm::Vm::spawn_method`]. Pass back
/// to `thread_status` / `join_thread` to retrieve the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadHandle(pub u64);

impl ThreadHandle {
    pub fn new() -> Self {
        ThreadHandle(NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed))
    }
    pub fn id(self) -> u64 { self.0 }
}

impl Default for ThreadHandle {
    fn default() -> Self { Self::new() }
}

/// Lifecycle state of a spawned thread.
#[derive(Debug, Clone)]
pub enum ThreadStatus {
    /// Spawned but not yet started (queued for scheduling).
    Pending,
    /// Currently executing (in the v1 sequential scheduler this is only
    /// observable from a debugger hook firing during the run).
    Running,
    /// Method returned normally. `Value::Null` if the method returned
    /// void; otherwise the actual returned value.
    Completed(Value),
    /// Method aborted — instruction budget exhausted, hit the call-stack
    /// depth limit, the method was on the denylist, or the CFG was
    /// missing. `String` describes which.
    Failed(String),
}

impl ThreadStatus {
    /// True once the thread reached `Completed` or `Failed`.
    pub fn is_terminal(&self) -> bool {
        matches!(self, ThreadStatus::Completed(_) | ThreadStatus::Failed(_))
    }
    /// Convenience accessor — returns the value only when `Completed`.
    pub fn value(&self) -> Option<&Value> {
        if let ThreadStatus::Completed(v) = self { Some(v) } else { None }
    }
}

/// Lightweight summary of one thread — what host UIs render in a thread
/// list. Doesn't include the full call stack or result snapshot.
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub handle: ThreadHandle,
    /// User-supplied label (often the method ref or a Runnable class name).
    pub name: String,
    pub status: ThreadStatus,
    /// Unix-epoch milliseconds — useful for time-axis displays.
    pub started_at_ms: u64,
    /// Set when status reaches a terminal state.
    pub finished_at_ms: Option<u64>,
    /// Snapshot of the call-stack depth at the deepest point reached
    /// during the run. Captured for display only (the live stack is
    /// torn down at completion).
    pub max_call_depth: usize,
}

impl ThreadInfo {
    pub fn new(handle: ThreadHandle, name: String) -> Self {
        Self {
            handle,
            name,
            status: ThreadStatus::Pending,
            started_at_ms: now_ms(),
            finished_at_ms: None,
            max_call_depth: 0,
        }
    }
    /// Mark terminal — sets `finished_at_ms` and records the status.
    pub fn finish(&mut self, status: ThreadStatus, peak_depth: usize) {
        self.status = status;
        self.finished_at_ms = Some(now_ms());
        self.max_call_depth = peak_depth;
    }
}

/// Holds every thread the VM has spawned in this session. Cleared by
/// `clear_finished_threads` (or never cleared if the host wants a full
/// audit trail).
#[derive(Debug, Default)]
pub struct ThreadScheduler {
    threads: Vec<ThreadInfo>,
}

impl ThreadScheduler {
    pub fn new() -> Self { Self::default() }

    /// Register a freshly-spawned thread and return its handle.
    pub(crate) fn register(&mut self, name: String) -> ThreadHandle {
        let handle = ThreadHandle::new();
        self.threads.push(ThreadInfo::new(handle, name));
        handle
    }

    /// Mark a thread terminal with the given status + peak depth seen
    /// during the run.
    pub(crate) fn finish(&mut self, handle: ThreadHandle, status: ThreadStatus, peak_depth: usize) {
        if let Some(info) = self.threads.iter_mut().find(|t| t.handle == handle) {
            info.finish(status, peak_depth);
        }
    }

    /// Mark a thread as currently running. v1 sequential scheduler only
    /// uses this internally; v2 can expose it for cancellation UIs.
    pub(crate) fn mark_running(&mut self, handle: ThreadHandle) {
        if let Some(info) = self.threads.iter_mut().find(|t| t.handle == handle) {
            info.status = ThreadStatus::Running;
        }
    }

    /// Find one thread by handle. Cheap linear scan — thread lists are
    /// small (dozens at most) so an index isn't worth the bookkeeping.
    pub fn get(&self, handle: ThreadHandle) -> Option<&ThreadInfo> {
        self.threads.iter().find(|t| t.handle == handle)
    }

    pub fn status(&self, handle: ThreadHandle) -> Option<ThreadStatus> {
        self.get(handle).map(|t| t.status.clone())
    }

    /// All threads, newest last. Use this to render a thread-list panel
    /// in the host UI.
    pub fn list(&self) -> &[ThreadInfo] { &self.threads }

    /// Drop every thread that has reached a terminal state — useful for
    /// long-running sessions where the audit trail would otherwise grow
    /// unboundedly.
    pub fn clear_finished(&mut self) {
        self.threads.retain(|t| !t.status.is_terminal());
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_unique_and_monotonic() {
        let a = ThreadHandle::new();
        let b = ThreadHandle::new();
        assert!(b.id() > a.id());
    }

    #[test]
    fn scheduler_registers_threads_and_returns_handle() {
        let mut s = ThreadScheduler::new();
        let h = s.register("MyRunnable.run()V".into());
        assert!(matches!(s.status(h), Some(ThreadStatus::Pending)));
        assert_eq!(s.list().len(), 1);
        assert_eq!(s.get(h).unwrap().name, "MyRunnable.run()V");
    }

    #[test]
    fn finish_flips_status_and_records_depth() {
        let mut s = ThreadScheduler::new();
        let h = s.register("X".into());
        s.finish(h, ThreadStatus::Completed(Value::Int(42)), 3);
        let info = s.get(h).unwrap();
        assert_eq!(info.max_call_depth, 3);
        assert!(info.finished_at_ms.is_some());
        match &info.status {
            ThreadStatus::Completed(Value::Int(n)) => assert_eq!(*n, 42),
            other => panic!("expected Completed(Int(42)), got {other:?}"),
        }
    }

    #[test]
    fn clear_finished_drops_only_terminal_threads() {
        let mut s = ThreadScheduler::new();
        let pending = s.register("a".into());
        let done    = s.register("b".into());
        s.finish(done, ThreadStatus::Completed(Value::Null), 0);
        s.clear_finished();
        assert_eq!(s.list().len(), 1);
        assert_eq!(s.list()[0].handle, pending);
    }

    #[test]
    fn thread_status_is_terminal_helper() {
        assert!(!ThreadStatus::Pending.is_terminal());
        assert!(!ThreadStatus::Running.is_terminal());
        assert!(ThreadStatus::Completed(Value::Null).is_terminal());
        assert!(ThreadStatus::Failed("x".into()).is_terminal());
    }
}
