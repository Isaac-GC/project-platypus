use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use platypus_dexmapper::Deobfuscator;

use crate::project::Project;

/// Shared application state held in Tauri's managed state.
///
/// `project` holds N slots; one is `active` (read by most commands) and
/// optionally one is `compare` (used by the diff/compare-mode commands —
/// formerly known as "slot B").
///
/// `cache_dir` is the platypus subdirectory under the OS cache directory
/// (e.g. `~/Library/Application Support/project_platypus/` on macOS).
/// Project metadata persists to `<cache_dir>/project.json`; decrypted
/// child APKs live under `<cache_dir>/extracted/`.
pub struct AppState {
    pub project:   Arc<RwLock<Project>>,
    pub cache_dir: PathBuf,
    /// PID of the currently-running `python3` script subprocess, if any.
    /// Set by `run_script`, cleared on completion. Read by `kill_script` to
    /// send `SIGTERM` to the process. Stored as `u32` (Unix PIDs fit) instead
    /// of the full `tokio::process::Child` so we don't have to fight ownership
    /// between `wait_with_output` (which consumes the Child) and the kill
    /// command (which needs to read it concurrently).
    pub running_script_pid: Arc<Mutex<Option<u32>>>,
    /// Loaded dexmapper deobfuscation mapping, if any. When set,
    /// `activity_rehydrate` rewrites the IR in place before returning it.
    /// Wrapped in `RwLock` so the load/clear commands don't block readers
    /// for long — load happens once per session.
    pub deobfuscator: Arc<RwLock<Option<Deobfuscator>>>,
}

impl AppState {
    /// Construct from a pre-resolved cache dir, restoring any persisted project.
    pub fn with_cache_dir(cache_dir: PathBuf) -> Self {
        let project = Project::load(&cache_dir);
        Self {
            project: Arc::new(RwLock::new(project)),
            cache_dir,
            running_script_pid: Arc::new(Mutex::new(None)),
            deobfuscator: Arc::new(RwLock::new(None)),
        }
    }
}
