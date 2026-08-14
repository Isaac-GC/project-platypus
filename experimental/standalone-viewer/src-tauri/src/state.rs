//! Per-process state for the standalone shell.
//!
//! Stores the most-recently-loaded APK path. The shell is single-APK by
//! design — if the user opens a second APK, this slot is replaced. (The
//! Project Platypus integration has multi-slot semantics; this shell
//! intentionally doesn't.)

use std::sync::RwLock;

use platypus_dexmapper::Deobfuscator;

#[derive(Default)]
pub struct AppState {
    /// Current APK path, set by `open_apk`. `None` until the user picks one.
    pub apk_path: RwLock<Option<String>>,
    /// Loaded deobfuscation mapping. `None` until the user loads one;
    /// when present, `activity_rehydrate` automatically rewrites the IR
    /// before returning it to the frontend.
    pub deobfuscator: RwLock<Option<Deobfuscator>>,
}

impl AppState {
    pub fn new() -> Self { Self::default() }
}
