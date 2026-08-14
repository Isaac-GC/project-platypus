//! Stub for the Unicorn-based AArch64 emulator harness.
//!
//! The full Python harness lives in
//! `unpacker/packer_backends/jiagu_unicorn.py` (~2,765 LoC). It maps
//! the SO's `PT_LOAD` segments, resolves dynamic relocations + JMPRELs
//! (libc imports → BRK trampolines serviced from Python), runs
//! `DT_INIT_ARRAY`, calls `JNI_OnLoad` with a mocked JavaVM/JNIEnv that
//! captures `FindClass`/`RegisterNatives`/`DefineClass`, and scans the
//! heap for DEX magic + checksums at exit. Even when no full DEX is
//! captured, it produces a trace of JNI calls + heap allocations that
//! is diagnostically useful.
//!
//! TODO(port): port the unicorn harness. The Rust replacement should
//! depend on the `unicorn-engine` crate (4.0+) and live in this
//! module. Until that lands, every call returns an error.
//!
//! Placeholder [`EmulationResult`] is provided so dependent callers
//! can still compile. The placeholder's fields match the *names* of
//! the Python `EmulationResult` dataclass so a future port can wire
//! through without API churn.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Placeholder for the Python `EmulationResult` dataclass. All fields
/// default-empty until the harness is ported.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulationResult {
    pub status: String,
    pub insns_executed: u64,
    pub elapsed_sec: f64,
    pub error: Option<String>,
    /// JNI call trace lines.
    pub jni_trace: Vec<String>,
    /// Syscall trace lines.
    pub syscall_trace: Vec<String>,
    /// Captured DEX payloads (heap scans + DefineClass hits).
    pub dex_payloads: Vec<Vec<u8>>,
    /// Captured RC4 decrypt buffers: `(vaddr, size, bytes)`.
    pub rc4_captures: Vec<(u64, usize, Vec<u8>)>,
    /// Captured single-byte-XOR decrypt buffers: `(vaddr, size, bytes)`.
    pub xor_captures: Vec<(u64, usize, Vec<u8>)>,
    /// `class FQCN → [(name, sig, fnptr_va)]` from RegisterNatives.
    pub registered_natives: HashMap<String, Vec<(String, String, u64)>>,
    /// Symbol names the second-stage `__arm_a_1` looks up via the
    /// custom `dlsym` (vaddr `0xca38`).
    pub inner_so_required_symbols: Vec<String>,
    /// True if the inner-SO `JNI_OnLoad` was actually invoked.
    pub inner_jni_onload_invoked: bool,
}

/// Inputs for the not-yet-ported Unicorn harness. Fields mirror the
/// Python `emulate_libjiagu(...)` keyword arguments.
///
/// `so_path` is required; other fields default to "no value" so
/// callers can construct partial inputs with struct-update syntax.
#[derive(Debug, Clone)]
pub struct EmulationInputs<'a> {
    pub so_path: &'a Path,
    pub package_name: Option<&'a str>,
    pub apk_md5: Option<&'a str>,
    pub asset_bytes: HashMap<String, Vec<u8>>,
    pub max_instructions: u64,
    pub mock_inner_so: Option<&'a Path>,
    pub verbose: bool,
}

impl<'a> EmulationInputs<'a> {
    /// Build a new inputs struct with default values for all optional
    /// fields. The SO path is the single required argument.
    pub fn new(so_path: &'a Path) -> Self {
        Self {
            so_path,
            package_name: None,
            apk_md5: None,
            asset_bytes: HashMap::new(),
            max_instructions: 0,
            mock_inner_so: None,
            verbose: false,
        }
    }
}

/// Stub: returns `Err` until the Unicorn harness is ported. The
/// Python implementation is at
/// `unpacker/packer_backends/jiagu_unicorn.py` and is ~2,765 LoC of
/// custom JNI mocking + libc trampolines.
pub fn emulate_libjiagu(_inputs: &EmulationInputs<'_>) -> Result<EmulationResult> {
    Err(anyhow!(
        "unicorn emulation not yet ported — see TODO in src/jiagu/unicorn.rs; \
         use the Python `unpacker/packer_backends/jiagu_unicorn.py` for now"
    ))
}
