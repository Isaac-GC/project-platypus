//! Static dumpers for Android packers (Jiagu/Qihoo, FengYue, Ijiami,
//! DexShield, Virbox).
//!
//! Rust port of the Python `unpacker/` module. Every backend is purely
//! static — no native code from the sample is ever executed.
//!
//! ## Public surface
//!
//! * [`detect`] — fingerprint a sample to a packer family.
//! * [`Backend`] — trait every per-packer module implements.
//! * [`run_one`] — top-level orchestrator: detect + dispatch + write
//!   manifest. Mirrors `dump_packer.run_one` in Python.
//! * Per-family modules: [`dexshield`], [`ijiami`], [`fengyue`], [`jiagu`],
//!   [`virbox`]. Each exposes a `run(input_path, out_dir, opts) -> Manifest`.
//!
//! ## What's NOT yet ported
//!
//! * `jiagu_unicorn` — the 2,765-line opt-in AArch64 emulator harness
//!   is stubbed in [`jiagu::unicorn`]; it returns `Err(UnicornUnavailable)`.
//!   The default jiagu path doesn't need it.
//! * `virbox` — the real cipher logic lives in a sibling
//!   `dump_virbox_dex.py` file that isn't under `unpacker/`. The stub
//!   reports `not_implemented` until that source surfaces.

pub mod axml;
pub mod common;
pub mod detect;

pub mod dexshield;
pub mod fengyue;
pub mod ijiami;
pub mod jiagu;
pub mod virbox;

pub use common::{
    sha256_bytes, sha256_file, CarvedEntry, Manifest, RecoveredDex, Stage, Unrecovered,
};
pub use detect::{detect, known_backends, Detection, FamilyHit};

use std::path::{Path, PathBuf};

/// Per-run options passed through to every backend. Matches the
/// keyword-argument surface of `unpacker/dump_packer.py::run_one`
/// (verbose, force, plus the jiagu-specific unicorn knobs).
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub verbose: bool,
    pub force: bool,
    pub use_unicorn: bool,
    pub unicorn_insns: u64,
    /// If set, the inner .so to feed into the unicorn harness's
    /// FindResource hook (mirrors the Python `mock_inner_so` arg).
    pub unicorn_mock_inner_so: Option<PathBuf>,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            verbose: false,
            force: false,
            use_unicorn: false,
            // Default budget matches Python: 5M instructions ≈ 30s wall
            // on debug interpreter at the packer dump rates we've seen.
            unicorn_insns: 50_000_000,
            unicorn_mock_inner_so: None,
        }
    }
}

/// Standard return shape — the per-backend `run()` either succeeds with
/// a [`Manifest`] (even if individual stages failed; that's encoded in
/// `stages[].ok`) or surfaces a hard I/O/parse failure as an `Err`.
pub type RunResult = Result<Manifest, anyhow::Error>;

/// Trait every per-packer module implements. Lets `run_one` dispatch
/// generically and lets callers swap in new backends without touching
/// the orchestrator.
pub trait Backend {
    /// Stable family name — `"jiagu"`, `"fengyue"`, etc. Used in the
    /// manifest `packer` field and as the dispatch key.
    fn name() -> &'static str;

    /// Run static recovery against `input_path`, writing artefacts to
    /// `out_dir` and returning the per-sample manifest.
    fn run(input_path: &Path, out_dir: &Path, opts: &RunOptions) -> RunResult;
}

/// Top-level orchestrator. Detect the family (or honour `override_packer`),
/// dispatch to the appropriate backend, fold in the detection summary,
/// and return the manifest.
///
/// Mirrors `unpacker/dump_packer.py::run_one`. The result is also
/// written to `out_dir/<stem>/manifest.json` by the backend itself.
pub fn run_one(
    input_path: &Path,
    out_root: &Path,
    override_packer: Option<&str>,
    opts: &RunOptions,
) -> RunResult {
    use std::time::Instant;
    let start = Instant::now();

    // Derive the per-sample output dir from the input stem (matches the
    // `<out>/<stem>/...` Python layout). Skips repeated `.apk.apk` etc.
    let stem = input_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "sample".into());
    let out_dir = out_root.join(stem);
    std::fs::create_dir_all(&out_dir)?;

    // 1) Detect.
    let det = detect(input_path)?;
    let packer = override_packer.unwrap_or(&det.primary);

    // 2) Dispatch.
    let mut manifest = match packer {
        "dexshield" => dexshield::Dexshield::run(input_path, &out_dir, opts)?,
        "ijiami" => ijiami::Ijiami::run(input_path, &out_dir, opts)?,
        "fengyue" => fengyue::Fengyue::run(input_path, &out_dir, opts)?,
        "jiagu" => jiagu::Jiagu::run(input_path, &out_dir, opts)?,
        "virbox" => virbox::Virbox::run(input_path, &out_dir, opts)?,
        other => {
            // Unknown / unsupported. Still emit a manifest so batch
            // mode produces uniform output.
            let m = Manifest {
                packer: other.to_string(),
                backend: "platypus_unpackers::run_one".into(),
                input: input_path.to_string_lossy().into_owned(),
                out_dir: out_dir.to_string_lossy().into_owned(),
                options: opts_as_json(opts),
                stages: vec![Stage::new(
                    "dispatch",
                    false,
                    format!("no backend registered for packer family {:?}", other),
                )],
                recovered_dexs: Vec::new(),
                unrecovered: vec![Unrecovered {
                    item: "inner classes.dex".into(),
                    reason: format!("packer family {:?} is unknown to platypus-unpackers", other),
                }],
                notes: serde_json::Map::new(),
                detection: serde_json::Value::Null,
                elapsed_sec: None,
                scaffold_note: None,
            };
            common::write_manifest(&out_dir, &m)?;
            common::write_unrecovered(&out_dir, &m.unrecovered, other)?;
            m
        }
    };

    // 3) Fold in detection + elapsed time, re-serialise so the manifest
    // on disk has both. Matches Python `run_one` augmentation.
    manifest.detection = serde_json::to_value(&det).unwrap_or(serde_json::Value::Null);
    manifest.elapsed_sec = Some(start.elapsed().as_secs_f64());
    common::write_manifest(&out_dir, &manifest)?;
    Ok(manifest)
}

/// Helper used by `run_one` and every backend to put the [`RunOptions`]
/// into the manifest's `options` field in the same shape Python emits.
pub(crate) fn opts_as_json(opts: &RunOptions) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("verbose".into(), serde_json::Value::Bool(opts.verbose));
    m.insert("force".into(), serde_json::Value::Bool(opts.force));
    m.insert("use_unicorn".into(), serde_json::Value::Bool(opts.use_unicorn));
    m.insert(
        "unicorn_insns".into(),
        serde_json::Value::from(opts.unicorn_insns),
    );
    if let Some(p) = &opts.unicorn_mock_inner_so {
        m.insert(
            "unicorn_mock_inner_so".into(),
            serde_json::Value::String(p.to_string_lossy().into_owned()),
        );
    }
    serde_json::Value::Object(m)
}
