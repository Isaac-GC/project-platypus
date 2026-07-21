//! `platypus-unpack` — CLI entry point for the static Android-packer
//! DEX dumper.
//!
//! Direct port of `unpacker/dump_packer.py` argparse surface:
//!   * positional `<input>` — APK / XAPK / `.zip`-bundled (or a directory
//!     when `--batch` is set).
//!   * `-o, --out` — output root (default `dump_out`).
//!   * `--packer auto|virbox|jiagu|ijiami|dexshield|fengyue` — force a
//!     specific backend instead of auto-detecting.
//!   * `-v, --verbose` — pass through to the backend's tracer.
//!   * `--force` — re-run even if a manifest already exists.
//!   * `--batch` — treat `<input>` as a directory and process every
//!     APK/XAPK/zip inside; emits `batch_index.json`.
//!   * `--test` — terse PASS/FAIL lines for CI.
//!   * `--use-unicorn`, `--unicorn-insns`, `--unicorn-mock-inner-so` —
//!     jiagu-only opt-in (currently routed to the stubbed emulator;
//!     the stub records the request but doesn't decrypt anything).
//!
//! Exit code mirrors the Python:
//!   0 — every sample produced at least one recovered DEX
//!   2 — some input was not a file or crashed in `--test` mode
//!   3 — `--test` ran but zero DEX were recovered for some sample

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, ValueEnum};

use platypus_unpackers::{detect, run_one, Manifest, RunOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Packer {
    Auto,
    Virbox,
    Jiagu,
    Ijiami,
    Dexshield,
    Fengyue,
}

impl Packer {
    fn as_override(self) -> Option<&'static str> {
        match self {
            Packer::Auto => None,
            Packer::Virbox => Some("virbox"),
            Packer::Jiagu => Some("jiagu"),
            Packer::Ijiami => Some("ijiami"),
            Packer::Dexshield => Some("dexshield"),
            Packer::Fengyue => Some("fengyue"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "platypus-unpack",
    about = "Static DEX dumper for Chinese-origin Android packers \
             (Virbox / Jiagu / FengYue / Ijiami / DexShield). \
             No native code from the sample is ever executed.",
    long_about = None,
)]
struct Args {
    /// APK or XAPK file (or a directory of them with --batch).
    input: PathBuf,

    /// Output root directory.
    #[arg(short = 'o', long = "out", default_value = "dump_out")]
    out: PathBuf,

    /// Force a particular backend instead of auto-detecting.
    #[arg(long = "packer", value_enum, default_value_t = Packer::Auto)]
    packer: Packer,

    /// Trace every step in the backend output.
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    verbose: bool,

    /// Re-run even if manifest.json already exists. (Reserved — backends
    /// currently always overwrite. The flag is plumbed through `RunOptions`
    /// so a future cache-skip path can honour it.)
    #[arg(long = "force", action = ArgAction::SetTrue)]
    force: bool,

    /// Treat `input` as a directory; process every APK/XAPK/zip inside.
    #[arg(long = "batch", action = ArgAction::SetTrue)]
    batch: bool,

    /// Terse PASS/FAIL summaries (CI mode).
    #[arg(long = "test", action = ArgAction::SetTrue)]
    test: bool,

    /// (jiagu only) enable the Unicorn-based emulator pass after the
    /// static carve. Currently routed to the stubbed emulator; the
    /// stub records the request as `unicorn_missing`.
    #[arg(long = "use-unicorn", action = ArgAction::SetTrue)]
    use_unicorn: bool,

    /// Per-call instruction budget for the Unicorn pass.
    #[arg(long = "unicorn-insns", default_value_t = 50_000_000)]
    unicorn_insns: u64,

    /// (jiagu only) Bypass the custom inner-SO loader. Path of the
    /// stand-in .so to inject for testing. Matches the Python
    /// `--unicorn-mock-inner-so` semantics (boolean flag in Python;
    /// here we accept a path so the harness has bytes to feed).
    #[arg(long = "unicorn-mock-inner-so")]
    unicorn_mock_inner_so: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let inputs: Vec<PathBuf> = if args.batch {
        if !args.input.is_dir() {
            eprintln!("--batch requires a directory, got {}", args.input.display());
            return ExitCode::from(2);
        }
        let mut v: Vec<PathBuf> = match std::fs::read_dir(&args.input) {
            Ok(rd) => rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.is_file()
                        && p.extension()
                            .and_then(|s| s.to_str())
                            .map(|s| {
                                let l = s.to_ascii_lowercase();
                                l == "apk" || l == "xapk" || l == "zip"
                            })
                            .unwrap_or(false)
                })
                .collect(),
            Err(e) => {
                eprintln!("failed to read directory {}: {e}", args.input.display());
                return ExitCode::from(2);
            }
        };
        v.sort();
        v
    } else {
        vec![args.input.clone()]
    };

    let opts = RunOptions {
        verbose: args.verbose,
        force: args.force,
        use_unicorn: args.use_unicorn,
        unicorn_insns: args.unicorn_insns,
        unicorn_mock_inner_so: args.unicorn_mock_inner_so.clone(),
    };

    let mut rc: u8 = 0;
    let mut summaries: Vec<Manifest> = Vec::with_capacity(inputs.len());

    for inp in &inputs {
        if !inp.is_file() {
            println!("FAIL  not a file: {}", inp.display());
            rc = rc.max(2);
            continue;
        }

        // Dispatch via either the user's --packer override or the
        // auto-detector. Both paths flow through the library's
        // `run_one` so the manifest shape is identical.
        let manifest = match drive_one(inp, &args.out, args.packer.as_override(), &opts) {
            Ok(m) => m,
            Err(e) => {
                if args.test {
                    println!(
                        "FAIL  {}: {e}",
                        inp.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                    );
                    rc = rc.max(2);
                    continue;
                } else {
                    eprintln!("error processing {}: {e:?}", inp.display());
                    rc = rc.max(2);
                    continue;
                }
            }
        };

        if args.test {
            let n_rec = manifest.recovered_dexs.iter().filter(|r| r.ok).count();
            let n_unr = manifest.unrecovered.len();
            let label = if n_rec > 0 { "PASS" } else { "FAIL" };
            println!(
                "{label}  {}  packer={}  recovered={n_rec}  unrecovered={n_unr}",
                inp.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
                manifest.packer,
            );
            if n_rec == 0 {
                rc = rc.max(3);
            }
        } else if !args.verbose {
            let n_rec = manifest.recovered_dexs.iter().filter(|r| r.ok).count();
            let n_unr = manifest.unrecovered.len();
            println!(
                "[{:>9}] {}  recovered={n_rec}  unrecovered={n_unr}  -> {}",
                manifest.packer,
                inp.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
                manifest.out_dir,
            );
        }

        summaries.push(manifest);
    }

    if args.batch && !args.test {
        let mut by_packer = std::collections::BTreeMap::<String, u64>::new();
        for m in &summaries {
            *by_packer.entry(m.packer.clone()).or_insert(0) += 1;
        }
        let idx = serde_json::json!({
            "n_total": inputs.len(),
            "n_processed": summaries.len(),
            "by_packer": by_packer,
        });
        let out_index = args.out.join("batch_index.json");
        if let Err(e) = std::fs::create_dir_all(&args.out)
            .and_then(|()| std::fs::write(&out_index, serde_json::to_string_pretty(&idx).unwrap()))
        {
            eprintln!("failed to write batch index {}: {e}", out_index.display());
            rc = rc.max(2);
        } else {
            println!(
                "[batch] processed {}/{}; index at {}",
                summaries.len(),
                inputs.len(),
                out_index.display(),
            );
        }
    }

    ExitCode::from(rc)
}

/// Wrap `run_one` with a graceful fallback for the case where the
/// detector hits an unknown family AND no override was supplied. The
/// library's `run_one` writes a placeholder manifest in that case; we
/// also surface a hint on stderr so the operator knows to inspect.
fn drive_one(
    inp: &Path,
    out: &Path,
    override_packer: Option<&str>,
    opts: &RunOptions,
) -> Result<Manifest> {
    // Pre-detect so we can emit a helpful diagnostic if neither the
    // override nor the auto-detect finds a known family.
    let det = detect(inp).with_context(|| format!("detect {}", inp.display()))?;
    if override_packer.is_none() && det.primary == "unknown" && !opts.verbose {
        eprintln!(
            "[detect] {} : no known packer family matched (confidence={}). \
             Markers: {}",
            inp.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
            det.confidence,
            det.all_families
                .iter()
                .map(|h| format!("{}({})", h.family, h.evidence))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    run_one(inp, out, override_packer, opts)
}
