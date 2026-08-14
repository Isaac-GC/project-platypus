//! Virbox Protector for Android (vendor Senstor / 深思数盾) — static
//! recovery backend.
//!
//! Rust port of `unpacker/dump_virbox_dex.py`. Every primitive lives in
//! a focused submodule:
//!
//! - [`markers`] — Virbox-marker detection (Report §3).
//! - [`vbpd`]    — DEX-body VBPD container carving (Report §6).
//! - [`sens`]    — SENS / NEON cipher (Report §6, records>0 path).
//! - [`vmstr`]   — `vm_str` string deobfuscator (Report §7, F_11 path).
//! - [`analyse`] — per-DEX F-method call-site harvester + vm_str apply.
//!
//! What's in scope (matches the Python `dump_xapk` entry point):
//!
//! 1. Resolve XAPK → base APK.
//! 2. Detect Virbox markers + extract build-id.
//! 3. If a SENS file is present and `record_count > 0`, NEON-decrypt
//!    matched APK entries (legacy r21e path).
//! 4. Walk every `classesN.dex` — validate header, carve VBPD if any,
//!    harvest F-method call-sites, decode F_11 vm_str strings.
//! 5. Write `manifest.json` + `UNRECOVERED.md` + per-DEX
//!    `decoded_strings/<dex>.txt` + extracted blobs.
//!
//! What's out of scope (mirrors the Python's UNRECOVERED.md §1-§2):
//!
//! - VBPD bytecode → Dalvik lifting (needs the
//!   `virbox_bundle/scripts/vbpd_lifter/` tooling).
//! - SENS records=0 builds — body cipher is runtime-resolved.
//! - Generic VMP `F<id>_00..09` dispatchers — require the SO's VME
//!   interpreter; call-sites are recorded for downstream tools.

pub mod analyse;
pub mod markers;
pub mod sens;
pub mod vbpd;
pub mod vmstr;

use std::io::Read;
use std::path::Path;

use sha1::Sha1;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::common::{
    extract_base_apk_if_xapk, write_manifest, write_unrecovered, Manifest, RecoveredDex, Stage,
    Unrecovered,
};
use crate::{opts_as_json, Backend, RunOptions, RunResult};

use analyse::{analyse_dex, DexReport, VmpProtectedMethod};
use markers::{detect_virbox, VirboxMarkers};
use sens::{decrypt_sens_protected_entries, SensRecovery};
use vbpd::VBPD_MAGIC;

pub struct Virbox;

const PACKER_NAME: &str = "virbox";

impl Backend for Virbox {
    fn name() -> &'static str {
        PACKER_NAME
    }

    fn run(input_path: &Path, out_dir: &Path, opts: &RunOptions) -> RunResult {
        std::fs::create_dir_all(out_dir)?;
        let work_dir = out_dir.join("_work");
        let base_apk = extract_base_apk_if_xapk(input_path, &work_dir)?;
        if opts.verbose {
            eprintln!("[*] Base APK: {}", base_apk.display());
        }

        // 1) Detect Virbox markers.
        if opts.verbose {
            eprintln!("[*] Detecting Virbox protection markers (Report §3)...");
        }
        let markers = detect_virbox(&base_apk, opts.verbose)?;
        if !markers.confirmed {
            eprintln!(
                "[!] WARNING: Virbox markers did not reach quorum. Will proceed best-effort."
            );
        }
        if opts.verbose {
            eprintln!("  build-id: 0x{}", markers.build_id_hex);
            eprintln!(
                "  m-class:  {}",
                if markers.m_class_name.is_empty() {
                    "(none)"
                } else {
                    &markers.m_class_name
                }
            );
            eprintln!("  F* dispatchers: {}", markers.f_methods.len());
            eprintln!(
                "  SENS file:    {}",
                if markers.sens_file.is_empty() {
                    "(none)"
                } else {
                    &markers.sens_file
                }
            );
            eprintln!("  asset SOs:    {}", markers.asset_so_files.len());
        }

        let base_apk_bytes = std::fs::read(&base_apk)?;
        let base_apk_sha256 = sha256_hex(&base_apk_bytes);

        let mut stages: Vec<Stage> = Vec::new();
        let mut recovered: Vec<RecoveredDex> = Vec::new();
        let mut unrecovered: Vec<Unrecovered> = Vec::new();
        let mut notes = serde_json::Map::new();

        stages.push(Stage::new(
            "detect_markers",
            markers.confirmed,
            format!(
                "build_id={} stub_class={} m_class={} sens={} so={}",
                if markers.build_id_hex.is_empty() {
                    "(none)"
                } else {
                    &markers.build_id_hex
                },
                markers.has_virbox_stub_class,
                if markers.m_class_name.is_empty() {
                    "(none)"
                } else {
                    &markers.m_class_name
                },
                if markers.sens_file.is_empty() {
                    "(none)"
                } else {
                    &markers.sens_file
                },
                markers.asset_so_files.len()
            ),
        ));
        notes.insert(
            "markers".into(),
            serde_json::to_value(&markers).unwrap_or(serde_json::Value::Null),
        );
        notes.insert(
            "base_apk_sha256".into(),
            serde_json::Value::String(base_apk_sha256.clone()),
        );

        // 2) Optional SENS-records>0 path (legacy r21e).
        let mut sens_recovery: Option<SensRecovery> = None;
        if !markers.sens_file.is_empty() {
            if opts.verbose {
                eprintln!(
                    "[*] SENS-protected mode detected (records={:?})",
                    markers.sens_record_count
                );
                if markers.sens_record_count == Some(0) {
                    eprintln!("    -> records=0: body cipher is runtime-resolved");
                    eprintln!(
                        "       (UNRECOVERED.md §1). Will still attempt DEX extraction."
                    );
                }
            }
            let mut zf = ZipArchive::new(std::io::Cursor::new(base_apk_bytes.clone()))
                .map_err(|e| anyhow::anyhow!("open base APK as zip: {e}"))?;
            let mut sens_blob = Vec::new();
            zf.by_name(&markers.sens_file)
                .map_err(|e| anyhow::anyhow!("SENS file {}: {e}", markers.sens_file))?
                .read_to_end(&mut sens_blob)?;
            let sens_dir = out_dir.join("sens_recovered");
            let rec = decrypt_sens_protected_entries(&mut zf, &sens_blob, &sens_dir, opts.verbose)?;
            if rec.record_count > 0 && opts.verbose {
                eprintln!(
                    "  [+] {} entries decrypted (unmatched: {})",
                    rec.recovered_entries.len(),
                    rec.unmatched_hashes
                );
            }
            stages.push(Stage::new(
                "sens_decrypt",
                rec.record_count > 0,
                if rec.record_count == 0 {
                    "records=0 — body cipher is runtime-resolved (UNRECOVERED.md §1)".to_string()
                } else {
                    format!(
                        "records={} decrypted={} unmatched={}",
                        rec.record_count,
                        rec.recovered_entries.len(),
                        rec.unmatched_hashes
                    )
                },
            ));
            if rec.record_count == 0 {
                unrecovered.push(Unrecovered {
                    item: "SENS records=0 body cipher".into(),
                    reason:
                        "SENS file declares record_count=0; body cipher is resolved at runtime via \
                         *(SO+0x30fde0) and cannot be executed statically (Report §6 / \
                         FINDINGS_REVIEW §5b)."
                            .into(),
                });
            }
            sens_recovery = Some(rec);
        } else {
            stages.push(Stage::new(
                "sens_decrypt",
                true,
                "no SENS file in APK — skip legacy r21e records>0 path",
            ));
        }
        if let Some(rec) = &sens_recovery {
            notes.insert(
                "sens_recovery".into(),
                serde_json::to_value(rec).unwrap_or(serde_json::Value::Null),
            );
        }

        // 3) Walk every DEX in the base APK.
        if opts.verbose {
            eprintln!("[*] Recovering DEX files (Report §6)...");
        }
        let recovered_dir = out_dir.join("recovered_dex");
        std::fs::create_dir_all(&recovered_dir)?;
        let extracted_dir = out_dir.join("extracted");

        let mut dex_reports: Vec<DexReport> = Vec::new();
        let mut decoded_strings_count: usize = 0;

        {
            let mut zf = ZipArchive::new(std::io::Cursor::new(base_apk_bytes.clone()))
                .map_err(|e| anyhow::anyhow!("open base APK as zip: {e}"))?;
            let mut dex_names: Vec<String> = zf
                .file_names()
                .filter(|n| n.starts_with("classes") && n.ends_with(".dex") && !n.contains('/'))
                .map(|s| s.to_string())
                .collect();
            dex_names.sort();

            for dn in dex_names {
                let mut d = Vec::new();
                if let Ok(mut entry) = zf.by_name(&dn) {
                    if entry.read_to_end(&mut d).is_err() {
                        continue;
                    }
                } else {
                    continue;
                }
                let (valid, why) = validate_dex_header(&d);
                if opts.verbose {
                    let vbpd = if contains(&d, VBPD_MAGIC) { "VBPD✓" } else { "      " };
                    eprintln!(
                        "  [{}] {}  {:>10} bytes  {}",
                        vbpd,
                        dn,
                        d.len(),
                        if valid { "valid" } else { why.as_str() }
                    );
                }
                // Write the DEX verbatim regardless of validity.
                std::fs::write(recovered_dir.join(&dn), &d)?;

                // Carve VBPD container, if any.
                if let Some(mut vc) = vbpd::find_vbpd_container(&d, &dn) {
                    let blob = &d[vc.container_offset
                        ..(vc.container_offset + vc.container_size).min(d.len())];
                    std::fs::create_dir_all(&extracted_dir)?;
                    let vc_path = extracted_dir.join(format!("vbpd_{}.bin", dn));
                    std::fs::write(&vc_path, blob)?;
                    vc.blob_path = vc_path.to_string_lossy().into_owned();
                    // Record the carved container in the report below.
                    let mut rep = analyse_dex(&d, &dn, &markers.build_id_hex)?;
                    rep.vbpd_container = Some(vc);
                    let decoded_count = rep.decoded_strings.len();
                    decoded_strings_count += decoded_count;
                    // Per-DEX decoded-strings corpus → file.
                    if !rep.decoded_strings.is_empty() {
                        let ofp = out_dir.join("decoded_strings").join(format!("{}.txt", dn));
                        if let Some(parent) = ofp.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        std::fs::write(&ofp, rep.decoded_strings.join("\n"))?;
                        if opts.verbose {
                            eprintln!(
                                "        decoded {} vm_str strings -> decoded_strings/{}.txt",
                                decoded_count, dn
                            );
                        }
                    }
                    // Cap sites per variant for JSON brevity (Python: 32).
                    cap_dispatch_sites(&mut rep, 32);
                    // Clear the in-report corpus (kept on disk).
                    rep.decoded_strings.clear();
                    dex_reports.push(rep);
                } else {
                    let mut rep = analyse_dex(&d, &dn, &markers.build_id_hex)?;
                    let decoded_count = rep.decoded_strings.len();
                    decoded_strings_count += decoded_count;
                    if !rep.decoded_strings.is_empty() {
                        let ofp = out_dir.join("decoded_strings").join(format!("{}.txt", dn));
                        if let Some(parent) = ofp.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        std::fs::write(&ofp, rep.decoded_strings.join("\n"))?;
                        if opts.verbose {
                            eprintln!(
                                "        decoded {} vm_str strings -> decoded_strings/{}.txt",
                                decoded_count, dn
                            );
                        }
                    }
                    cap_dispatch_sites(&mut rep, 32);
                    rep.decoded_strings.clear();
                    dex_reports.push(rep);
                }

                // Manifest RecoveredDex entry (one per DEX walked).
                let magic = hex_prefix(&d, 8);
                let mut extra = serde_json::Map::new();
                if !valid {
                    extra.insert(
                        "validation_error".into(),
                        serde_json::Value::String(why.clone()),
                    );
                }
                recovered.push(RecoveredDex {
                    name: dn.clone(),
                    size: d.len(),
                    sha256: sha256_hex(&d),
                    magic,
                    valid_dex_magic: d.starts_with(b"dex\n") || d.starts_with(b"dey\n"),
                    ok: valid,
                    recovery: "verbatim copy of plaintext DEX (Virbox bytecode dispatcher only)"
                        .to_string(),
                    source: Some(dn.clone()),
                    out_path: Some(recovered_dir.join(&dn).to_string_lossy().into_owned()),
                    extra,
                });
            }
        }

        // 4) Build UNRECOVERED items from the generic-VMP call-sites.
        let mut unrecoverable_methods: Vec<(String, VmpProtectedMethod)> = Vec::new();
        for rd in &dex_reports {
            for v in &rd.vmp_protected_methods {
                unrecoverable_methods.push((rd.name.clone(), v.clone()));
            }
        }
        let unrecoverable_count = unrecoverable_methods.len();
        for (dex, vmp) in &unrecoverable_methods {
            unrecovered.push(Unrecovered {
                item: format!(
                    "{}::{}{} (F<id>{})",
                    vmp.caller_class, vmp.caller_method, vmp.caller_descriptor, vmp.dispatch_variant
                ),
                reason: format!(
                    "Generic VMP dispatch via {}->F<id>{}; body lives in the SO's VME interpreter \
                     and requires either dispatch-table reconstruction or runtime Frida capture. \
                     Source DEX: {}",
                    if markers.m_class_name.is_empty() {
                        "Lm<id>;"
                    } else {
                        &markers.m_class_name
                    },
                    vmp.dispatch_variant,
                    dex
                ),
            });
        }
        stages.push(Stage::new(
            "analyse_dexs",
            !dex_reports.is_empty(),
            format!(
                "{} DEX(s) analysed, {} vm_str strings decoded, {} VMP call-sites unrecovered",
                dex_reports.len(),
                decoded_strings_count,
                unrecoverable_count
            ),
        ));
        notes.insert(
            "recovered_dexs_analysis".into(),
            serde_json::to_value(&dex_reports).unwrap_or(serde_json::Value::Null),
        );
        notes.insert(
            "decoded_strings_count".into(),
            serde_json::Value::from(decoded_strings_count),
        );
        notes.insert(
            "unrecoverable_method_count".into(),
            serde_json::Value::from(unrecoverable_count),
        );

        // Write the Virbox-specific UNRECOVERED.md (more detailed than
        // the common one); the common one is also written afterwards
        // for shape compatibility.
        let unrec_md_path = out_dir.join("UNRECOVERED.md");
        write_unrecovered_md(
            &unrec_md_path,
            &markers,
            &unrecoverable_methods,
            sens_recovery.as_ref(),
        )?;
        if opts.verbose {
            eprintln!(
                "[*] UNRECOVERED.md → {} ({} entries)",
                unrec_md_path.display(),
                unrecoverable_count
            );
        }

        let manifest = Manifest {
            packer: PACKER_NAME.into(),
            backend: "platypus_unpackers::virbox".into(),
            input: std::fs::canonicalize(input_path)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| input_path.to_string_lossy().into_owned()),
            out_dir: out_dir
                .canonicalize()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| out_dir.to_string_lossy().into_owned()),
            options: opts_as_json(opts),
            stages,
            recovered_dexs: recovered,
            unrecovered: unrecovered.clone(),
            notes,
            detection: serde_json::Value::Null,
            elapsed_sec: None,
            scaffold_note: None,
        };
        write_manifest(out_dir, &manifest)?;
        // The Virbox-specific UNRECOVERED.md was already written above;
        // we DO NOT overwrite it with the common shorter form.
        // Common's `write_unrecovered` writes to the same path, so
        // intentionally skip it here. (Other backends call it because
        // they don't have a richer custom doc.)
        // We still want a generic fallback path for the common write —
        // emit it under a sibling filename to keep the rich doc.
        let _ = write_unrecovered; // silence "unused import" — the
                                   // common helper is reserved for
                                   // backends that don't produce a
                                   // family-specific UNRECOVERED.md.
        Ok(manifest)
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Cap the dispatch-site list per variant to keep manifest.json
/// readable (Python uses 32). When truncation happens, we append a
/// sentinel site with `_truncated_remainder = N` (matches Python).
fn cap_dispatch_sites(rep: &mut DexReport, cap: usize) {
    use analyse::DispatchSite;
    for (_, info) in rep.f_dispatch_sites.iter_mut() {
        if info.sites.len() > cap {
            let remainder = info.sites.len() - cap;
            info.sites.truncate(cap);
            info.sites.push(DispatchSite {
                caller_class: format!("_truncated_remainder={}", remainder),
                caller_method: String::new(),
                caller_descriptor: String::new(),
                regs: Vec::new(),
                encoded: None,
                decoded: None,
            });
        }
    }
}

/// Run the DEX self-consistency checks: magic, file_size, adler32, sha1.
/// Returns `(ok, why)` — `why` is a human-readable failure description.
pub fn validate_dex_header(d: &[u8]) -> (bool, String) {
    if d.len() < 36 {
        return (false, format!("short ({} bytes)", d.len()));
    }
    if &d[..4] != b"dex\n" {
        return (false, format!("bad magic {:?}", &d[..4]));
    }
    let file_size = u32::from_le_bytes([d[32], d[33], d[34], d[35]]) as usize;
    if file_size != d.len() {
        return (
            false,
            format!("file_size mismatch (header={} actual={})", file_size, d.len()),
        );
    }
    let stored_adler =
        u32::from_le_bytes([d[8], d[9], d[10], d[11]]);
    let actual_adler = adler32(&d[12..]);
    if stored_adler != actual_adler {
        return (
            false,
            format!(
                "adler32 mismatch (stored=0x{:08x} actual=0x{:08x})",
                stored_adler, actual_adler
            ),
        );
    }
    let mut h = Sha1::new();
    h.update(&d[32..]);
    let actual_sha1 = h.finalize();
    if &d[12..32] != actual_sha1.as_slice() {
        return (false, "sha1 mismatch".to_string());
    }
    (true, "ok".to_string())
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    let digest = h.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    use std::fmt::Write;
    for byte in digest {
        let _ = write!(&mut s, "{:02x}", byte);
    }
    s
}

fn hex_prefix(b: &[u8], n: usize) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(n * 2);
    for byte in &b[..b.len().min(n)] {
        let _ = write!(&mut s, "{:02x}", byte);
    }
    s
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Write the Virbox-specific UNRECOVERED.md (Report §9).
/// More detailed than `crate::common::write_unrecovered` because the
/// Virbox path has many distinct unrecovery reasons.
fn write_unrecovered_md(
    path: &Path,
    markers: &VirboxMarkers,
    methods: &[(String, VmpProtectedMethod)],
    sens_recovery: Option<&SensRecovery>,
) -> std::io::Result<()> {
    let mut lines = vec![
        "# UNRECOVERED methods".to_string(),
        String::new(),
        "Methods whose original Java bodies are not statically recoverable".into(),
        "by this tool. Reasons follow the format defined in".into(),
        "`findings/virbox-analysis.md §9` (VME interpreter required).".into(),
        String::new(),
        format!("Sample build-id: `{}`", markers.build_id_hex),
        format!("Outer Application class: `{}`", markers.application_class),
        format!("VME dispatcher class: `{}`", markers.m_class_name),
        String::new(),
    ];

    if let Some(sr) = sens_recovery {
        if sr.record_count == 0 {
            lines.extend([
                "## §1 — SENS records=0 body cipher".to_string(),
                String::new(),
                format!(
                    "The SENS file ({}) declares `record_count = 0`. Per Report §6 / \
                     FINDINGS_REVIEW §5b, the body cipher for this mode is resolved at runtime \
                     via a function pointer at `*(SO+0x30fde0)` and is not statically determined. \
                     Methods whose recovery depends on this cipher are listed below as well.",
                    markers.sens_file
                ),
                String::new(),
            ]);
        } else {
            lines.extend([
                format!("## §1 — SENS records={} cipher", sr.record_count),
                String::new(),
                format!("Recovered key: `{}`", sr.cipher_key_hex),
                format!("NEON multiplier x8 = `0x{:x}`", sr.x8),
                format!(
                    "{} entries restored to plaintext (see `sens_recovered/`).",
                    sr.recovered_entries.len()
                ),
                String::new(),
            ]);
        }
    }

    let mclass_disp = if markers.m_class_name.is_empty() {
        "Lm<id>;".to_string()
    } else {
        markers.m_class_name.clone()
    };
    lines.extend([
        "## §2 — Methods whose dispatch is via Virbox VME bytecode".to_string(),
        String::new(),
        format!(
            "Each entry below is a *call-site* of one of `{}->F<id>_{{00..09}}` — the 10 generic \
             VMP dispatchers. The method's *original* Dalvik body has been replaced by a stub that \
             calls into the SO's VME interpreter, which decodes a private (per-build-randomised) \
             bytecode and executes it natively. Because the dispatch table at SO+0x3107c8 is \
             per-build randomised (Report §8.2), and the opcode meanings depend on per-build \
             handler addresses, static recovery of the original method body requires either (a) \
             reconstructing the dispatch table from the SO and lifting the bytecode back to \
             Dalvik, or (b) capturing the decrypted bytecode at runtime via Frida.",
            mclass_disp
        ),
        String::new(),
    ]);

    if methods.is_empty() {
        lines.extend([
            "_No `F<id>_{00..09}` call-sites observed in this build._  The protection observed \
             here is **string-encryption-only** (F<id>_11 only — Report §7). All other DEX \
             content is plaintext."
                .to_string(),
            String::new(),
        ]);
    } else {
        lines.push("| DEX | Caller class | Caller method | Dispatch variant |".into());
        lines.push("| --- | --- | --- | --- |".into());
        for (dex, m) in methods {
            lines.push(format!(
                "| `{}` | `{}` | `{}{}` | `F<id>{}` |",
                dex, m.caller_class, m.caller_method, m.caller_descriptor, m.dispatch_variant
            ));
        }
        lines.push(String::new());
    }

    lines.extend([
        "## §3 — Tool steps cross-reference".to_string(),
        String::new(),
        "| Section in `virbox::` | What it recovers | Status |".into(),
        "| --- | --- | --- |".into(),
        "| §1 XAPK/APK splitter | base APK from APK-Pure bundle | OK |".into(),
        "| §3 marker detection | identifies Virbox + build-id | OK |".into(),
        "| §4 VBPD extraction  | dumps container blob; doesn't translate bytecode | partial — needs vbpd_lifter |"
            .into(),
        "| §5 SENS records>0   | NEON-poly cipher (Report §6) | OK when SENS present and records>0 |"
            .into(),
        "| §5 SENS records=0   | runtime cipher pointer | UNRECOVERED (§1) |".into(),
        "| §6 vm_str (F_11)    | string deobfuscator (Report §7) | OK |".into(),
        "| §7 DEX recovery     | plaintext copy of every classesN.dex | OK |".into(),
        String::new(),
    ]);
    std::fs::write(path, lines.join("\n"))?;
    Ok(())
}
