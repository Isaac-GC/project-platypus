//! Qihoo 360 Jiagu backend.
//!
//! Direct port of `unpacker/packer_backends/jiagu.py`. What this
//! backend can do statically:
//!
//! - Identify the packer via `assets/.jgapp`, `assets/libjiagu*.so`,
//!   variant-named loaders (`libjg<tag>.so`), and the stub Application
//!   class (`com.stub.StubApp`, `com.qihoo.util.StubApp`).
//! - Recover the original Application class FQCN from the manifest
//!   `<meta-data>` indirection.
//! - Carve the outer stub `classes.dex` (Java shell + meta-data key).
//! - Carve `assets/.jgapp`, every `assets/libjiagu*.so`, every
//!   variant loader, and every `lib/<abi>/libjiagu_sdk_*Protected.so`
//!   to `<out>/extracted/`.
//! - Parse the `qh\x00\x01` trailer appended to `classes.dex` —
//!   recovers ~50 key/value metadata entries per sample. See
//!   [`trailer`] for the format.
//! - Walk plaintext `code_item`s in entry-0's tail + post-e0 +
//!   pre-e0 buffers ([`codeitems`]).
//! - Static cipher analysis of `libjiagu_a64.so` ([`static_cipher`]).
//! - Static inner-SO decryption with the hardcoded RC4 key ([`rc4`]).
//!
//! What it cannot do statically:
//!
//! - Decrypt the bulk DEX payload (entries 1..n-1 of the trailer's
//!   data section). The Jiagu loader derives that key inside
//!   `JNI_OnLoad` from the APK signing certificate fingerprint + per-
//!   build constants, gated by anti-debug / anti-emulator interlocks.
//!
//! The (opt-in) Unicorn-based emulator harness from the Python is
//! stubbed at [`unicorn::emulate_libjiagu`]. When `RunOptions::use_unicorn`
//! is true we record a `unicorn_pass` stage as failed (with the
//! "not ported" reason) — matching the rest of the Python stage shape
//! so consumers don't need a special case.

pub mod codeitems;
pub mod rc4;
pub mod static_cipher;
pub mod trailer;
pub mod unicorn;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::common::{
    carve_all_dexs, carve_entries, extract_base_apk_if_xapk, read_manifest_strings,
    write_manifest, write_unrecovered, CarvedEntry, Manifest, RecoveredDex, Stage, Unrecovered,
};
use crate::{opts_as_json, Backend, RunOptions, RunResult};

use codeitems::{build_synthetic_dex, recover_from_carved, serialize_code_items};
use rc4 as jiagu_rc4;
use static_cipher as jsc;
use trailer::{parse_trailer, summarise_trailer, JiaguTrailer};

pub struct Jiagu;

const PACKER_NAME: &str = "jiagu";

impl Backend for Jiagu {
    fn name() -> &'static str {
        PACKER_NAME
    }

    fn run(input_path: &Path, out_dir: &Path, opts: &RunOptions) -> RunResult {
        std::fs::create_dir_all(out_dir)?;
        let apk_path = extract_base_apk_if_xapk(input_path, &out_dir.join("xapk"))?;
        let extracted_dir = out_dir.join("extracted");
        std::fs::create_dir_all(&extracted_dir)?;

        let variant_loader_re =
            Regex::new(r"assets/libjg[a-z]{2,5}(_(a64|x64|x86))?\.so$").unwrap();
        let jiagu_sdk_re = Regex::new(r"lib/[^/]+/libjiagu_sdk_.*\.so$").unwrap();
        let primary_so_re = Regex::new(r"assets/libjiagu(_a64|_x64|_x86)?\.so$").unwrap();

        let bytes = std::fs::read(&apk_path)?;
        let mut zf = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
        let names: Vec<String> = zf.file_names().map(|s| s.to_string()).collect();
        let manifest_strs = read_manifest_strings(&mut zf);

        let jgapp = names.iter().any(|n| n == "assets/.jgapp");
        let jiagu_so: Vec<String> =
            names.iter().filter(|n| primary_so_re.is_match(n)).cloned().collect();
        let variant_so: Vec<String> =
            names.iter().filter(|n| variant_loader_re.is_match(n)).cloned().collect();
        let sdk_libs: Vec<String> =
            names.iter().filter(|n| jiagu_sdk_re.is_match(n)).cloned().collect();

        let mut stages: Vec<Stage> = Vec::new();
        let mut recovered: Vec<RecoveredDex> = Vec::new();
        let mut unrecovered: Vec<Unrecovered> = Vec::new();
        let mut notes = serde_json::Map::new();

        // Stage 1 — verify markers.
        stages.push(Stage::new(
            "verify_markers",
            jgapp || !jiagu_so.is_empty() || !variant_so.is_empty(),
            format!(
                "jgapp={} libjiagu={} variants={} sdk_libs={}",
                jgapp,
                jiagu_so.len(),
                variant_so.len(),
                sdk_libs.len()
            ),
        ));
        let mut markers_map = serde_json::Map::new();
        markers_map.insert("jgapp".into(), serde_json::Value::Bool(jgapp));
        markers_map.insert("libjiagu".into(), to_string_array(&jiagu_so));
        markers_map.insert("variants".into(), to_string_array(&variant_so));
        markers_map.insert("sdk_libs".into(), to_string_array(&sdk_libs));
        notes.insert("markers".into(), serde_json::Value::Object(markers_map));

        // Stage 2 — resolve real Application class (best-effort from AXML).
        let real_app_axml = resolve_real_application(&manifest_strs);

        // Stage 3 — carve outer stub DEX(s) verbatim.
        let mut dex_recs = carve_all_dexs(&mut zf, out_dir)?;
        for r in &mut dex_recs {
            r.ok = r.valid_dex_magic;
            r.recovery = "verbatim copy of outer stub DEX (Jiagu Java shell)".into();
        }
        let dex_count = dex_recs.len();
        let first_dex_name = dex_recs.first().map(|r| r.name.clone());
        recovered.extend(dex_recs);
        stages.push(Stage::new(
            "carve_outer_stub_dex",
            dex_count > 0,
            format!("{} stub DEX file(s) copied", dex_count),
        ));

        // Stage 4 — parse the qh trailer.
        let mut trailer_summary: Option<serde_json::Value> = None;
        let mut trailer_real_app: Option<String> = None;
        if let Some(name) = &first_dex_name {
            let mut dex_bytes: Vec<u8> = Vec::new();
            let _ = zf.by_name(name).map(|mut e| {
                use std::io::Read;
                let _ = e.read_to_end(&mut dex_bytes);
            });
            let tr = if dex_bytes.is_empty() {
                None
            } else {
                parse_trailer(&dex_bytes)
            };
            if let Some(tr) = tr {
                let (artefacts, summary) = carve_trailer_artefacts(&tr, &extracted_dir)?;
                notes.insert(
                    "trailer_artefacts".into(),
                    serde_json::Value::Array(artefacts.clone()),
                );
                let mut tr_notes = serde_json::Map::new();
                let n_metadata = summary
                    .get("metadata")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                tr_notes.insert(
                    "n_metadata".into(),
                    serde_json::Value::from(n_metadata as u64),
                );
                copy_summary_field(&summary, &mut tr_notes, "n_entries");
                copy_summary_field(&summary, &mut tr_notes, "original_app");
                copy_summary_field(&summary, &mut tr_notes, "package");
                copy_summary_field(&summary, &mut tr_notes, "version_code");
                copy_summary_field(&summary, &mut tr_notes, "version_name");
                copy_summary_field(&summary, &mut tr_notes, "jiagu_version");
                copy_summary_field(&summary, &mut tr_notes, "protect_time");
                copy_summary_field(&summary, &mut tr_notes, "stub_class");
                copy_summary_field(&summary, &mut tr_notes, "entry0_format");
                copy_summary_field(&summary, &mut tr_notes, "entry0_format_by_data");
                copy_summary_field(&summary, &mut tr_notes, "entry0_format_by_version");
                notes.insert("trailer".into(), serde_json::Value::Object(tr_notes));
                trailer_real_app = summary
                    .get("original_app")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .filter(|s| !s.is_empty());
                let data_section_len = summary
                    .get("data_section_len")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let n_entries = summary
                    .get("n_entries")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                stages.push(Stage::new(
                    "parse_jiagu_trailer",
                    true,
                    format!(
                        "{} metadata entries, {} encrypted data entries ({} bytes total)",
                        n_metadata, n_entries, data_section_len
                    ),
                ));
                trailer_summary = Some(summary);
            } else {
                stages.push(Stage::new(
                    "parse_jiagu_trailer",
                    false,
                    r"no qh\x00\x01 trailer found in outer DEX",
                ));
            }
        }

        let real_app = trailer_real_app.clone().unwrap_or(real_app_axml.clone());
        let app_source = if trailer_real_app.is_some() {
            "trailer"
        } else if !real_app_axml.is_empty() {
            "axml"
        } else {
            ""
        };
        notes.insert(
            "original_application".into(),
            serde_json::Value::String(real_app.clone()),
        );
        notes.insert(
            "original_application_source".into(),
            serde_json::Value::String(app_source.into()),
        );
        stages.push(Stage::new(
            "resolve_real_application",
            !real_app.is_empty(),
            format!(
                "original_application={:?} (source={})",
                real_app, app_source
            ),
        ));

        // Stage 5 — carve Jiagu assets.
        let mut to_carve: Vec<String> = Vec::new();
        if jgapp {
            to_carve.push("assets/.jgapp".into());
        }
        to_carve.extend(jiagu_so.iter().cloned());
        to_carve.extend(variant_so.iter().cloned());
        to_carve.extend(sdk_libs.iter().cloned());
        let carved = carve_entries(&mut zf, &to_carve, &extracted_dir)?;
        stages.push(Stage::new(
            "carve_jiagu_assets",
            !carved.is_empty(),
            format!(
                "{} file(s) carved to {}/",
                carved.len(),
                extracted_dir
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("extracted")
            ),
        ));
        notes.insert(
            "carved_artefacts".into(),
            serde_json::to_value(&carved).unwrap_or(serde_json::Value::Null),
        );

        // Stage 6 — characterise inner-DEX recoverability based on entry0_format.
        let e0_fmt = trailer_summary
            .as_ref()
            .and_then(|s| s.get("entry0_format"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let jiagu_version_str = trailer_summary
            .as_ref()
            .and_then(|s| s.get("jiagu_version"))
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        match e0_fmt.as_str() {
            "v1_plaintext_codeitems" => {
                unrecovered.push(Unrecovered {
                    item: "inner DEX class/string/type/method tables".into(),
                    reason: format!(
                        "Jiagu {} (older variant): entry 0's body is plaintext concatenated \
                         DEX code_items (carved to extracted/jiagu_entry0_body.bin) — useful \
                         for forensics but not sufficient to rebuild a runnable DEX. The \
                         required class_defs, string_data, type/method/proto/field tables live \
                         in encrypted entries 1..n-1, decrypted under a per-build runtime key \
                         derived inside libjiagu*.so. See by-packer/jiagu.md §Recovery.",
                        jiagu_version_str
                    ),
                });
                stages.push(Stage::new(
                    "inner_dex_decryption",
                    false,
                    "PARTIAL recovery — entry 0 plaintext code_items carved \
                     (jiagu_entry0_body.bin); inner DEX tables remain encrypted in entries 1..n-1",
                ));
            }
            "v2_nibble_obfuscated" => {
                let pt_size = trailer_summary
                    .as_ref()
                    .and_then(|s| s.get("plaintext_tail_size"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if pt_size > 0 {
                    unrecovered.push(Unrecovered {
                        item: "inner DEX class/string/type/method tables + the nibble-obfuscated prefix of entry 0".into(),
                        reason: format!(
                            "Jiagu {} (newer variant): entry 0 splits into a nibble-obfuscated \
                             prefix and a plaintext code_items tail; the tail was carved to \
                             extracted/jiagu_entry0_codeitems.bin ({} bytes recovered). The \
                             class_defs, string_data, type/method/proto/field tables remain \
                             encrypted in entries 1..n-1 under a per-build runtime key derived \
                             inside libjiagu*.so. See by-packer/jiagu.md §Recovery.",
                            jiagu_version_str, pt_size
                        ),
                    });
                    stages.push(Stage::new(
                        "inner_dex_decryption",
                        false,
                        format!(
                            "PARTIAL recovery — plaintext code_items tail ({} bytes) carved \
                             from v2 entry 0; nibble-obfuscated prefix + entries 1..n-1 remain \
                             encrypted",
                            pt_size
                        ),
                    ));
                } else {
                    unrecovered.push(Unrecovered {
                        item: "inner DEX bulk payload (entry 0 obfuscated + entries 1..n-1 encrypted)".into(),
                        reason: format!(
                            "Jiagu {} (newer variant): entry 0's prefix is nibble-obfuscated \
                             (dominant bytes from {{0x0f,0x1e,0x2d,0x3c}}); entries 1..n-1 \
                             are AES-equivalent encrypted under a per-build runtime key. Static \
                             carving (extracted/jiagu_entry0.bin, jiagu_pre_e0.bin, \
                             jiagu_post_e0.bin, jiagu_entry_table.bin) preserves the bytes for \
                             downstream runtime work. See by-packer/jiagu.md §Recovery.",
                            jiagu_version_str
                        ),
                    });
                    stages.push(Stage::new(
                        "inner_dex_decryption",
                        false,
                        "bulk payload flagged unrecoverable — newer Jiagu variant with full \
                         encryption + obfuscation (no plaintext tail)",
                    ));
                }
            }
            other => {
                unrecovered.push(Unrecovered {
                    item: "inner DEX bulk payload (entries 1..n-1)".into(),
                    reason: format!(
                        "Jiagu variant (entry-0 format={}): bulk DEX bytes live in the trailer's \
                         data section, encrypted under a per-build runtime key. Raw regions \
                         carved to extracted/ for downstream work. See by-packer/jiagu.md.",
                        other
                    ),
                });
                stages.push(Stage::new(
                    "inner_dex_decryption",
                    false,
                    "bulk payload flagged unrecoverable — runtime-derived key + anti-debug gating",
                ));
            }
        }

        // Stage 7 — Plaintext code_item recovery.
        if trailer_summary.is_some() {
            let plaintext_outcome = run_plaintext_code_item_stage(out_dir, &extracted_dir);
            match plaintext_outcome {
                Ok(Some((stage, rec, plaintext_notes))) => {
                    if let Some(rec) = rec {
                        recovered.push(rec);
                    }
                    if let Some(n) = plaintext_notes {
                        notes.insert("plaintext_code_items".into(), n);
                    }
                    stages.push(stage);
                }
                Ok(None) => {
                    // No artefacts on disk → silently skip (matches Python).
                }
                Err(e) => {
                    stages.push(Stage::new(
                        "plaintext_code_item_recovery",
                        false,
                        format!("exception: {e}"),
                    ));
                }
            }
        }

        // Stage 8 — Static cipher analysis of libjiagu_a64.so.
        let primary_so = pick_primary_so(&jiagu_so, &variant_so);
        if let Some(primary_so) = primary_so.clone() {
            let so_path = extracted_dir.join(primary_so.replace('/', "_"));
            if so_path.exists() {
                match std::fs::read(&so_path) {
                    Ok(so_bytes) => {
                        let summary = jsc::summarise(&so_bytes);
                        let mut cipher_info = serde_json::Map::new();
                        cipher_info.insert(
                            "so".into(),
                            serde_json::Value::String(primary_so.clone()),
                        );
                        cipher_info.insert(
                            "rc4_prgas".into(),
                            serde_json::to_value(&summary.rc4_prgas)
                                .unwrap_or(serde_json::Value::Null),
                        );
                        if let Some(xor) = &summary.xor_a5 {
                            // Persist decoded loader strings.
                            let strings_path = extracted_dir.join("jiagu_loader_strings_xor_a5.txt");
                            let mut content = String::new();
                            content.push_str(&format!(
                                "# Jiagu loader-strings region in {}\n",
                                primary_so
                            ));
                            content.push_str(&format!(
                                "# XOR-0xa5-decoded, starts at offset {:#x}\n",
                                xor.start_off
                            ));
                            content.push_str(&format!(
                                "# {} ASCII runs (>=6 chars)\n\n",
                                xor.decoded_strings.len()
                            ));
                            for s in &xor.decoded_strings {
                                match std::str::from_utf8(s) {
                                    Ok(utf) => {
                                        content.push_str(utf);
                                        content.push('\n');
                                    }
                                    Err(_) => {
                                        content.push_str(&format!("{:?}\n", s));
                                    }
                                }
                            }
                            let _ = std::fs::write(&strings_path, content);
                            let mut x = serde_json::Map::new();
                            x.insert(
                                "start_off".into(),
                                serde_json::Value::from(xor.start_off as u64),
                            );
                            x.insert(
                                "n_anchor_matches".into(),
                                serde_json::Value::from(xor.n_anchor_matches as u64),
                            );
                            x.insert(
                                "n_strings".into(),
                                serde_json::Value::from(xor.decoded_strings.len() as u64),
                            );
                            x.insert(
                                "strings_out".into(),
                                serde_json::Value::String(
                                    relative_path_string(&strings_path, out_dir),
                                ),
                            );
                            cipher_info.insert(
                                "xor_a5_region".into(),
                                serde_json::Value::Object(x),
                            );
                        } else {
                            cipher_info.insert(
                                "xor_a5_region".into(),
                                serde_json::Value::Null,
                            );
                        }
                        stages.push(Stage::new(
                            "static_cipher_analysis",
                            !summary.rc4_prgas.is_empty(),
                            format!(
                                "RC4 PRGA: {} found; XOR-0xa5: {} ({} anchors)",
                                summary.rc4_prgas.len(),
                                if summary.xor_a5.is_some() { "yes" } else { "no" },
                                summary.xor_a5.as_ref().map(|x| x.n_anchor_matches).unwrap_or(0),
                            ),
                        ));
                        notes.insert(
                            "jiagu_static_cipher".into(),
                            serde_json::Value::Object(cipher_info),
                        );
                    }
                    Err(e) => stages.push(Stage::new(
                        "static_cipher_analysis",
                        false,
                        format!("static cipher analysis failed: {e:?}"),
                    )),
                }
            }
        }

        // Stage 9 — Static inner-SO decryption.
        if let Some(primary_so) = primary_so.clone() {
            let so_path = extracted_dir.join(primary_so.replace('/', "_"));
            if so_path.exists() {
                match std::fs::read(&so_path) {
                    Ok(so_bytes) => {
                        let inner = jiagu_rc4::find_inner_so_payload(&so_bytes, None, None);
                        match inner {
                            Some((va, _, inflated)) => {
                                let inner_path =
                                    extracted_dir.join("jiagu_inner_so_decrypted.bin");
                                std::fs::write(&inner_path, &inflated)?;
                                stages.push(Stage::new(
                                    "inner_so_decrypt",
                                    true,
                                    format!(
                                        "inner-SO payload at vaddr {:#x}, decrypted + inflated \
                                         to {} bytes ({})",
                                        va,
                                        inflated.len(),
                                        inner_path
                                            .file_name()
                                            .and_then(|s| s.to_str())
                                            .unwrap_or("jiagu_inner_so_decrypted.bin")
                                    ),
                                ));
                                let mut m = serde_json::Map::new();
                                m.insert("payload_vaddr".into(), serde_json::Value::from(va));
                                m.insert(
                                    "inflated_size".into(),
                                    serde_json::Value::from(inflated.len() as u64),
                                );
                                m.insert(
                                    "key_hex".into(),
                                    serde_json::Value::String(hex_lower(&jiagu_rc4::INNER_SO_KEY)),
                                );
                                m.insert(
                                    "out_file".into(),
                                    serde_json::Value::String(relative_path_string(
                                        &inner_path,
                                        out_dir,
                                    )),
                                );
                                notes.insert("jiagu_inner_so".into(), serde_json::Value::Object(m));
                            }
                            None => stages.push(Stage::new(
                                "inner_so_decrypt",
                                false,
                                "no RC4+zlib payload found at any vaddr in any PT_LOAD segment \
                                 (build may use different cipher/key)",
                            )),
                        }
                    }
                    Err(e) => stages.push(Stage::new(
                        "inner_so_decrypt",
                        false,
                        format!("inner-SO decryption failed: {e:?}"),
                    )),
                }
            }
        }

        // Stage 10 (OPTIONAL) — Unicorn harness. Stubbed.
        if opts.use_unicorn {
            // Record the request so consumers can see we recognised the flag.
            stages.push(Stage::new(
                "unicorn_pass",
                false,
                format!(
                    "use_unicorn=true requested but the Rust unicorn harness is not yet \
                     ported (insn budget {}); fall back to the Python \
                     `unpacker/packer_backends/jiagu_unicorn.py` for now",
                    opts.unicorn_insns
                ),
            ));
            // Touch the inputs struct so callers see a real call-site if they
            // want to wire it up in the future.
            let _ = unicorn::EmulationInputs::<'_> {
                so_path: input_path,
                package_name: None,
                apk_md5: None,
                asset_bytes: Default::default(),
                max_instructions: opts.unicorn_insns,
                mock_inner_so: opts.unicorn_mock_inner_so.as_deref(),
                verbose: opts.verbose,
            };
        }

        let manifest = Manifest {
            packer: PACKER_NAME.into(),
            backend: "platypus_unpackers::jiagu".into(),
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
        write_unrecovered(out_dir, &unrecovered, PACKER_NAME)?;

        if opts.verbose {
            eprintln!(
                "[jiagu] markers: jgapp={} libjiagu={} variants={} sdk_libs={}",
                jgapp,
                jiagu_so.len(),
                variant_so.len(),
                sdk_libs.len()
            );
            eprintln!(
                "[jiagu] real Application class: {}",
                if real_app.is_empty() {
                    "(unresolved)"
                } else {
                    real_app.as_str()
                }
            );
            eprintln!(
                "[jiagu] {} Jiagu artefact(s) carved → {}",
                carved.len(),
                extracted_dir.display()
            );
        }

        // Suppress unused-import / variable warnings for `apk_path` (it's used
        // upstream — XAPK extraction may have written a new file at out_dir/xapk).
        let _ = &apk_path;
        Ok(manifest)
    }
}

// ---------------------------------------------------------------------------
// Helpers — trailer artefact carving (port of `_carve_trailer_artefacts`).
// ---------------------------------------------------------------------------

/// Write the decoded trailer summary plus carve every region the static
/// parser can reach. Returns `(artefacts_list, summary)`.
///
/// Artefacts written (matches the Python list 1:1):
/// - `jiagu_trailer.json` — full summary (metadata + structural)
/// - `jiagu_data_section.bin` — full encrypted data section
/// - `jiagu_entry0.bin` — raw bytes of entry 0
/// - `jiagu_entry0_header.bin` — first 16 bytes
/// - `jiagu_entry0_body.bin` — entry 0 minus the 16-byte header
/// - `jiagu_entry0_codeitems.bin` — plaintext tail (when present)
/// - `jiagu_pre_e0.bin` — bytes between the entry table and entry 0
/// - `jiagu_post_e0.bin` — bytes after entry 0 ends
/// - `jiagu_entry_table.bin` — encrypted `(size, off)` pairs
fn carve_trailer_artefacts(
    trailer: &JiaguTrailer,
    out_dir: &Path,
) -> std::io::Result<(Vec<serde_json::Value>, serde_json::Value)> {
    std::fs::create_dir_all(out_dir)?;
    let mut artefacts: Vec<serde_json::Value> = Vec::new();

    let summary = summarise_trailer(trailer);

    // 1) Full trailer summary.
    let summary_path = out_dir.join("jiagu_trailer.json");
    let summary_text = serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".into());
    std::fs::write(&summary_path, &summary_text)?;
    artefacts.push(artefact_json(&[
        ("name", json_str("jiagu_trailer.json")),
        ("kind", json_str("trailer_metadata")),
        (
            "size",
            serde_json::Value::from(summary_text.as_bytes().len() as u64),
        ),
        (
            "n_metadata_entries",
            summary
                .get("metadata")
                .and_then(|v| v.as_array())
                .map(|a| serde_json::Value::from(a.len() as u64))
                .unwrap_or(serde_json::Value::from(0u64)),
        ),
        (
            "n_data_entries",
            summary
                .get("n_entries")
                .cloned()
                .unwrap_or(serde_json::Value::from(0u64)),
        ),
        (
            "entry0_format",
            summary
                .get("entry0_format")
                .cloned()
                .unwrap_or(serde_json::Value::String("unknown".into())),
        ),
        (
            "out_path",
            json_str(&summary_path.to_string_lossy()),
        ),
    ]));

    let ds = &trailer.data_section;

    // 2) Raw data section.
    let data_path = out_dir.join("jiagu_data_section.bin");
    std::fs::write(&data_path, ds)?;
    artefacts.push(artefact_json(&[
        ("name", json_str("jiagu_data_section.bin")),
        ("kind", json_str("encrypted_data_section")),
        ("size", serde_json::Value::from(ds.len() as u64)),
        ("out_path", json_str(&data_path.to_string_lossy())),
    ]));

    // 3) Encrypted entry table.
    if !trailer.encrypted_table.is_empty() {
        let tbl_path = out_dir.join("jiagu_entry_table.bin");
        std::fs::write(&tbl_path, &trailer.encrypted_table)?;
        let n_pairs = if trailer.n_entries > 0 {
            trailer.n_entries as i64 - 1
        } else {
            0
        };
        artefacts.push(artefact_json(&[
            ("name", json_str("jiagu_entry_table.bin")),
            ("kind", json_str("encrypted_entry_table")),
            (
                "size",
                serde_json::Value::from(trailer.encrypted_table.len() as u64),
            ),
            ("n_pairs", serde_json::Value::from(n_pairs)),
            ("out_path", json_str(&tbl_path.to_string_lossy())),
        ]));
    }

    // 4) Entry 0's raw bytes.
    let e0_off = trailer.entry0_off as usize;
    let e0_size = trailer.entry0_size as usize;
    if e0_off > 0 && e0_size > 0 && e0_off + e0_size <= ds.len() {
        let entry0 = &ds[e0_off..e0_off + e0_size];
        let e0_path = out_dir.join("jiagu_entry0.bin");
        std::fs::write(&e0_path, entry0)?;
        artefacts.push(artefact_json(&[
            ("name", json_str("jiagu_entry0.bin")),
            ("kind", json_str("data_entry_0")),
            ("size", serde_json::Value::from(entry0.len() as u64)),
            (
                "entry0_format",
                summary
                    .get("entry0_format")
                    .cloned()
                    .unwrap_or(serde_json::Value::String("unknown".into())),
            ),
            ("out_path", json_str(&e0_path.to_string_lossy())),
        ]));

        let e0_hdr_path = out_dir.join("jiagu_entry0_header.bin");
        std::fs::write(&e0_hdr_path, &entry0[..16])?;
        artefacts.push(artefact_json(&[
            ("name", json_str("jiagu_entry0_header.bin")),
            ("kind", json_str("data_entry_0_header")),
            ("size", serde_json::Value::from(16u64)),
            (
                "note",
                json_str("opaque per-build header — likely IV/MAC for the encrypted entries"),
            ),
            ("out_path", json_str(&e0_hdr_path.to_string_lossy())),
        ]));

        let e0_body_path = out_dir.join("jiagu_entry0_body.bin");
        std::fs::write(&e0_body_path, &entry0[16..])?;
        artefacts.push(artefact_json(&[
            ("name", json_str("jiagu_entry0_body.bin")),
            ("kind", json_str("data_entry_0_body")),
            (
                "size",
                serde_json::Value::from((entry0.len() - 16) as u64),
            ),
            (
                "note",
                json_str(
                    "plaintext concatenated DEX code_items in Jiagu 1.3.9.x; \
                     nibble-obfuscated in 1.4.0.x — see by-packer/jiagu.md",
                ),
            ),
            ("out_path", json_str(&e0_body_path.to_string_lossy())),
        ]));

        // Plaintext code_items tail.
        let pt_off = summary
            .get("plaintext_tail_offset")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let pt_size = summary
            .get("plaintext_tail_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        if pt_size > 0 {
            let tail = &entry0[16 + pt_off..];
            let tail_path = out_dir.join("jiagu_entry0_codeitems.bin");
            std::fs::write(&tail_path, tail)?;
            artefacts.push(artefact_json(&[
                ("name", json_str("jiagu_entry0_codeitems.bin")),
                ("kind", json_str("data_entry_0_plaintext_codeitems")),
                ("size", serde_json::Value::from(tail.len() as u64)),
                (
                    "note",
                    json_str(&format!(
                        "plaintext concatenated DEX code_items carved from entry-0's tail \
                         (offset {} within body). For v1 builds this is the whole body. For v2 \
                         builds this is the portion past the nibble-obfuscated prefix.",
                        pt_off
                    )),
                ),
                ("out_path", json_str(&tail_path.to_string_lossy())),
            ]));
        }

        // 5) Encrypted pre-entry0 region.
        let tbl_end = if trailer.n_entries > 0 {
            12 + (trailer.n_entries as usize) * 8
        } else {
            12 + 12
        };
        if e0_off > tbl_end {
            let pre_e0 = &ds[tbl_end..e0_off];
            let pre_path = out_dir.join("jiagu_pre_e0.bin");
            std::fs::write(&pre_path, pre_e0)?;
            artefacts.push(artefact_json(&[
                ("name", json_str("jiagu_pre_e0.bin")),
                ("kind", json_str("encrypted_pre_e0")),
                ("size", serde_json::Value::from(pre_e0.len() as u64)),
                (
                    "note",
                    json_str("encrypted bytes between the entry table and entry 0"),
                ),
                ("out_path", json_str(&pre_path.to_string_lossy())),
            ]));
        }

        // 6) Encrypted post-entry0 region.
        let e0_end = e0_off + e0_size;
        if e0_end < ds.len() {
            let post_e0 = &ds[e0_end..];
            let post_path = out_dir.join("jiagu_post_e0.bin");
            std::fs::write(&post_path, post_e0)?;
            artefacts.push(artefact_json(&[
                ("name", json_str("jiagu_post_e0.bin")),
                ("kind", json_str("encrypted_post_e0")),
                ("size", serde_json::Value::from(post_e0.len() as u64)),
                (
                    "note",
                    json_str("encrypted bytes after entry 0 — entries 1..n-1 payloads"),
                ),
                ("out_path", json_str(&post_path.to_string_lossy())),
            ]));
        }
    }

    Ok((artefacts, summary))
}

// ---------------------------------------------------------------------------
// Helpers — plaintext code-item stage.
// ---------------------------------------------------------------------------

type PlaintextStageResult = (Stage, Option<RecoveredDex>, Option<serde_json::Value>);

fn run_plaintext_code_item_stage(
    out_dir: &Path,
    extracted_dir: &Path,
) -> std::io::Result<Option<PlaintextStageResult>> {
    let e0_body_path = extracted_dir.join("jiagu_entry0_body.bin");
    let post_e0_path = extracted_dir.join("jiagu_post_e0.bin");
    let pre_e0_path = extracted_dir.join("jiagu_pre_e0.bin");
    let e0_body = if e0_body_path.exists() {
        std::fs::read(&e0_body_path)?
    } else {
        Vec::new()
    };
    let post_e0 = if post_e0_path.exists() {
        std::fs::read(&post_e0_path)?
    } else {
        Vec::new()
    };
    let pre_e0 = if pre_e0_path.exists() {
        std::fs::read(&pre_e0_path)?
    } else {
        Vec::new()
    };
    if e0_body.is_empty() && post_e0.is_empty() {
        return Ok(None);
    }
    let (items, mut rec) = recover_from_carved(&e0_body, &post_e0, &pre_e0);
    if items.is_empty() {
        return Ok(None);
    }

    let ser = serialize_code_items(&items);
    let ser_path = extracted_dir.join("jiagu_recovered_code_items.bin");
    std::fs::write(&ser_path, &ser)?;

    let syn_path = extracted_dir.join("jiagu_recovered.dex");
    let syn_dex = build_synthetic_dex(&items);
    let synthetic_ok = !syn_dex.is_empty();
    if synthetic_ok {
        std::fs::write(&syn_path, &syn_dex)?;
        rec.synthetic_dex_bytes = syn_dex.len();
    }

    // RecoveredDex entry.
    let dex_entry = RecoveredDex {
        name: relative_path_string(&syn_path, out_dir),
        size: rec.synthetic_dex_bytes,
        sha256: crate::common::sha256_bytes(&syn_dex),
        magic: hex_lower(&syn_dex[..syn_dex.len().min(8)]),
        valid_dex_magic: rec.synthetic_dex_bytes > 0,
        ok: synthetic_ok && rec.synthetic_dex_bytes > 0,
        recovery: format!(
            "synthetic DEX wrapping {} recovered plaintext code_items (method names are \
             synthetic; bytecode is real)",
            rec.total_code_items
        ),
        source: None,
        out_path: Some(syn_path.to_string_lossy().into_owned()),
        extra: serde_json::Map::new(),
    };

    let mut plaintext_notes = serde_json::Map::new();
    plaintext_notes.insert("total".into(), serde_json::Value::from(rec.total_code_items as u64));
    plaintext_notes.insert(
        "entry0".into(),
        serde_json::Value::from(rec.entry0_code_items as u64),
    );
    plaintext_notes.insert(
        "post_e0".into(),
        serde_json::Value::from(rec.post_e0_code_items as u64),
    );
    plaintext_notes.insert(
        "pre_e0".into(),
        serde_json::Value::from(rec.pre_e0_code_items as u64),
    );
    plaintext_notes.insert(
        "total_bytecode_bytes".into(),
        serde_json::Value::from(rec.total_bytes as u64),
    );
    plaintext_notes.insert(
        "plaintext_runs_post_e0".into(),
        serde_json::to_value(&rec.plaintext_runs_post_e0).unwrap_or(serde_json::Value::Null),
    );
    plaintext_notes.insert(
        "serialized_blob".into(),
        serde_json::Value::String(relative_path_string(&ser_path, out_dir)),
    );
    plaintext_notes.insert(
        "serialized_blob_size".into(),
        serde_json::Value::from(ser.len() as u64),
    );
    plaintext_notes.insert(
        "synthetic_dex".into(),
        if synthetic_ok {
            serde_json::Value::String(relative_path_string(&syn_path, out_dir))
        } else {
            serde_json::Value::Null
        },
    );
    plaintext_notes.insert(
        "synthetic_dex_size".into(),
        serde_json::Value::from(rec.synthetic_dex_bytes as u64),
    );

    let stage = Stage::new(
        "plaintext_code_item_recovery",
        true,
        format!(
            "recovered {} code_items ({} bytes) — entry0={}, post_e0={}, pre_e0={}; \
             synthetic DEX ={} ({} bytes)",
            rec.total_code_items,
            rec.entry0_bytes + rec.post_e0_bytes,
            rec.entry0_code_items,
            rec.post_e0_code_items,
            rec.pre_e0_code_items,
            if synthetic_ok { "yes" } else { "failed" },
            rec.synthetic_dex_bytes,
        ),
    );

    Ok(Some((
        stage,
        Some(dex_entry),
        Some(serde_json::Value::Object(plaintext_notes)),
    )))
}

// ---------------------------------------------------------------------------
// Helpers — small JSON / string utilities.
// ---------------------------------------------------------------------------

fn resolve_real_application(manifest_strs: &[String]) -> String {
    // Skip Jiagu's own stub class names + RePlugin.
    let stub_names: HashSet<&str> = [
        "com.stub.StubApp",
        "com.qihoo.util.StubApp",
        "com.qihoo360.replugin.RePlugin",
    ]
    .iter()
    .copied()
    .collect();
    let re = Regex::new(r"^[a-zA-Z_][\w.]*\.[A-Z]\w+$").unwrap();
    for s in manifest_strs {
        if s.is_empty() || !s.contains('.') {
            continue;
        }
        if stub_names.contains(s.as_str()) {
            continue;
        }
        if re.is_match(s) && s.ends_with("Application") {
            return s.clone();
        }
    }
    String::new()
}

fn to_string_array(v: &[String]) -> serde_json::Value {
    serde_json::Value::Array(v.iter().map(|s| serde_json::Value::String(s.clone())).collect())
}

fn copy_summary_field(
    summary: &serde_json::Value,
    out: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    let v = summary.get(key).cloned().unwrap_or(serde_json::Value::Null);
    out.insert(key.into(), v);
}

fn pick_primary_so(jiagu_so: &[String], variant_so: &[String]) -> Option<String> {
    let mut all: Vec<&String> = Vec::new();
    all.extend(jiagu_so.iter());
    all.extend(variant_so.iter());
    for n in &all {
        let lower = n.to_lowercase();
        if n.contains("_a64") || lower.contains("a64") {
            return Some((*n).clone());
        }
    }
    all.first().map(|s| (*s).clone())
}

fn relative_path_string(p: &Path, base: &Path) -> String {
    // Python uses `Path.relative_to(out_dir.parent)` — mirror that:
    // try to make `p` relative to `base.parent()`, falling back to the
    // absolute path's string form.
    if let Some(parent) = base.parent() {
        if let Ok(rel) = p.strip_prefix(parent) {
            return rel.to_string_lossy().into_owned();
        }
    }
    if let Ok(rel) = p.strip_prefix(base) {
        return rel.to_string_lossy().into_owned();
    }
    p.to_string_lossy().into_owned()
}

fn hex_lower(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(&mut s, "{:02x}", byte);
    }
    s
}

fn json_str(s: &str) -> serde_json::Value {
    serde_json::Value::String(s.to_string())
}

fn artefact_json(fields: &[(&str, serde_json::Value)]) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for (k, v) in fields {
        m.insert((*k).into(), v.clone());
    }
    serde_json::Value::Object(m)
}

// Suppress unused-import warnings for items only used via the re-exports.
#[allow(dead_code)]
fn _force_use_carved_entry(_e: &CarvedEntry) {}
#[allow(dead_code)]
fn _force_use_pathbuf(_p: &PathBuf) {}
