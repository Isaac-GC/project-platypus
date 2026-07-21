//! FengYue / StormStub backend (`com.storm.fengyue.StubApplication`).
//!
//! Direct port of `unpacker/packer_backends/fengyue.py`. Full static
//! DEX recovery: decrypts `assets/jiami.dat` with the hardcoded
//! AES-128-CBC key = IV = `b"1234567812345678"` baked into
//! `libdexload_a64.so`'s `.rodata` and validates against the embedded
//! DEX `adler32` field.
//!
//! See the original Python docstring + `by-packer/fengyue.md` for the
//! loader RE walk-through.

use std::path::Path;

use regex::Regex;

use crate::common::{
    self, carve_all_dexs, carve_entries, extract_base_apk_if_xapk, read_manifest_strings,
    sha256_bytes, write_manifest, write_unrecovered, Manifest, RecoveredDex, Stage, Unrecovered,
};
use crate::{opts_as_json, Backend, RunOptions, RunResult};

pub struct Fengyue;

const PACKER_NAME: &str = "fengyue";

// AES-128-CBC key + IV — both literally "1234567812345678" (ASCII).
// Encoded statically in libdexload_a64.so's .rodata; AES_KEYCODE and
// AES_IV are RELATIVE relocations both pointing at the same 16-byte
// string. Verified by reading the relocations + bytes at vaddr 0x2c218
// in the shared a64 loader (sha256 7292d73f242c5a6b701254c32da7521175fe4bb41bfb07e7d0537c8ddd8a624e).
const FENGYUE_KEY: &[u8; 16] = b"1234567812345678";
const FENGYUE_IV: &[u8; 16] = b"1234567812345678";

impl Backend for Fengyue {
    fn name() -> &'static str {
        PACKER_NAME
    }

    fn run(input_path: &Path, out_dir: &Path, opts: &RunOptions) -> RunResult {
        std::fs::create_dir_all(out_dir)?;
        let apk_path = extract_base_apk_if_xapk(input_path, &out_dir.join("xapk"))?;
        let extracted_dir = out_dir.join("extracted");
        std::fs::create_dir_all(&extracted_dir)?;

        let loader_re = Regex::new(r"assets/libdexload_(arm|a64|x86|x64)\.so$").unwrap();

        let bytes = std::fs::read(&apk_path)?;
        let mut zf = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;

        let names: Vec<String> = zf.file_names().map(|s| s.to_string()).collect();
        let manifest_strs = read_manifest_strings(&mut zf);

        let loaders: Vec<String> =
            names.iter().filter(|n| loader_re.is_match(n)).cloned().collect();
        let stub_present = manifest_strs.iter().any(|s| s.contains("com.storm.fengyue"));

        let mut stages: Vec<Stage> = Vec::new();
        let mut recovered: Vec<RecoveredDex> = Vec::new();
        let mut unrecovered: Vec<Unrecovered> = Vec::new();
        let mut notes = serde_json::Map::new();

        stages.push(Stage::new(
            "verify_markers",
            !loaders.is_empty() || stub_present,
            format!("libdexload={} stub={}", loaders.len(), stub_present),
        ));
        let mut marker_map = serde_json::Map::new();
        marker_map.insert(
            "loaders".into(),
            serde_json::Value::Array(loaders.iter().map(|s| serde_json::Value::String(s.clone())).collect()),
        );
        marker_map.insert("stub_present".into(), serde_json::Value::Bool(stub_present));
        notes.insert("markers".into(), serde_json::Value::Object(marker_map));

        let real_app = resolve_real_application(&manifest_strs);
        let meta_key = find_metadata_key(&manifest_strs);
        stages.push(Stage::new(
            "resolve_real_application",
            !real_app.is_empty(),
            format!(
                "original_application={:?} meta_data_key={:?}",
                real_app, meta_key
            ),
        ));
        notes.insert(
            "original_application".into(),
            serde_json::Value::String(real_app.clone()),
        );
        notes.insert(
            "meta_data_key_candidate".into(),
            serde_json::Value::String(meta_key.clone()),
        );

        // Carve outer stub DEX(s) verbatim.
        let mut dex_recs = carve_all_dexs(&mut zf, out_dir)?;
        for r in &mut dex_recs {
            r.ok = r.valid_dex_magic;
            r.recovery = "verbatim copy of outer stub DEX (FengYue Java shell)".into();
        }
        let stub_dex_names: std::collections::HashSet<String> =
            dex_recs.iter().map(|r| r.name.clone()).collect();
        let dex_count = dex_recs.len();
        recovered.extend(dex_recs);
        stages.push(Stage::new(
            "carve_outer_stub_dex",
            dex_count > 0,
            format!("{} stub DEX file(s) copied", dex_count),
        ));

        // Carve loader .so files for reference / re-RE.
        let carved = carve_entries(&mut zf, &loaders, &extracted_dir)?;
        stages.push(Stage::new(
            "carve_fengyue_loaders",
            !carved.is_empty(),
            format!("{} loader(s) carved to extracted/", carved.len()),
        ));
        notes.insert(
            "carved_artefacts".into(),
            serde_json::to_value(&carved).unwrap_or(serde_json::Value::Null),
        );

        // Locate and decrypt assets/jiami.dat.
        let jiami_path = "assets/jiami.dat";
        let jiami_present = names.iter().any(|n| n == jiami_path);
        if jiami_present {
            let mut ct = Vec::new();
            std::io::Read::read_to_end(&mut zf.by_name(jiami_path)?, &mut ct)?;
            let (dex, info) = recover_dex_from_jiami(&ct);
            stages.push(Stage::new(
                "decrypt_jiami_dat",
                info.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
                format!(
                    "jiami.dat={:?}B → DEX={:?}B adler32 stored={:?} actual={:?} match={:?}",
                    info.get("ciphertext_size").unwrap_or(&serde_json::Value::Null),
                    info.get("dex_file_size").unwrap_or(&serde_json::Value::Null),
                    info.get("dex_adler32_stored").unwrap_or(&serde_json::Value::Null),
                    info.get("dex_adler32_actual").unwrap_or(&serde_json::Value::Null),
                    info.get("ok").unwrap_or(&serde_json::Value::Null),
                ),
            ));
            notes.insert("jiami_decrypt".into(), serde_json::Value::Object(info.clone()));
            if info.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                // Pick a filename that doesn't collide with any stub
                // DEX we already wrote. FengYue's recovered DEX
                // *replaces* the stub at runtime, so call it
                // `classes.dex` if no stub was carved, otherwise
                // `classes_recovered.dex`.
                let out_name = if stub_dex_names.contains("classes.dex") {
                    "classes_recovered.dex"
                } else {
                    "classes.dex"
                };
                let out_path = out_dir.join(out_name);
                std::fs::write(&out_path, &dex)?;
                let mut extra = serde_json::Map::new();
                extra.insert(
                    "ciphertext_size".into(),
                    info.get("ciphertext_size").cloned().unwrap_or(serde_json::Value::Null),
                );
                recovered.push(RecoveredDex {
                    name: out_name.to_string(),
                    size: dex.len(),
                    sha256: info
                        .get("dex_sha256")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    magic: hex_prefix(&dex, 8),
                    valid_dex_magic: true,
                    ok: true,
                    recovery: format!(
                        "Decrypted from assets/jiami.dat with AES-128-CBC \
                         key=IV={:?} (FengYue/StormStub static key — see \
                         by-packer/fengyue.md §3)",
                        String::from_utf8_lossy(FENGYUE_KEY)
                    ),
                    source: Some(jiami_path.into()),
                    out_path: Some(out_path.to_string_lossy().into_owned()),
                    extra,
                });
            } else {
                unrecovered.push(Unrecovered {
                    item: "inner classes.dex (decrypt failed)".into(),
                    reason: info
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown failure decrypting jiami.dat")
                        .to_string(),
                });
            }
        } else {
            stages.push(Stage::new(
                "decrypt_jiami_dat",
                false,
                "assets/jiami.dat not present — unusual FengYue layout?",
            ));
            unrecovered.push(Unrecovered {
                item: "inner classes.dex".into(),
                reason: "assets/jiami.dat is missing; this sample fingerprints \
                         as FengYue (libdexload_*.so / stub class) but the \
                         encrypted-DEX asset is in an unexpected location. \
                         Inspect manually."
                    .into(),
            });
        }

        let manifest = Manifest {
            packer: PACKER_NAME.into(),
            backend: "platypus_unpackers::fengyue".into(),
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
            eprintln!("[fengyue] markers: libdexload={} stub={}", loaders.len(), stub_present);
            eprintln!("[fengyue] real Application class: {}", if real_app.is_empty() { "(unresolved)" } else { real_app.as_str() });
            eprintln!("[fengyue] meta-data key candidate: {}", if meta_key.is_empty() { "(none)" } else { meta_key.as_str() });
            eprintln!("[fengyue] {} loader(s) carved → {}", carved.len(), extracted_dir.display());
        }

        let _ = common::sha256_file; // silence "unused" if used elsewhere
        let _ = sha256_bytes;
        Ok(manifest)
    }
}

// ─── FengYue-specific helpers ──────────────────────────────────────────────

/// Find the real Application class FQCN by looking for any string that
/// matches `*Application` and isn't the stub itself. FengYue stores it
/// via a randomised `<meta-data>` key in AndroidManifest.xml — we cheat
/// and pull it out of the string pool directly.
fn resolve_real_application(manifest_strs: &[String]) -> String {
    let re = Regex::new(r"^[a-zA-Z_][\w.]*\.[A-Z]\w*Application$").unwrap();
    let stub = "com.storm.fengyue.StubApplication";
    for s in manifest_strs {
        if s == stub {
            continue;
        }
        if re.is_match(s) {
            return s.clone();
        }
    }
    String::new()
}

/// Best-effort find of the randomised 8-12 letter `<meta-data>` key
/// FengYue uses to indirect to the real Application class name. Just
/// returns the first matching token; not load-bearing for the actual
/// DEX decrypt.
fn find_metadata_key(manifest_strs: &[String]) -> String {
    let re = Regex::new(r"^[A-Za-z]{8,12}$").unwrap();
    manifest_strs
        .iter()
        .find(|s| re.is_match(s))
        .cloned()
        .unwrap_or_default()
}

/// Decrypt `jiami.dat` and trim to the embedded DEX `file_size`.
/// Returns (dex_bytes, info_map) where info carries enough fields for
/// the manifest to verify the recovery.
fn recover_dex_from_jiami(data: &[u8]) -> (Vec<u8>, serde_json::Map<String, serde_json::Value>) {
    let mut info = serde_json::Map::new();
    info.insert(
        "ciphertext_size".into(),
        serde_json::Value::from(data.len()),
    );
    if data.is_empty() || data.len() % 16 != 0 {
        info.insert("ok".into(), serde_json::Value::Bool(false));
        info.insert(
            "reason".into(),
            serde_json::Value::String(format!(
                "jiami.dat length {} not AES-block-aligned",
                data.len()
            )),
        );
        return (Vec::new(), info);
    }
    let pt = match platypus_crypto::aes_cbc_nopad_decrypt(FENGYUE_KEY, FENGYUE_IV, data) {
        Some(pt) => pt,
        None => {
            info.insert("ok".into(), serde_json::Value::Bool(false));
            info.insert(
                "reason".into(),
                serde_json::Value::String("AES decryption failed".into()),
            );
            return (Vec::new(), info);
        }
    };

    if !pt.starts_with(b"dex\n") {
        info.insert("ok".into(), serde_json::Value::Bool(false));
        info.insert(
            "reason".into(),
            serde_json::Value::String(format!(
                "decrypted magic {:?} is not DEX",
                &pt[..pt.len().min(8)]
            )),
        );
        info.insert(
            "decrypted_first_bytes".into(),
            serde_json::Value::String(hex_prefix(&pt, 32)),
        );
        return (Vec::new(), info);
    }
    if pt.len() < 36 {
        info.insert("ok".into(), serde_json::Value::Bool(false));
        info.insert(
            "reason".into(),
            serde_json::Value::String(format!(
                "plaintext too short to contain DEX header ({} bytes)",
                pt.len()
            )),
        );
        return (Vec::new(), info);
    }
    let file_size = u32::from_le_bytes([pt[32], pt[33], pt[34], pt[35]]) as usize;
    if file_size == 0 || file_size > pt.len() {
        info.insert("ok".into(), serde_json::Value::Bool(false));
        info.insert(
            "reason".into(),
            serde_json::Value::String(format!(
                "DEX header file_size {} out of range (plaintext length {})",
                file_size,
                pt.len()
            )),
        );
        return (Vec::new(), info);
    }
    let dex = pt[..file_size].to_vec();
    let stored = u32::from_le_bytes([dex[8], dex[9], dex[10], dex[11]]);
    let actual = adler32(&dex[12..]);
    let ok = stored == actual;
    info.insert("ok".into(), serde_json::Value::Bool(ok));
    info.insert("plaintext_size".into(), serde_json::Value::from(pt.len()));
    info.insert("dex_file_size".into(), serde_json::Value::from(file_size));
    info.insert("dex_padding_bytes".into(), serde_json::Value::from(pt.len() - file_size));
    info.insert(
        "dex_adler32_stored".into(),
        serde_json::Value::String(format!("0x{:08x}", stored)),
    );
    info.insert(
        "dex_adler32_actual".into(),
        serde_json::Value::String(format!("0x{:08x}", actual)),
    );
    info.insert(
        "dex_sha256".into(),
        serde_json::Value::String(sha256_bytes(&dex)),
    );
    info.insert(
        "algorithm".into(),
        serde_json::Value::String("AES-128-CBC".into()),
    );
    info.insert(
        "key_ascii".into(),
        serde_json::Value::String(String::from_utf8_lossy(FENGYUE_KEY).into_owned()),
    );
    info.insert(
        "iv_ascii".into(),
        serde_json::Value::String(String::from_utf8_lossy(FENGYUE_IV).into_owned()),
    );
    if !ok {
        info.insert(
            "reason".into(),
            serde_json::Value::String(
                "adler32 mismatch — wrong key/IV/algorithm or corrupted blob".into(),
            ),
        );
    }
    (dex, info)
}

/// Adler-32 over `data` — matches `zlib.adler32` exactly. We inline
/// rather than pulling in another crate; it's 10 lines and covered by
/// the FengYue recovery test.
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

fn hex_prefix(b: &[u8], n: usize) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(n * 2);
    for byte in &b[..b.len().min(n)] {
        let _ = write!(&mut s, "{:02x}", byte);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_matches_zlib() {
        // zlib.adler32(b"hello") == 0x062c0215
        assert_eq!(adler32(b"hello"), 0x062c0215);
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"a"), 0x00620062);
    }

    #[test]
    fn aes_decrypt_round_trips_a_known_vector() {
        // Encrypt then decrypt to confirm the internal AES-CBC wiring +
        // key/IV. Plaintext is one block of identifying ASCII so a
        // regression here surfaces with a readable diff.
        let pt_in = b"FENGYUE_DEX_TEST";
        let ct = platypus_crypto::aes_cbc_nopad_encrypt(FENGYUE_KEY, FENGYUE_IV, pt_in).unwrap();
        let pt = platypus_crypto::aes_cbc_nopad_decrypt(FENGYUE_KEY, FENGYUE_IV, &ct).unwrap();
        assert_eq!(&pt, pt_in);
    }
}
