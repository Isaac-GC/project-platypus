//! Virbox-marker detection (Report §3).
//!
//! The Virbox build-id (8 hex chars) is stitched into every marker:
//!
//! - Application class `v<buildId>.l<buildId>` in `AndroidManifest.xml`.
//! - Helper class `Lm<buildId>;` declaring 10-16 `F<buildId>_NN` native
//!   dispatcher methods.
//! - Per-arch asset SO `assets/l<buildId>_<arch>.so`.
//! - `Lvirbox/StubApp;` (string match in the outer DEX).
//! - `virbox/%s` or `virbox error: unused ins in vm` strings in any SO.
//!
//! We require any 3 of these 5 markers to mark a sample as
//! "confirmed Virbox" — same threshold the Python uses.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::axml::parse_axml_strings;
use platypus_dex::parser::ParsedDex;

/// Bytes that, if present in an outer DEX, confirm the Virbox stub
/// Application class (Report §3 marker).
pub const VIRBOX_STUB_CLASSES: &[&[u8]] = &[b"Lvirbox/StubApp", b"Lvirbox/Application"];
/// VME error string baked into every Virbox SO (Report §3).
pub const VIRBOX_VME_ERROR_STR: &[u8] = b"virbox error: unused ins in vm";
/// Self-ID format string baked into every Virbox SO (Report §3).
pub const VIRBOX_SO_ID_STR: &[u8] = b"virbox/%s";

/// Asset-SO ARCH suffix observed in the Virbox per-arch loader filename.
const VIRBOX_SO_ARCH_RE: &str = r"^l([0-9a-fA-F]{8})_(a32|a64|x86|x64)\.so$";

/// Application-class build-id regex (`v<8hex>.l<8hex>`).
const VIRBOX_APPNAME_RE: &str = r"v[0-9a-fA-F]{8}\.l[0-9a-fA-F]{8}";

/// Aggregated marker results for a single APK.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VirboxMarkers {
    /// The Application class name as it appears in the manifest,
    /// e.g. `v53a46fa6.l53a46fa6`. Empty if no marker found.
    pub application_class: String,
    /// 8-char hex build-id extracted from the markers. Empty if not found.
    pub build_id_hex: String,
    /// True iff one of [`VIRBOX_STUB_CLASSES`] appears in the outer DEX.
    pub has_virbox_stub_class: bool,
    /// Helper class name `Lm<buildId>;`. Empty if not found.
    pub m_class_name: String,
    /// `F<buildId>_NN → descriptor` table (10-16 entries on a real build).
    pub f_methods: HashMap<String, String>,
    /// One entry per `assets/l<buildId>_<arch>.so` carried in the APK.
    pub asset_so_files: Vec<AssetSo>,
    /// SENS file path within the APK (`assets/*.dat`), empty if none.
    pub sens_file: String,
    /// SENS header's `record_count` field. `None` if no SENS file.
    pub sens_record_count: Option<u32>,
    /// True iff any SO contains the `virbox/%s` or VME-error strings.
    pub so_id_string_present: bool,
    /// True iff at least 3 of the 5 markers matched.
    pub confirmed: bool,
    /// Free-form diagnostic notes.
    pub notes: Vec<String>,
}

/// One per-arch loader SO entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSo {
    pub name: String,
    pub build_id: String,
    pub arch: String,
    pub size: u64,
}

/// Pull the `<application android:name=...>` value out of binary AXML.
///
/// We look for the literal stub-name regex `v[0-9a-f]{8}.l[0-9a-f]{8}`
/// in the AXML string table — for Virbox builds this is reliable because
/// the name is unique enough that no other appearance is plausible.
///
/// The Python version also looks for the UTF-16-LE encoded form in the
/// raw AXML bytes; here we let [`parse_axml_strings`] do the decoding
/// and then scan the resulting `Vec<String>`. This is equivalent for
/// well-formed AXML (the string pool stores the same bytes either way).
pub fn parse_application_from_manifest(manifest_xml_bytes: &[u8]) -> Option<String> {
    let re = Regex::new(VIRBOX_APPNAME_RE).ok()?;
    let strings = parse_axml_strings(manifest_xml_bytes);
    // Pick the most-frequently-occurring match (the Python uses
    // `Counter().most_common(1)`). Falls back to the first match if the
    // AXML parse fails — we don't have anything else to go on.
    let mut counts: HashMap<String, usize> = HashMap::new();
    for s in &strings {
        if re.is_match(s) {
            *counts.entry(s.clone()).or_insert(0) += 1;
        }
    }
    if let Some((best, _)) = counts.into_iter().max_by_key(|(_, c)| *c) {
        return Some(best);
    }
    // Last-resort: scan the raw bytes for the ASCII pattern (covers
    // packers that ship the name as a plain string outside the AXML
    // pool).
    if let Some(m) = re.find(&String::from_utf8_lossy(manifest_xml_bytes)) {
        return Some(m.as_str().to_string());
    }
    None
}

/// Return `(F-method-table, helper-class-name)` for every
/// `F<buildId>_NN` native method declared in the helper class
/// `Lm<buildId>;`. When `expected_class` is `None` we auto-detect
/// against the `Lm…;` pattern.
///
/// Implemented against [`ParsedDex`] for cheap re-use of the existing
/// DEX parser — the per-method-id walk is one borrow each.
pub fn scan_dex_for_f_methods(
    dex_bytes: &[u8],
    dex_name: &str,
    expected_class: Option<&str>,
) -> std::io::Result<(HashMap<String, String>, String)> {
    let parsed = ParsedDex::from_bytes(dex_bytes.to_vec(), dex_name.to_string())?;
    let re = Regex::new(r"^F([0-9a-fA-F]{8})_(\d{2})$").unwrap();
    let mut found: HashMap<String, String> = HashMap::new();
    let mut auto_class = String::new();
    for m in &parsed.method_ids {
        let name = &m.method_name;
        if !name.starts_with('F') || !name.contains('_') {
            continue;
        }
        if !re.is_match(name) {
            continue;
        }
        // Verify class matches the `Lm<buildId>;` pattern.
        let cls = &m.class_name;
        if !(cls.starts_with("Lm") && cls.ends_with(';')) {
            continue;
        }
        if let Some(exp) = expected_class {
            if cls != exp {
                continue;
            }
        }
        auto_class = cls.clone();
        // proto_desc is pre-formatted as "(params)return-type".
        found.insert(name.clone(), m.proto_desc.clone());
    }
    Ok((found, auto_class))
}

/// Run the marker-detection pipeline against a base APK on disk.
pub fn detect_virbox(apk_path: &Path, verbose: bool) -> std::io::Result<VirboxMarkers> {
    let mut m = VirboxMarkers::default();
    let bytes = std::fs::read(apk_path)?;
    let mut zf = ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let names: Vec<String> = zf.file_names().map(|s| s.to_string()).collect();

    // 1) Manifest stub Application class.
    if names.iter().any(|n| n == "AndroidManifest.xml") {
        let mut mf = Vec::new();
        if let Ok(mut e) = zf.by_name("AndroidManifest.xml") {
            if e.read_to_end(&mut mf).is_ok() {
                if let Some(app) = parse_application_from_manifest(&mf) {
                    // build-id = the 8 hex chars between leading 'v' and '.'
                    if let Some(dot) = app.find('.') {
                        let v = &app[..dot];
                        if v.starts_with('v') && v.len() == 9 {
                            m.build_id_hex = v[1..].to_lowercase();
                        }
                    }
                    if verbose {
                        eprintln!(
                            "  [+] Application class = {}  (buildId={})",
                            app, m.build_id_hex
                        );
                    }
                    m.application_class = app;
                }
            }
        }
    }

    // 2) Asset SOs `l<buildId>_<arch>.so`.
    let so_re = Regex::new(VIRBOX_SO_ARCH_RE).unwrap();
    let mut sorted_names = names.clone();
    sorted_names.sort();
    for n in &sorted_names {
        if !n.starts_with("assets/") || !n.ends_with(".so") {
            continue;
        }
        let stem = n.rsplit('/').next().unwrap_or(n);
        if let Some(caps) = so_re.captures(stem) {
            let build_id = caps.get(1).unwrap().as_str().to_lowercase();
            let arch = caps.get(2).unwrap().as_str().to_string();
            let size = zf.by_name(n).map(|e| e.size()).unwrap_or(0);
            m.asset_so_files.push(AssetSo {
                name: n.clone(),
                build_id: build_id.clone(),
                arch,
                size,
            });
            if m.build_id_hex.is_empty() {
                m.build_id_hex = build_id;
            }
        }
    }

    if m.build_id_hex.is_empty() {
        m.notes
            .push("no Virbox build-id derived from manifest or asset SOs".to_string());
        return Ok(m);
    }

    if verbose {
        eprintln!(
            "  [+] Found {} per-arch asset SO(s)",
            m.asset_so_files.len()
        );
    }

    // 3) Stub classes + Lm<buildId> helper.
    let m_class_expected = format!("Lm{};", m.build_id_hex);
    let mut candidate_dex_names: Vec<String> = Vec::new();
    candidate_dex_names.push("classes.dex".to_string());
    for i in 2..20 {
        candidate_dex_names.push(format!("classes{}.dex", i));
    }
    for cand in &candidate_dex_names {
        if !names.iter().any(|n| n == cand) {
            continue;
        }
        let mut dx = Vec::new();
        if let Ok(mut e) = zf.by_name(cand) {
            if e.read_to_end(&mut dx).is_err() {
                continue;
            }
        } else {
            continue;
        }
        if VIRBOX_STUB_CLASSES.iter().any(|pat| contains(&dx, pat)) {
            m.has_virbox_stub_class = true;
        }
        if m.m_class_name.is_empty() {
            if let Ok((f, c)) = scan_dex_for_f_methods(&dx, cand, Some(&m_class_expected)) {
                if !f.is_empty() {
                    m.m_class_name = c.clone();
                    m.f_methods = f;
                    if verbose {
                        eprintln!(
                            "  [+] {} declares {} F<buildId>_NN dispatchers in {}",
                            c,
                            m.f_methods.len(),
                            cand
                        );
                    }
                }
            }
        }
    }

    // 4) SENS file (legacy r21e — may be absent in newer builds).
    for n in &names {
        if !n.starts_with("assets/") || !n.ends_with(".dat") {
            continue;
        }
        let sz = zf.by_name(n).map(|e| e.size()).unwrap_or(0);
        if !(32..=5_000_000).contains(&sz) {
            continue;
        }
        let mut blob = Vec::new();
        if let Ok(mut e) = zf.by_name(n) {
            if e.read_to_end(&mut blob).is_err() {
                continue;
            }
        } else {
            continue;
        }
        if blob.len() >= 4 && &blob[..4] == super::sens::SENS_MAGIC {
            m.sens_file = n.clone();
            if blob.len() >= super::sens::SENS_RECCOUNT_OFFSET + 4 {
                m.sens_record_count = Some(u32::from_le_bytes(
                    blob[super::sens::SENS_RECCOUNT_OFFSET..super::sens::SENS_RECCOUNT_OFFSET + 4]
                        .try_into()
                        .unwrap(),
                ));
            }
            if verbose {
                eprintln!(
                    "  [+] SENS file at {} (records={:?})",
                    n, m.sens_record_count
                );
            }
            break;
        }
    }

    // 5) Self-ID string present in any SO.
    for so in &m.asset_so_files {
        let mut d = Vec::new();
        if let Ok(mut e) = zf.by_name(&so.name) {
            if e.read_to_end(&mut d).is_ok() {
                if contains(&d, VIRBOX_SO_ID_STR) || contains(&d, VIRBOX_VME_ERROR_STR) {
                    m.so_id_string_present = true;
                    break;
                }
            }
        }
    }

    // Confidence: any 3 of 5 markers.
    let score = [
        m.has_virbox_stub_class,
        !m.m_class_name.is_empty(),
        !m.asset_so_files.is_empty(),
        !m.sens_file.is_empty(),
        m.so_id_string_present,
    ]
    .iter()
    .filter(|b| **b)
    .count();
    m.confirmed = score >= 3;
    if !m.confirmed {
        m.notes.push(format!(
            "only {}/5 Virbox markers matched; classification uncertain",
            score
        ));
    }
    Ok(m)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
