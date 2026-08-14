//! Auto-detect the Android packer family for an APK or XAPK.
//!
//! Direct port of `unpacker/packer_backends/detector.py`. Reads only
//! the ZIP central directory plus `AndroidManifest.xml`; never executes
//! anything from the sample.
//!
//! Returns the **primary** packer family (the one whose backend should
//! run) plus the full list of *all* detected markers, including add-on
//! tooling (PangleArmor, App Cloner, embedded Ali Mobisec, …) so the
//! caller can decide whether the sample is interesting beyond the
//! primary protector.

use std::io::Read;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::axml::parse_axml_strings;

/// Priority order — when multiple families fire, the one that owns the
/// **protected DEX** wins. Add-ons (PangleArmor, AppCloner, Ali Mobisec)
/// are never primary; the unknown-fallback path filters them out before
/// gauging confidence.
const PRIMARY_PRIORITY: &[&str] = &[
    "virbox",
    "jiagu",
    "ijiami",
    "dexshield",
    "fengyue",
    "bangcle",
    "tencent-legu",
    "ducex",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub primary: String,
    pub confidence: String,
    pub all_families: Vec<FamilyHit>,
    pub markers: serde_json::Map<String, serde_json::Value>,
    pub is_xapk: bool,
    /// For XAPK: the inner base-APK entry name. For plain APK: the
    /// input path itself.
    pub base_apk_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyHit {
    pub family: String,
    pub evidence: String,
}

/// Return a snapshot of the backend names this crate knows how to
/// dispatch to. Matches Python `known_backends()`.
pub fn known_backends() -> &'static [&'static str] {
    &["virbox", "jiagu", "ijiami", "dexshield", "fengyue"]
}

/// Detect the packer family for an APK or XAPK at `input_path`.
///
/// For XAPK input, transparently picks the inner `base.apk` for
/// classification (and reports its entry-name on the returned Detection).
pub fn detect(input_path: &Path) -> std::io::Result<Detection> {
    if !input_path.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{}", input_path.display()),
        ));
    }
    let bytes = std::fs::read(input_path)?;
    let mut zf = match ZipArchive::new(std::io::Cursor::new(bytes)) {
        Ok(z) => z,
        Err(_) => {
            return Ok(Detection {
                primary: "unknown".into(),
                confidence: "none".into(),
                all_families: Vec::new(),
                markers: {
                    let mut m = serde_json::Map::new();
                    m.insert("error".into(), serde_json::Value::String("not a zip".into()));
                    m
                },
                is_xapk: false,
                base_apk_path: input_path.to_string_lossy().into_owned(),
            });
        }
    };

    let names: Vec<String> = zf.file_names().map(|s| s.to_string()).collect();
    let has_apk_inside = names.iter().any(|n| n.ends_with(".apk"));
    let has_manifest_json = names.iter().any(|n| n == "manifest.json");

    let (findings, markers, is_xapk, base_apk_path) = if has_manifest_json && has_apk_inside {
        // ── XAPK path ──
        // Find base.apk via manifest.json's split_apks[].id=="base"; if
        // missing or malformed, fall back to the largest .apk entry.
        let mut base_name: Option<String> = None;
        if let Ok(mut e) = zf.by_name("manifest.json") {
            let mut buf = String::new();
            if e.read_to_string(&mut buf).is_ok() {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&buf) {
                    if let Some(splits) = json.get("split_apks").and_then(|v| v.as_array()) {
                        for s in splits {
                            if s.get("id").and_then(|v| v.as_str()) == Some("base") {
                                if let Some(name) = s.get("file").and_then(|v| v.as_str()) {
                                    base_name = Some(name.to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        if base_name.as_deref().map_or(true, |n| !names.iter().any(|m| m == n)) {
            let mut apks: Vec<(u64, String)> = names
                .iter()
                .filter(|n| n.ends_with(".apk"))
                .filter_map(|n| zf.by_name(n).ok().map(|e| (e.size(), n.clone())))
                .collect();
            apks.sort_by(|a, b| b.0.cmp(&a.0));
            base_name = apks.first().map(|(_, n)| n.clone());
        }
        if let Some(bn) = &base_name {
            let mut inner_bytes = Vec::new();
            let read_ok = zf
                .by_name(bn)
                .ok()
                .and_then(|mut e| e.read_to_end(&mut inner_bytes).ok())
                .is_some();
            if read_ok {
                if let Ok(mut inner) = ZipArchive::new(std::io::Cursor::new(inner_bytes)) {
                    let (f, m) = classify_zip(&mut inner);
                    (f, m, true, bn.clone())
                } else {
                    let mut m = serde_json::Map::new();
                    m.insert(
                        "error".into(),
                        serde_json::Value::String("xapk inner is not a zip".into()),
                    );
                    (Vec::new(), m, true, bn.clone())
                }
            } else {
                let mut m = serde_json::Map::new();
                m.insert(
                    "error".into(),
                    serde_json::Value::String("xapk inner read failed".into()),
                );
                (Vec::new(), m, true, bn.clone())
            }
        } else {
            let mut m = serde_json::Map::new();
            m.insert(
                "error".into(),
                serde_json::Value::String("xapk has no inner .apk".into()),
            );
            (Vec::new(), m, true, String::new())
        }
    } else {
        let (f, m) = classify_zip(&mut zf);
        (f, m, false, input_path.to_string_lossy().into_owned())
    };

    let families_found: std::collections::HashSet<&str> =
        findings.iter().map(|(f, _)| f.as_str()).collect();
    let mut primary = "unknown".to_string();
    for cand in PRIMARY_PRIORITY {
        if families_found.contains(*cand) {
            primary = (*cand).to_string();
            break;
        }
    }
    let confidence = if primary == "unknown" {
        let non_addon = findings
            .iter()
            .any(|(f, _)| !["appcloner", "panglearmor", "alijiagu"].contains(&f.as_str()));
        if non_addon { "low" } else { "none" }.to_string()
    } else {
        // The Python: "high if we have either virbox SOs, jiagu
        // .jgapp+libjiagu, or fengyue loader+stub". The original
        // returns "high" for ANY primary hit — we mirror that exactly
        // rather than re-deriving per-family scoring here.
        "high".to_string()
    };

    Ok(Detection {
        primary,
        confidence,
        all_families: findings
            .into_iter()
            .map(|(family, evidence)| FamilyHit { family, evidence })
            .collect(),
        markers,
        is_xapk,
        base_apk_path,
    })
}

// ─── Per-zip family classification ────────────────────────────────────────

fn classify_zip<R: std::io::Read + std::io::Seek>(
    zf: &mut ZipArchive<R>,
) -> (Vec<(String, String)>, serde_json::Map<String, serde_json::Value>) {
    let names: Vec<String> = zf.file_names().map(|s| s.to_string()).collect();
    let asset_files: Vec<&str> = names
        .iter()
        .filter(|n| n.starts_with("assets/"))
        .map(|s| s.as_str())
        .collect();
    let lib_files: Vec<&str> = names
        .iter()
        .filter(|n| n.starts_with("lib/"))
        .map(|s| s.as_str())
        .collect();

    let manifest_strs: Vec<String> = {
        let mut buf = Vec::new();
        if let Ok(mut e) = zf.by_name("AndroidManifest.xml") {
            if e.read_to_end(&mut buf).is_ok() {
                parse_axml_strings(&buf)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    };

    // Pre-compile every regex once. These are the same patterns as
    // detector.py; no behaviour change.
    let virbox_so_re = Regex::new(r"assets/l[0-9a-f]{8}_(a32|a64|x86|x64)\.so$").unwrap();
    let virbox_bld_re = Regex::new(r"^l([0-9a-f]{8})_(a32|a64|x86|x64)\.so$").unwrap();
    let virbox_appname_re = Regex::new(r"^v[0-9a-f]{8}\.l[0-9a-f]{8}$").unwrap();
    let jiagu_so_re =
        Regex::new(r"^assets/libjiagu(_a64|_x64|_x86)?\.so$").unwrap();
    let jiagu_variant_re =
        Regex::new(r"assets/libjg[a-z]{2,5}(_(a64|x64|x86))?\.so$").unwrap();
    let jiagu_sdk_re = Regex::new(r"lib/[^/]+/libjiagu_sdk_.*\.so$").unwrap();
    let fengyue_loader_re = Regex::new(r"assets/libdexload_(arm|a64|x86|x64)\.so$").unwrap();
    let ijiami_loader_re = Regex::new(
        r"lib/[^/]+/(libexecmain|libexec|libsmainso|libsecmain|libsecexe)\.so$",
    )
    .unwrap();
    let dexshield_re = Regex::new(r"lib/[^/]+/libDexHelper(-x86)?\.so$").unwrap();
    let ducex_re = Regex::new(r"lib/[^/]+/libducex\.so$").unwrap();
    let ali_sgmain_re = Regex::new(r"libsgmain(so)?(-[\d.]+)?\.so$").unwrap();

    let mut findings: Vec<(String, String)> = Vec::new();
    let mut markers: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    // ── Virbox ──
    let virbox_so: Vec<&str> =
        asset_files.iter().copied().filter(|n| virbox_so_re.is_match(n)).collect();
    let virbox_kqk = names.iter().any(|n| n == "assets/kqkticwjgzy.dat");
    let virbox_stub = manifest_strs.iter().any(|s| s.contains("virbox/StubApp") || s.contains("Lvirbox/StubApp"));
    let virbox_appname = manifest_strs.iter().any(|s| virbox_appname_re.is_match(s));
    let virbox_score = (virbox_so.is_empty() as i32 ^ 1) + virbox_kqk as i32
        + virbox_stub as i32 + virbox_appname as i32;
    if virbox_score >= 2 || (!virbox_so.is_empty() && virbox_score >= 1) {
        let mut bid = String::new();
        if let Some(first) = virbox_so.first() {
            let basename = std::path::Path::new(first)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if let Some(c) = virbox_bld_re.captures(basename) {
                bid = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            }
        }
        findings.push((
            "virbox".into(),
            format!(
                "build={} so={} kqk={} stub={}",
                bid,
                virbox_so.len(),
                virbox_kqk,
                virbox_stub
            ),
        ));
        let mut m = serde_json::Map::new();
        m.insert("build_id".into(), serde_json::Value::String(bid));
        m.insert("asset_so_count".into(), serde_json::Value::from(virbox_so.len()));
        m.insert("has_kqk".into(), serde_json::Value::Bool(virbox_kqk));
        m.insert("has_stub_class".into(), serde_json::Value::Bool(virbox_stub));
        m.insert("has_app_name".into(), serde_json::Value::Bool(virbox_appname));
        m.insert("score".into(), serde_json::Value::from(virbox_score));
        markers.insert("virbox".into(), serde_json::Value::Object(m));
    }

    // ── Qihoo 360 Jiagu ──
    let jgapp = names.iter().any(|n| n == "assets/.jgapp");
    let jiagu_so: Vec<&str> =
        asset_files.iter().copied().filter(|n| jiagu_so_re.is_match(n)).collect();
    let jiagu_variant: Vec<&str> =
        asset_files.iter().copied().filter(|n| jiagu_variant_re.is_match(n)).collect();
    let jiagu_sdk: Vec<&str> =
        lib_files.iter().copied().filter(|n| jiagu_sdk_re.is_match(n)).collect();
    if !jiagu_so.is_empty() || jgapp || !jiagu_variant.is_empty() {
        let mut evs: Vec<String> = Vec::new();
        if jgapp { evs.push(".jgapp".into()); }
        if !jiagu_so.is_empty() {
            evs.push(format!("libjiagu({})", jiagu_so.len()));
        }
        if let Some(first) = jiagu_variant.first() {
            let basename = std::path::Path::new(first)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            evs.push(format!("variant={}", basename));
        }
        if !jiagu_sdk.is_empty() {
            evs.push(format!("jiagu_sdk({})", jiagu_sdk.len()));
        }
        findings.push(("jiagu".into(), evs.join(" ")));
        let mut m = serde_json::Map::new();
        m.insert("jgapp".into(), serde_json::Value::Bool(jgapp));
        m.insert(
            "libjiagu_assets".into(),
            serde_json::Value::Array(jiagu_so.iter().map(|s| serde_json::Value::String((*s).to_string())).collect()),
        );
        m.insert(
            "variant_assets".into(),
            serde_json::Value::Array(jiagu_variant.iter().map(|s| serde_json::Value::String((*s).to_string())).collect()),
        );
        m.insert(
            "sdk_libs".into(),
            serde_json::Value::Array(jiagu_sdk.iter().map(|s| serde_json::Value::String((*s).to_string())).collect()),
        );
        markers.insert("jiagu".into(), serde_json::Value::Object(m));
    }

    // ── FengYue / com.storm.fengyue ──
    let dexload: Vec<&str> =
        asset_files.iter().copied().filter(|n| fengyue_loader_re.is_match(n)).collect();
    let fengyue_stub = manifest_strs.iter().any(|s| s.contains("com.storm.fengyue"));
    if !dexload.is_empty() || fengyue_stub {
        findings.push((
            "fengyue".into(),
            format!("libdexload({}) stub={}", dexload.len(), fengyue_stub),
        ));
        let mut m = serde_json::Map::new();
        m.insert(
            "loaders".into(),
            serde_json::Value::Array(dexload.iter().map(|s| serde_json::Value::String((*s).to_string())).collect()),
        );
        m.insert("stub_present".into(), serde_json::Value::Bool(fengyue_stub));
        markers.insert("fengyue".into(), serde_json::Value::Object(m));
    }

    // ── Ijiami (爱加密) ──
    let ijiami_so: Vec<&str> =
        lib_files.iter().copied().filter(|n| ijiami_loader_re.is_match(n)).collect();
    let ijiami_dat: Vec<&str> = asset_files
        .iter()
        .copied()
        .filter(|n| *n == "assets/ijiami.dat" || *n == "assets/ijiami.ajm")
        .collect();
    let ijiami_stub = manifest_strs.iter().any(|s| {
        matches!(
            s.as_str(),
            "com.shell.NativeApplication"
                | "com.shell.NativeApplicationE"
                | "cn.securitystack.stss.NativeApplication"
        )
    });
    if !ijiami_so.is_empty() || !ijiami_dat.is_empty() || ijiami_stub {
        findings.push((
            "ijiami".into(),
            format!("so={} dat={} stub={}", ijiami_so.len(), ijiami_dat.len(), ijiami_stub),
        ));
        let mut m = serde_json::Map::new();
        m.insert(
            "loader_libs".into(),
            serde_json::Value::Array(ijiami_so.iter().map(|s| serde_json::Value::String((*s).to_string())).collect()),
        );
        m.insert(
            "dat_assets".into(),
            serde_json::Value::Array(ijiami_dat.iter().map(|s| serde_json::Value::String((*s).to_string())).collect()),
        );
        m.insert("stub_present".into(), serde_json::Value::Bool(ijiami_stub));
        markers.insert("ijiami".into(), serde_json::Value::Object(m));
    }

    // ── DexShield ──
    let dexshield_so: Vec<&str> =
        lib_files.iter().copied().filter(|n| dexshield_re.is_match(n)).collect();
    if !dexshield_so.is_empty() {
        findings.push(("dexshield".into(), format!("so={}", dexshield_so.len())));
        let mut m = serde_json::Map::new();
        m.insert(
            "loader_libs".into(),
            serde_json::Value::Array(dexshield_so.iter().map(|s| serde_json::Value::String((*s).to_string())).collect()),
        );
        markers.insert("dexshield".into(), serde_json::Value::Object(m));
    }

    // ── Ducex / Triada ──
    let ducex_so: Vec<&str> =
        lib_files.iter().copied().filter(|n| ducex_re.is_match(n)).collect();
    let mxini = names.iter().any(|n| n == "assets/mx.ini");
    if !ducex_so.is_empty() || mxini {
        findings.push((
            "ducex".into(),
            format!("so={} mxini={}", ducex_so.len(), mxini),
        ));
        let mut m = serde_json::Map::new();
        m.insert(
            "loader_libs".into(),
            serde_json::Value::Array(ducex_so.iter().map(|s| serde_json::Value::String((*s).to_string())).collect()),
        );
        m.insert("mxini".into(), serde_json::Value::Bool(mxini));
        markers.insert("ducex".into(), serde_json::Value::Object(m));
    }

    // ── App Cloner (modding tool; not a Java packer) ──
    if names.iter().any(|n| n == "assets/app_cloner.dat" || n == "assets/app_cloner_branding.png") {
        findings.push(("appcloner".into(), "app_cloner.dat present".into()));
        markers.insert("appcloner".into(), serde_json::Value::Bool(true));
    }

    // ── PangleArmor (SDK-only) ──
    let pangle: Vec<&str> = lib_files
        .iter()
        .copied()
        .filter(|n| n.to_lowercase().contains("libpanglearmor"))
        .collect();
    if !pangle.is_empty() {
        findings.push(("panglearmor".into(), format!("so={}", pangle.len())));
        markers.insert(
            "panglearmor".into(),
            serde_json::Value::Array(pangle.iter().map(|s| serde_json::Value::String((*s).to_string())).collect()),
        );
    }

    // ── Ali Mobisec (sgmain) ──
    let ali: Vec<&str> = lib_files.iter().copied().filter(|n| ali_sgmain_re.is_match(n)).collect();
    if !ali.is_empty() {
        findings.push(("alijiagu".into(), format!("sgmain={}", ali.len())));
        markers.insert(
            "alijiagu".into(),
            serde_json::Value::Array(ali.iter().map(|s| serde_json::Value::String((*s).to_string())).collect()),
        );
    }

    // Carry a small sample of manifest strings into the marker bag for
    // forensic triage. Bound at 200 entries × 256 chars each — matches
    // the Python cap exactly.
    let sample: Vec<serde_json::Value> = manifest_strs
        .iter()
        .take(200)
        .filter(|s| s.len() < 256)
        .map(|s| serde_json::Value::String(s.clone()))
        .collect();
    markers.insert("manifest_strings_sample".into(), serde_json::Value::Array(sample));

    let _ = PathBuf::new(); // silence unused import in some toolchains
    (findings, markers)
}
