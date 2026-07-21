//! Shared types + helpers used by every packer backend.
//!
//! Mirrors `unpacker/packer_backends/_common.py` plus the implicit
//! "manifest dict" shape that `packer_backends/__init__.py` documents.
//! In Python the manifest is a free-form dict; here we make it a
//! concrete `Manifest` struct so each backend gets compile-time
//! field-name checking and serde just works.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

// ─── Hashing ────────────────────────────────────────────────────────────────

/// SHA-256 of an in-memory buffer, returned as a lowercase hex string —
/// matches `hashlib.sha256(b).hexdigest()` exactly.
pub fn sha256_bytes(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex(&h.finalize())
}

/// SHA-256 of a file by 1 MiB streaming read — matches the Python
/// `sha256_file(path)` chunked-read behaviour. Useful for large APKs
/// where we don't want a full mmap.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

// ─── APK / XAPK handling ───────────────────────────────────────────────────

/// Open an APK or XAPK and return a `ZipArchive` reader. For XAPK input,
/// reads the inner `base.apk` bytes into memory and returns a `ZipArchive`
/// over them — matching the Python `open_apk()` shape.
///
/// Use [`extract_base_apk_if_xapk`] when you need the base APK
/// **materialised to disk** (downstream backends that re-open it).
pub fn open_apk(input_path: &Path) -> io::Result<ZipArchive<std::io::Cursor<Vec<u8>>>> {
    let bytes = std::fs::read(input_path)?;
    let mut outer = ZipArchive::new(std::io::Cursor::new(bytes.clone()))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let names: Vec<String> = outer.file_names().map(|s| s.to_string()).collect();
    let is_xapk = names.iter().any(|n| n == "manifest.json")
        && names.iter().any(|n| n == "base.apk");
    if is_xapk {
        let mut inner = Vec::new();
        outer
            .by_name("base.apk")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            .read_to_end(&mut inner)?;
        return ZipArchive::new(std::io::Cursor::new(inner))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
    }
    // Re-create the archive from the original bytes — we consumed the
    // first one above when reading file_names().
    ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// If `input_path` is an XAPK, materialise the inner base APK to
/// `dest_dir/base.apk` and return that path. Otherwise return
/// `input_path.to_path_buf()`. Handles both APKMirror (`base.apk`) and
/// APK-Pure (package-named) layouts: reads `manifest.json`'s
/// `split_apks` array to find the `id=="base"` entry, with a
/// largest-`.apk`-entry fallback.
pub fn extract_base_apk_if_xapk(input_path: &Path, dest_dir: &Path) -> io::Result<PathBuf> {
    let bytes = std::fs::read(input_path)?;
    let mut zf = ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let names: Vec<String> = zf.file_names().map(|s| s.to_string()).collect();
    let has_apk = names.iter().any(|n| n.ends_with(".apk"));
    let has_manifest = names.iter().any(|n| n == "manifest.json");
    if !(has_manifest && has_apk) {
        return Ok(input_path.to_path_buf());
    }

    // Try to read manifest.json's split_apks[].id=="base".
    let mut base_name: Option<String> = None;
    if let Ok(mut entry) = zf.by_name("manifest.json") {
        let mut buf = String::new();
        if entry.read_to_string(&mut buf).is_ok() {
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

    // Fallback: pick the largest .apk entry.
    if base_name.as_deref().map_or(true, |n| !names.iter().any(|m| m == n)) {
        let mut apks: Vec<(u64, String)> = names
            .iter()
            .filter(|n| n.ends_with(".apk"))
            .filter_map(|n| zf.by_name(n).ok().map(|e| (e.size(), n.clone())))
            .collect();
        apks.sort_by(|a, b| b.0.cmp(&a.0));
        base_name = apks.first().map(|(_, n)| n.clone());
    }

    let base_name = base_name.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("XAPK {} contains no .apk entry", input_path.display()),
        )
    })?;
    std::fs::create_dir_all(dest_dir)?;
    let out_path = dest_dir.join("base.apk");
    let mut fin = zf
        .by_name(&base_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut fout = File::create(&out_path)?;
    io::copy(&mut fin, &mut fout)?;
    Ok(out_path)
}

// ─── Carving (copy named ZIP entries to disk) ──────────────────────────────

/// Copy named entries out of `zf` into `out_dir`. Returns a list of
/// `{name, size, sha256, out_path}` records for the manifest.
///
/// Entries with `/` in their name are flattened to `_` so a single
/// directory holds them all (matches the Python behaviour).
pub fn carve_entries<R: std::io::Read + std::io::Seek>(
    zf: &mut ZipArchive<R>,
    entries: &[String],
    out_dir: &Path,
) -> io::Result<Vec<CarvedEntry>> {
    std::fs::create_dir_all(out_dir)?;
    let mut recs = Vec::new();
    for name in entries {
        let mut data = Vec::new();
        let read_ok = match zf.by_name(name) {
            Ok(mut e) => e.read_to_end(&mut data).is_ok(),
            Err(_) => false, // KeyError equivalent — skip silently
        };
        if !read_ok {
            continue;
        }
        let rel = name.replace('/', "_");
        let dest = out_dir.join(&rel);
        File::create(&dest)?.write_all(&data)?;
        recs.push(CarvedEntry {
            name: name.clone(),
            size: data.len(),
            sha256: sha256_bytes(&data),
            out_path: dest.to_string_lossy().into_owned(),
        });
    }
    Ok(recs)
}

/// Carve every top-level `classesN.dex` entry verbatim from the APK,
/// returning records suitable for `Manifest::recovered_dexs`.
pub fn carve_all_dexs<R: std::io::Read + std::io::Seek>(
    zf: &mut ZipArchive<R>,
    out_dir: &Path,
) -> io::Result<Vec<RecoveredDex>> {
    std::fs::create_dir_all(out_dir)?;
    let mut names: Vec<String> = zf
        .file_names()
        .filter(|n| n.ends_with(".dex") && !n.contains('/'))
        .map(|s| s.to_string())
        .collect();
    names.sort();
    let mut recs = Vec::new();
    for n in &names {
        let mut data = Vec::new();
        zf.by_name(n)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            .read_to_end(&mut data)?;
        let dest = out_dir.join(n);
        File::create(&dest)?.write_all(&data)?;
        let magic = &data[..data.len().min(8)];
        let valid_dex_magic =
            magic.starts_with(b"dex\n") || magic.starts_with(b"dey\n");
        recs.push(RecoveredDex {
            name: n.clone(),
            size: data.len(),
            sha256: sha256_bytes(&data),
            magic: hex(magic),
            valid_dex_magic,
            ok: valid_dex_magic,
            recovery: String::new(),
            source: None,
            out_path: Some(dest.to_string_lossy().into_owned()),
            extra: serde_json::Map::new(),
        });
    }
    Ok(recs)
}

/// Best-effort AXML string-pool read for `AndroidManifest.xml`. Returns
/// an empty list on any failure (missing entry, malformed AXML, etc.) —
/// callers treat the absence of strings as inconclusive, never as an
/// error.
pub fn read_manifest_strings<R: std::io::Read + std::io::Seek>(
    zf: &mut ZipArchive<R>,
) -> Vec<String> {
    let mut data = Vec::new();
    if let Ok(mut e) = zf.by_name("AndroidManifest.xml") {
        if e.read_to_end(&mut data).is_err() {
            return Vec::new();
        }
    } else {
        return Vec::new();
    }
    crate::axml::parse_axml_strings(&data)
}

// ─── Manifest output ───────────────────────────────────────────────────────

pub fn write_manifest(out_dir: &Path, manifest: &Manifest) -> io::Result<PathBuf> {
    std::fs::create_dir_all(out_dir)?;
    let p = out_dir.join("manifest.json");
    let json = serde_json::to_string_pretty(manifest).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("manifest serialize: {e}"))
    })?;
    File::create(&p)?.write_all(json.as_bytes())?;
    Ok(p)
}

/// Write a per-sample UNRECOVERED.md listing each unrecovered item.
/// Matches the Python rendering byte-for-byte (single empty entry text
/// when items is empty, dash-bullets otherwise).
pub fn write_unrecovered(
    out_dir: &Path,
    items: &[Unrecovered],
    packer: &str,
) -> io::Result<PathBuf> {
    std::fs::create_dir_all(out_dir)?;
    let p = out_dir.join("UNRECOVERED.md");
    let mut lines = vec![
        format!("# Unrecovered items for this sample ({})", packer),
        String::new(),
        format!(
            "These items could not be recovered statically. See \
             `../by-packer/{}.md` for the family's recovery capability.",
            packer
        ),
        String::new(),
    ];
    if items.is_empty() {
        lines.push("_None — full static recovery achieved._".to_string());
    } else {
        for it in items {
            lines.push(format!("- **{}** — {}", it.item, it.reason));
        }
    }
    File::create(&p)?.write_all(lines.join("\n").as_bytes())?;
    Ok(p)
}

// ─── Manifest shape ────────────────────────────────────────────────────────
//
// These mirror the dict shape documented in
// `unpacker/packer_backends/__init__.py`. We use `serde_json::Value` for
// fields where Python uses free-form dicts (notes, options, detection)
// to keep the JSON identical to the Python output. Backends fill in
// strongly-typed fields where the shape is stable across all packers
// (stages, recovered_dexs, unrecovered).

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub packer: String,
    pub backend: String,
    pub input: String,
    pub out_dir: String,
    pub options: serde_json::Value,
    pub stages: Vec<Stage>,
    pub recovered_dexs: Vec<RecoveredDex>,
    pub unrecovered: Vec<Unrecovered>,
    #[serde(skip_serializing_if = "serde_json::Map::is_empty", default)]
    pub notes: serde_json::Map<String, serde_json::Value>,
    /// Detection info populated by `dump_packer` after the backend
    /// returns — backends themselves leave this `Value::Null`.
    #[serde(skip_serializing_if = "serde_json::Value::is_null", default)]
    pub detection: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_sec: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scaffold_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

impl Stage {
    pub fn new(name: impl Into<String>, ok: bool, detail: impl Into<String>) -> Self {
        Self { name: name.into(), ok, detail: detail.into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredDex {
    pub name: String,
    pub size: usize,
    pub sha256: String,
    pub magic: String,
    pub valid_dex_magic: bool,
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub recovery: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_path: Option<String>,
    /// Free-form per-backend extras (e.g. fengyue stuffs the AES key/IV +
    /// adler32 numbers in here). Flattened into the parent JSON object
    /// when serialised so the output stays Python-shape-compatible.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unrecovered {
    pub item: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedEntry {
    pub name: String,
    pub size: usize,
    pub sha256: String,
    pub out_path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_python_hashlib() {
        // hashlib.sha256(b"hello").hexdigest()
        assert_eq!(
            sha256_bytes(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        );
        assert_eq!(
            sha256_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }
}
