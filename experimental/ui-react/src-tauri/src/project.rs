//! Multi-APK project model.
//!
//! A `Project` holds N `Slot`s. Each slot is one *logical* APK — either:
//!  - a standalone APK,
//!  - a base APK plus its splits (which appear as one slot, not several), or
//!  - an APK that was extracted/decrypted from another slot (its `parent_id` is set).
//!
//! Per-slot heavyweight data (DEX files, parsed manifest, resources) is rebuilt
//! from disk on every load. Only the *metadata* (paths, sha256, declared splits,
//! parentage) is persisted to `project.json` in the cache directory.
//!
//! Slot identity is the SHA-256 of the **base** APK. This makes "loading the
//! same file twice" idempotent — you'll just refocus the existing slot.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use project_platypus_native::apk::arsc::{self, ResourceTable};
use project_platypus_native::apk::axml;
use project_platypus_native::apk::split::SplitApk;
use project_platypus_native::apk::zip::ApkZip;
use project_platypus_native::dex::parser::DexFileWithRaw;

// ── Persisted shape ───────────────────────────────────────────────────────────

/// Snapshot of the project that lives on disk as `<cache>/project.json`.
/// Just metadata — the heavy data is rehydrated from `base_path`/`split_paths`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectPersist {
    pub slots: Vec<SlotPersist>,
    pub active_slot_id: Option<String>,
    pub compare_slot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotPersist {
    pub id: String,
    pub display_name: String,
    pub base_path: String,
    #[serde(default)]
    pub split_paths: Vec<String>,
    pub sha256: String,
    pub package_name: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<i64>,
    /// `<uses-split>` declarations parsed from the base manifest.
    #[serde(default)]
    pub declared_splits: Vec<String>,
    /// Set when this slot was extracted from another (e.g. APK in assets).
    pub parent_id: Option<String>,
    /// True if `base_path` lives inside the platypus cache dir.
    #[serde(default)]
    pub is_cached: bool,
    /// Methods the user has marked as deobfuscation helpers in the UI.
    /// Stored as `(class_norm, method_name)` pairs (class without
    /// `L`/`;` wrapper). Persisted per-slot so reopening an APK
    /// restores the user's curated set.
    #[serde(default)]
    pub deobf_marks: Vec<(String, String)>,
}

// ── In-memory shape ───────────────────────────────────────────────────────────

/// One logical APK with all its parsed data ready to query.
pub struct Slot {
    pub id: String,
    pub display_name: String,
    pub base_path: String,
    pub split_paths: Vec<String>,
    pub sha256: String,
    pub package_name: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<i64>,
    pub declared_splits: Vec<String>,
    pub parent_id: Option<String>,
    pub is_cached: bool,

    // Live data, rebuilt from disk on each load.
    pub dex_files: Vec<DexFileWithRaw>,
    pub resources: Option<ResourceTable>,
    pub manifest_xml: Option<String>,
    /// All ZIP entries across base + splits, with the originating split name.
    /// `(split_name_or_empty, entry_name)`.
    pub entry_names: Vec<(String, String)>,
    /// Auto-detected embedded APKs/ZIPs containing classes.dex inside this slot's
    /// assets/resources. Surfaced in the UI for one-click "Load as APK".
    pub embedded_candidates: Vec<EmbeddedCandidate>,
    /// User-curated "this method is a deobfuscator" marks. Set membership
    /// drives the DEOBFUSCATION bottom-bar tab. Persisted across restarts
    /// via `SlotPersist.deobf_marks`.
    ///
    /// Key shape: `(class_norm, method_name)` where `class_norm` is the
    /// L/;-stripped form (e.g. `"com/dualtext/compare/SystemSingleton"`)
    /// and `method_name` is the bare method name without proto
    /// (e.g. `"KotlinClass"`). Mark per *name*, not per overload — if a
    /// class has two `decrypt` methods with different protos they share
    /// one mark. That matches the user's mental model: "this helper".
    pub deobf_marks: std::collections::BTreeSet<(String, String)>,
}

/// One auto-detected embedded APK (or ZIP-with-classes.dex) inside a slot.
///
/// Detection criterion (intentionally relaxed): the entry's bytes parse as a
/// ZIP and contain at least one `classes*.dex` member. AndroidManifest is
/// **not** required — some embedded payloads ship a malformed APK with just
/// DEX content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddedCandidate {
    /// Path inside the parent ZIP, e.g. `assets/payload.apk` or `res/raw/data.bin`.
    pub entry_path: String,
    /// Which split the entry came from (`""` = base APK).
    pub split_name: String,
    /// Size of the embedded blob in bytes.
    pub size: u64,
    /// SHA-256 of the embedded blob (used as the future child slot's id).
    pub sha256: String,
    /// True if `AndroidManifest.xml` was found inside the embedded ZIP.
    pub has_manifest: bool,
    /// Number of `classes*.dex` members found inside.
    pub dex_count: usize,
    /// Best-guess display name extracted from the entry path.
    pub suggested_name: String,
}

impl Slot {
    /// Public-facing summary for the frontend.
    pub fn summary(&self) -> SlotSummary {
        SlotSummary {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            base_path: self.base_path.clone(),
            split_paths: self.split_paths.clone(),
            sha256: self.sha256.clone(),
            package_name: self.package_name.clone(),
            version_name: self.version_name.clone(),
            version_code: self.version_code,
            declared_splits: self.declared_splits.clone(),
            // Splits the user has actually loaded (filename only, not full path).
            loaded_splits: self.split_paths.iter()
                .filter_map(|p| Path::new(p).file_name().and_then(|s| s.to_str()).map(String::from))
                .collect(),
            parent_id: self.parent_id.clone(),
            is_cached: self.is_cached,
            dex_count: self.dex_files.len(),
            embedded_candidates: self.embedded_candidates.clone(),
        }
    }

    fn to_persist(&self) -> SlotPersist {
        SlotPersist {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            base_path: self.base_path.clone(),
            split_paths: self.split_paths.clone(),
            sha256: self.sha256.clone(),
            package_name: self.package_name.clone(),
            version_name: self.version_name.clone(),
            version_code: self.version_code,
            declared_splits: self.declared_splits.clone(),
            parent_id: self.parent_id.clone(),
            is_cached: self.is_cached,
            deobf_marks: self.deobf_marks.iter().cloned().collect(),
        }
    }
}

/// Frontend-facing slot summary (no heavy data).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotSummary {
    pub id: String,
    pub display_name: String,
    pub base_path: String,
    pub split_paths: Vec<String>,
    pub sha256: String,
    pub package_name: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<i64>,
    /// `<uses-split>` declarations from the base manifest.
    pub declared_splits: Vec<String>,
    /// Names of splits the user has actually loaded (not paths).
    pub loaded_splits: Vec<String>,
    pub parent_id: Option<String>,
    pub is_cached: bool,
    pub dex_count: usize,
    /// Auto-detected embedded APKs/ZIPs containing classes.dex.
    pub embedded_candidates: Vec<EmbeddedCandidate>,
}

// ── Project ──────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct Project {
    pub slots: Vec<Slot>,
    pub active_slot_id: Option<String>,
    /// Slot used as the "B" side in the diff/compare view.
    pub compare_slot_id: Option<String>,
}

impl Project {
    pub fn new() -> Self { Self::default() }

    pub fn find(&self, id: &str) -> Option<&Slot> {
        self.slots.iter().find(|s| s.id == id)
    }

    pub fn find_mut(&mut self, id: &str) -> Option<&mut Slot> {
        self.slots.iter_mut().find(|s| s.id == id)
    }

    pub fn active(&self) -> Option<&Slot> {
        self.active_slot_id.as_deref().and_then(|id| self.find(id))
    }

    pub fn compare(&self) -> Option<&Slot> {
        self.compare_slot_id.as_deref().and_then(|id| self.find(id))
    }

    /// Add or refocus a slot (idempotent on sha256). Returns the slot id.
    pub fn upsert(&mut self, slot: Slot) -> String {
        if let Some(existing) = self.slots.iter().position(|s| s.sha256 == slot.sha256) {
            // Replace heavy data, keep id stable.
            let id = self.slots[existing].id.clone();
            let mut s = slot;
            s.id = id.clone();
            self.slots[existing] = s;
            id
        } else {
            let id = slot.id.clone();
            self.slots.push(slot);
            id
        }
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.slots.len();
        self.slots.retain(|s| s.id != id);
        let removed = self.slots.len() != before;
        if removed {
            if self.active_slot_id.as_deref() == Some(id) {
                self.active_slot_id = self.slots.first().map(|s| s.id.clone());
            }
            if self.compare_slot_id.as_deref() == Some(id) {
                self.compare_slot_id = None;
            }
        }
        removed
    }

    pub fn set_active(&mut self, id: &str) -> bool {
        if self.find(id).is_some() {
            self.active_slot_id = Some(id.to_string());
            true
        } else {
            false
        }
    }

    pub fn set_compare(&mut self, id: Option<&str>) -> bool {
        match id {
            None => { self.compare_slot_id = None; true }
            Some(id) => {
                if self.find(id).is_some() {
                    self.compare_slot_id = Some(id.to_string());
                    true
                } else { false }
            }
        }
    }

    // ── Persistence ────────────────────────────────────────────────────────

    fn project_json(cache_dir: &Path) -> PathBuf { cache_dir.join("project.json") }

    pub fn save(&self, cache_dir: &Path) -> std::io::Result<()> {
        let persist = ProjectPersist {
            slots: self.slots.iter().map(|s| s.to_persist()).collect(),
            active_slot_id: self.active_slot_id.clone(),
            compare_slot_id: self.compare_slot_id.clone(),
        };
        let json = serde_json::to_string_pretty(&persist)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(Self::project_json(cache_dir), json)?;
        Ok(())
    }

    /// Try to restore the project from `<cache>/project.json`. Slots whose
    /// underlying files are missing are silently dropped.
    pub fn load(cache_dir: &Path) -> Self {
        let path = Self::project_json(cache_dir);
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => return Self::new(),
        };
        let persist: ProjectPersist = match serde_json::from_str(&raw) {
            Ok(p) => p,
            Err(_) => return Self::new(),
        };

        let mut project = Project::new();
        for sp in persist.slots {
            // Skip slots whose base file no longer exists on disk.
            if !Path::new(&sp.base_path).exists() {
                continue;
            }
            // Drop missing splits silently — user can re-add.
            let live_splits: Vec<String> = sp.split_paths.iter()
                .filter(|p| Path::new(p).exists())
                .cloned()
                .collect();
            match load_slot_from_disk(
                &sp.id,
                &sp.display_name,
                &sp.base_path,
                &live_splits,
                sp.parent_id.clone(),
                sp.is_cached,
            ) {
                Ok(mut slot) => {
                    // Restore the persisted deobf marks. The loader
                    // returns a fresh slot with an empty set; we layer
                    // the persisted set on top here so the ergonomic
                    // create-path doesn't need a "previous marks"
                    // parameter that's None in 99% of calls.
                    slot.deobf_marks = sp.deobf_marks.into_iter().collect();
                    project.slots.push(slot);
                }
                Err(_)   => continue,
            }
        }
        // Restore active id if it still exists.
        if let Some(id) = persist.active_slot_id {
            if project.find(&id).is_some() {
                project.active_slot_id = Some(id);
            } else {
                project.active_slot_id = project.slots.first().map(|s| s.id.clone());
            }
        } else {
            project.active_slot_id = project.slots.first().map(|s| s.id.clone());
        }
        if let Some(id) = persist.compare_slot_id {
            if project.find(&id).is_some() {
                project.compare_slot_id = Some(id);
            }
        }
        project
    }
}

// ── Loader helpers ───────────────────────────────────────────────────────────

/// SHA-256 of a file, hex-encoded.
pub fn file_sha256(path: &Path) -> std::io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// SHA-256 of bytes, hex-encoded.
pub fn bytes_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Build a fresh `Slot` by reading `base_path` (and any `split_paths`) from disk.
///
/// `id_override` lets the caller pin the slot id (used when reusing an existing
/// id during force-reload). Pass `None` to derive id from the base sha256.
#[allow(clippy::too_many_arguments)]
pub fn load_slot_from_disk(
    id_override: &str,
    display_name_hint: &str,
    base_path: &str,
    split_paths: &[String],
    parent_id: Option<String>,
    is_cached: bool,
) -> Result<Slot, String> {
    let p = Path::new(base_path);
    if !p.exists() {
        return Err(format!("File not found: {}", base_path));
    }

    let sha256 = file_sha256(p).map_err(|e| e.to_string())?;
    let id = if id_override.is_empty() { sha256.clone() } else { id_override.to_string() };

    // Decide whether to treat as a single APK or a split bundle.
    let has_splits = !split_paths.is_empty();
    let (dex_files, resources, manifest_xml, entry_names, declared_splits) =
        if has_splits || p.is_dir() {
            load_split_bundle(base_path, split_paths)?
        } else {
            load_single_apk(base_path)?
        };

    // Best-effort metadata from the manifest.
    let (package_name, version_name, version_code) = manifest_xml
        .as_deref()
        .map(extract_manifest_meta)
        .unwrap_or((None, None, None));

    let display_name = if !display_name_hint.is_empty() {
        display_name_hint.to_string()
    } else {
        package_name.clone()
            .unwrap_or_else(|| Path::new(base_path).file_name()
                .and_then(|s| s.to_str()).unwrap_or("apk").to_string())
    };

    // Auto-detect embedded APKs/ZIPs-with-DEX in assets/resources.
    // Best-effort: if the scan errors on a single entry it's just skipped.
    let embedded_candidates = scan_embedded(base_path, split_paths);

    Ok(Slot {
        id,
        display_name,
        base_path: base_path.to_string(),
        split_paths: split_paths.to_vec(),
        sha256,
        package_name,
        version_name,
        version_code,
        declared_splits,
        parent_id,
        is_cached,
        dex_files,
        resources,
        manifest_xml,
        entry_names,
        embedded_candidates,
        // New slots start with no deobf marks; Project::load reseeds
        // this from SlotPersist below so reopening an APK restores
        // whatever the user marked previously.
        deobf_marks: std::collections::BTreeSet::new(),
    })
}

type LoadOk = (
    Vec<DexFileWithRaw>,            // dex files
    Option<ResourceTable>,           // resources
    Option<String>,                  // manifest XML (resolved if possible)
    Vec<(String, String)>,           // (split_name, entry_name)
    Vec<String>,                     // declared splits from <uses-split>
);

fn load_single_apk(path: &str) -> Result<LoadOk, String> {
    let p = Path::new(path);
    let lower = path.to_lowercase();
    let archive_ext = lower.ends_with(".apk") || lower.ends_with(".aab")
        || lower.ends_with(".aar") || lower.ends_with(".jar")
        || lower.ends_with(".xapk") || lower.ends_with(".apkm");

    // Sniff the first bytes so we route by *content*, not extension — embedded
    // droppers frequently name a bare DEX as `.jar`/`.bin`/no extension.
    let mut magic = [0u8; 4];
    let read_ok = {
        use std::io::Read;
        fs::File::open(p).and_then(|mut f| f.read(&mut magic)).map(|n| n >= 4).unwrap_or(false)
    };
    let is_dex = read_ok && &magic == b"dex\n";
    let is_zip = read_ok && &magic[..2] == b"PK";

    // Standalone DEX (by magic, or a non-archive extension that isn't a ZIP) —
    // no manifest, no splits, no entry list.
    if is_dex || (!archive_ext && !is_zip) {
        let bytes = fs::read(p).map_err(|e| e.to_string())?;
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or(path).to_string();
        let dex = DexFileWithRaw::from_bytes(bytes, name).map_err(|e| e.to_string())?;
        return Ok((vec![dex], None, None, vec![], vec![]));
    }

    let apk = ApkZip::open(path).map_err(|e| e.to_string())?;
    let entry_list: Vec<(String, String)> = apk.list_entries().into_iter()
        .map(|n| (String::new(), n))
        .collect();

    let resources = apk.read_entry("resources.arsc").ok()
        .and_then(|d| arsc::parse(&d).ok());

    let manifest_xml = apk.read_entry("AndroidManifest.xml").ok()
        .and_then(|d| if let Some(ref r) = resources {
            axml::parse_with_resources(&d, r).ok()
        } else {
            axml::parse(&d).ok()
        })
        .map(|root| root.to_xml_string());

    let declared_splits = manifest_xml
        .as_deref()
        .map(extract_uses_splits)
        .unwrap_or_default();

    let dex_files: Vec<DexFileWithRaw> = apk.dex_files().into_iter()
        .filter_map(|(name, bytes)| DexFileWithRaw::from_bytes(bytes, name).ok())
        .collect();

    Ok((dex_files, resources, manifest_xml, entry_list, declared_splits))
}

fn load_split_bundle(base: &str, splits: &[String]) -> Result<LoadOk, String> {
    // Build the path list for SplitApk: base first, then every loaded split.
    let p = Path::new(base);
    let split_apk = if p.is_dir() && splits.is_empty() {
        SplitApk::from_dir(base).map_err(|e| e.to_string())?
    } else {
        let mut all: Vec<String> = vec![base.to_string()];
        all.extend(splits.iter().cloned());
        let refs: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        SplitApk::from_files(&refs).map_err(|e| e.to_string())?
    };

    let entry_list: Vec<(String, String)> = split_apk.list_all_files();
    let resources = split_apk.resources().ok();
    let manifest_xml = split_apk
        .manifest_resolved()
        .or_else(|_| split_apk.manifest())
        .ok()
        .map(|r| r.to_xml_string());

    let declared_splits = manifest_xml
        .as_deref()
        .map(extract_uses_splits)
        .unwrap_or_default();

    let dex_files: Vec<DexFileWithRaw> = split_apk.dex_files().into_iter()
        .filter_map(|(name, bytes)| DexFileWithRaw::from_bytes(bytes, name).ok())
        .collect();

    Ok((dex_files, resources, manifest_xml, entry_list, declared_splits))
}

/// Extract `(package_name, version_name, version_code)` from manifest XML.
fn extract_manifest_meta(xml: &str) -> (Option<String>, Option<String>, Option<i64>) {
    let pkg = first_attr(xml, "package");
    let vname = first_attr(xml, "android:versionName");
    let vcode = first_attr(xml, "android:versionCode")
        .and_then(|s| s.parse::<i64>().ok());
    (pkg, vname, vcode)
}

/// Extract `<uses-split android:name="..." />` declarations.
fn extract_uses_splits(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(start) = xml[cursor..].find("<uses-split") {
        let abs = cursor + start;
        let end = match xml[abs..].find('>') {
            Some(e) => abs + e,
            None => break,
        };
        if let Some(name) = first_attr(&xml[abs..=end], "android:name") {
            out.push(name);
        }
        cursor = end + 1;
    }
    out
}

/// Crude attribute extractor — finds the first `name="value"` occurrence.
/// Good enough for the well-formed XML we re-emit from the parsed manifest.
fn first_attr(xml: &str, name: &str) -> Option<String> {
    let needle = format!(" {}=\"", name);
    let start = xml.find(&needle)? + needle.len();
    let end = xml[start..].find('"')? + start;
    Some(xml[start..end].to_string())
}

// ── Cache ────────────────────────────────────────────────────────────────────

/// Copy `bytes` into the cache directory under a sha256-derived filename and
/// return the absolute path. Used when persisting decrypted/extracted APKs.
pub fn cache_bytes(cache_dir: &Path, bytes: &[u8], suggested_name: &str) -> std::io::Result<PathBuf> {
    let sha = bytes_sha256(bytes);
    let mut name = String::new();
    // Keep the original extension if any so the file is recognisable on disk.
    let ext = Path::new(suggested_name)
        .extension().and_then(|e| e.to_str()).unwrap_or("apk");
    name.push_str(&sha[..16]);
    name.push('.');
    name.push_str(ext);
    let target = cache_dir.join("extracted").join(name);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    if !target.exists() {
        let mut f = fs::File::create(&target)?;
        f.write_all(bytes)?;
    }
    Ok(target)
}

/// Wipe all files inside `<cache>/extracted/` (decrypted child APKs).
/// Project metadata in `project.json` is left intact, but child slots
/// pointing into the cache become invalid and should be removed in the same
/// transaction by the caller.
pub fn wipe_extracted(cache_dir: &Path) -> std::io::Result<()> {
    let dir = cache_dir.join("extracted");
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

// ── Embedded-APK scan ────────────────────────────────────────────────────────

/// Walk every ZIP entry in the slot's base APK + every loaded split looking for
/// embedded ZIPs that contain at least one `classes*.dex`. Returns the list of
/// candidates (may be empty). Errors on individual entries are silently skipped.
fn scan_embedded(base_path: &str, split_paths: &[String]) -> Vec<EmbeddedCandidate> {
    let mut out = Vec::new();
    let p = Path::new(base_path);
    if p.is_dir() {
        // Directory of splits: nothing single-file-ish to scan at the directory level.
        return out;
    }
    let lower = base_path.to_lowercase();
    let is_zip = lower.ends_with(".apk") || lower.ends_with(".aab")
        || lower.ends_with(".aar") || lower.ends_with(".jar")
        || lower.ends_with(".xapk") || lower.ends_with(".apkm");
    if !is_zip {
        return out;
    }

    // Helper closure: scan one APK file, tagging hits with its split name.
    let scan_one = |path: &str, split_name: &str, sink: &mut Vec<EmbeddedCandidate>| {
        let zip = match ApkZip::open(path) {
            Ok(z)  => z,
            Err(_) => return,
        };
        for entry in zip.list_entries() {
            // Trivially skip the things we KNOW aren't embedded payloads.
            if is_native_apk_member(&entry) { continue; }

            let bytes = match zip.read_entry(&entry) {
                Ok(b)  => b,
                Err(_) => continue,
            };
            if bytes.len() < 8 { continue; }

            // ── Bare DEX (e.g. assets/payload.dex, or a dropper DEX named to
            //    look like something else). Detected by magic, not extension. ──
            if &bytes[..4] == b"dex\n" {
                sink.push(EmbeddedCandidate {
                    entry_path: entry.clone(),
                    split_name: split_name.to_string(),
                    size: bytes.len() as u64,
                    sha256: bytes_sha256(&bytes),
                    has_manifest: false,
                    dex_count: 1,
                    suggested_name: Path::new(&entry).file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("embedded.dex")
                        .to_string(),
                });
                continue;
            }

            // ── ZIP-with-classes.dex (apk / jar / aab). EOCD is ≥ 22 bytes. ──
            if bytes.len() < 22 || &bytes[..2] != b"PK" { continue; }

            // Try to parse as ZIP. ApkZip::from_bytes accepts a Vec<u8>.
            let inner = match ApkZip::from_bytes(bytes.clone()) {
                Ok(z)  => z,
                Err(_) => continue,
            };
            let inner_entries = inner.list_entries();
            let dex_count = inner_entries.iter()
                .filter(|n| {
                    let lc = n.to_lowercase();
                    lc.starts_with("classes") && lc.ends_with(".dex")
                })
                .count();
            if dex_count == 0 { continue; }

            let has_manifest = inner_entries.iter()
                .any(|n| n.eq_ignore_ascii_case("AndroidManifest.xml"));

            sink.push(EmbeddedCandidate {
                entry_path: entry.clone(),
                split_name: split_name.to_string(),
                size: bytes.len() as u64,
                sha256: bytes_sha256(&bytes),
                has_manifest,
                dex_count,
                suggested_name: Path::new(&entry).file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("embedded.apk")
                    .to_string(),
            });
        }
    };

    scan_one(base_path, "", &mut out);
    for split in split_paths {
        let split_name = Path::new(split).file_name()
            .and_then(|s| s.to_str()).unwrap_or("").to_string();
        scan_one(split, &split_name, &mut out);
    }
    out
}

/// Skip entries that obviously aren't embedded APKs to keep the scan cheap.
/// We don't try to be exhaustive — if something slips through, the bytes-check
/// in `scan_embedded` filters it out.
fn is_native_apk_member(name: &str) -> bool {
    let lc = name.to_lowercase();
    lc == "androidmanifest.xml"
        || lc == "resources.arsc"
        || lc.starts_with("meta-inf/")
        || (lc.starts_with("classes") && lc.ends_with(".dex"))
        || lc.starts_with("res/drawable")
        || lc.starts_with("res/mipmap")
        || lc.starts_with("res/layout")
        || lc.starts_with("res/anim")
        || lc.starts_with("res/color")
        || lc.starts_with("lib/") && lc.ends_with(".so")
}

/// Read an embedded entry from `parent_slot`, write it to the cache, and
/// return the cache path. Used by the `project_load_embedded` command.
pub fn extract_embedded_to_cache(
    parent_slot: &Slot,
    entry_path: &str,
    cache_dir: &Path,
) -> Result<PathBuf, String> {
    // The entry might live in any of the parent's APK files (base or splits).
    // Locate the right one by checking each in turn.
    let mut tried_paths: Vec<&str> = vec![&parent_slot.base_path];
    for sp in &parent_slot.split_paths { tried_paths.push(sp); }

    let mut bytes_opt: Option<Vec<u8>> = None;
    for path in tried_paths {
        if let Ok(zip) = ApkZip::open(path) {
            if let Ok(b) = zip.read_entry(entry_path) {
                bytes_opt = Some(b);
                break;
            }
        }
    }
    let bytes = bytes_opt.ok_or_else(||
        format!("Entry '{}' not found in slot '{}'", entry_path, parent_slot.id)
    )?;

    let suggested = Path::new(entry_path).file_name()
        .and_then(|s| s.to_str()).unwrap_or("embedded.apk");
    cache_bytes(cache_dir, &bytes, suggested).map_err(|e| e.to_string())
}

/// Write arbitrary bytes (e.g. produced by a deobfuscation method run) into
/// the cache as a candidate APK. Validates that the bytes parse as a ZIP
/// containing at least one `classes*.dex` before returning the path.
pub fn cache_bytes_as_apk(
    bytes: &[u8],
    suggested_name: &str,
    cache_dir: &Path,
) -> Result<PathBuf, String> {
    if bytes.len() < 22 || &bytes[..2] != b"PK" {
        return Err("Bytes are not a ZIP archive (no PK header)".into());
    }
    let inner = ApkZip::from_bytes(bytes.to_vec())
        .map_err(|e| format!("Bytes don't parse as ZIP: {}", e))?;
    let dex_present = inner.list_entries().iter().any(|n| {
        let lc = n.to_lowercase();
        lc.starts_with("classes") && lc.ends_with(".dex")
    });
    if !dex_present {
        return Err("ZIP contains no classes*.dex member".into());
    }
    cache_bytes(cache_dir, bytes, suggested_name).map_err(|e| e.to_string())
}
