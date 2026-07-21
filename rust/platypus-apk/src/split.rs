/// Split APK support.
///
/// A split APK set consists of a base APK and zero or more configuration/feature
/// splits. This module aggregates them for DEX loading, resource access, and
/// manifest parsing.

use std::path::Path;
use super::{ApkError, zip::ApkZip, arsc::ResourceTable, axml::XmlNode};

pub struct SplitApk {
    /// All APKs in the split set. The base APK is **always** at index 0.
    splits: Vec<(String, ApkZip)>,  // (split_name, apk)
}

// ── Base-APK detection ────────────────────────────────────────────────────────

/// Score an APK for likelihood of being the base split.
/// Higher is more likely. Bits (from most to least significant):
///   bit 2 — has resources.arsc  (definitive)
///   bit 1 — manifest has no `split` attribute
///   bit 0 — filename is "base.apk"
fn base_score(name: &str, apk: &ApkZip) -> u8 {
    let mut score = 0u8;

    // Bit 2 — definitive: only the base APK ships resources.arsc.
    if apk.has_entry("resources.arsc") {
        score |= 0b100;
    }

    // Bit 1 — the base manifest has no `split` attribute.
    // Config/feature splits have e.g. `split="config.arm64_v8a"`.
    if let Ok(data) = apk.read_entry("AndroidManifest.xml") {
        if let Ok(root) = super::axml::parse(&data) {
            // No `split` attribute → this is the base.
            if root.attr("split").map(|v| v.is_empty()).unwrap_or(true) {
                score |= 0b010;
            }
        }
    }

    // Bit 0 — conventional filename.
    if name == "base.apk" {
        score |= 0b001;
    }

    score
}

/// Return the index of the most likely base APK in `splits`.
fn detect_base(splits: &[(String, ApkZip)]) -> usize {
    splits
        .iter()
        .enumerate()
        .max_by_key(|(_, (name, apk))| base_score(name, apk))
        .map(|(i, _)| i)
        .unwrap_or(0)
}

impl SplitApk {
    /// Load all APK files from a directory and auto-detect which one is the
    /// base APK, regardless of filename.
    ///
    /// Detection order (first match wins):
    /// 1. Contains `resources.arsc`           — definitive: only the base has it
    /// 2. Manifest has no `split` attribute    — base manifests omit this attribute
    /// 3. Filename is exactly `base.apk`       — conventional name
    /// 4. Alphabetically first                 — last resort
    pub fn from_dir(dir: &str) -> Result<Self, ApkError> {
        let entries = std::fs::read_dir(dir)?;
        let mut paths: Vec<std::path::PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("apk"))
            .collect();
        paths.sort(); // stable alphabetical order as the fallback

        let paths_str: Vec<&str> = paths.iter()
            .filter_map(|p| p.to_str())
            .collect();
        Self::from_files(&paths_str)
    }

    /// Load from an explicit list of APK file paths, auto-detecting the base APK.
    ///
    /// If the caller already knows which file is the base, place it first in
    /// the slice and it will be preserved in position 0 (it will still score
    /// highest in the detection and remain first).
    pub fn from_files(paths: &[&str]) -> Result<Self, ApkError> {
        if paths.is_empty() {
            return Err(ApkError::Parse("no APK files provided".into()));
        }
        let mut splits: Vec<(String, ApkZip)> = Vec::new();
        for path in paths {
            let name = Path::new(path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(path)
                .to_string();
            let apk = ApkZip::open(path)?;
            splits.push((name, apk));
        }
        let base_idx = detect_base(&splits);
        if base_idx != 0 {
            splits.swap(0, base_idx);
        }
        Ok(SplitApk { splits })
    }

    /// Load from bytes: list of `(filename, bytes)` pairs, auto-detecting the base APK.
    pub fn from_bytes_list(list: Vec<(String, Vec<u8>)>) -> Result<Self, ApkError> {
        if list.is_empty() {
            return Err(ApkError::Parse("no APK data provided".into()));
        }
        let mut splits = Vec::new();
        for (name, data) in list {
            let apk = ApkZip::from_bytes(data)?;
            splits.push((name, apk));
        }
        let base_idx = detect_base(&splits);
        if base_idx != 0 {
            splits.swap(0, base_idx);
        }
        Ok(SplitApk { splits })
    }

    /// The base APK (first in the list).
    fn base(&self) -> &ApkZip {
        &self.splits[0].1
    }

    /// Aggregate all DEX files from all splits.
    /// Returns `(filename, bytes)` pairs — base DEX first, then splits.
    /// Config-split DEX names are prefixed with their split filename to avoid
    /// collisions (e.g. `"config.arm64_v8a.apk!classes.dex"`).
    pub fn dex_files(&self) -> Vec<(String, Vec<u8>)> {
        let mut result = Vec::new();
        for (idx, (split_name, apk)) in self.splits.iter().enumerate() {
            for (dex_name, bytes) in apk.dex_files() {
                // Index 0 is always the base — no prefix needed.
                let full_name = if idx == 0 || self.splits.len() == 1 {
                    dex_name
                } else {
                    format!("{}!{}", split_name, dex_name)
                };
                result.push((full_name, bytes));
            }
        }
        result
    }

    /// Parse AndroidManifest.xml from the base APK.
    pub fn manifest(&self) -> Result<XmlNode, ApkError> {
        let data = self.base().read_entry("AndroidManifest.xml")?;
        super::axml::parse(&data)
    }

    /// Parse and resolve AndroidManifest.xml using resources from the base APK.
    pub fn manifest_resolved(&self) -> Result<XmlNode, ApkError> {
        let manifest_data = self.base().read_entry("AndroidManifest.xml")?;
        let resources_data = self.base().read_entry("resources.arsc")?;
        let resources = super::arsc::parse(&resources_data)?;
        super::axml::parse_with_resources(&manifest_data, &resources)
    }

    /// Parse resources.arsc from the base APK.
    pub fn resources(&self) -> Result<ResourceTable, ApkError> {
        let data = self.base().read_entry("resources.arsc")?;
        super::arsc::parse(&data)
    }

    /// List all files across all splits as (split_name, entry_name) pairs.
    pub fn list_all_files(&self) -> Vec<(String, String)> {
        let mut result = Vec::new();
        for (split_name, apk) in &self.splits {
            for entry in apk.list_entries() {
                result.push((split_name.clone(), entry));
            }
        }
        result
    }

    /// List files from all splits matching a prefix (e.g. "res/layout").
    pub fn list_files_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        self.list_all_files()
            .into_iter()
            .filter(|(_, name)| name.starts_with(prefix))
            .collect()
    }

    /// Read a named file — tries the base APK first, then other splits.
    pub fn read_file(&self, name: &str) -> Result<Vec<u8>, ApkError> {
        for (_, apk) in &self.splits {
            if apk.has_entry(name) {
                return apk.read_entry(name);
            }
        }
        Err(ApkError::NotFound(name.to_string()))
    }

    /// Check if a file exists in any split.
    pub fn has_file(&self, name: &str) -> bool {
        self.splits.iter().any(|(_, apk)| apk.has_entry(name))
    }

    /// Package name from the base manifest.
    pub fn package_name(&self) -> Option<String> {
        let data = self.base().read_entry("AndroidManifest.xml").ok()?;
        let root = super::axml::parse(&data).ok()?;
        root.attr("package").map(|s| s.to_string())
    }

    /// Version name from the base manifest.
    pub fn version_name(&self) -> Option<String> {
        let data = self.base().read_entry("AndroidManifest.xml").ok()?;
        let root = super::axml::parse(&data).ok()?;
        root.attr("android:versionName").map(|s| s.to_string())
    }

    /// All drawable paths across all splits.
    pub fn drawables(&self) -> Vec<(String, String)> {
        self.list_files_with_prefix("res/drawable")
    }

    /// All layout paths across all splits.
    pub fn layouts(&self) -> Vec<(String, String)> {
        self.list_files_with_prefix("res/layout")
    }

    /// Number of APK splits.
    pub fn split_count(&self) -> usize {
        self.splits.len()
    }

    /// Names of all splits.
    pub fn split_names(&self) -> Vec<String> {
        self.splits.iter().map(|(n, _)| n.clone()).collect()
    }
}
