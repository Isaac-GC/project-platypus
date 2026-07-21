//! Deobfuscation mapping loader + lookup API.
//!
//! Reads mapping files produced by the `dexmapper` Python tool — both
//! flavours: the JSON form (richer; includes confidence + match type) and
//! the ProGuard text form (smaller; what's commonly bundled with apps).
//!
//! ```no_run
//! use platypus_dexmapper::Deobfuscator;
//! let deob = Deobfuscator::load_json("mapping.json").unwrap();
//! assert_eq!(deob.real_class("p.q.a").map(str::to_string),
//!            Some("okhttp3.OkHttpClient".to_string()));
//! ```
//!
//! The library is consumed by:
//!   - the `platypus-dexmapper` CLI (this crate, `src/bin/cli.rs`)
//!   - both viewer shells' Tauri commands (`standalone-viewer`, `ui-react`)
//!     — they hold a `Deobfuscator` in app state and call
//!     `apply_to_activity_view` after rehydration so the frontend
//!     receives real names without any client-side knowledge of the
//!     mapping schema.

pub mod format;
pub mod refs;
pub mod descriptors;
/// Only compiled when the `rehydrate` feature is on. Provides
/// `Deobfuscator::apply_to_activity_view`, which mutates a
/// `platypus_rehydrate::ir::ActivityView` in place. The standalone build
/// of this crate omits this module entirely — no transitive dep on
/// `platypus-rehydrate`.
#[cfg(feature = "rehydrate")]
pub mod apply;

// ── Producer pipeline ──────────────────────────────────────────────────────
// Everything below is gated behind the `producer` feature. It mirrors the
// Python dexmapper's index-and-match pipeline: JVM .class parser, SQLite
// index, smali/java source parsers, Maven downloader+POM resolver,
// multi-tier matcher, indexer orchestrator, and in-place patcher.
#[cfg(feature = "producer")] pub mod bytecode;
/// Lambda detection + call-signature hashing. Kotlin / Compose lambdas
/// are everywhere in modern Android binaries (every `{ ... }` block in
/// a Compose `setContent` ends up as a synthetic class), and they
/// preserve enough shape under R8 that we can match them across binaries
/// even when names are gone. See `lambda::classify_lambda`.
#[cfg(feature = "producer")] pub mod lambda;
/// DEX bridge — uses [`platypus_dex`] + [`platypus_apk`] so the producer
/// pipeline can index from `.dex` files and `.apk` bundles (not just
/// JAR/AAR), and so the matcher can analyse obfuscated DEX classes
/// directly without going through baksmali / jadx first.
#[cfg(feature = "producer")] pub mod bytecode_dex;
#[cfg(feature = "producer")] pub mod db;
#[cfg(feature = "producer")] pub mod sources;
#[cfg(feature = "producer")] pub mod analysis;
#[cfg(feature = "producer")] pub mod matching;
#[cfg(feature = "producer")] pub mod patching;

pub use format::{Mapping, MappingFile, MethodEntry, FieldEntry, MappingFormat};
pub use refs::{JvmRef, parse_method_ref};

use std::collections::HashMap;
use std::path::Path;

/// Lookup-ready deobfuscator built from a `MappingFile`. Cheap to clone —
/// not. Cheap to share via `Arc` / a Tauri `State` — yes.
#[derive(Debug, Default)]
pub struct Deobfuscator {
    /// Path the mapping was loaded from. Surfaced in `info()`.
    source_path: Option<String>,
    /// Detected source format (proguard vs. json).
    source_format: Option<MappingFormat>,
    /// Obfuscated dotted class FQN → entry.
    by_class: HashMap<String, Mapping>,
}

/// Public summary of the loaded mapping. Returned to the frontend via the
/// Tauri command so users can confirm what's loaded.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MappingInfo {
    pub path: Option<String>,
    pub format: Option<String>,
    pub class_count: usize,
    pub method_count: usize,
    pub field_count: usize,
}

impl Deobfuscator {
    pub fn new() -> Self { Self::default() }

    /// Load from a mapping file. Format is auto-detected by extension and
    /// content sniff: `.json` / starts with `{` → JSON; else ProGuard text.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|e| format!("mapping file is not UTF-8: {e}"))?;
        let file = MappingFile::parse_auto(text)
            .map_err(|e| format!("parse mapping {}: {e}", path.display()))?;
        let mut d = Self::from_file(file);
        d.source_path = Some(path.to_string_lossy().into_owned());
        Ok(d)
    }

    /// Convenience: load a JSON mapping file.
    pub fn load_json<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        let file = MappingFile::parse_json(&text)
            .map_err(|e| format!("parse json mapping: {e}"))?;
        let mut d = Self::from_file(file);
        d.source_path = Some(path.to_string_lossy().into_owned());
        Ok(d)
    }

    /// Convenience: load a ProGuard mapping file.
    pub fn load_proguard<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        let file = MappingFile::parse_proguard(&text)
            .map_err(|e| format!("parse proguard mapping: {e}"))?;
        let mut d = Self::from_file(file);
        d.source_path = Some(path.to_string_lossy().into_owned());
        Ok(d)
    }

    /// Build from an already-parsed `MappingFile`. Indexes by dotted class
    /// name for O(1) lookup; later entries with the same obfuscated class
    /// overwrite earlier ones (last-write-wins matches the dexmapper CLI's
    /// behaviour when batches are concatenated).
    pub fn from_file(file: MappingFile) -> Self {
        let mut by_class = HashMap::with_capacity(file.mappings.len());
        let format = Some(file.format);
        for m in file.mappings {
            by_class.insert(normalize_class(&m.obfuscated_class), m);
        }
        Self { source_path: None, source_format: format, by_class }
    }

    pub fn info(&self) -> MappingInfo {
        let mut methods = 0;
        let mut fields = 0;
        for m in self.by_class.values() {
            methods += m.methods.len();
            fields += m.fields.len();
        }
        MappingInfo {
            path: self.source_path.clone(),
            format: self.source_format.map(|f| f.as_str().to_string()),
            class_count: self.by_class.len(),
            method_count: methods,
            field_count: fields,
        }
    }

    pub fn is_empty(&self) -> bool { self.by_class.is_empty() }

    // ── Class / method / field lookups ─────────────────────────────────────

    /// Real (dotted) class name for an obfuscated class. Accepts both
    /// dotted (`p.q.a`) and JVM-internal (`Lp/q/a;`) inputs. Returns
    /// `None` if no mapping was found.
    pub fn real_class(&self, obf: &str) -> Option<&str> {
        let key = normalize_class(obf);
        self.by_class.get(&key).map(|m| m.real_class.as_str())
    }

    /// Real method name within a class. Pass the obfuscated class name
    /// and the obfuscated method name; the descriptor is optional but
    /// disambiguates overloads (R8 happily produces `a(I)V` and
    /// `a(Ljava/lang/String;)V` both renamed to `a`).
    pub fn real_method(&self, obf_class: &str, obf_method: &str, obf_desc: Option<&str>) -> Option<&str> {
        let m = self.by_class.get(&normalize_class(obf_class))?;
        method_lookup(&m.methods, obf_method, obf_desc).map(|e| e.real_name.as_str())
    }

    pub fn real_field(&self, obf_class: &str, obf_field: &str, obf_desc: Option<&str>) -> Option<&str> {
        let m = self.by_class.get(&normalize_class(obf_class))?;
        field_lookup(&m.fields, obf_field, obf_desc).map(|e| e.real_name.as_str())
    }

    /// Translate a dotted FQN, applying inner-class suffixes after the
    /// outermost match. `p.q.a$Builder` → `okhttp3.OkHttpClient$Builder`
    /// when `p.q.a` is mapped to `okhttp3.OkHttpClient` and `p.q.a$Builder`
    /// has no direct mapping of its own.
    pub fn translate_class(&self, name: &str) -> String {
        let dotted = jvm_to_dotted(name);
        // Direct hit?
        if let Some(real) = self.real_class(&dotted) { return real.to_string(); }
        // Inner-class fallback.
        if let Some((outer, inner_tail)) = split_outer_inner(&dotted) {
            if let Some(real_outer) = self.real_class(outer) {
                return format!("{real_outer}{inner_tail}");
            }
        }
        // Pass through unchanged when we have no idea.
        dotted
    }

    /// Translate a JVM method ref like `Lcom/foo/Bar;->a(I)V`. Falls
    /// through to the input string when any piece can't be resolved.
    pub fn translate_method_ref(&self, raw: &str) -> String {
        match parse_method_ref(raw) {
            None => raw.to_string(),
            Some(JvmRef { class, method, desc }) => {
                let real_class = self.translate_class(&class);
                let real_method = self.real_method(&class, &method, Some(&desc))
                    .map(str::to_string)
                    .unwrap_or(method);
                format!("L{};->{}{}", real_class.replace('.', "/"), real_method, desc)
            }
        }
    }

    /// Convenience: apply the mapping to a freshly-rehydrated
    /// `ActivityView` in-place, replacing every obfuscated class/method
    /// reference we recognise. Used by the viewer Tauri commands.
    ///
    /// Only compiled with the `rehydrate` feature — the standalone build
    /// of the crate omits this method along with the `platypus-rehydrate`
    /// dep.
    #[cfg(feature = "rehydrate")]
    pub fn apply_to_activity_view(&self, view: &mut platypus_rehydrate::ir::ActivityView) {
        apply::activity_view(self, view);
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn method_lookup<'a>(entries: &'a [MethodEntry], name: &str, desc: Option<&str>) -> Option<&'a MethodEntry> {
    // Prefer exact (name, desc) match; fall back to first name-only match
    // when no descriptor is supplied or the descriptor doesn't appear in
    // the mapping. The dexmapper output normally always has descriptors
    // but ProGuard files sometimes omit them.
    if let Some(d) = desc {
        if let Some(hit) = entries.iter().find(|e| e.obfuscated_name == name && e.obfuscated_descriptor.as_deref() == Some(d)) {
            return Some(hit);
        }
    }
    entries.iter().find(|e| e.obfuscated_name == name)
}

fn field_lookup<'a>(entries: &'a [FieldEntry], name: &str, desc: Option<&str>) -> Option<&'a FieldEntry> {
    if let Some(d) = desc {
        if let Some(hit) = entries.iter().find(|e| e.obfuscated_name == name && e.obfuscated_descriptor.as_deref() == Some(d)) {
            return Some(hit);
        }
    }
    entries.iter().find(|e| e.obfuscated_name == name)
}

/// Strip a JVM internal class wrapper (`Lcom/foo/Bar;` → `com.foo.Bar`)
/// and dot-normalise slashes. Idempotent on already-dotted input.
pub fn normalize_class(s: &str) -> String { jvm_to_dotted(s) }

pub fn jvm_to_dotted(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.starts_with('L') && trimmed.ends_with(';') {
        trimmed[1..trimmed.len() - 1].replace('/', ".")
    } else {
        trimmed.replace('/', ".")
    }
}

pub fn dotted_to_jvm(s: &str) -> String {
    if s.starts_with('L') && s.ends_with(';') { return s.to_string(); }
    format!("L{};", s.replace('.', "/"))
}

/// `com.foo.Bar$Inner$Deeper` → `Some(("com.foo.Bar", "$Inner$Deeper"))`.
/// `com.foo.Bar` → `None`.
fn split_outer_inner(dotted: &str) -> Option<(&str, &str)> {
    dotted.find('$').map(|i| (&dotted[..i], &dotted[i..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_JSON: &str = r#"{
      "mappings": [
        {
          "obfuscated_class": "p.q.a",
          "real_class": "okhttp3.OkHttpClient",
          "confidence": 0.9,
          "match_type": "structural+methods",
          "methods": [
            {
              "obfuscated_name": "a",
              "obfuscated_descriptor": "(Lokhttp3/Request;)Lokhttp3/Call;",
              "real_name": "newCall",
              "real_descriptor": "(Lokhttp3/Request;)Lokhttp3/Call;"
            },
            {
              "obfuscated_name": "a",
              "obfuscated_descriptor": "()I",
              "real_name": "writeTimeoutMillis",
              "real_descriptor": "()I"
            }
          ],
          "fields": [
            {
              "obfuscated_name": "b",
              "obfuscated_descriptor": "Lokhttp3/Dispatcher;",
              "real_name": "dispatcher"
            }
          ]
        }
      ]
    }"#;

    fn deob() -> Deobfuscator {
        Deobfuscator::from_file(MappingFile::parse_json(SAMPLE_JSON).unwrap())
    }

    #[test]
    fn class_lookup_both_forms() {
        let d = deob();
        assert_eq!(d.real_class("p.q.a"), Some("okhttp3.OkHttpClient"));
        assert_eq!(d.real_class("Lp/q/a;"), Some("okhttp3.OkHttpClient"));
        assert_eq!(d.real_class("nope"), None);
    }

    #[test]
    fn method_overload_resolution() {
        let d = deob();
        assert_eq!(d.real_method("p.q.a", "a", Some("()I")), Some("writeTimeoutMillis"));
        assert_eq!(d.real_method("p.q.a", "a", Some("(Lokhttp3/Request;)Lokhttp3/Call;")), Some("newCall"));
        // Name-only falls back to the first match.
        assert!(d.real_method("p.q.a", "a", None).is_some());
    }

    #[test]
    fn translate_inner_class() {
        let d = deob();
        assert_eq!(d.translate_class("p.q.a$Builder"), "okhttp3.OkHttpClient$Builder");
    }

    #[test]
    fn translate_method_ref_roundtrip() {
        let d = deob();
        let out = d.translate_method_ref("Lp/q/a;->a(Lokhttp3/Request;)Lokhttp3/Call;");
        assert_eq!(out, "Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;");
    }

    #[test]
    fn field_lookup() {
        let d = deob();
        assert_eq!(d.real_field("p.q.a", "b", Some("Lokhttp3/Dispatcher;")), Some("dispatcher"));
    }

    #[test]
    fn info_counts() {
        let d = deob();
        let i = d.info();
        assert_eq!(i.class_count, 1);
        assert_eq!(i.method_count, 2);
        assert_eq!(i.field_count, 1);
    }
}

