//! In-place patcher. Given a `MappingFile` plus an `ClassMatch` (or a
//! pre-built `MappingFile`), rewrite smali / java source trees so the
//! obfuscated identifiers are replaced with their real names.
//!
//! Mirrors `dexmapper.patching.patcher` — same regexes, same fallback
//! "copy-as-is" behaviour for classes without a mapping.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::analysis::java_parser::JavaClass;
use crate::analysis::smali_parser::SmaliClass;
use crate::format::{Mapping, MappingFile};
use crate::matching::ClassMatch;

#[derive(Debug, Clone)]
pub struct MappingBuilder {
    inner: MappingFile,
}

impl Default for MappingBuilder {
    fn default() -> Self { Self::new() }
}

impl MappingBuilder {
    pub fn new() -> Self { Self { inner: MappingFile { mappings: Vec::new(), format: crate::format::MappingFormat::Json } } }

    /// Add a `ClassMatch` filtered by minimum confidence (both at the
    /// class level and per-method/per-field).
    pub fn add_class_match(&mut self, cm: &ClassMatch, min_confidence: f32) {
        if cm.confidence < min_confidence { return; }
        let methods = cm.method_matches.iter()
            .filter(|m| m.confidence >= min_confidence)
            .map(|m| crate::format::MethodEntry {
                obfuscated_name: m.obfuscated_name.clone(),
                obfuscated_descriptor: Some(m.obfuscated_descriptor.clone()),
                real_name: m.real_name.clone(),
                real_descriptor: Some(m.real_descriptor.clone()),
            }).collect();
        let fields = cm.field_matches.iter()
            .filter(|f| f.confidence >= min_confidence)
            .map(|f| crate::format::FieldEntry {
                obfuscated_name: f.obfuscated_name.clone(),
                obfuscated_descriptor: Some(f.obfuscated_descriptor.clone()),
                real_name: f.real_name.clone(),
            }).collect();
        self.inner.mappings.push(Mapping {
            obfuscated_class: cm.obfuscated_fqn.clone(),
            real_class: cm.real_fqn.clone(),
            confidence: Some(cm.confidence),
            match_type: Some(cm.match_type.clone()),
            methods, fields,
        });
    }

    pub fn build(self) -> MappingFile { self.inner }
}

// ── Smali patcher ─────────────────────────────────────────────────────────

pub struct SmaliPatcher<'a> {
    mapping: &'a MappingFile,
    /// class internal name (`com/foo/Bar`) AND dotted (`com.foo.Bar`) → real.
    class_map: HashMap<String, String>,
    /// obf_class_fqn → (obf_method_name → real_name).
    method_map: HashMap<String, HashMap<String, String>>,
    field_map: HashMap<String, HashMap<String, String>>,
    method_decl_re: Regex,
    invoke_re: Regex,
    field_decl_re: Regex,
    field_access_re: Regex,
}

impl<'a> SmaliPatcher<'a> {
    pub fn new(mapping: &'a MappingFile) -> Self {
        let mut class_map: HashMap<String, String> = HashMap::new();
        let mut method_map: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut field_map: HashMap<String, HashMap<String, String>> = HashMap::new();

        for entry in &mapping.mappings {
            let obf_internal  = entry.obfuscated_class.replace('.', "/");
            let real_internal = entry.real_class.replace('.', "/");
            class_map.insert(obf_internal, real_internal);
            class_map.insert(entry.obfuscated_class.clone(), entry.real_class.clone());

            let mm = method_map.entry(entry.obfuscated_class.clone()).or_default();
            for me in &entry.methods { mm.insert(me.obfuscated_name.clone(), me.real_name.clone()); }
            let fm = field_map.entry(entry.obfuscated_class.clone()).or_default();
            for fe in &entry.fields { fm.insert(fe.obfuscated_name.clone(), fe.real_name.clone()); }
        }
        Self {
            mapping,
            class_map, method_map, field_map,
            method_decl_re:  Regex::new(r"^(\.method\s+.+?\s+)(\S+?)(\(.*)").unwrap(),
            invoke_re:       Regex::new(r"^(\s+invoke-\S+\s+\{[^}]*\},\s*L[^;]+;->)(\w+)(\(.*)").unwrap(),
            field_decl_re:   Regex::new(r"^(\.field\s+.*?\s+)(\w+)(:.*)").unwrap(),
            field_access_re: Regex::new(r"^(\s+[isf](?:get|put)(?:-\w+)?\s+\S+,\s*\S+,\s*L[^;]+;->)(\w+)(:.*)").unwrap(),
        }
    }

    pub fn patch_text(&self, text: &str, class_fqn: &str) -> String {
        let empty: HashMap<String, String> = HashMap::new();
        let method_names = self.method_map.get(class_fqn).unwrap_or(&empty);
        let field_names  = self.field_map.get(class_fqn).unwrap_or(&empty);
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            let mut line = self.patch_class_refs(line.to_string());
            line = self.patch_method_decl(&line, method_names);
            line = self.patch_invoke(&line, method_names);
            line = self.patch_field_decl(&line, field_names);
            line = self.patch_field_access(&line, field_names);
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    fn patch_class_refs(&self, mut line: String) -> String {
        // Apply longest keys first so `com/foo/Bar$Inner` is replaced
        // before `com/foo/Bar`.
        let mut keys: Vec<&String> = self.class_map.keys().filter(|k| k.contains('/')).collect();
        keys.sort_by(|a, b| b.len().cmp(&a.len()));
        for obf in keys {
            let needle = format!("L{obf};");
            if line.contains(&needle) {
                let real = format!("L{};", self.class_map[obf]);
                line = line.replace(&needle, &real);
            }
        }
        line
    }

    fn patch_method_decl(&self, line: &str, names: &HashMap<String, String>) -> String {
        if let Some(c) = self.method_decl_re.captures(line) {
            let name = &c[2];
            if let Some(real) = names.get(name) {
                return format!("{}{}{}", &c[1], real, &c[3]);
            }
        }
        line.to_string()
    }

    fn patch_invoke(&self, line: &str, names: &HashMap<String, String>) -> String {
        if let Some(c) = self.invoke_re.captures(line) {
            let name = &c[2];
            if let Some(real) = names.get(name) {
                return format!("{}{}{}", &c[1], real, &c[3]);
            }
        }
        line.to_string()
    }

    fn patch_field_decl(&self, line: &str, names: &HashMap<String, String>) -> String {
        if let Some(c) = self.field_decl_re.captures(line) {
            let name = &c[2];
            if let Some(real) = names.get(name) {
                return format!("{}{}{}", &c[1], real, &c[3]);
            }
        }
        line.to_string()
    }

    fn patch_field_access(&self, line: &str, names: &HashMap<String, String>) -> String {
        if let Some(c) = self.field_access_re.captures(line) {
            let name = &c[2];
            if let Some(real) = names.get(name) {
                return format!("{}{}{}", &c[1], real, &c[3]);
            }
        }
        line.to_string()
    }

    /// Patch every smali file in `classes`, writing to `out_dir` while
    /// preserving the relative path under `src_dir`. Classes with no
    /// mapping are copied verbatim.
    pub fn patch_directory(&self, src_dir: &Path, out_dir: &Path, classes: &[SmaliClass])
        -> Result<PatchStats, String>
    {
        let lookup: HashMap<&str, &Mapping> = self.mapping.mappings.iter()
            .map(|m| (m.obfuscated_class.as_str(), m)).collect();
        let mut patched = 0;
        let mut skipped = 0;
        for cls in classes {
            let rel = cls.smali_path.strip_prefix(src_dir).unwrap_or(&cls.smali_path);
            let dst: PathBuf = out_dir.join(rel);
            if let Some(parent) = dst.parent() { std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?; }
            if lookup.contains_key(cls.fqn.as_str()) {
                let text = std::fs::read_to_string(&cls.smali_path).map_err(|e| format!("read: {e}"))?;
                let new_text = self.patch_text(&text, &cls.fqn);
                std::fs::write(&dst, new_text).map_err(|e| format!("write: {e}"))?;
                patched += 1;
            } else {
                std::fs::copy(&cls.smali_path, &dst).map_err(|e| format!("copy: {e}"))?;
                skipped += 1;
            }
        }
        Ok(PatchStats { patched, skipped })
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct PatchStats { pub patched: usize, pub skipped: usize }

// ── Java patcher ──────────────────────────────────────────────────────────

pub struct JavaPatcher<'a> {
    mapping: &'a MappingFile,
    class_map: HashMap<String, String>,
    method_map: HashMap<String, HashMap<String, String>>,
    field_map: HashMap<String, HashMap<String, String>>,
}

impl<'a> JavaPatcher<'a> {
    pub fn new(mapping: &'a MappingFile) -> Self {
        let mut class_map: HashMap<String, String> = HashMap::new();
        let mut method_map: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut field_map: HashMap<String, HashMap<String, String>> = HashMap::new();
        for entry in &mapping.mappings {
            let obf_simple  = entry.obfuscated_class.rsplit('.').next().unwrap_or(&entry.obfuscated_class).to_string();
            let real_simple = entry.real_class.rsplit('.').next().unwrap_or(&entry.real_class).to_string();
            class_map.insert(obf_simple, real_simple);
            class_map.insert(entry.obfuscated_class.clone(), entry.real_class.clone());
            let mm = method_map.entry(entry.obfuscated_class.clone()).or_default();
            for me in &entry.methods { mm.insert(me.obfuscated_name.clone(), me.real_name.clone()); }
            let fm = field_map.entry(entry.obfuscated_class.clone()).or_default();
            for fe in &entry.fields { fm.insert(fe.obfuscated_name.clone(), fe.real_name.clone()); }
        }
        Self { mapping, class_map, method_map, field_map }
    }

    pub fn patch_text(&self, text: &str, class_fqn: &str) -> String {
        let mut out = text.to_string();
        // Apply class renames longest-first so `Foo$Inner` runs before `Foo`.
        let mut keys: Vec<&String> = self.class_map.keys().collect();
        keys.sort_by(|a, b| b.len().cmp(&a.len()));
        for obf in keys {
            let obf_simple  = obf.rsplit('.').next().unwrap_or(obf);
            let real_simple = self.class_map[obf].rsplit('.').next().unwrap_or(&self.class_map[obf]);
            out = whole_word_replace(&out, obf_simple, real_simple);
        }
        let empty: HashMap<String, String> = HashMap::new();
        let method_names = self.method_map.get(class_fqn).unwrap_or(&empty);
        for (obf, real) in method_names { out = whole_word_replace(&out, obf, real); }
        let field_names = self.field_map.get(class_fqn).unwrap_or(&empty);
        for (obf, real) in field_names { out = whole_word_replace(&out, obf, real); }
        out
    }

    pub fn patch_directory(&self, src_dir: &Path, out_dir: &Path, classes: &[JavaClass])
        -> Result<PatchStats, String>
    {
        let lookup: HashMap<&str, &Mapping> = self.mapping.mappings.iter()
            .map(|m| (m.obfuscated_class.as_str(), m)).collect();
        let mut patched = 0;
        let mut skipped = 0;
        for cls in classes {
            let rel = cls.java_path.strip_prefix(src_dir).unwrap_or(&cls.java_path);
            let dst: PathBuf = out_dir.join(rel);
            if let Some(parent) = dst.parent() { std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?; }
            if lookup.contains_key(cls.fqn.as_str()) {
                let text = std::fs::read_to_string(&cls.java_path).map_err(|e| format!("read: {e}"))?;
                let new_text = self.patch_text(&text, &cls.fqn);
                std::fs::write(&dst, new_text).map_err(|e| format!("write: {e}"))?;
                patched += 1;
            } else {
                std::fs::copy(&cls.java_path, &dst).map_err(|e| format!("copy: {e}"))?;
                skipped += 1;
            }
        }
        Ok(PatchStats { patched, skipped })
    }
}

/// Whole-word replace — only rewrites `needle` when it's bounded by
/// non-identifier characters on both sides. Used for Java text patching
/// where naively-replacing `a` would corrupt every word containing `a`.
fn whole_word_replace(text: &str, needle: &str, replacement: &str) -> String {
    // Escape needle for regex, then compile with explicit `\b` boundaries.
    let pat = format!(r"\b{}\b", regex::escape(needle));
    let re = match Regex::new(&pat) { Ok(r) => r, Err(_) => return text.to_string() };
    re.replace_all(text, replacement).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{Mapping, MappingFile, MappingFormat, MethodEntry, FieldEntry};

    fn mapping() -> MappingFile {
        MappingFile {
            mappings: vec![Mapping {
                obfuscated_class: "a.b.c".into(),
                real_class: "com.lib.Foo".into(),
                confidence: Some(0.95),
                match_type: Some("fingerprint".into()),
                methods: vec![MethodEntry {
                    obfuscated_name: "a".into(),
                    obfuscated_descriptor: Some("()V".into()),
                    real_name: "init".into(),
                    real_descriptor: Some("()V".into()),
                }],
                fields: vec![FieldEntry {
                    obfuscated_name: "b".into(),
                    obfuscated_descriptor: Some("Lcom/lib/Foo;".into()),
                    real_name: "instance".into(),
                }],
            }],
            format: MappingFormat::Json,
        }
    }

    #[test]
    fn smali_method_invoke_rewritten() {
        let m = mapping();
        let p = SmaliPatcher::new(&m);
        let src = "\
.class public La/b/c;
.super Ljava/lang/Object;
.method public a()V
    invoke-virtual {p0}, La/b/c;->a()V
    iget-object v0, p0, La/b/c;->b:Lcom/lib/Foo;
    return-void
.end method
";
        let out = p.patch_text(src, "a.b.c");
        assert!(out.contains("Lcom/lib/Foo;"));
        assert!(out.contains("Lcom/lib/Foo;->init()V"));
        assert!(out.contains("Lcom/lib/Foo;->instance:Lcom/lib/Foo;"));
    }

    #[test]
    fn java_simple_replacement() {
        let m = mapping();
        let p = JavaPatcher::new(&m);
        // Note: `b` is referenced both as a field and as a variable;
        // whole-word boundaries mean nothing else like `ab` is touched.
        let src = "package x.y; class c { public int b; public void a() { System.out.println(this.b); } } ";
        let out = p.patch_text(src, "a.b.c");
        assert!(out.contains("class Foo"));
        // method name `a` → `init`
        assert!(out.contains("void init()"));
        // field name `b` → `instance`
        assert!(out.contains("public int instance"));
        assert!(out.contains("this.instance"));
    }
}
