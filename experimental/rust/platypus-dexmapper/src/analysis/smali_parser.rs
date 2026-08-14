//! Smali file parser. Reads `.smali` files produced by baksmali / jadx
//! into a structured representation the matcher can score against. Pure
//! regex-driven — Smali is line-oriented enough that we don't need a
//! grammar.
//!
//! Mirrors the Python `dexmapper.analysis.smali_parser` exactly.

use std::path::{Path, PathBuf};

use regex::Regex;

// ── Data model ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SmaliField {
    pub name: String,
    pub descriptor: String,
    pub flags: String,
}

#[derive(Debug, Clone)]
pub struct SmaliCallEdge {
    /// Internal class form, with the L…; wrapper preserved (matches
    /// Python output).
    pub callee_class: String,
    pub callee_name: String,
    pub callee_descriptor: String,
    /// `virtual` | `static` | `interface` | `special` | `direct`.
    pub call_type: String,
}

#[derive(Debug, Clone)]
pub struct SmaliFieldRef {
    pub owner: String,       // Lcom/foo/Bar;
    pub name: String,
    pub descriptor: String,
}

#[derive(Debug, Clone)]
pub struct SmaliMethod {
    pub name: String,
    pub descriptor: String,
    pub flags: String,
    pub call_edges: Vec<SmaliCallEdge>,
    pub field_gets: Vec<SmaliFieldRef>,
    pub field_puts: Vec<SmaliFieldRef>,
    pub local_count: u32,
    pub line_start: usize,
}

#[derive(Debug, Clone)]
pub struct SmaliClass {
    pub smali_path: PathBuf,
    /// `Lcom/example/Foo;`
    pub class_name: String,
    /// `com/example/Foo`
    pub internal_name: String,
    /// `com.example.Foo`
    pub fqn: String,
    pub package: String,
    pub simple_name: String,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub flags: String,
    pub source: Option<String>,
    pub fields: Vec<SmaliField>,
    pub methods: Vec<SmaliMethod>,
}

// ── Regexes — built once, reused per file ──────────────────────────────────

struct Patterns {
    class:      Regex,
    super_:     Regex,
    implements: Regex,
    source:     Regex,
    field:      Regex,
    method:     Regex,
    locals:     Regex,
    registers:  Regex,
    end_method: Regex,
    invoke:     Regex,
    iget:       Regex,
    iput:       Regex,
    sget:       Regex,
    sput:       Regex,
}

impl Patterns {
    fn new() -> Self {
        Self {
            class:      Regex::new(r"^\.class\s+(.+?)\s+(L[^;]+;)\s*$").unwrap(),
            super_:     Regex::new(r"^\.super\s+(L[^;]+;)\s*$").unwrap(),
            implements: Regex::new(r"^\.implements\s+(L[^;]+;)\s*$").unwrap(),
            source:     Regex::new(r#"^\.source\s+"(.+)"\s*$"#).unwrap(),
            // `.field ... name:descriptor` with an optional `= initialValue`
            // suffix (the latter appears on `static final` fields that R8
            // collapses to literal constants).
            field:      Regex::new(r"^\.field\s+(.+?)\s+(\w+):(\S+)(?:\s*=.*)?\s*$").unwrap(),
            method:     Regex::new(r"^\.method\s+(.+?)\s+(\S+)\(([^)]*)\)(\S+)\s*$").unwrap(),
            locals:     Regex::new(r"^\s+\.locals\s+(\d+)\s*$").unwrap(),
            registers:  Regex::new(r"^\s+\.registers\s+(\d+)\s*$").unwrap(),
            end_method: Regex::new(r"^\.end\s+method\s*$").unwrap(),
            invoke:     Regex::new(
                r"^\s+invoke-(\w+)(?:/range)?\s+\{[^}]*\},\s*(L[^;]+;)->(\S+)\(([^)]*)\)(\S+)\s*$"
            ).unwrap(),
            iget: Regex::new(
                r"^\s+[isf]get(?:-\w+)?\s+\S+,\s*\S+,\s*(L[^;]+;)->(\w+):(\S+)\s*$"
            ).unwrap(),
            iput: Regex::new(
                r"^\s+[isf]put(?:-\w+)?\s+\S+,\s*\S+,\s*(L[^;]+;)->(\w+):(\S+)\s*$"
            ).unwrap(),
            sget: Regex::new(
                r"^\s+sget(?:-\w+)?\s+\S+,\s*(L[^;]+;)->(\w+):(\S+)\s*$"
            ).unwrap(),
            sput: Regex::new(
                r"^\s+sput(?:-\w+)?\s+\S+,\s*(L[^;]+;)->(\w+):(\S+)\s*$"
            ).unwrap(),
        }
    }
}

fn smali_class_to_names(smali: &str) -> (String, String, String, String) {
    let internal: String = if smali.starts_with('L') && smali.ends_with(';') {
        smali[1..smali.len() - 1].to_string()
    } else {
        smali.replace('.', "/").trim_start_matches('L').trim_end_matches(';').to_string()
    };
    let fqn = internal.replace('/', ".");
    let (package, simple) = match fqn.rfind('.') {
        Some(i) => (fqn[..i].to_string(), fqn[i + 1..].to_string()),
        None => (String::new(), fqn.clone()),
    };
    (internal, fqn, package, simple)
}

/// Parse one `.smali` file. Returns `None` on I/O failure or when the file
/// has no `.class` directive at all.
pub fn parse_smali_file<P: AsRef<Path>>(path: P) -> Option<SmaliClass> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).ok()?;
    parse_smali_text(path, &text)
}

pub fn parse_smali_text(path: &Path, text: &str) -> Option<SmaliClass> {
    let p = Patterns::new();

    let mut class_name: Option<String> = None;
    let mut flags_str = String::new();
    let mut superclass: Option<String> = None;
    let mut interfaces: Vec<String> = Vec::new();
    let mut source: Option<String> = None;
    let mut fields: Vec<SmaliField> = Vec::new();
    let mut methods: Vec<SmaliMethod> = Vec::new();

    let mut current: Option<SmaliMethod> = None;

    for (lineno, raw) in text.lines().enumerate() {
        let line_num = lineno + 1;
        let trimmed = raw.trim();

        if current.is_none() {
            if let Some(c) = p.class.captures(trimmed) {
                flags_str  = c.get(1).unwrap().as_str().to_string();
                class_name = Some(c.get(2).unwrap().as_str().to_string());
                continue;
            }
            if let Some(c) = p.super_.captures(trimmed) {
                superclass = Some(c.get(1).unwrap().as_str().to_string());
                continue;
            }
            if let Some(c) = p.implements.captures(trimmed) {
                interfaces.push(c.get(1).unwrap().as_str().to_string());
                continue;
            }
            if let Some(c) = p.source.captures(trimmed) {
                source = Some(c.get(1).unwrap().as_str().to_string());
                continue;
            }
            if let Some(c) = p.field.captures(trimmed) {
                fields.push(SmaliField {
                    flags: c.get(1).unwrap().as_str().to_string(),
                    name:  c.get(2).unwrap().as_str().to_string(),
                    descriptor: c.get(3).unwrap().as_str().to_string(),
                });
                continue;
            }
            if let Some(c) = p.method.captures(trimmed) {
                let m_params = c.get(3).unwrap().as_str();
                let m_ret    = c.get(4).unwrap().as_str();
                current = Some(SmaliMethod {
                    name: c.get(2).unwrap().as_str().to_string(),
                    descriptor: format!("({m_params}){m_ret}"),
                    flags: c.get(1).unwrap().as_str().to_string(),
                    call_edges: Vec::new(),
                    field_gets: Vec::new(),
                    field_puts: Vec::new(),
                    local_count: 0,
                    line_start: line_num,
                });
                continue;
            }
        } else {
            if p.end_method.is_match(trimmed) {
                if let Some(m) = current.take() { methods.push(m); }
                continue;
            }
            // `current` is Some — we can safely use as_mut().
            let cur = current.as_mut().unwrap();
            if let Some(c) = p.locals.captures(raw)    { cur.local_count = c[1].parse().unwrap_or(0); continue; }
            if let Some(c) = p.registers.captures(raw) { cur.local_count = c[1].parse().unwrap_or(0); continue; }
            if let Some(c) = p.invoke.captures(raw) {
                let call_type = c.get(1).unwrap().as_str().to_string();
                let cls       = c.get(2).unwrap().as_str().to_string();
                let name      = c.get(3).unwrap().as_str().to_string();
                let params    = c.get(4).unwrap().as_str();
                let ret       = c.get(5).unwrap().as_str();
                cur.call_edges.push(SmaliCallEdge {
                    callee_class: cls,
                    callee_name: name,
                    callee_descriptor: format!("({params}){ret}"),
                    call_type,
                });
                continue;
            }
            // iget / sget
            if let Some(c) = p.iget.captures(raw).or_else(|| p.sget.captures(raw)) {
                cur.field_gets.push(SmaliFieldRef {
                    owner: c.get(1).unwrap().as_str().to_string(),
                    name:  c.get(2).unwrap().as_str().to_string(),
                    descriptor: c.get(3).unwrap().as_str().to_string(),
                });
                continue;
            }
            // iput / sput
            if let Some(c) = p.iput.captures(raw).or_else(|| p.sput.captures(raw)) {
                cur.field_puts.push(SmaliFieldRef {
                    owner: c.get(1).unwrap().as_str().to_string(),
                    name:  c.get(2).unwrap().as_str().to_string(),
                    descriptor: c.get(3).unwrap().as_str().to_string(),
                });
                continue;
            }
        }
    }

    let class_name = class_name?;
    let (internal, fqn, package, simple) = smali_class_to_names(&class_name);
    Some(SmaliClass {
        smali_path: path.to_path_buf(),
        class_name,
        internal_name: internal,
        fqn,
        package,
        simple_name: simple,
        superclass,
        interfaces,
        flags: flags_str,
        source,
        fields,
        methods,
    })
}

/// Recursively parse every `.smali` file in `directory`.
pub fn parse_smali_dir<P: AsRef<Path>>(directory: P) -> Vec<SmaliClass> {
    let mut paths: Vec<PathBuf> = walkdir::WalkDir::new(directory.as_ref())
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file()
                    && e.path().extension().is_some_and(|x| x == "smali"))
        .map(|e| e.path().to_path_buf())
        .collect();
    paths.sort();
    paths.into_iter().filter_map(parse_smali_file).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
.class public final Lcom/example/Foo;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;
.source "Foo.java"

.field public static final TAG:Ljava/lang/String; = "Foo"

.method public constructor <init>()V
    .locals 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public run()V
    .locals 2
    sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;
    const-string v1, "hi"
    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
    return-void
.end method
"#;

    #[test]
    fn parses_basic_class() {
        let p = std::path::PathBuf::from("/tmp/Foo.smali");
        let c = parse_smali_text(&p, SAMPLE).expect("parse");
        assert_eq!(c.fqn, "com.example.Foo");
        assert_eq!(c.simple_name, "Foo");
        assert_eq!(c.superclass.as_deref(), Some("Ljava/lang/Object;"));
        assert_eq!(c.interfaces, vec!["Ljava/lang/Runnable;".to_string()]);
        assert_eq!(c.fields.len(), 1);
        assert_eq!(c.methods.len(), 2);
        let run = &c.methods[1];
        assert_eq!(run.name, "run");
        assert_eq!(run.descriptor, "()V");
        assert_eq!(run.call_edges.len(), 1);
        assert_eq!(run.field_gets.len(), 1);
        assert_eq!(run.field_gets[0].name, "out");
    }
}
