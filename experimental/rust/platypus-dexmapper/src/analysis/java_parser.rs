//! Java source file parser for jadx-decompiled output. Pure regex — we
//! don't aim for full Java grammar support, only enough to extract class
//! / method / field structure for the matcher.
//!
//! Mirrors `dexmapper.analysis.java_parser`.

use std::path::{Path, PathBuf};

use regex::Regex;

#[derive(Debug, Clone)]
pub struct JavaField {
    pub name: String,
    pub java_type: String,
    pub flags: String,
}

#[derive(Debug, Clone)]
pub struct JavaMethod {
    pub name: String,
    pub return_type: String,
    pub params: Vec<(String, String)>,  // (type, name)
    pub flags: String,
    pub body_calls: Vec<String>,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone)]
pub struct JavaClass {
    pub java_path: PathBuf,
    pub fqn: String,
    pub package: String,
    pub simple_name: String,
    pub flags: String,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub fields: Vec<JavaField>,
    pub methods: Vec<JavaMethod>,
    pub inner_classes: Vec<JavaClass>,
}

struct Patterns {
    package:     Regex,
    class_decl:  Regex,
    field:       Regex,
    method:      Regex,
    constructor: Regex,
    call:        Regex,
}

const MODIFIERS: &str = r"(?:(?:public|protected|private|static|final|abstract|synchronized|native|strictfp|transient|volatile)\s+)*";

impl Patterns {
    fn new() -> Self {
        // NB: the regexes are intentionally on single lines — raw strings
        // do NOT process `\` line-continuations the way C / Python string
        // literals do, so wrapping these into multi-line `r"\..."` blocks
        // ends up baking a literal newline into the pattern. Keep flat.
        Self {
            package: Regex::new(r"^\s*package\s+([\w.]+)\s*;").unwrap(),
            class_decl: Regex::new(&format!(
                r"^\s*({MODIFIERS})(?:class|interface|enum|@interface)\s+(\w+)(?:\s+extends\s+([\w.<>, ]+?))?(?:\s+implements\s+([\w.<>, ]+?))?\s*\{{"
            )).unwrap(),
            field: Regex::new(&format!(
                r"^\s*({MODIFIERS})([\w.<>\[\]]+)\s+(\w+)\s*(?:=.+?)?\s*;"
            )).unwrap(),
            method: Regex::new(&format!(
                r"^\s*({MODIFIERS})([\w.<>\[\]]+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w., ]+\s*)?\{{"
            )).unwrap(),
            constructor: Regex::new(&format!(
                r"^\s*({MODIFIERS})(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w., ]+\s*)?\{{"
            )).unwrap(),
            call: Regex::new(r"\b(\w+)\s*\(").unwrap(),
        }
    }
}

fn parse_params(params_str: &str) -> Vec<(String, String)> {
    if params_str.trim().is_empty() { return Vec::new(); }
    let mut out = Vec::new();
    for part in params_str.split(',') {
        let part = part.trim();
        let tokens: Vec<&str> = part.split_whitespace().collect();
        if tokens.len() >= 2 {
            out.push((tokens[..tokens.len() - 1].join(" "),
                      tokens.last().unwrap().to_string()));
        } else if tokens.len() == 1 {
            out.push((tokens[0].to_string(), String::new()));
        }
    }
    out
}

/// True when `s` is a Java access / non-access modifier keyword — used
/// by the method-vs-constructor disambiguator above.
fn is_java_modifier(s: &str) -> bool {
    matches!(s, "public" | "protected" | "private" | "static" | "final"
                | "abstract" | "synchronized" | "native" | "strictfp"
                | "transient" | "volatile")
}

fn keyword_ish(s: &str) -> bool {
    matches!(s, "if" | "for" | "while" | "switch" | "catch" | "return"
              | "new" | "throw" | "assert" | "synchronized" | "else")
}

fn extract_body_calls(p: &Patterns, body: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for line in body {
        for cap in p.call.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                let name = m.as_str();
                if !keyword_ish(name) { out.push(name.to_string()); }
            }
        }
    }
    out
}

pub fn parse_java_file<P: AsRef<Path>>(path: P) -> Option<JavaClass> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).ok()?;
    parse_java_text(path, &text)
}

pub fn parse_java_text(path: &Path, text: &str) -> Option<JavaClass> {
    let p = Patterns::new();
    let lines: Vec<&str> = text.lines().collect();

    let package = lines.iter().take(20)
        .find_map(|l| p.package.captures(l).map(|c| c[1].to_string()))
        .unwrap_or_default();

    // Outer class decl (the first one in source order).
    let mut class_name = path.file_stem()
        .and_then(|s| s.to_str()).unwrap_or("").to_string();
    let mut flags_str = String::new();
    let mut superclass: Option<String> = None;
    let mut interfaces: Vec<String> = Vec::new();
    for line in &lines {
        if let Some(c) = p.class_decl.captures(line) {
            flags_str = c[1].trim().to_string();
            class_name = c[2].to_string();
            superclass = c.get(3).map(|m| m.as_str().trim().to_string());
            interfaces = c.get(4)
                .map(|m| m.as_str().split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();
            break;
        }
    }
    let fqn = if package.is_empty() { class_name.clone() } else { format!("{package}.{class_name}") };

    // Scan for fields and methods. Methods cover a brace-balanced body so
    // we know where each method ends; everything outside method bodies
    // and not matching the method regex is candidate field-decl territory.
    let mut fields: Vec<JavaField> = Vec::new();
    let mut methods: Vec<JavaMethod> = Vec::new();

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];

        // Try method first — its regex is more specific than the field
        // regex (it requires a `(` and ending `{`).
        //
        // A constructor like `public Foo(String n) {` will *also* match
        // the method regex because the optional MODIFIERS group can
        // backtrack to empty — leaving `return_type = "public"` and
        // `name = "Foo"`. We detect that case by checking whether the
        // matched `name` equals the class name, in which case we route
        // through the constructor branch instead. Mirrors the Python
        // tool's ordering.
        if let Some(c) = p.method.captures(line) {
            let flags = c[1].trim().to_string();
            let return_type = c[2].to_string();
            let name = c[3].to_string();
            let params = parse_params(&c[4]);

            let start = i + 1;
            let (body, end) = consume_braced_body(&lines, i);

            let is_ctor = name == class_name && is_java_modifier(&return_type);
            let (final_name, final_return, final_flags) = if is_ctor {
                // Constructor mis-routed via the method regex — fold the
                // would-be return type ("public", "protected", …) into
                // the flags string and rewrite the name / return type.
                let merged = format!("{flags} {return_type}").trim().to_string();
                ("<init>".to_string(), "V".to_string(), merged)
            } else {
                (name, return_type, flags)
            };
            methods.push(JavaMethod {
                name: final_name,
                return_type: final_return,
                params,
                flags: final_flags,
                body_calls: extract_body_calls(&p, &body),
                line_start: start,
                line_end: end + 1,
            });
            i = end + 1;
            continue;
        }
        if let Some(c) = p.constructor.captures(line) {
            // Constructor only counts if the name matches the class.
            if c[2] == class_name {
                let flags = c[1].trim().to_string();
                let params = parse_params(&c[3]);
                let start = i + 1;
                let (body, end) = consume_braced_body(&lines, i);
                methods.push(JavaMethod {
                    name: "<init>".into(),
                    return_type: "V".into(),
                    params, flags,
                    body_calls: extract_body_calls(&p, &body),
                    line_start: start,
                    line_end: end + 1,
                });
                i = end + 1;
                continue;
            }
        }
        if let Some(c) = p.field.captures(line) {
            let flags = c[1].trim().to_string();
            let java_type = c[2].to_string();
            let name = c[3].to_string();
            // Skip return-type-shaped collisions inside method bodies —
            // we should not be reaching this branch from inside a method
            // since the body consumer skips past those. But guard anyway:
            // Java has no top-level statement that matches `field` other
            // than declarations.
            fields.push(JavaField { name, java_type, flags });
        }
        i += 1;
    }

    Some(JavaClass {
        java_path: path.to_path_buf(),
        fqn,
        package,
        simple_name: class_name,
        flags: flags_str,
        superclass,
        interfaces,
        fields,
        methods,
        inner_classes: Vec::new(),
    })
}

/// Starting at `lines[start]` (which is the opening line of a brace
/// block — has a `{`), find the matching `}` and return the lines in
/// between plus the index of the closing `}` line.
fn consume_braced_body<'a>(lines: &[&'a str], start: usize) -> (Vec<&'a str>, usize) {
    let mut depth = 0i32;
    let mut body: Vec<&'a str> = Vec::new();
    let mut i = start;
    let mut seen_open = false;
    while i < lines.len() {
        let line = lines[i];
        for ch in line.chars() {
            match ch {
                '{' => { depth += 1; seen_open = true; }
                '}' => { depth -= 1; }
                _ => {}
            }
        }
        if seen_open && i > start { body.push(line); }
        if seen_open && depth == 0 { return (body, i); }
        i += 1;
    }
    (body, lines.len().saturating_sub(1))
}

/// Recursively parse every `.java` file under `directory`.
pub fn parse_java_dir<P: AsRef<Path>>(directory: P) -> Vec<JavaClass> {
    let mut paths: Vec<PathBuf> = walkdir::WalkDir::new(directory.as_ref())
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file()
                    && e.path().extension().is_some_and(|x| x == "java"))
        .map(|e| e.path().to_path_buf())
        .collect();
    paths.sort();
    paths.into_iter().filter_map(parse_java_file).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
package com.example;

public final class Foo {
    public String name;
    private int count;

    public Foo(String n) {
        this.name = n;
    }

    public String greet(String who) {
        return name + " " + who;
    }
}
"#;

    #[test]
    fn parses_basic_class() {
        let p = std::path::PathBuf::from("/tmp/Foo.java");
        let c = parse_java_text(&p, SAMPLE).expect("parse");
        assert_eq!(c.fqn, "com.example.Foo");
        assert_eq!(c.package, "com.example");
        assert_eq!(c.simple_name, "Foo");
        assert_eq!(c.fields.len(), 2);
        // 1 constructor + 1 method
        assert_eq!(c.methods.len(), 2);
        assert_eq!(c.methods[0].name, "<init>");
        assert_eq!(c.methods[1].name, "greet");
        assert_eq!(c.methods[1].return_type, "String");
        assert_eq!(c.methods[1].params.len(), 1);
        assert_eq!(c.methods[1].params[0], ("String".to_string(), "who".to_string()));
    }
}
