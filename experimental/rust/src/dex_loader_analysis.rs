//! Static detection of dynamic dex-loading sites.
//!
//! Finds invocations of `DexClassLoader`, `InMemoryDexClassLoader`,
//! `PathClassLoader`, `BaseDexClassLoader`, and `DelegateLastClassLoader`
//! constructors. For each loader site it also enumerates *byte-source*
//! invocations in the same containing method (e.g. `AssetManager.open`,
//! `ContentResolver.openInputStream`, `FileInputStream.<init>`,
//! `Class.getResourceAsStream`) and extracts the static string argument when
//! present.
//!
//! This is **not** a sound dataflow analysis — it just pairs same-method
//! observations. For a typical pattern
//!
//! ```text
//! InputStream is = ctx.getAssets().open("payload.dex");
//! byte[] data    = decrypt(readBytes(is));
//! ClassLoader cl = new InMemoryDexClassLoader(ByteBuffer.wrap(data), parent);
//! ```
//!
//! the analysis correctly surfaces the loader site + the asset name. For
//! cross-method indirection the user can chase the chain manually using the
//! existing `find_calls`/`find_exec` machinery.

use serde::{Deserialize, Serialize};

use crate::dex::clazz::Clazz;
use crate::dex::debug_info;
use crate::dex::instructions::Instruction;
use crate::dex::method::Method;
use crate::dex::parser::DexFileWithRaw;

// ── Result types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DexLoaderSite {
    /// Short name of the loader, e.g. `"DexClassLoader"`, `"InMemoryDexClassLoader"`.
    pub loader_class: String,
    /// Class containing the construction.
    pub caller_class: String,
    /// Method containing the construction (with proto, e.g. `"loadStuff()V"`).
    pub caller_method: String,
    /// Codepoint of the `<init>` invoke instruction.
    pub codepoint: u32,
    /// Source line if debug info is present.
    pub line_number: Option<u32>,
    /// Full Smali invoke string (for display).
    pub instruction: String,
    /// Byte-source method calls observed in the same method, in source order.
    /// The user can chase any of these via `find_exec` to recover plaintext bytes.
    pub byte_sources: Vec<ByteSource>,
    /// Distinct static string arguments seen on byte-source calls — these are
    /// the most likely "what asset/file does this loader read" candidates.
    pub candidate_assets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteSource {
    /// "AssetManager.open" / "Context.openFileInput" / etc — the method that
    /// produces an `InputStream` (or bytes).
    pub kind: String,
    /// Full Dalvik method ref of the call.
    pub method_ref: String,
    /// First static-string argument if statically resolvable (e.g. "payload.dex").
    pub argument: Option<String>,
    pub codepoint: u32,
}

// ── Pattern tables ───────────────────────────────────────────────────────────

/// Loader classes whose `<init>` indicates dynamic dex loading. The match is
/// substring-based against the invoke instruction string.
const LOADER_PATTERNS: &[(&str, &str)] = &[
    ("Ldalvik/system/DexClassLoader;-><init>(",          "DexClassLoader"),
    ("Ldalvik/system/InMemoryDexClassLoader;-><init>(",  "InMemoryDexClassLoader"),
    ("Ldalvik/system/PathClassLoader;-><init>(",         "PathClassLoader"),
    ("Ldalvik/system/BaseDexClassLoader;-><init>(",      "BaseDexClassLoader"),
    ("Ldalvik/system/DelegateLastClassLoader;-><init>(", "DelegateLastClassLoader"),
];

/// Byte-source method patterns. Each entry is `(substring, short_kind)`. The
/// substring is matched against the invoke instruction string after the `}, `.
const BYTE_SOURCE_PATTERNS: &[(&str, &str)] = &[
    ("Landroid/content/res/AssetManager;->open(",         "AssetManager.open"),
    ("Landroid/content/res/AssetManager;->openFd(",       "AssetManager.openFd"),
    ("Landroid/content/res/AssetManager;->openNonAsset(", "AssetManager.openNonAsset"),
    ("Landroid/content/Context;->openFileInput(",         "Context.openFileInput"),
    ("Landroid/content/Context;->getCacheDir(",           "Context.getCacheDir"),
    ("Landroid/content/Context;->getFilesDir(",           "Context.getFilesDir"),
    ("Landroid/content/ContentResolver;->openInputStream(", "ContentResolver.openInputStream"),
    ("Ljava/io/FileInputStream;-><init>(",                "FileInputStream"),
    ("Ljava/lang/Class;->getResourceAsStream(",           "Class.getResourceAsStream"),
    ("Ljava/lang/ClassLoader;->getResourceAsStream(",     "ClassLoader.getResourceAsStream"),
];

// ── Analysis entry points ────────────────────────────────────────────────────

/// Scan one DEX file for loader sites.
pub fn analyze_dex(dex: &DexFileWithRaw) -> Vec<DexLoaderSite> {
    let mut out = Vec::new();
    for class_def in &dex.parsed.class_defs {
        let clazz = match Clazz::new(class_def, dex) {
            Ok(c)  => c,
            Err(_) => continue,
        };
        for method in &clazz.methods {
            scan_method(method, &mut out);
        }
    }
    out
}

/// Scan an entire slot's worth of DEX files.
pub fn analyze_all(dex_files: &[DexFileWithRaw]) -> Vec<DexLoaderSite> {
    let mut out = Vec::new();
    for dex in dex_files {
        out.extend(analyze_dex(dex));
    }
    out
}

// ── Per-method scanner ──────────────────────────────────────────────────────

fn scan_method(method: &Method, out: &mut Vec<DexLoaderSite>) {
    // First pass: collect loader inits and byte sources from this method.
    let mut loader_inits: Vec<(&Instruction, &'static str)> = Vec::new();
    let mut byte_sources: Vec<ByteSource> = Vec::new();

    for instr in &method.instructions {
        let istr = &instr.instruction_str;
        // Cheap pre-filter — every interesting site contains "invoke".
        if !istr.contains("invoke") { continue; }

        // Loader init?
        for (pat, name) in LOADER_PATTERNS {
            if istr.contains(pat) {
                loader_inits.push((instr, name));
                break;
            }
        }
        // Byte source?
        for (pat, kind) in BYTE_SOURCE_PATTERNS {
            if istr.contains(pat) {
                let method_ref = extract_method_ref(istr).unwrap_or_else(|| istr.clone());
                let argument = extract_first_string_arg(method, instr);
                byte_sources.push(ByteSource {
                    kind: (*kind).into(),
                    method_ref,
                    argument,
                    codepoint: instr.codepoint,
                });
                break;
            }
        }
    }

    if loader_inits.is_empty() {
        return;
    }

    // Distinct candidate-asset string args (preserve insertion order).
    let mut candidate_assets: Vec<String> = Vec::new();
    for bs in &byte_sources {
        if let Some(s) = &bs.argument {
            if !candidate_assets.iter().any(|x| x == s) {
                candidate_assets.push(s.clone());
            }
        }
    }

    for (init_instr, loader_name) in &loader_inits {
        out.push(DexLoaderSite {
            loader_class:   (*loader_name).into(),
            caller_class:   method.class_name.clone(),
            caller_method:  format!("{}{}", method.method_name, method.proto_desc),
            codepoint:      init_instr.codepoint,
            line_number:    debug_info::lookup_line(&method.line_map, init_instr.codepoint),
            instruction:    init_instr.instruction_str.clone(),
            byte_sources:   byte_sources.clone(),
            candidate_assets: candidate_assets.clone(),
        });
    }
}

// ── Extraction helpers ───────────────────────────────────────────────────────

/// Pull `"Lcom/Foo;->bar(...)V"` out of an invoke instruction string.
fn extract_method_ref(istr: &str) -> Option<String> {
    let after = istr.find("}, ")
        .map(|p| p + 3)
        .or_else(|| istr.find("} ..").map(|p| p + 4))
        .or_else(|| istr.rfind('}').map(|p| p + 1))?;
    let rest = istr[after..].trim();
    if rest.contains("->") { Some(rest.to_string()) } else { None }
}

/// Backward-scan the method for the most recent `const-string vN, "…"` where
/// `vN` is the first non-`this` argument register of `invoke`. Best-effort —
/// returns `None` if the arg isn't a static literal.
fn extract_first_string_arg(method: &Method, invoke: &Instruction) -> Option<String> {
    let arg_regs = invoke_arg_regs(invoke);
    if arg_regs.is_empty() { return None; }

    // Pick the first "data" arg: skip the receiver for non-static invokes.
    let is_static = invoke.instruction_str.starts_with("invoke-static");
    let target_reg = if is_static {
        arg_regs[0]
    } else if arg_regs.len() >= 2 {
        arg_regs[1]
    } else {
        return None;
    };

    // Find the position of the invoke and walk backward.
    let invoke_idx = method.instructions.iter()
        .position(|i| i.codepoint == invoke.codepoint)?;
    for earlier in method.instructions[..invoke_idx].iter().rev() {
        let istr = &earlier.instruction_str;
        if !istr.starts_with("const-string") { continue; }
        if earlier.v_a != Some(target_reg as i64) { continue; }
        // Extract the literal between the first `"` and the last `"`.
        let first = istr.find('"')?;
        let last  = istr.rfind('"')?;
        if last <= first { return None; }
        return Some(unescape_smali(&istr[first + 1 .. last]));
    }
    None
}

/// Same as `analysis::extract_arg_regs` but local to this module so we don't
/// have to expose a private analysis helper.
fn invoke_arg_regs(instr: &Instruction) -> Vec<u32> {
    use crate::dex::instructions::InstructionKind;
    match &instr.kind {
        InstructionKind::InvokeKind | InstructionKind::InvokePolymorphic => {
            let count = instr.v_a.unwrap_or(0) as usize;
            let regs  = [instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g];
            regs[..count.min(5)].iter()
                .filter_map(|&v| v.map(|x| x as u32))
                .collect()
        }
        InstructionKind::InvokeKindRange | InstructionKind::InvokeCustom => {
            let count = instr.v_a.unwrap_or(0) as usize;
            let start = instr.v_c.unwrap_or(0) as u32;
            (0..count as u32).map(|i| start + i).collect()
        }
        _ => Vec::new(),
    }
}

/// Undo the standard Smali string escapes (`\\`, `\"`, `\n`, `\r`, `\t`).
fn unescape_smali(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n')  => out.push('\n'),
                Some('r')  => out.push('\r'),
                Some('t')  => out.push('\t'),
                Some('"')  => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => { out.push('\\'); out.push(other); }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}
