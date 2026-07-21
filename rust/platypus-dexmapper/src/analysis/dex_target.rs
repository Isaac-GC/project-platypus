//! Build a [`crate::analysis::smali_parser::SmaliClass`] view straight
//! out of parsed DEX, so the matcher can run against an APK without
//! shelling out to baksmali / jadx first.
//!
//! Two entry points:
//!
//!   * [`smali_classes_from_dex`] / [`smali_classes_from_dex_files`] —
//!     in-memory DEX → matcher-ready classes.
//!   * [`smali_classes_from_apk`] — open an APK, parse every
//!     `classes*.dex`, return a flat list.
//!
//! The returned `SmaliClass` carries an empty `smali_path` — patching
//! relies on real on-disk files, so the DEX-direct path is for
//! *matching* and *mapping-file emission* only, not in-place patching.

use std::path::{Path, PathBuf};

use platypus_apk::zip::ApkZip;
use platypus_dex::clazz::Clazz;
use platypus_dex::instructions::InstructionKind;
use platypus_dex::parser::DexFileWithRaw;

use crate::analysis::smali_parser::{
    SmaliCallEdge, SmaliClass, SmaliField, SmaliFieldRef, SmaliMethod,
};

/// Convert every class in a single parsed DEX into a `SmaliClass`.
/// `apk_label` is used as the synthetic file path (e.g.
/// `"classes.dex#Lcom/foo/Bar;"`) so the matcher's `patch_directory`
/// can still uniquely identify each class, even though no actual file
/// exists.
pub fn smali_classes_from_dex(dex: &DexFileWithRaw, apk_label: &str) -> Vec<SmaliClass> {
    let mut out = Vec::with_capacity(dex.parsed.class_defs.len());
    for class_def in &dex.parsed.class_defs {
        let Ok(c) = Clazz::new(class_def, dex) else { continue; };
        out.push(clazz_to_smali_class(&c, dex, class_def, apk_label));
    }
    out
}

pub fn smali_classes_from_dex_files(dex_files: &[DexFileWithRaw], apk_label: &str) -> Vec<SmaliClass> {
    let mut out = Vec::new();
    for d in dex_files { out.extend(smali_classes_from_dex(d, apk_label)); }
    out
}

pub fn smali_classes_from_apk<P: AsRef<Path>>(path: P) -> Vec<SmaliClass> {
    let path = path.as_ref();
    let Ok(apk) = ApkZip::open(path.to_string_lossy().as_ref()) else { return Vec::new(); };
    let label = path.file_name().and_then(|s| s.to_str()).unwrap_or("app.apk").to_string();
    let mut dexes: Vec<DexFileWithRaw> = Vec::new();
    for (name, bytes) in apk.dex_files() {
        if let Ok(d) = DexFileWithRaw::from_bytes(bytes, name.clone()) { dexes.push(d); }
    }
    smali_classes_from_dex_files(&dexes, &label)
}

// ── Internals ──────────────────────────────────────────────────────────────

fn clazz_to_smali_class(
    c: &Clazz,
    dex: &DexFileWithRaw,
    class_def: &platypus_dex::parser::ClassDefItem,
    apk_label: &str,
) -> SmaliClass {
    let class_name = c.class_name.clone(); // already `Lcom/foo/Bar;`
    let internal = strip_l_semi(&class_name).to_string();
    let fqn = internal.replace('/', ".");
    let (package, simple) = match fqn.rfind('.') {
        Some(i) => (fqn[..i].to_string(), fqn[i + 1..].to_string()),
        None => (String::new(), fqn.clone()),
    };

    let superclass = if class_def.superclass_idx == u32::MAX {
        None
    } else {
        dex.parsed.type_ids.get(class_def.superclass_idx as usize)
            .map(|t| t.type_name.clone()) // keep `Lcom/foo;` form for SmaliClass
    };

    let methods = c.methods.iter().map(|m| {
        let mut call_edges: Vec<SmaliCallEdge> = Vec::new();
        let mut field_gets: Vec<SmaliFieldRef> = Vec::new();
        let mut field_puts: Vec<SmaliFieldRef> = Vec::new();

        for ins in &m.instructions {
            match ins.kind {
                InstructionKind::InvokeKind | InstructionKind::InvokeKindRange => {
                    let Some(idx) = ins.v_b else { continue; };
                    if idx < 0 { continue; }
                    let Some(mid) = dex.parsed.method_ids.get(idx as usize) else { continue; };
                    call_edges.push(SmaliCallEdge {
                        callee_class: mid.class_name.clone(),
                        callee_name:  mid.method_name.clone(),
                        callee_descriptor: mid.proto_desc.clone(),
                        call_type: invoke_smali_name(ins.opcode).to_string(),
                    });
                }
                InstructionKind::IGet => smali_field_ref(dex, ins.v_c, &mut field_gets),
                InstructionKind::IPut => smali_field_ref(dex, ins.v_c, &mut field_puts),
                InstructionKind::SGet => smali_field_ref(dex, ins.v_b, &mut field_gets),
                InstructionKind::SPut => smali_field_ref(dex, ins.v_b, &mut field_puts),
                _ => {}
            }
        }

        SmaliMethod {
            name: m.method_name.clone(),
            descriptor: m.proto_desc.clone(),
            flags: String::new(),
            call_edges,
            field_gets,
            field_puts,
            local_count: m.registers_size as u32,
            line_start: 0,
        }
    }).collect();

    let fields = c.static_fields.iter().chain(c.instance_fields.iter())
        .map(|f| SmaliField {
            name: f.name.clone(),
            descriptor: f.type_name.clone(),
            flags: String::new(),
        })
        .collect();

    // Convert the raw access-flag bitmask into the same space-joined
    // textual form the smali parser produces (so downstream
    // `flags.contains("abstract")` checks work). Includes the bits
    // the matcher cares about — abstract, interface, enum, final,
    // static, public.
    let flags = dex_class_flags_text(class_def.access_flags);

    SmaliClass {
        // Synthetic path so patch_directory can still discriminate. We
        // never write to it.
        smali_path: PathBuf::from(format!("{}#{}", apk_label, class_name)),
        class_name,
        internal_name: internal,
        fqn,
        package,
        simple_name: simple,
        superclass,
        interfaces: Vec::new(),
        flags,
        source: None,
        fields,
        methods,
    }
}

fn dex_class_flags_text(bits: u32) -> String {
    let mut out: Vec<&'static str> = Vec::new();
    if bits & 0x0001 != 0 { out.push("public"); }
    if bits & 0x0010 != 0 { out.push("final"); }
    if bits & 0x0200 != 0 { out.push("interface"); }
    if bits & 0x0400 != 0 { out.push("abstract"); }
    if bits & 0x1000 != 0 { out.push("synthetic"); }
    if bits & 0x2000 != 0 { out.push("annotation"); }
    if bits & 0x4000 != 0 { out.push("enum"); }
    out.join(" ")
}

fn smali_field_ref(dex: &DexFileWithRaw, idx: Option<i64>, into: &mut Vec<SmaliFieldRef>) {
    let Some(i) = idx else { return; };
    if i < 0 { return; }
    let Some(f) = dex.parsed.field_ids.get(i as usize) else { return; };
    into.push(SmaliFieldRef {
        owner: f.class_name.clone(),
        name: f.field_name.clone(),
        descriptor: f.type_name.clone(),
    });
}

/// Map a Dalvik invoke-* opcode to the textual call-type smali files
/// use (`virtual` / `static` / `interface` / `direct` / `super`).
/// Mirrors the strings the regex-based smali parser captures, so the
/// matcher's struct-hash computation is consistent.
fn invoke_smali_name(opcode: u8) -> &'static str {
    match opcode {
        0x6e | 0x74 => "virtual",
        0x6f | 0x75 => "super",
        0x70 | 0x76 => "direct",
        0x71 | 0x77 => "static",
        0x72 | 0x78 => "interface",
        _           => "virtual",
    }
}

fn strip_l_semi(s: &str) -> &str {
    s.strip_prefix('L').and_then(|s| s.strip_suffix(';')).unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_name_table() {
        assert_eq!(invoke_smali_name(0x6e), "virtual");
        assert_eq!(invoke_smali_name(0x74), "virtual");
        assert_eq!(invoke_smali_name(0x71), "static");
        assert_eq!(invoke_smali_name(0x72), "interface");
    }
}
