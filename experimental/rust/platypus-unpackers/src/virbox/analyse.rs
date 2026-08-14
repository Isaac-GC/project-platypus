//! Per-DEX static analysis (Report §5 F-method table; §7 vm_str;
//! §8 VMP body dispatch).
//!
//! Walks every method body in a DEX, finds every call-site of
//! `Lm<buildId>;->F<buildId>_NN(...)` (the Virbox VME dispatchers), and
//! classifies each one:
//!
//! - `F<id>_11` — vm_str deobfuscator. We try to recover the const-string
//!   argument and decode it via [`vmstr::vm_str_decode`].
//! - `F<id>_00..09` — generic VMP dispatchers. Not statically recoverable;
//!   each call-site is added to the `vmp_protected_methods` list.
//! - `F<id>_10..15` — specialised helpers. Recorded but not flagged
//!   "unrecovered" — behaviour depends on SO state.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use platypus_dex::parser::{ClassDataItem, DexFileWithRaw, EncodedMethod};

use super::vbpd::{find_vbpd_container, VbpdContainer};
use super::vmstr::vm_str_decode;

/// One harvested call-site of `Lm<id>;->F<id>_NN(...)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchSite {
    pub caller_class: String,
    pub caller_method: String,
    pub caller_descriptor: String,
    /// Register list at the call-site (omitted for invoke-static/range
    /// — that variant lists registers as a range, not a 5-reg nibble).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub regs: Vec<u8>,
    /// Raw encoded string read from the const-string source (F_11 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoded: Option<String>,
    /// Plaintext recovered via vm_str (F_11 only). `None` if the input
    /// wasn't decodable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<String>,
}

/// One bucket of call-sites grouped by F-method suffix (e.g. `"_11"`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DispatchBucket {
    pub sites: Vec<DispatchSite>,
    pub count: usize,
}

/// One generic-VMP call-site (F_00..09) — recorded for UNRECOVERED.md.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmpProtectedMethod {
    pub caller_class: String,
    pub caller_method: String,
    pub caller_descriptor: String,
    pub dispatch_variant: String,
    pub regs: Vec<u8>,
}

/// Per-DEX report (matches the Python `DexReport` dataclass).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexReport {
    pub name: String,
    pub size: usize,
    pub sha256: String,
    pub classes_count: usize,
    pub methods_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vbpd_container: Option<VbpdContainer>,
    pub f_dispatch_sites: HashMap<String, DispatchBucket>,
    /// Full list of decoded vm_str plaintexts. Cleared by the
    /// orchestrator before writing to JSON (kept separately on disk).
    pub decoded_strings: Vec<String>,
    pub vmp_protected_methods: Vec<VmpProtectedMethod>,
}

/// Dalvik instruction widths (in bytes). Mirrors the Python `INSN_WIDTH`
/// table. 0 marks payloads (handled specially in [`disasm_iter`]).
#[rustfmt::skip]
const INSN_WIDTH: [u8; 256] = {
    let mut w = [2u8; 256];
    // Format-by-opcode (only entries that differ from the default of 2).
    // Most of the table is filled with the Python literal; everything
    // unlisted defaults to 2 (which is what the Python's .get(op, 2) does).
    let pairs: &[(usize, u8)] = &[
        (0x02, 4), (0x03, 6), (0x05, 4), (0x06, 6),
        (0x08, 4), (0x09, 6),
        (0x13, 4), (0x14, 6), (0x15, 4), (0x16, 4), (0x17, 6),
        (0x18, 10), (0x19, 4), (0x1a, 4), (0x1b, 6), (0x1c, 4),
        (0x1f, 4),
        (0x20, 4), (0x22, 4), (0x23, 4), (0x24, 6), (0x25, 6), (0x26, 6),
        (0x29, 4), (0x2a, 6), (0x2b, 6), (0x2c, 6), (0x2d, 4), (0x2e, 4), (0x2f, 4),
        (0x30, 4), (0x31, 4), (0x32, 4), (0x33, 4), (0x34, 4), (0x35, 4), (0x36, 4), (0x37, 4),
        (0x38, 4), (0x39, 4), (0x3a, 4), (0x3b, 4), (0x3c, 4), (0x3d, 4),
        (0x44, 4), (0x45, 4), (0x46, 4), (0x47, 4), (0x48, 4), (0x49, 4), (0x4a, 4), (0x4b, 4),
        (0x4c, 4), (0x4d, 4), (0x4e, 4), (0x4f, 4), (0x50, 4), (0x51, 4),
        (0x52, 4), (0x53, 4), (0x54, 4), (0x55, 4), (0x56, 4), (0x57, 4), (0x58, 4), (0x59, 4),
        (0x5a, 4), (0x5b, 4), (0x5c, 4), (0x5d, 4), (0x5e, 4), (0x5f, 4),
        (0x60, 4), (0x61, 4),
        (0x62, 4), (0x63, 4), (0x64, 4), (0x65, 4), (0x66, 4), (0x67, 4), (0x68, 4), (0x69, 4),
        (0x6a, 4), (0x6b, 4), (0x6c, 4), (0x6d, 4),
        (0x6e, 6), (0x6f, 6), (0x70, 6), (0x71, 6), (0x72, 6),
        (0x74, 6), (0x75, 6), (0x76, 6), (0x77, 6), (0x78, 6),
        (0x90, 4), (0x91, 4), (0x92, 4), (0x93, 4), (0x94, 4), (0x95, 4), (0x96, 4), (0x97, 4),
        (0x98, 4), (0x99, 4), (0x9a, 4), (0x9b, 4), (0x9c, 4), (0x9d, 4), (0x9e, 4), (0x9f, 4),
        (0xa0, 4), (0xa1, 4), (0xa2, 4), (0xa3, 4), (0xa4, 4), (0xa5, 4), (0xa6, 4), (0xa7, 4),
        (0xa8, 4), (0xa9, 4), (0xaa, 4), (0xab, 4), (0xac, 4), (0xad, 4), (0xae, 4), (0xaf, 4),
        (0xd0, 4), (0xd1, 4), (0xd2, 4), (0xd3, 4), (0xd4, 4), (0xd5, 4), (0xd6, 4), (0xd7, 4),
        (0xd8, 4), (0xd9, 4), (0xda, 4), (0xdb, 4), (0xdc, 4), (0xdd, 4), (0xde, 4), (0xdf, 4),
        (0xe0, 4), (0xe1, 4), (0xe2, 4),
        (0xfa, 8), (0xfb, 10), (0xfc, 6), (0xfd, 6), (0xfe, 4), (0xff, 4),
    ];
    let mut i = 0;
    while i < pairs.len() {
        let (op, width) = pairs[i];
        w[op] = width;
        i += 1;
    }
    w
};

/// One yielded instruction from [`disasm_iter`].
struct Insn<'a> {
    pc: usize,
    op: u8,
    raw: &'a [u8],
}

/// Stream Dalvik instructions starting at `insns_off`, walking
/// `insns_bytes` bytes. Handles the three payload pseudo-instructions
/// (packed-switch, sparse-switch, fill-array-data) inline.
fn disasm_iter<'a>(d: &'a [u8], insns_off: usize, insns_bytes: usize) -> Vec<Insn<'a>> {
    let end = (insns_off + insns_bytes).min(d.len());
    let mut out = Vec::new();
    let mut i = insns_off;
    while i + 2 <= end {
        let op = d[i];
        let mut width = INSN_WIDTH[op as usize] as usize;
        // op 0x00 is nop OR payload pseudo-instruction.
        if op == 0x00 {
            let tag = if i + 2 <= end { d[i + 1] } else { 0 };
            if tag == 0x01 && i + 4 <= end {
                // packed-switch-payload
                let size = u16::from_le_bytes([d[i + 2], d[i + 3]]) as usize;
                width = 8 + size * 4;
            } else if tag == 0x02 && i + 4 <= end {
                // sparse-switch-payload
                let size = u16::from_le_bytes([d[i + 2], d[i + 3]]) as usize;
                width = 4 + size * 8;
            } else if tag == 0x03 && i + 8 <= end {
                // fill-array-data-payload
                let element_width = u16::from_le_bytes([d[i + 2], d[i + 3]]) as usize;
                let size = u32::from_le_bytes([d[i + 4], d[i + 5], d[i + 6], d[i + 7]]) as usize;
                let mut bsize = size * element_width;
                if bsize & 1 != 0 {
                    bsize += 1;
                }
                width = 8 + bsize;
            }
        }
        if width == 0 {
            width = 2;
        }
        let stop = (i + width).min(end);
        out.push(Insn {
            pc: i,
            op,
            raw: &d[i..stop],
        });
        i += width;
    }
    out
}

/// Walk *backwards* from `invoke_off` looking for the most recent
/// `const-string` / `const-string/jumbo` that writes into register
/// `target_reg`. We do this only within the same code_item.
fn find_const_string_for_register(
    insns: &[Insn<'_>],
    invoke_pc: usize,
    target_reg: u8,
    parsed: &platypus_dex::parser::ParsedDex,
) -> Option<String> {
    let mut last_const: Option<String> = None;
    for ins in insns {
        if ins.pc >= invoke_pc {
            break;
        }
        if ins.op == 0x1a && ins.raw.len() >= 4 {
            // const-string vAA, string@BBBB (21c, 4 bytes)
            let v_aa = ins.raw[1];
            let str_idx = u16::from_le_bytes([ins.raw[2], ins.raw[3]]) as usize;
            if v_aa == target_reg {
                if let Some(s) = parsed.lookup_string(str_idx) {
                    last_const = Some(s.to_string());
                }
            }
        } else if ins.op == 0x1b && ins.raw.len() >= 6 {
            // const-string/jumbo vAA, string@BBBBBBBB (31c, 6 bytes)
            let v_aa = ins.raw[1];
            let str_idx =
                u32::from_le_bytes([ins.raw[2], ins.raw[3], ins.raw[4], ins.raw[5]]) as usize;
            if v_aa == target_reg {
                if let Some(s) = parsed.lookup_string(str_idx) {
                    last_const = Some(s.to_string());
                }
            }
        }
    }
    last_const
}

/// Iterator over `(class_name, method_idx, code_off)` for every method
/// with a non-zero `code_off` in `parsed`. Replays the
/// `method_idx_diff` accumulation done by the DEX format.
fn iter_methods_with_code(parsed: &platypus_dex::parser::ParsedDex) -> Vec<(String, u32, u64)> {
    let mut out = Vec::new();
    for cd in &parsed.class_defs {
        let Some(class_data): Option<&ClassDataItem> = cd.class_data.as_ref() else { continue };
        let cls_name = cd.type_name.clone();
        for kind in [&class_data.direct_methods, &class_data.virtual_methods] {
            let mut last_idx: u64 = 0;
            for em in kind {
                let EncodedMethod {
                    method_idx_diff,
                    access_flags: _,
                    code_off,
                } = em;
                last_idx += method_idx_diff;
                if *code_off == 0 {
                    continue;
                }
                out.push((cls_name.clone(), last_idx as u32, *code_off));
            }
        }
    }
    out
}

/// Walk a single DEX and produce its [`DexReport`].
///
/// - Validates the header (via the parser's own checks).
/// - Detects the VBPD container, if any.
/// - For every F<buildId>_NN call-site, records (caller_class,
///   caller_method, arg-string-if-const).
/// - Statically decodes F<buildId>_11 const-string arguments via vm_str.
pub fn analyse_dex(
    dex_bytes: &[u8],
    dex_name: &str,
    build_id_hex: &str,
) -> std::io::Result<DexReport> {
    let dex = DexFileWithRaw::from_bytes(dex_bytes.to_vec(), dex_name.to_string())?;
    let parsed = &dex.parsed;

    let sha256 = {
        let mut h = Sha256::new();
        h.update(dex_bytes);
        let digest = h.finalize();
        let mut s = String::with_capacity(digest.len() * 2);
        use std::fmt::Write;
        for b in digest {
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    };

    let mut rep = DexReport {
        name: dex_name.to_string(),
        size: dex_bytes.len(),
        sha256,
        classes_count: parsed.class_defs.len(),
        methods_count: parsed.method_ids.len(),
        vbpd_container: None,
        f_dispatch_sites: HashMap::new(),
        decoded_strings: Vec::new(),
        vmp_protected_methods: Vec::new(),
    };

    // VBPD container.
    rep.vbpd_container = find_vbpd_container(dex_bytes, dex_name);

    // Locate F<buildId>_NN method-ids in this DEX.
    let f_prefix = format!("F{}_", build_id_hex);
    let m_class = format!("Lm{};", build_id_hex);
    let mut targets: HashMap<u32, String> = HashMap::new();
    for (idx, m) in parsed.method_ids.iter().enumerate() {
        if m.class_name == m_class && m.method_name.starts_with(&f_prefix) {
            // Python keeps the leading `_`: name[len(F_PREFIX)-1:]
            // For F<id>_11 with f_prefix="F<id>_", that's "_11".
            let suffix = m.method_name[f_prefix.len() - 1..].to_string();
            targets.insert(idx as u32, suffix);
        }
    }

    if targets.is_empty() {
        return Ok(rep);
    }

    // Walk every method body. For each invoke-static / invoke-static/range
    // that targets one of those method-ids, harvest a call-site record.
    let raw = dex.raw_bytes();
    let vmp_variants: std::collections::HashSet<&str> = [
        "_00", "_01", "_02", "_03", "_04", "_05", "_06", "_07", "_08", "_09",
    ]
    .iter()
    .copied()
    .collect();

    for (cls_name, m_idx, code_off) in iter_methods_with_code(parsed) {
        // Read the code_item header to find insns_off + insns_bytes.
        // The code_item is 16 bytes; insns follow at code_off + 16.
        let co = code_off as usize;
        if co + 16 > raw.len() {
            continue;
        }
        let insns_size =
            u32::from_le_bytes([raw[co + 12], raw[co + 13], raw[co + 14], raw[co + 15]]) as usize;
        let insns_off = co + 16;
        let insns_bytes = insns_size * 2;
        if insns_off + insns_bytes > raw.len() {
            continue;
        }
        let insns = disasm_iter(raw, insns_off, insns_bytes);

        for ins in &insns {
            let (suff, raw_b) = match ins.op {
                0x71 if ins.raw.len() >= 6 => {
                    // invoke-static (format 35c, 6 bytes)
                    let midx = u16::from_le_bytes([ins.raw[2], ins.raw[3]]) as u32;
                    match targets.get(&midx) {
                        Some(s) => (s.clone(), ins.raw),
                        None => continue,
                    }
                }
                0x76 if ins.raw.len() >= 6 => {
                    // invoke-static/range (format 3rc, 6 bytes)
                    let midx = u16::from_le_bytes([ins.raw[2], ins.raw[3]]) as u32;
                    match targets.get(&midx) {
                        Some(s) => (s.clone(), ins.raw),
                        None => continue,
                    }
                }
                _ => continue,
            };

            // Resolve caller method + proto descriptor.
            let (mname, descriptor) = parsed
                .method_ids
                .get(m_idx as usize)
                .map(|m| (m.method_name.clone(), m.proto_desc.clone()))
                .unwrap_or_default();

            let bucket = rep
                .f_dispatch_sites
                .entry(suff.clone())
                .or_default();
            bucket.count += 1;

            // 35c-format invoke-static yields 5-nibble register list.
            // invoke-static/range omits it (the range is implicit).
            let mut site = DispatchSite {
                caller_class: cls_name.clone(),
                caller_method: mname.clone(),
                caller_descriptor: descriptor.clone(),
                regs: Vec::new(),
                encoded: None,
                decoded: None,
            };
            if ins.op == 0x71 {
                let arg_count = (raw_b[1] >> 4) & 0xf;
                let mut regs = vec![
                    raw_b[4] & 0xf,            // C
                    (raw_b[4] >> 4) & 0xf,     // D
                    raw_b[5] & 0xf,            // E
                    (raw_b[5] >> 4) & 0xf,     // F
                    raw_b[1] & 0xf,            // G
                ];
                regs.truncate(arg_count as usize);
                site.regs = regs;

                if suff == "_11" && !site.regs.is_empty() {
                    let target_reg = site.regs[0];
                    if let Some(s) = find_const_string_for_register(
                        &insns,
                        ins.pc,
                        target_reg,
                        parsed,
                    ) {
                        site.encoded = Some(s.clone());
                        if let Some(dec) = vm_str_decode(&s) {
                            rep.decoded_strings.push(dec.clone());
                            site.decoded = Some(dec);
                        }
                    }
                } else if vmp_variants.contains(suff.as_str()) {
                    rep.vmp_protected_methods.push(VmpProtectedMethod {
                        caller_class: cls_name.clone(),
                        caller_method: mname.clone(),
                        caller_descriptor: descriptor.clone(),
                        dispatch_variant: suff.clone(),
                        regs: site.regs.clone(),
                    });
                }
            }
            // For invoke-static/range we don't expand the register
            // list — matches the Python which also leaves it off the
            // site record for 0x76.
            bucket.sites.push(site);
        }
    }

    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walking an empty insn stream should produce no instructions
    /// without panicking.
    #[test]
    fn disasm_iter_empty() {
        let buf = vec![];
        let v = disasm_iter(&buf, 0, 0);
        assert!(v.is_empty());
    }

    /// A trivial nop should be yielded as a 2-byte instruction.
    #[test]
    fn disasm_iter_handles_nop() {
        let buf = vec![0x00, 0x00, 0x0e, 0x00]; // nop + return-void
        let v = disasm_iter(&buf, 0, 4);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].op, 0x00);
        assert_eq!(v[1].op, 0x0e);
    }
}
