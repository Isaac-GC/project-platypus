//! Jiagu plaintext-`code_item` recovery.
//!
//! Empirical finding (2026-05-18): Jiagu's "encrypted" data section
//! (entries 1..n-1 after the `qh\x00\x01` trailer) is only PARTIALLY
//! encrypted. The class/method/type/string ID tables and the
//! `string_data` section are encrypted into `pre_e0` (~1 MB blob with
//! full entropy ≈ 7.999), but the bulk Dalvik method bodies are
//! concatenated as plaintext `code_item` structures in:
//!
//! - the latter ~2.6 MB of entry 0 (already carved as
//!   `jiagu_entry0_body.bin` by `jiagu.py`)
//! - the large plaintext middle of `jiagu_post_e0.bin`
//!
//! This module walks those byte ranges with a strict `code_item`
//! parser (including `try_item[]` and `encoded_catch_handler_list` for
//! items with tries), so we recover the full body of every protected
//! method *for which the bytecode is in the data section*.
//!
//! Pure-static — no Unicorn, no Frida, no device-side decryption.
//!
//! See `unpacker/packer_backends/jiagu_codeitems.py` for the full
//! discussion + module-level docstring.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

// ---------------------------------------------------------------------------
// ULEB128 / SLEB128 helpers.
// ---------------------------------------------------------------------------

/// Decode a ULEB128 value from `buf` starting at `off`. Returns
/// `Some((value, bytes_consumed))` or `None` on overflow / EOF.
fn uleb128(buf: &[u8], off: usize) -> Option<(u32, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut n = 0usize;
    loop {
        if off + n >= buf.len() {
            return None;
        }
        let b = buf[off + n];
        n += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift > 32 {
            return None;
        }
    }
    Some((result as u32, n))
}

/// Decode an SLEB128 value from `buf` starting at `off`.
fn sleb128(buf: &[u8], off: usize) -> Option<(i32, usize)> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    let mut n = 0usize;
    loop {
        if off + n >= buf.len() {
            return None;
        }
        let b = buf[off + n];
        n += 1;
        result |= ((b & 0x7f) as i64) << shift;
        shift += 7;
        if (b & 0x80) == 0 {
            if (b & 0x40) != 0 {
                result |= -(1i64 << shift);
            }
            break;
        }
        if shift > 32 {
            return None;
        }
    }
    Some((result as i32, n))
}

/// Encode a u32 as ULEB128. Matches the Python `_uleb128_emit`.
fn uleb128_emit(mut v: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// code_item parser.
// ---------------------------------------------------------------------------

/// A single recovered Dalvik `code_item`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeItem {
    /// Offset within the source buffer.
    pub off: usize,
    /// End offset (exclusive) within the source buffer.
    pub body_end: usize,
    pub regs: u16,
    pub ins: u16,
    pub outs: u16,
    pub tries: u16,
    pub debug_off: u32,
    /// Count of u16 instruction code-units.
    pub insns_size: u32,
    /// Full `code_item` bytes (off..body_end).
    pub bytes: Vec<u8>,
}

/// Try to parse a `code_item` at `off` in `buf`. Returns `None` if the
/// bytes there don't look like a valid item.
///
/// Validation is strict (matches Python `parse_code_item`):
/// - `registers_size ≤ 256`, `ins_size ≤ 256`, `outs_size ≤ 256`,
///   `tries ≤ 64`
/// - `ins_size ≤ registers_size` (when `registers_size > 0`)
/// - `insns_size ∈ (0, 8192]`
/// - `debug_info_off < 2^24`
/// - if `tries > 0`, each `try_item`'s range must lie within `insns_size`
/// - the `encoded_catch_handler_list` must parse without overflow
pub fn parse_code_item(buf: &[u8], off: usize) -> Option<CodeItem> {
    if off + 16 > buf.len() {
        return None;
    }
    let regs = u16::from_le_bytes(buf[off..off + 2].try_into().ok()?);
    let ins = u16::from_le_bytes(buf[off + 2..off + 4].try_into().ok()?);
    let outs = u16::from_le_bytes(buf[off + 4..off + 6].try_into().ok()?);
    let tries = u16::from_le_bytes(buf[off + 6..off + 8].try_into().ok()?);
    let debug_off = u32::from_le_bytes(buf[off + 8..off + 12].try_into().ok()?);
    let insns_size = u32::from_le_bytes(buf[off + 12..off + 16].try_into().ok()?);
    if regs > 256 || outs > 256 || tries > 64 || ins > 256 {
        return None;
    }
    if regs > 0 && ins > regs {
        return None;
    }
    if insns_size == 0 || insns_size > 8192 {
        return None;
    }
    if debug_off > (1 << 24) {
        return None;
    }
    let mut p = off + 16 + (insns_size as usize) * 2;
    if p > buf.len() {
        return None;
    }
    if tries > 0 {
        if (insns_size & 1) == 1 {
            p += 2;
            if p > buf.len() {
                return None;
            }
        }
        for _ in 0..tries {
            if p + 8 > buf.len() {
                return None;
            }
            let sa = u32::from_le_bytes(buf[p..p + 4].try_into().ok()?);
            let ic = u16::from_le_bytes(buf[p + 4..p + 6].try_into().ok()?);
            let _ho = u16::from_le_bytes(buf[p + 6..p + 8].try_into().ok()?);
            if sa + (ic as u32) > insns_size {
                return None;
            }
            p += 8;
        }
        let (sz, n) = uleb128(buf, p)?;
        if sz > 256 {
            return None;
        }
        p += n;
        for _ in 0..sz {
            let (ssz, n) = sleb128(buf, p)?;
            p += n;
            let cnt = ssz.unsigned_abs() as u32;
            for _ in 0..cnt {
                let (_ti, n) = uleb128(buf, p)?;
                p += n;
                let (_ad, n) = uleb128(buf, p)?;
                p += n;
            }
            if ssz <= 0 {
                let (_ad, n) = uleb128(buf, p)?;
                p += n;
            }
        }
    }
    Some(CodeItem {
        off,
        body_end: p,
        regs,
        ins,
        outs,
        tries,
        debug_off,
        insns_size,
        bytes: buf[off..p].to_vec(),
    })
}

/// Walk through `buf` greedily finding plaintext `code_item`s.
///
/// Assumes items are 4-byte aligned relative to the start of `buf`.
/// After each successful parse, jumps to the next 4-byte boundary past
/// the body. On a failed parse, advances by 2 bytes (the regs_size u16
/// is 2-byte-aligned, so a 2-byte step is fine).
pub fn walk_code_items(buf: &[u8]) -> Vec<CodeItem> {
    let mut out = Vec::new();
    if buf.len() < 16 {
        return out;
    }
    let n = buf.len();
    let mut off = 0usize;
    while off + 16 < n {
        if let Some(ci) = parse_code_item(buf, off) {
            let next = (ci.body_end + 3) & !3;
            out.push(ci);
            off = next;
        } else {
            off += 2;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Entropy-guided scanning (skip encrypted regions cheaply).
// ---------------------------------------------------------------------------

fn entropy(buf: &[u8]) -> f64 {
    if buf.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in buf {
        counts[b as usize] += 1;
    }
    let n = buf.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

/// Find byte ranges of `buf` whose 256-byte-window Shannon entropy is
/// below `thresh`. Returns a list of `(start, end)` byte offsets.
///
/// DEX data sections are byte-distribution heavy on 0x00..small ULEB128
/// continuations (typical entropy 4.5–6.0). Encrypted data has entropy
/// > 7.5. The default threshold 6.5 cleanly separates the two.
pub fn find_plaintext_runs(buf: &[u8], chunk: usize, thresh: f64) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let n = buf.len();
    let mut in_run = false;
    let mut run_start = 0usize;
    let mut off = 0usize;
    while off < n {
        let end = (off + chunk).min(n);
        let sub = &buf[off..end];
        if sub.is_empty() {
            break;
        }
        let e = entropy(sub);
        if e < thresh {
            if !in_run {
                in_run = true;
                run_start = off;
            }
        } else if in_run {
            runs.push((run_start, off));
            in_run = false;
        }
        off += chunk;
    }
    if in_run {
        runs.push((run_start, n));
    }
    runs
}

// ---------------------------------------------------------------------------
// Synthetic DEX builder.
// ---------------------------------------------------------------------------

const DEX_MAGIC: &[u8; 8] = b"dex\n035\x00";
const DEX_HEADER_SIZE: usize = 0x70;

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

/// Build a minimal-yet-valid DEX file that wraps the recovered
/// `code_item`s.
///
/// The synthetic DEX has:
/// - one class `LRecovered;` (subclass of `Ljava/lang/Object;`)
/// - one method per recovered `code_item`, named `m00000`, `m00001`,
///   ... — all `static synthetic` with proto `()V`
/// - the original `code_item` bytes verbatim
///
/// NOTE: this DEX does not run on ART. It does parse correctly under
/// `androguard` / `dexdump`, exposing the bytecode for analysis.
///
/// Direct port of `jiagu_codeitems.build_synthetic_dex`. The Python
/// version's layout decisions (string ordering, class_data emitted
/// after code_items, map_list at the very end) are preserved 1:1.
pub fn build_synthetic_dex(code_items: &[CodeItem]) -> Vec<u8> {
    build_synthetic_dex_with(code_items, b"LRecovered;", b"m")
}

/// Variant that lets the caller pick custom class descriptor + method
/// name prefix. Matches `build_synthetic_dex(class_name=..., method_prefix=...)`.
pub fn build_synthetic_dex_with(
    code_items: &[CodeItem],
    class_name: &[u8],
    method_prefix: &[u8],
) -> Vec<u8> {
    // Cap to keep the output reasonable — > 65535 methods break some
    // Dalvik u16 limits.
    let cap = 65535usize;
    let code_items: &[CodeItem] = if code_items.len() > cap {
        &code_items[..cap]
    } else {
        code_items
    };

    // ---- String table -----------------------------------------------------
    let mut strs: Vec<Vec<u8>> = Vec::new();
    strs.push(b"Ljava/lang/Object;".to_vec());
    strs.push(class_name.to_vec());
    strs.push(b"V".to_vec()); // shorty for ()V
    strs.push(b"()V".to_vec());
    for i in 0..code_items.len() {
        let mut name = Vec::from(method_prefix);
        name.extend_from_slice(format!("{:05}", i).as_bytes());
        strs.push(name);
    }
    strs.sort();
    let str_idx: HashMap<Vec<u8>, u32> =
        strs.iter().enumerate().map(|(i, s)| (s.clone(), i as u32)).collect();
    let str_count = strs.len() as u32;

    // ---- Type IDs (index into strings) -----------------------------------
    let mut type_ids_strs: Vec<Vec<u8>> =
        vec![b"Ljava/lang/Object;".to_vec(), class_name.to_vec()];
    type_ids_strs.sort_by_key(|s| str_idx[s]);
    // Dedup preserving insertion order.
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    type_ids_strs.retain(|s| seen.insert(s.clone()));
    // Add 'V' (void) to type_ids if not already present.
    if !type_ids_strs.iter().any(|s| s == b"V") {
        type_ids_strs.push(b"V".to_vec());
    }
    let type_idx_recovered = type_ids_strs.iter().position(|s| s == class_name).unwrap();
    let type_idx_object = type_ids_strs
        .iter()
        .position(|s| s == b"Ljava/lang/Object;")
        .unwrap();
    let type_idx_void = type_ids_strs.iter().position(|s| s == b"V").unwrap();
    let type_ids: Vec<u32> = type_ids_strs.iter().map(|s| str_idx[s]).collect();
    let type_count = type_ids.len() as u32;

    // ---- Proto IDs --------------------------------------------------------
    let proto_count = 1u32;
    let proto_shorty_idx = str_idx[&b"V".to_vec()];
    let proto_return_type_idx = type_idx_void as u32;
    let proto_parameters_off: u32 = 0;

    // ---- Field IDs --------------------------------------------------------
    let field_count = 0u32;

    // ---- Method IDs -------------------------------------------------------
    let method_count = code_items.len() as u32;
    let mut method_ids_bin: Vec<u8> = Vec::with_capacity(method_count as usize * 8);
    for i in 0..method_count {
        let mut name = Vec::from(method_prefix);
        name.extend_from_slice(format!("{:05}", i).as_bytes());
        method_ids_bin.extend_from_slice(&(type_idx_recovered as u16).to_le_bytes());
        method_ids_bin.extend_from_slice(&(0u16).to_le_bytes());
        method_ids_bin.extend_from_slice(&str_idx[&name].to_le_bytes());
    }

    // ---- Class Defs -------------------------------------------------------
    let class_count = 1u32;

    // ---- Layout offsets ---------------------------------------------------
    let header_off = 0u32;
    let string_ids_off = DEX_HEADER_SIZE as u32;
    let type_ids_off = string_ids_off + str_count * 4;
    let proto_ids_off = type_ids_off + type_count * 4;
    let field_ids_off = proto_ids_off + proto_count * 12;
    let method_ids_off = field_ids_off + field_count * 8;
    let class_defs_off = method_ids_off + method_count * 8;
    let data_off = class_defs_off + class_count * 32;

    // ---- Build data section ----------------------------------------------
    let mut data: Vec<u8> = Vec::new();
    let cur_data_offset = |d_len: usize| data_off + d_len as u32;

    // 1. string_data items.
    let mut string_data_offsets: Vec<u32> = Vec::with_capacity(strs.len());
    for s in &strs {
        string_data_offsets.push(cur_data_offset(data.len()));
        data.extend_from_slice(&uleb128_emit(s.len() as u32));
        data.extend_from_slice(s);
        data.push(0); // null terminator
    }

    // 2. (Python builds + rewinds a placeholder class_data_item here; we
    //    skip that — we'll write the real one after the code_items.)

    // 3. code_items, 4-byte aligned.
    while (data_off as usize + data.len()) % 4 != 0 {
        data.push(0);
    }
    let mut code_offsets: Vec<u32> = Vec::with_capacity(code_items.len());
    for ci in code_items {
        while (data_off as usize + data.len()) % 4 != 0 {
            data.push(0);
        }
        code_offsets.push(cur_data_offset(data.len()));
        data.extend_from_slice(&ci.bytes);
    }

    // 4. class_data_item (no alignment needed).
    let class_data_off_val = cur_data_offset(data.len());
    data.extend_from_slice(&uleb128_emit(0)); // static_fields_size
    data.extend_from_slice(&uleb128_emit(0)); // instance_fields_size
    data.extend_from_slice(&uleb128_emit(method_count));
    data.extend_from_slice(&uleb128_emit(0)); // virtual_methods_size
    // access_flags = ACC_STATIC|ACC_PUBLIC|ACC_SYNTHETIC = 0x9 | 0x1000 = 0x1009
    let acc: u32 = 0x1009;
    let mut prev = 0u32;
    for i in 0..method_count {
        let diff = i - prev;
        prev = i;
        data.extend_from_slice(&uleb128_emit(diff));
        data.extend_from_slice(&uleb128_emit(acc));
        data.extend_from_slice(&uleb128_emit(code_offsets[i as usize]));
    }

    // 5. map_list — 4-byte aligned.
    while (data_off as usize + data.len()) % 4 != 0 {
        data.push(0);
    }
    let map_off = cur_data_offset(data.len());

    // Build map entries: (kind, size, offset)
    let mut map_entries: Vec<(u16, u32, u32)> = Vec::new();
    let add_map = |kind: u16, size: u32, off: u32, entries: &mut Vec<(u16, u32, u32)>| {
        entries.push((kind, size, off));
    };
    add_map(0x0000, 1, header_off, &mut map_entries); // TYPE_HEADER_ITEM
    if str_count > 0 {
        add_map(0x0001, str_count, string_ids_off, &mut map_entries);
    }
    if type_count > 0 {
        add_map(0x0002, type_count, type_ids_off, &mut map_entries);
    }
    if proto_count > 0 {
        add_map(0x0003, proto_count, proto_ids_off, &mut map_entries);
    }
    if field_count > 0 {
        add_map(0x0004, field_count, field_ids_off, &mut map_entries);
    }
    if method_count > 0 {
        add_map(0x0005, method_count, method_ids_off, &mut map_entries);
    }
    if class_count > 0 {
        add_map(0x0006, class_count, class_defs_off, &mut map_entries);
    }
    add_map(
        0x2001,
        code_items.len() as u32,
        if !code_offsets.is_empty() {
            code_offsets[0]
        } else {
            0
        },
        &mut map_entries,
    );
    add_map(
        0x2002,
        str_count,
        if !string_data_offsets.is_empty() {
            string_data_offsets[0]
        } else {
            0
        },
        &mut map_entries,
    );
    add_map(0x2000, 1, class_data_off_val, &mut map_entries);
    add_map(0x1000, 1, map_off, &mut map_entries);

    data.extend_from_slice(&(map_entries.len() as u32).to_le_bytes());
    for (kind, size, off) in &map_entries {
        data.extend_from_slice(&kind.to_le_bytes());
        data.extend_from_slice(&(0u16).to_le_bytes());
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(&off.to_le_bytes());
    }

    // ---- Build proto_ids --------------------------------------------------
    let mut proto_ids_bin = Vec::with_capacity(12);
    proto_ids_bin.extend_from_slice(&proto_shorty_idx.to_le_bytes());
    proto_ids_bin.extend_from_slice(&proto_return_type_idx.to_le_bytes());
    proto_ids_bin.extend_from_slice(&proto_parameters_off.to_le_bytes());

    // ---- string_ids -------------------------------------------------------
    let mut string_ids_bin = Vec::with_capacity(strs.len() * 4);
    for off in &string_data_offsets {
        string_ids_bin.extend_from_slice(&off.to_le_bytes());
    }

    // ---- type_ids ---------------------------------------------------------
    let mut type_ids_bin = Vec::with_capacity(type_ids.len() * 4);
    for si in &type_ids {
        type_ids_bin.extend_from_slice(&si.to_le_bytes());
    }

    // ---- class_defs -------------------------------------------------------
    let mut class_defs_bin = Vec::with_capacity(32);
    class_defs_bin.extend_from_slice(&(type_idx_recovered as u32).to_le_bytes());
    class_defs_bin.extend_from_slice(&0x1u32.to_le_bytes()); // access_flags ACC_PUBLIC
    class_defs_bin.extend_from_slice(&(type_idx_object as u32).to_le_bytes());
    class_defs_bin.extend_from_slice(&0u32.to_le_bytes()); // interfaces_off
    class_defs_bin.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // source_file_idx (NO_INDEX)
    class_defs_bin.extend_from_slice(&0u32.to_le_bytes()); // annotations_off
    class_defs_bin.extend_from_slice(&class_data_off_val.to_le_bytes());
    class_defs_bin.extend_from_slice(&0u32.to_le_bytes()); // static_values_off

    // ---- Final assembly --------------------------------------------------
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&string_ids_bin);
    body.extend_from_slice(&type_ids_bin);
    body.extend_from_slice(&proto_ids_bin);
    // no fields
    body.extend_from_slice(&method_ids_bin);
    body.extend_from_slice(&class_defs_bin);
    body.extend_from_slice(&data);

    let file_size = DEX_HEADER_SIZE + body.len();
    let data_size = data.len() as u32;

    // ---- Header ----------------------------------------------------------
    let mut hdr = vec![0u8; DEX_HEADER_SIZE];
    hdr[0..8].copy_from_slice(DEX_MAGIC);
    // checksum at +8, signature at +12 — patched later.
    hdr[32..36].copy_from_slice(&(file_size as u32).to_le_bytes());
    hdr[36..40].copy_from_slice(&(DEX_HEADER_SIZE as u32).to_le_bytes());
    hdr[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // endian_tag
    hdr[44..48].copy_from_slice(&0u32.to_le_bytes()); // link_size
    hdr[48..52].copy_from_slice(&0u32.to_le_bytes()); // link_off
    hdr[52..56].copy_from_slice(&map_off.to_le_bytes());
    hdr[56..60].copy_from_slice(&str_count.to_le_bytes());
    hdr[60..64].copy_from_slice(&string_ids_off.to_le_bytes());
    hdr[64..68].copy_from_slice(&type_count.to_le_bytes());
    hdr[68..72].copy_from_slice(&type_ids_off.to_le_bytes());
    hdr[72..76].copy_from_slice(&proto_count.to_le_bytes());
    hdr[76..80].copy_from_slice(&proto_ids_off.to_le_bytes());
    hdr[80..84].copy_from_slice(&field_count.to_le_bytes());
    hdr[84..88].copy_from_slice(&(if field_count > 0 { field_ids_off } else { 0 }).to_le_bytes());
    hdr[88..92].copy_from_slice(&method_count.to_le_bytes());
    hdr[92..96].copy_from_slice(&method_ids_off.to_le_bytes());
    hdr[96..100].copy_from_slice(&class_count.to_le_bytes());
    hdr[100..104].copy_from_slice(&class_defs_off.to_le_bytes());
    hdr[104..108].copy_from_slice(&data_size.to_le_bytes());
    hdr[108..112].copy_from_slice(&data_off.to_le_bytes());

    let mut full: Vec<u8> = Vec::with_capacity(hdr.len() + body.len());
    full.extend_from_slice(&hdr);
    full.extend_from_slice(&body);

    // Compute SHA-1 over bytes [32..end] and patch into hdr[12..32].
    let mut sha = Sha1::new();
    sha.update(&full[32..]);
    let sig = sha.finalize();
    full[12..32].copy_from_slice(&sig);

    // Compute Adler-32 over bytes [12..end] and patch into hdr[8..12].
    let checksum = adler32(&full[12..]);
    full[8..12].copy_from_slice(&checksum.to_le_bytes());

    full
}

// ---------------------------------------------------------------------------
// Top-level driver.
// ---------------------------------------------------------------------------

/// Summary of what was recovered. Mirrors Python `RecoveryResult`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecoveryResult {
    pub entry0_code_items: usize,
    pub entry0_bytes: usize,
    pub post_e0_code_items: usize,
    pub post_e0_bytes: usize,
    pub pre_e0_code_items: usize,
    pub pre_e0_bytes: usize,
    pub total_code_items: usize,
    pub total_bytes: usize,
    /// (start_hex, end_hex, size) tuples for the post-e0 plaintext runs.
    pub plaintext_runs_post_e0: Vec<PlaintextRun>,
    pub synthetic_dex_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaintextRun {
    pub start_hex: String,
    pub end_hex: String,
    pub size: usize,
}

/// Walk all plaintext regions and return `(items, summary)`.
///
/// `entry0_body`, `post_e0`, `pre_e0` are the byte buffers carved by
/// `jiagu.py::_carve_trailer_artefacts` — i.e.
/// `jiagu_entry0_body.bin`, `jiagu_post_e0.bin`, `jiagu_pre_e0.bin`.
pub fn recover_from_carved(
    entry0_body: &[u8],
    post_e0: &[u8],
    pre_e0: &[u8],
) -> (Vec<CodeItem>, RecoveryResult) {
    let mut result = RecoveryResult::default();
    let mut all_items: Vec<CodeItem> = Vec::new();

    let e0_items = walk_code_items(entry0_body);
    result.entry0_code_items = e0_items.len();
    result.entry0_bytes = e0_items.iter().map(|it| it.body_end - it.off).sum();
    all_items.extend(e0_items);

    if !post_e0.is_empty() {
        let post_items = walk_code_items(post_e0);
        result.post_e0_code_items = post_items.len();
        result.post_e0_bytes = post_items.iter().map(|it| it.body_end - it.off).sum();
        all_items.extend(post_items);
        let runs = find_plaintext_runs(post_e0, 256, 6.5);
        result.plaintext_runs_post_e0 = runs
            .into_iter()
            .map(|(s, e)| PlaintextRun {
                start_hex: format!("0x{:x}", s),
                end_hex: format!("0x{:x}", e),
                size: e - s,
            })
            .collect();
    }

    if !pre_e0.is_empty() {
        let pre_items = walk_code_items(pre_e0);
        result.pre_e0_code_items = pre_items.len();
        result.pre_e0_bytes = pre_items.iter().map(|it| it.body_end - it.off).sum();
        all_items.extend(pre_items);
    }

    result.total_code_items = all_items.len();
    result.total_bytes = result.entry0_bytes + result.post_e0_bytes + result.pre_e0_bytes;
    (all_items, result)
}

/// Concatenate all `code_item` bytes with a tiny TLV index for
/// forensics. Format:
///
/// ```text
///   magic            = b"JIAG_CI\x01"     (8 bytes)
///   n_items          = u32 LE
///   item[n]:
///     regs           = u16
///     ins            = u16
///     outs           = u16
///     tries          = u16
///     debug_off      = u32
///     insns_size     = u32
///     body_size      = u32                # total bytes following
///     body           = body_size bytes
/// ```
///
/// Direct port of Python `serialize_code_items`. The Python uses
/// `struct.pack('<HHHHIIi', ...)` — note `i` (signed) for `body_size`.
/// We mirror that signed-32 encoding for byte-for-byte compatibility,
/// even though body_size is logically unsigned.
pub fn serialize_code_items(items: &[CodeItem]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"JIAG_CI\x01");
    out.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for it in items {
        out.extend_from_slice(&it.regs.to_le_bytes());
        out.extend_from_slice(&it.ins.to_le_bytes());
        out.extend_from_slice(&it.outs.to_le_bytes());
        out.extend_from_slice(&it.tries.to_le_bytes());
        out.extend_from_slice(&it.debug_off.to_le_bytes());
        out.extend_from_slice(&it.insns_size.to_le_bytes());
        // Python uses signed i32 here — `len(body)` rarely overflows that
        // but we keep the encoding identical for binary compatibility.
        let body_len = it.bytes.len() as i32;
        out.extend_from_slice(&body_len.to_le_bytes());
        out.extend_from_slice(&it.bytes);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb128_round_trip() {
        for &v in &[0u32, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x12345, u32::MAX] {
            let buf = uleb128_emit(v);
            let (got, n) = uleb128(&buf, 0).unwrap();
            assert_eq!(got, v, "v={v:#x}");
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn sleb128_round_trip_small_values() {
        // Build manually for a couple of known small values: 0, 1, -1, 64, -64.
        // SLEB128 encoding for 0 = 0x00, 1 = 0x01, -1 = 0x7f, 64 = 0xc0 0x00, -64 = 0x40
        let cases: &[(i32, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (-1, &[0x7f]),
            (64, &[0xc0, 0x00]),
            (-64, &[0x40]),
        ];
        for (v, enc) in cases {
            let (got, n) = sleb128(enc, 0).unwrap();
            assert_eq!(got, *v);
            assert_eq!(n, enc.len());
        }
    }

    #[test]
    fn parse_code_item_no_tries() {
        // Minimal code_item: regs=1, ins=0, outs=0, tries=0,
        // debug_off=0, insns_size=1, then a 2-byte insn (return-void = 0x0e 0x00).
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&[0x0e, 0x00]);
        let ci = parse_code_item(&buf, 0).expect("code_item parses");
        assert_eq!(ci.regs, 1);
        assert_eq!(ci.insns_size, 1);
        assert_eq!(ci.body_end, 18);
    }

    #[test]
    fn parse_code_item_rejects_bogus_header() {
        // insns_size = 0 → reject
        let buf = vec![0u8; 32];
        assert!(parse_code_item(&buf, 0).is_none());
    }

    #[test]
    fn build_synthetic_dex_parses_min_header() {
        // Build a single fake code_item and roundtrip through the builder.
        let ci = CodeItem {
            off: 0,
            body_end: 18,
            regs: 1,
            ins: 0,
            outs: 0,
            tries: 0,
            debug_off: 0,
            insns_size: 1,
            bytes: {
                let mut v = Vec::new();
                v.extend_from_slice(&1u16.to_le_bytes());
                v.extend_from_slice(&0u16.to_le_bytes());
                v.extend_from_slice(&0u16.to_le_bytes());
                v.extend_from_slice(&0u16.to_le_bytes());
                v.extend_from_slice(&0u32.to_le_bytes());
                v.extend_from_slice(&1u32.to_le_bytes());
                v.extend_from_slice(&[0x0e, 0x00]);
                v
            },
        };
        let dex = build_synthetic_dex(&[ci]);
        assert!(dex.len() > 0x70);
        assert_eq!(&dex[..8], DEX_MAGIC);
        // checksum should be patched (not zero).
        let cksm = u32::from_le_bytes(dex[8..12].try_into().unwrap());
        assert_ne!(cksm, 0);
        // Verify adler32 matches.
        let actual = adler32(&dex[12..]);
        assert_eq!(cksm, actual);
    }

    #[test]
    fn adler32_known_vectors() {
        assert_eq!(adler32(b"hello"), 0x062c0215);
        assert_eq!(adler32(b""), 1);
    }
}
