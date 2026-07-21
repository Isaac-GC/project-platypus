//! Static cipher analysis for Jiagu's `libjiagu*.so` loader.
//!
//! Identifies and applies the static ciphers used by Jiagu's ARM64
//! loader (`libjiagu_a64.so`), without executing any code from the SO.
//! Complements the (still-unported) Unicorn-based emulator pass by
//! working entirely on the SO's bytes.
//!
//! Identified ciphers (across 16 distinct SHA-256s observed in the
//! corpus):
//!
//! 1. **Modified RC4 PRGA** at function start ~0xddfc (varies per build):
//!    `i += 2`, `j += S[i] + 1`. Used to decrypt one large
//!    buffer per JNI_OnLoad invocation.
//! 2. **Single-byte XOR (key in first byte of input)** in a function
//!    at ~0xd614 — format `[key:1][len:u32 LE][data:len]`.
//! 3. **Single-byte XOR with constant key 0xa5** for a static data
//!    section inside the SO itself.
//!
//! See `unpacker/packer_backends/jiagu_static_cipher.py` for the full
//! reverse-engineering write-up.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ELF parsing — minimal AArch64 ELF64 support.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Phdr {
    p_type: u32,
    #[allow(dead_code)]
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    #[allow(dead_code)]
    p_paddr: u64,
    p_filesz: u64,
    #[allow(dead_code)]
    p_memsz: u64,
    #[allow(dead_code)]
    p_align: u64,
}

fn parse_phdrs(d: &[u8]) -> Vec<Phdr> {
    let mut out = Vec::new();
    if d.len() < 0x40 || &d[..4] != b"\x7fELF" || d[4] != 2 {
        return out;
    }
    let e_phoff = u64::from_le_bytes(d[0x20..0x28].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(d[0x36..0x38].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(d[0x38..0x3a].try_into().unwrap()) as usize;
    for i in 0..e_phnum {
        let base = e_phoff + i * e_phentsize;
        if base + 0x38 > d.len() {
            break;
        }
        let ph = &d[base..base + 0x38];
        out.push(Phdr {
            p_type: u32::from_le_bytes(ph[0..4].try_into().unwrap()),
            p_flags: u32::from_le_bytes(ph[4..8].try_into().unwrap()),
            p_offset: u64::from_le_bytes(ph[8..16].try_into().unwrap()),
            p_vaddr: u64::from_le_bytes(ph[16..24].try_into().unwrap()),
            p_paddr: u64::from_le_bytes(ph[24..32].try_into().unwrap()),
            p_filesz: u64::from_le_bytes(ph[32..40].try_into().unwrap()),
            p_memsz: u64::from_le_bytes(ph[40..48].try_into().unwrap()),
            p_align: u64::from_le_bytes(ph[48..56].try_into().unwrap()),
        });
    }
    out
}

fn off_to_va(phs: &[Phdr], off: usize) -> Option<u64> {
    let off = off as u64;
    for p in phs {
        if p.p_type == 1 && p.p_offset <= off && off < p.p_offset + p.p_filesz {
            return Some(p.p_vaddr + (off - p.p_offset));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// AArch64 instruction decoders — just enough for the signature scan.
// ---------------------------------------------------------------------------

/// `ADD (immediate, 32-bit)` — returns `(Rd, Rn, imm12)` if matched.
fn decode_add_imm32(ins: u32) -> Option<(u32, u32, u32)> {
    if (ins >> 24) != 0b0001_0001 {
        return None;
    }
    if ((ins >> 22) & 1) != 0 {
        // shift = 0 only
        return None;
    }
    Some((ins & 0x1f, (ins >> 5) & 0x1f, (ins >> 10) & 0xfff))
}

/// `STRB (immediate, unsigned offset)` — returns `(Rt, Rn, imm12)` if
/// matched.
fn decode_strb_imm(ins: u32) -> Option<(u32, u32, u32)> {
    if (ins >> 22) != 0b0011_1001_00 {
        return None;
    }
    Some((ins & 0x1f, (ins >> 5) & 0x1f, (ins >> 10) & 0xfff))
}

// ---------------------------------------------------------------------------
// Cipher fingerprinting types.
// ---------------------------------------------------------------------------

/// Located instance of the modified-RC4 PRGA inside the SO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rc4Prga {
    /// Virtual address of the function's `sub sp, sp, #imm` prologue
    /// (0 if not found).
    pub prologue_va: u64,
    /// Virtual address of the `add wX, wX, #2` PRGA-invariant
    /// instruction.
    pub prga_inner_va: u64,
    /// Virtual address right after the loop's backward branch (the
    /// first instruction executed once the PRGA loop completes).
    pub loop_end_va: Option<u64>,
    /// Virtual addresses of `ret` instructions in the function body
    /// (typically 1–2 — canary-success + canary-fail paths).
    pub ret_vas: Vec<u64>,
}

/// Located instance of the SIMD-XOR cipher function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimdXor {
    pub prologue_va: u64,
    /// First instruction after the scalar tail loop.
    pub simd_exit_va: u64,
}

/// XOR-0xa5-encoded loader-strings data region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XorA5Region {
    pub start_off: usize,
    pub decoded_strings: Vec<Vec<u8>>,
    pub n_anchor_matches: usize,
}

/// Aggregate of all static-cipher findings for one libjiagu*.so.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiaguStaticCipherSummary {
    pub rc4_prgas: Vec<Rc4Prga>,
    pub simd_xors: Vec<SimdXor>,
    pub xor_a5: Option<XorA5Region>,
}

// ---------------------------------------------------------------------------
// RC4 PRGA finder.
// ---------------------------------------------------------------------------

fn read_u32_le(d: &[u8], off: usize) -> Option<u32> {
    if off + 4 > d.len() {
        return None;
    }
    Some(u32::from_le_bytes(d[off..off + 4].try_into().unwrap()))
}

/// Locate every Jiagu-style modified-RC4 PRGA in the given SO bytes.
///
/// The smoking gun is two adjacent instructions:
///
/// ```text
///     add wX, wX, #2          (increment i by 2 — the RC4 mod)
///     strb wX, [xN, #0x100]   (store i back to state[0x100])
/// ```
///
/// where `Rd_of_add == Rt_of_strb == Rn_of_add` (the `i` variable).
pub fn find_rc4_prga(so_bytes: &[u8]) -> Vec<Rc4Prga> {
    let phs = parse_phdrs(so_bytes);
    let mut out: Vec<Rc4Prga> = Vec::new();
    if so_bytes.len() < 8 {
        return out;
    }
    let mut off = 0usize;
    while off + 8 <= so_bytes.len() {
        let ins1 = read_u32_le(so_bytes, off).unwrap();
        let ins2 = read_u32_le(so_bytes, off + 4).unwrap();
        if let (Some(a), Some(s)) = (decode_add_imm32(ins1), decode_strb_imm(ins2)) {
            let (rd_a, rn_a, imm_a) = a;
            let (rt_s, _rn_s, imm_s) = s;
            if imm_a == 2 && imm_s == 0x100 && rd_a == rt_s && rd_a == rn_a {
                // Walk back for `sub sp, sp, #imm`.
                let mut prologue_off: Option<usize> = None;
                let mut back = 4usize;
                while back < 0x400 {
                    if off < back {
                        break;
                    }
                    let ins = read_u32_le(so_bytes, off - back).unwrap_or(0);
                    if (ins >> 22) == 0b1101000100
                        && (ins & 0x1f) == 31
                        && ((ins >> 5) & 0x1f) == 31
                    {
                        prologue_off = Some(off - back);
                        break;
                    }
                    back += 4;
                }
                // Find loop_end — scan forward for a backward branch within 512 bytes.
                let mut loop_end_off: Option<usize> = None;
                let mut o = off;
                while o < off + 0x200 {
                    if o + 4 > so_bytes.len() {
                        break;
                    }
                    let ins = read_u32_le(so_bytes, o).unwrap();
                    // B.cond (0101 0100 imm19 0 cond)
                    if (ins >> 24) == 0x54 {
                        let mut imm19 = ((ins >> 5) & 0x7_ffff) as i32;
                        if imm19 & (1 << 18) != 0 {
                            imm19 -= 1 << 19;
                        }
                        let target = (o as i64) + (imm19 as i64) * 4;
                        if target <= off as i64 {
                            loop_end_off = Some(o + 4);
                            break;
                        }
                    }
                    let opc = ins >> 24;
                    if opc == 0xb4 || opc == 0xb5 || opc == 0x34 || opc == 0x35 {
                        let mut imm19 = ((ins >> 5) & 0x7_ffff) as i32;
                        if imm19 & (1 << 18) != 0 {
                            imm19 -= 1 << 19;
                        }
                        let target = (o as i64) + (imm19 as i64) * 4;
                        if target <= off as i64 {
                            loop_end_off = Some(o + 4);
                            break;
                        }
                    }
                    o += 4;
                }
                // Find RET(s) inside the function body.
                let mut ret_vas: Vec<u64> = Vec::new();
                if let Some(lend) = loop_end_off {
                    let mut o = lend;
                    while o < lend + 0x200 {
                        if o + 4 > so_bytes.len() {
                            break;
                        }
                        let ins = read_u32_le(so_bytes, o).unwrap();
                        if ins == 0xd65f03c0 {
                            if let Some(va) = off_to_va(&phs, o) {
                                ret_vas.push(va);
                            }
                            if ret_vas.len() >= 2 {
                                break;
                            }
                        }
                        o += 4;
                    }
                }
                out.push(Rc4Prga {
                    prologue_va: prologue_off.and_then(|o| off_to_va(&phs, o)).unwrap_or(0),
                    prga_inner_va: off_to_va(&phs, off).unwrap_or(0),
                    loop_end_va: loop_end_off.and_then(|o| off_to_va(&phs, o)),
                    ret_vas,
                });
            }
        }
        off += 4;
    }
    out
}

// ---------------------------------------------------------------------------
// SIMD-XOR (single-byte XOR with per-input key) function finder.
// ---------------------------------------------------------------------------

const SIMD_XOR_SIG: [u8; 8] = [0x21, 0x1c, 0x20, 0x6e, 0x42, 0x1c, 0x20, 0x6e];

fn find_all_subseq(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return out;
    }
    let last = haystack.len() - needle.len();
    let mut i = 0usize;
    while i <= last {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
            i += 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Locate Jiagu's SIMD single-byte XOR routine.
///
/// Anchored on `eor v1.16b, v1.16b, v0.16b` immediately followed by
/// `eor v2.16b, v2.16b, v0.16b` (these two are rarely adjacent outside
/// a vectorised XOR loop).
pub fn find_simd_xor(so_bytes: &[u8]) -> Vec<SimdXor> {
    let phs = parse_phdrs(so_bytes);
    let mut out: Vec<SimdXor> = Vec::new();
    for off in find_all_subseq(so_bytes, &SIMD_XOR_SIG) {
        // Walk backward for the function prologue.
        let mut prologue_off: Option<usize> = None;
        let mut back = 4usize;
        while back < 0x400 {
            if off < back {
                break;
            }
            let ins = read_u32_le(so_bytes, off - back).unwrap_or(0);
            if (ins >> 22) == 0b1101000100 && (ins & 0x1f) == 31 && ((ins >> 5) & 0x1f) == 31 {
                prologue_off = Some(off - back);
                break;
            }
            back += 4;
        }
        // Walk forward — find the first instruction past two backward branches
        // (SIMD loop b.ne + scalar tail b.ne).
        let mut exit_off: Option<usize> = None;
        let mut branch_count = 0u32;
        let mut o = off;
        while o < off + 0x200 {
            if o + 4 > so_bytes.len() {
                break;
            }
            let ins = read_u32_le(so_bytes, o).unwrap();
            if (ins >> 24) == 0x54 {
                let mut imm19 = ((ins >> 5) & 0x7_ffff) as i32;
                if imm19 & (1 << 18) != 0 {
                    imm19 -= 1 << 19;
                }
                let target = (o as i64) + (imm19 as i64) * 4;
                if target < o as i64 {
                    branch_count += 1;
                    if branch_count == 2 {
                        exit_off = Some(o + 4);
                        break;
                    }
                }
            }
            o += 4;
        }
        let Some(exit_off) = exit_off else { continue };
        out.push(SimdXor {
            prologue_va: prologue_off.and_then(|o| off_to_va(&phs, o)).unwrap_or(0),
            simd_exit_va: off_to_va(&phs, exit_off).unwrap_or(0),
        });
    }
    // Deduplicate by prologue_va, preserving order.
    let mut seen = std::collections::HashSet::new();
    let mut unique = Vec::new();
    for s in out {
        if seen.insert(s.prologue_va) {
            unique.push(s);
        }
    }
    unique
}

// ---------------------------------------------------------------------------
// XOR-0xa5 data section extractor.
// ---------------------------------------------------------------------------

const XOR_A5_ANCHORS: &[&[u8]] = &[
    b"com.qihoo.permmgr",
    b"com.qihoo.apps",
    b"Lcom/qihoo/util/",
    b"qihoo",
    b"InMemoryDexClassLoader",
];

/// Locate the XOR-0xa5-encoded data section inside libjiagu*.so.
/// Returns `None` if no anchor strings are found.
pub fn find_xor_a5_region(so_bytes: &[u8]) -> Option<XorA5Region> {
    let mut matches: Vec<(usize, &[u8])> = Vec::new();
    for anchor in XOR_A5_ANCHORS {
        let enc: Vec<u8> = anchor.iter().map(|b| b ^ 0xa5).collect();
        for pos in find_all_subseq(so_bytes, &enc) {
            matches.push((pos, *anchor));
        }
    }
    if matches.is_empty() {
        return None;
    }
    let earliest = matches.iter().map(|(p, _)| *p).min().unwrap();
    let start = earliest.saturating_sub(0x8000);
    // Find the last zero-run of >= 16 bytes before `earliest`.
    let mut zero_run_end: Option<usize> = None;
    let mut o = earliest;
    while o > start {
        let prev = o.saturating_sub(16);
        if prev + 16 > so_bytes.len() {
            o = prev;
            continue;
        }
        let slice = &so_bytes[prev..prev + 16];
        if slice.iter().all(|&b| b == 0) {
            zero_run_end = Some(prev + 16);
            break;
        }
        if prev == 0 {
            break;
        }
        o = prev;
    }
    let zero_run_end = zero_run_end.unwrap_or_else(|| earliest.saturating_sub(0x100));

    let region_end = (earliest + 0x40000).min(so_bytes.len());
    let decoded: Vec<u8> = so_bytes[zero_run_end..region_end]
        .iter()
        .map(|b| b ^ 0xa5)
        .collect();
    // ASCII runs of >= 6 printable chars (`\x20..=\x7e`).
    let mut runs: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    for &b in &decoded {
        if (0x20..=0x7e).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= 6 {
                runs.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= 6 {
        runs.push(cur);
    }
    Some(XorA5Region {
        start_off: zero_run_end,
        decoded_strings: runs,
        n_anchor_matches: matches.len(),
    })
}

// ---------------------------------------------------------------------------
// Public summary entry point.
// ---------------------------------------------------------------------------

/// Static-only cipher analysis of a libjiagu*.so payload.
pub fn summarise(so_bytes: &[u8]) -> JiaguStaticCipherSummary {
    JiaguStaticCipherSummary {
        rc4_prgas: find_rc4_prga(so_bytes),
        simd_xors: find_simd_xor(so_bytes),
        xor_a5: find_xor_a5_region(so_bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_imm32_decoder() {
        // ADD W1, W1, #2  → encoding: 0x11000821 (sf=0, sh=0, imm12=2, Rn=1, Rd=1)
        // Reconstructed: opcode bits 0001 0001 (>>24), imm12 << 10, Rn << 5, Rd
        let ins: u32 = (0b0001_0001u32 << 24) | (2u32 << 10) | (1u32 << 5) | 1u32;
        let dec = decode_add_imm32(ins).expect("decodes");
        assert_eq!(dec, (1, 1, 2));
    }

    #[test]
    fn strb_imm_decoder() {
        // STRB W1, [X0, #0x100] — base opcode 0011_1001_00 (>>22), imm12=0x100,
        // Rn=0, Rt=1.
        let ins: u32 = (0b0011_1001_00u32 << 22) | (0x100u32 << 10) | (0u32 << 5) | 1u32;
        let dec = decode_strb_imm(ins).expect("decodes");
        assert_eq!(dec, (1, 0, 0x100));
    }

    #[test]
    fn find_rc4_prga_locates_synthetic_pair() {
        // Build a minimal ELF with one PT_LOAD covering the instructions.
        let add: u32 = (0b0001_0001u32 << 24) | (2u32 << 10) | (1u32 << 5) | 1u32;
        let strb: u32 = (0b0011_1001_00u32 << 22) | (0x100u32 << 10) | (0u32 << 5) | 1u32;
        let mut text = Vec::new();
        text.extend_from_slice(&add.to_le_bytes());
        text.extend_from_slice(&strb.to_le_bytes());
        // Build a tiny ELF64.
        let mut so = vec![0u8; 0x80];
        so[..4].copy_from_slice(b"\x7fELF");
        so[4] = 2;
        so[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        so[0x36..0x38].copy_from_slice(&0x38u16.to_le_bytes());
        so[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        let ph = 0x40usize;
        so[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        so[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
        so[ph + 8..ph + 16].copy_from_slice(&0x80u64.to_le_bytes()); // p_offset
        so[ph + 16..ph + 24].copy_from_slice(&0x1000u64.to_le_bytes()); // p_vaddr
        so[ph + 32..ph + 40].copy_from_slice(&(text.len() as u64).to_le_bytes()); // p_filesz
        so.extend_from_slice(&text);
        let prgas = find_rc4_prga(&so);
        assert!(!prgas.is_empty(), "expected at least one PRGA match");
        assert_eq!(prgas[0].prga_inner_va, 0x1000);
    }

    #[test]
    fn xor_a5_finds_anchor() {
        // Encode the longer anchor "com.qihoo.permmgr" with XOR 0xa5 — pad
        // with zeros around it so the zero-run-walk can find a boundary.
        // The decoded-strings filter requires >= 6 printable ASCII, so we
        // need an anchor at least that length (the Python uses the same
        // 6-char filter).
        let mut buf = vec![0u8; 64];
        let anchor: &[u8] = b"com.qihoo.permmgr";
        let enc: Vec<u8> = anchor.iter().map(|b| b ^ 0xa5).collect();
        buf.extend_from_slice(&enc);
        // Trailing non-printable byte to terminate the printable run.
        buf.push(0x00);
        buf.extend_from_slice(&[0x00; 32]);
        let r = find_xor_a5_region(&buf).expect("anchor found");
        assert!(r.n_anchor_matches >= 1);
        assert!(r.decoded_strings.iter().any(|s| {
            s.windows(anchor.len()).any(|w| w == anchor)
        }));
    }
}
