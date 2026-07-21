//! Jiagu custom-PRGA RC4 cipher and inner-SO decryption pipeline.
//!
//! Replicates Jiagu's RC4 variant statically — no Unicorn, no runtime
//! emulation.
//!
//! Cipher characterisation (see `jiagu_rc4.py` for the full RE
//! walkthrough):
//!
//! - **KSA**: standard RC4 KSA with identity initial S-box.
//! - **PRGA — CUSTOM**: differs from textbook RC4 in three ways:
//!   1. Initial state is `(i=3, j=5)` NOT `(0, 0)`.
//!   2. `i` increments by **2** per byte (not 1).
//!   3. `j = (j + S[i] + 1) & 0xff` (+1 added per step).
//!   4. Output keystream byte = `S[(S[i] + S[j]) & 0xff]` (standard).
//!
//! The hardcoded 10-byte inner-SO key sits at vaddr `0x4ecb1` in the
//! dominant 1.4.0.4 build, preceded by the C++ class name
//! `"10DynCryptor"`.
//!
//! Inner-SO decryption pipeline:
//!
//! 1. RC4-decrypt the encrypted payload at vaddr `0x70250` with the
//!    hardcoded key (custom-PRGA above).
//! 2. The result is a length-prefixed zlib stream:
//!    - `bytes[0..4]` = u32 LE inflated length
//!    - `bytes[4..]` = zlib (deflate) stream
//! 3. `zlib.decompress` → inner-SO body in a custom container format.
//!
//! The inner SO contains the actual DEX-decryption code, whose
//! per-build key derivation is **not** recovered by this module.

use std::io::Read;

use anyhow::{anyhow, Context, Result};
use flate2::read::ZlibDecoder;

/// 10-byte hardcoded RC4 key for the inner-SO decryption step. Found
/// in `.rodata` at vaddr `0x4ecb1` of libjiagu_a64.so (dominant
/// 1.4.0.x cohort). Preceded by the `"10DynCryptor"` C++ class name.
pub const INNER_SO_KEY: [u8; 10] = [
    0x76, 0x56, 0x57, 0x34, 0x23, 0x91, 0x23, 0x53, 0x56, 0x74,
];

/// Default inner-SO payload location for the dominant 1.4.0.x cohort.
pub const INNER_SO_PAYLOAD_VADDR: u64 = 0x70250;
/// Approximate payload size for the dominant 1.4.0.4 build.
pub const INNER_SO_PAYLOAD_SIZE: u64 = 780_753;

/// Standard RC4 KSA with identity initial S-box.
///
/// Returns a 256-byte permutation. Pass `key_len=None` to use
/// `key.len()`.
pub fn jiagu_rc4_ksa(key: &[u8], key_len: Option<usize>) -> [u8; 256] {
    let key_len = key_len.unwrap_or(key.len()).max(1);
    let mut s = [0u8; 256];
    for i in 0..256 {
        s[i] = i as u8;
    }
    let mut j: u32 = 0;
    for i in 0..256 {
        j = (j + s[i] as u32 + key[i % key_len] as u32) & 0xff;
        s.swap(i, j as usize);
    }
    s
}

/// Custom-PRGA RC4 variant matching Jiagu's loader behaviour:
/// initial `(i, j) = (3, 5)`, `i += 2` per byte, `j = (j + S[i] + 1) & 0xff`.
///
/// Mutates a private copy of `s`; the caller's `s` is unchanged.
pub fn jiagu_rc4_prga(s: &[u8; 256], data: &[u8]) -> Vec<u8> {
    let mut s = *s;
    let mut i: u32 = 3;
    let mut j: u32 = 5;
    let mut out = vec![0u8; data.len()];
    for k in 0..data.len() {
        i = (i + 2) & 0xff;
        j = (j + s[i as usize] as u32 + 1) & 0xff;
        s.swap(i as usize, j as usize);
        let idx = (s[i as usize] as u32 + s[j as usize] as u32) & 0xff;
        out[k] = data[k] ^ s[idx as usize];
    }
    out
}

/// One-shot RC4 decrypt with the Jiagu custom-PRGA variant. Pass
/// `None` for `key` to use the hardcoded [`INNER_SO_KEY`].
pub fn jiagu_rc4_decrypt(data: &[u8], key: Option<&[u8]>) -> Vec<u8> {
    let k = key.unwrap_or(&INNER_SO_KEY);
    let s = jiagu_rc4_ksa(k, None);
    jiagu_rc4_prga(&s, data)
}

/// Translate a vaddr to a file offset using PT_LOAD segments. Returns
/// `None` if `va` is not mapped by any `PT_LOAD`.
fn va_to_off(so_bytes: &[u8], va: u64) -> Option<usize> {
    if so_bytes.len() < 0x40 || &so_bytes[..4] != b"\x7fELF" {
        return None;
    }
    let e_phoff = u64::from_le_bytes(so_bytes[0x20..0x28].try_into().ok()?);
    let e_phentsize = u16::from_le_bytes(so_bytes[0x36..0x38].try_into().ok()?);
    let e_phnum = u16::from_le_bytes(so_bytes[0x38..0x3a].try_into().ok()?);
    for i in 0..e_phnum as usize {
        let base = e_phoff as usize + i * e_phentsize as usize;
        if base + 0x38 > so_bytes.len() {
            return None;
        }
        let ph = &so_bytes[base..base + 0x38];
        let p_type = u32::from_le_bytes(ph[0..4].try_into().ok()?);
        let p_off = u64::from_le_bytes(ph[8..16].try_into().ok()?);
        let p_vaddr = u64::from_le_bytes(ph[16..24].try_into().ok()?);
        let p_filesz = u64::from_le_bytes(ph[32..40].try_into().ok()?);
        if p_type == 1 && p_vaddr <= va && va < p_vaddr + p_filesz {
            return Some((p_off + (va - p_vaddr)) as usize);
        }
    }
    None
}

/// Run the full inner-SO decryption pipeline.
///
/// 1. Extract the encrypted payload from the outer libjiagu_a64.so at
///    `payload_vaddr` (default: `INNER_SO_PAYLOAD_VADDR`).
/// 2. RC4-decrypt with the custom-PRGA variant + key.
/// 3. zlib-inflate the (length-prefixed) stream.
///
/// Returns the inflated inner-SO body bytes (≈ 1.78 MB on the dominant
/// build).
pub fn decrypt_inner_so(
    so_bytes: &[u8],
    payload_vaddr: u64,
    payload_size: Option<u64>,
    key: &[u8],
) -> Result<Vec<u8>> {
    let off = va_to_off(so_bytes, payload_vaddr)
        .ok_or_else(|| anyhow!("vaddr {:#x} not in any PT_LOAD segment", payload_vaddr))?;
    let available = so_bytes.len() - off;
    let size = match payload_size {
        Some(s) => (s as usize).min(available),
        None => available.min(1_500_000), // 1.5 MB cap
    };
    if size < 256 {
        return Err(anyhow!("payload region too small ({} bytes)", size));
    }

    let ciphertext = &so_bytes[off..off + size];
    let plaintext = jiagu_rc4_decrypt(ciphertext, Some(key));

    if plaintext.len() < 4 {
        return Err(anyhow!("RC4 output shorter than 4 bytes"));
    }
    let inflated_len = u32::from_le_bytes(plaintext[0..4].try_into().unwrap()) as u64;
    if inflated_len < 0x100 || inflated_len > 0x4000_0000 {
        return Err(anyhow!("implausible inflated length {}", inflated_len));
    }
    let head = &plaintext[4..6];
    if head != b"\x78\x9c" && head != b"\x78\xda" && head != b"\x78\x01" {
        return Err(anyhow!(
            "no zlib header at offset 4 (got {:02x}{:02x})",
            head[0],
            head[1]
        ));
    }
    let mut dec = ZlibDecoder::new(&plaintext[4..]);
    let mut inflated = Vec::with_capacity(inflated_len as usize);
    dec.read_to_end(&mut inflated)
        .with_context(|| "zlib decompression failed")?;
    if inflated.len() as u64 != inflated_len {
        return Err(anyhow!(
            "inflated length mismatch: expected {}, got {}",
            inflated_len,
            inflated.len()
        ));
    }
    Ok(inflated)
}

/// Discover the inner-SO payload location in a libjiagu_a64.so.
///
/// Tries the default location first, then walks `PT_LOAD` segments
/// looking for a region that RC4-decrypts to a length-prefixed zlib
/// stream.
///
/// Returns `(payload_vaddr, payload_size_used, inflated_bytes)` on
/// success, or `None` if no valid payload is found. (Matches the
/// Python triple shape with `payload_size_used = None` always — kept
/// for future use.)
pub fn find_inner_so_payload(
    so_bytes: &[u8],
    key: Option<&[u8]>,
    candidate_offsets: Option<&[u64]>,
) -> Option<(u64, Option<u64>, Vec<u8>)> {
    let key = key.unwrap_or(&INNER_SO_KEY);
    let mut candidates: Vec<u64> = Vec::new();
    if let Some(extras) = candidate_offsets {
        candidates.extend_from_slice(extras);
    }
    candidates.insert(0, INNER_SO_PAYLOAD_VADDR);
    for va in &candidates {
        if let Ok(inflated) = decrypt_inner_so(so_bytes, *va, None, key) {
            return Some((*va, None, inflated));
        }
    }
    // Scan all PT_LOAD segments for any 4-byte aligned offset that
    // decrypts to a length-prefixed zlib stream. Fast: only checks the
    // first 8 RC4 bytes per candidate.
    if so_bytes.len() < 0x40 || &so_bytes[..4] != b"\x7fELF" {
        return None;
    }
    let e_phoff = u64::from_le_bytes(so_bytes[0x20..0x28].try_into().ok()?) as usize;
    let e_phentsize = u16::from_le_bytes(so_bytes[0x36..0x38].try_into().ok()?) as usize;
    let e_phnum = u16::from_le_bytes(so_bytes[0x38..0x3a].try_into().ok()?) as usize;
    for i in 0..e_phnum {
        let base = e_phoff + i * e_phentsize;
        if base + 0x38 > so_bytes.len() {
            break;
        }
        let ph = &so_bytes[base..base + 0x38];
        let p_type = u32::from_le_bytes(ph[0..4].try_into().ok()?);
        let p_off = u64::from_le_bytes(ph[8..16].try_into().ok()?) as usize;
        let p_vaddr = u64::from_le_bytes(ph[16..24].try_into().ok()?);
        let p_filesz = u64::from_le_bytes(ph[32..40].try_into().ok()?) as usize;
        if p_type != 1 {
            continue;
        }
        let end = p_filesz.saturating_sub(64);
        let mut off = 0usize;
        while off < end {
            if p_off + off + 8 > so_bytes.len() {
                break;
            }
            let head = jiagu_rc4_decrypt(&so_bytes[p_off + off..p_off + off + 8], Some(key));
            let zh = &head[4..6];
            if zh == b"\x78\x9c" || zh == b"\x78\xda" || zh == b"\x78\x01" {
                let length = u32::from_le_bytes(head[0..4].try_into().unwrap()) as u64;
                if length > 0x1000 && length < 0x1000_0000 {
                    let va = p_vaddr + off as u64;
                    if let Ok(inflated) = decrypt_inner_so(so_bytes, va, None, key) {
                        return Some((va, None, inflated));
                    }
                }
            }
            off += 4;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn inner_so_key_exact_bytes() {
        // The exact 10-byte key is load-bearing — guard it explicitly.
        assert_eq!(
            INNER_SO_KEY,
            [0x76, 0x56, 0x57, 0x34, 0x23, 0x91, 0x23, 0x53, 0x56, 0x74]
        );
        assert_eq!(&INNER_SO_KEY[..], b"vVW4#\x91#SVt");
    }

    #[test]
    fn rc4_round_trips_through_custom_prga() {
        // The cipher is symmetric. encrypt(decrypt(x, k), k) == x.
        let plaintext = b"PLATYPUS_JIAGU_RC4_ROUND_TRIP_TEST";
        let ct = jiagu_rc4_decrypt(plaintext, None);
        assert_ne!(&ct[..], &plaintext[..], "rc4 must transform the plaintext");
        let pt2 = jiagu_rc4_decrypt(&ct, None);
        assert_eq!(&pt2[..], &plaintext[..]);
    }

    #[test]
    fn rc4_initial_state_is_3_5_not_0_0() {
        // The first output byte under (3, 5, +2/+1) differs from textbook
        // RC4. We assert "differs from a textbook-RC4 first byte" indirectly
        // by computing two RC4s starting from the same KSA but different
        // initial states and confirming they don't match. This catches a
        // regression where someone restores (0, 0).
        let s = jiagu_rc4_ksa(b"hello", None);
        let custom = jiagu_rc4_prga(&s, &[0; 8]);
        // Textbook RC4 starting at (0, 0), i += 1, j += S[i]:
        let textbook = {
            let mut s = s;
            let mut i: u32 = 0;
            let mut j: u32 = 0;
            let mut out = [0u8; 8];
            for k in 0..8 {
                i = (i + 1) & 0xff;
                j = (j + s[i as usize] as u32) & 0xff;
                s.swap(i as usize, j as usize);
                let idx = (s[i as usize] as u32 + s[j as usize] as u32) & 0xff;
                out[k] = s[idx as usize];
            }
            out
        };
        assert_ne!(&custom[..], &textbook[..]);
    }

    #[test]
    fn decrypt_inner_so_round_trips_synthetic_so() {
        // Build a minimal ELF64 with a single PT_LOAD covering our payload.
        // We choose a vaddr that maps directly to our chosen file offset so
        // the va_to_off helper resolves cleanly.

        // Pick payload bytes: encode a chunk of "Hello, Jiagu inner-SO!"
        // ≥ 0x100 bytes (decrypt_inner_so enforces the 0x100 minimum to
        // reject implausible length prefixes), zlib-compress it, prepend
        // the LE u32 length, then RC4-encrypt with the standard inner key.
        let plain: Vec<u8> = (0..0x200).map(|i| b"Hello, Jiagu inner-SO! "[i % 23]).collect();
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&plain).unwrap();
        let zlib_stream = enc.finish().unwrap();
        let mut payload_plain = Vec::new();
        payload_plain.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        payload_plain.extend_from_slice(&zlib_stream);
        // Pad to ≥ 512 bytes (the decrypt_inner_so 256-minimum is on
        // ciphertext, not plaintext; padding here just keeps us safe).
        while payload_plain.len() < 512 {
            payload_plain.push(0);
        }
        let payload_ct = jiagu_rc4_decrypt(&payload_plain, None);

        // Build a tiny ELF64 header + one phdr + the payload at offset 0x1000.
        let mut so = vec![0u8; 0x1000];
        so[..4].copy_from_slice(b"\x7fELF");
        so[4] = 2; // ELFCLASS64
        // e_phoff at 0x20
        so[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        // e_phentsize at 0x36
        so[0x36..0x38].copy_from_slice(&0x38u16.to_le_bytes());
        // e_phnum at 0x38
        so[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        // One PT_LOAD phdr at 0x40
        let ph = 0x40usize;
        so[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        so[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
        so[ph + 8..ph + 16].copy_from_slice(&0x1000u64.to_le_bytes()); // p_offset
        so[ph + 16..ph + 24].copy_from_slice(&0x10000u64.to_le_bytes()); // p_vaddr
        so[ph + 24..ph + 32].copy_from_slice(&0x10000u64.to_le_bytes()); // p_paddr
        so[ph + 32..ph + 40].copy_from_slice(&(payload_ct.len() as u64).to_le_bytes()); // p_filesz
        so[ph + 40..ph + 48].copy_from_slice(&(payload_ct.len() as u64).to_le_bytes()); // p_memsz
        so[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align
        so.extend_from_slice(&payload_ct);

        // Now decrypt at vaddr 0x10000.
        let out = decrypt_inner_so(&so, 0x10000, None, &INNER_SO_KEY).expect("decrypts");
        assert_eq!(out, plain);
    }
}
