//! SENS / NEON cipher (Report §6 — legacy r21e `records>0` path).
//!
//! Per-APK-entry stream-XOR decryption used by older Virbox builds
//! (itachi-family).  The cipher state lives in `assets/*.dat` with the
//! `SENS` magic; for builds where the SENS record table is non-empty,
//! the cipher key is statically derivable:
//!
//! 1. The 16-byte cipher key sits at `SENS + 0x08`, XOR-obfuscated with
//!    `0x2A` (Report §6).
//! 2. A multiplier `x8` is derived from the key via a NEON polynomial
//!    mixer ([`derive_x8`], FINDINGS_REVIEW §5a / §11).
//! 3. Each APK entry's filename is hashed via a 64-bit rolling hash
//!    ([`vmp_hash`], itachi 0x2820b8). The hash is matched against the
//!    SENS record table; matched entries are XOR-decrypted under
//!    `keystream[j] = (x8 * (base + j)) & 0xff`.
//!
//! For `record_count == 0` builds the body cipher is runtime-resolved
//! via a function pointer at `*(SO+0x30fde0)` and cannot be executed
//! statically (Report §6 / FINDINGS_REVIEW §5b). The recovery struct
//! still surfaces the derived key + x8 so downstream tooling can pick
//! up where we leave off.

use std::collections::HashSet;
use std::io::Read;

use serde::{Deserialize, Serialize};
use zip::ZipArchive;

/// Offset (within the SENS blob) of the 16-byte obfuscated cipher key.
pub const SENS_KEY_OFFSET: usize = 8;
/// Length of the obfuscated cipher key.
pub const SENS_KEY_LEN: usize = 16;
/// Offset (within the SENS blob) of the little-endian u32 record count.
pub const SENS_RECCOUNT_OFFSET: usize = 0x1c;
/// Offset (within the SENS blob) of the first 16-byte record (hash + body).
pub const SENS_RECORDS_OFFSET: usize = 0x20;

/// `SENS` magic — the first 4 bytes of every legacy r21e cipher blob.
pub const SENS_MAGIC: &[u8; 4] = b"SENS";

/// 64-bit rolling hash recovered from itachi 0x2820b8
/// (Report §6 + FINDINGS_REVIEW §4).
///
/// The hash chews through `name` one byte at a time. On even iterations
/// the next state is built from a 7-bit left shift of the accumulator
/// XOR'd with the input byte; on odd iterations it's a quirky shift-by-
/// 11 mix that masks the input to 11 bits and complements the upper
/// bits. The walk continues until a NUL byte is consumed — for filename
/// inputs (`b"classes.dex"` etc.) that means we always run one extra
/// iteration past the end with `b = 0`.
pub fn vmp_hash(name: &[u8]) -> u64 {
    if name.is_empty() {
        return 0;
    }
    let mut h: u64 = 0;
    let mut i: usize = 0;
    let mut b: u8 = name[0];
    // Python `name_p1 = name[1:] + b"\x00"` — we read from `name[i+1]`
    // with a one-past-end implicit NUL.
    loop {
        let (x11, x12) = if (i & 1) == 0 {
            let x12 = h >> 3;
            let x11 = (b as u64) ^ h.wrapping_shl(7);
            (x11, x12)
        } else {
            let x11 = ((b as u64) & 0x7ff) | ((h & ((1u64 << 53) - 1)).wrapping_shl(11));
            let x12 = !(h >> 5);
            (x11, x12)
        };
        let next_idx = i + 1;
        b = if next_idx < name.len() {
            name[next_idx]
        } else {
            0
        };
        let x11 = x11 ^ x12;
        h ^= x11;
        i += 1;
        if b == 0 {
            break;
        }
    }
    h
}

/// NEON polynomial mixer that turns the 16-byte SENS key into the 32-bit
/// multiplier used by [`neon_decrypt`].
///
/// Original native code (FINDINGS_REVIEW §5a, §11):
/// ```text
///     w8 = sum(K[i] << (i+1) for i in 0..7) & 0xFFFFFFFF
/// ```
/// Only the first 7 bytes of the key participate.
pub fn derive_x8(key: &[u8]) -> u32 {
    let mut w8: u32 = 0;
    // (shift, idx) pairs — matches the Python tuple literal exactly.
    for &(shift, idx) in &[(1u32, 0usize), (2, 1), (3, 2), (4, 3), (5, 4), (6, 5), (7, 6)] {
        let k = *key.get(idx).unwrap_or(&0) as u32;
        w8 = w8.wrapping_add(k << shift);
    }
    w8
}

/// Stream-XOR decryptor with keystream byte
/// `keystream[j] = (x8 * (base + j)) & 0xff`.
///
/// The cipher is symmetric: running it twice with the same key/base
/// returns the original buffer. Default `base` is 100 (the value the
/// Virbox loader uses; we keep it as an explicit arg so a regression
/// test can pin it).
pub fn neon_decrypt(ct: &[u8], x8: u32, base: u32) -> Vec<u8> {
    ct.iter()
        .enumerate()
        .map(|(j, &c)| {
            let keystream = x8.wrapping_mul(base.wrapping_add(j as u32)) & 0xff;
            c ^ (keystream as u8)
        })
        .collect()
}

/// One entry successfully decrypted by [`decrypt_sens_protected_entries`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensRecoveredEntry {
    pub name: String,
    pub size: usize,
    /// First 4 bytes of plaintext, hex-encoded.
    pub magic: String,
}

/// Summary of the SENS recovery pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensRecovery {
    /// Recovered cipher key, hex-encoded (16 bytes).
    pub cipher_key_hex: String,
    /// Derived NEON multiplier (matches the Python `x8` field).
    pub x8: u32,
    /// Record count claimed by the SENS header (0 means runtime-cipher
    /// build; recovery is best-effort markers only).
    pub record_count: u32,
    /// Entries we managed to decrypt to plaintext (empty when
    /// `record_count == 0`).
    pub recovered_entries: Vec<SensRecoveredEntry>,
    /// Number of SENS-table hashes that *didn't* match any APK entry
    /// filename. Non-zero is a sign of either a renamed-asset packer
    /// variant or a hash-implementation drift.
    pub unmatched_hashes: usize,
}

/// Run the records>0 NEON-decrypt pipeline against `zf` and the SENS
/// blob bytes.
///
/// Mirrors the Python `decrypt_sens_protected_entries` 1:1. Writes
/// decrypted entries verbatim under `out_dir/<entry-name>` (parents
/// auto-created). Returns the [`SensRecovery`] summary regardless of
/// whether `record_count` is zero — callers inspect the returned struct
/// to decide what to do next.
pub fn decrypt_sens_protected_entries<R: std::io::Read + std::io::Seek>(
    zf: &mut ZipArchive<R>,
    sens_blob: &[u8],
    out_dir: &std::path::Path,
    verbose: bool,
) -> std::io::Result<SensRecovery> {
    if sens_blob.len() < SENS_RECORDS_OFFSET {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SENS blob shorter than header",
        ));
    }
    // 1) Recover the 16-byte cipher key (XOR 0x2A).
    let key: Vec<u8> = sens_blob[SENS_KEY_OFFSET..SENS_KEY_OFFSET + SENS_KEY_LEN]
        .iter()
        .map(|b| b ^ 0x2A)
        .collect();
    let record_count = u32::from_le_bytes(
        sens_blob[SENS_RECCOUNT_OFFSET..SENS_RECCOUNT_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let x8 = derive_x8(&key);
    let mut rec = SensRecovery {
        cipher_key_hex: hex(&key),
        x8,
        record_count,
        recovered_entries: Vec::new(),
        unmatched_hashes: 0,
    };

    if record_count == 0 {
        // Records=0 path: body cipher is runtime-resolved.
        // See module-level docstring + UNRECOVERED.md §1.
        return Ok(rec);
    }

    // 2) Pull the record-table hashes.
    let mut sens_hashes: HashSet<u64> = HashSet::with_capacity(record_count as usize);
    for i in 0..(record_count as usize) {
        let ro = SENS_RECORDS_OFFSET + i * 16;
        if ro + 8 > sens_blob.len() {
            break;
        }
        let h = u64::from_le_bytes(sens_blob[ro..ro + 8].try_into().unwrap());
        sens_hashes.insert(h);
    }

    // 3) Walk the APK and decrypt matched entries.
    std::fs::create_dir_all(out_dir)?;
    let names: Vec<String> = zf.file_names().map(|s| s.to_string()).collect();
    for name in names {
        let h = vmp_hash(name.as_bytes());
        if !sens_hashes.contains(&h) {
            continue;
        }
        let mut ct = Vec::new();
        if let Ok(mut entry) = zf.by_name(&name) {
            if entry.read_to_end(&mut ct).is_err() {
                continue;
            }
        } else {
            continue;
        }
        let pt = neon_decrypt(&ct, x8, 100);
        let op = out_dir.join(&name);
        if let Some(parent) = op.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&op, &pt)?;
        let magic = hex(&pt[..pt.len().min(4)]);
        if verbose {
            eprintln!(
                "    [+] decrypted {}  size={}  magic={}",
                name,
                pt.len(),
                magic
            );
        }
        rec.recovered_entries.push(SensRecoveredEntry {
            name: name.clone(),
            size: pt.len(),
            magic,
        });
        sens_hashes.remove(&h);
    }
    rec.unmatched_hashes = sens_hashes.len();
    Ok(rec)
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(&mut s, "{:02x}", byte);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-vector captured from the Python reference:
    /// `vmp_hash(b"classes.dex") == 0x3da1dd70fb519c32`.
    #[test]
    fn vmp_hash_known_vector() {
        assert_eq!(vmp_hash(b"classes.dex"), 0x3da1dd70fb519c32);
    }

    /// Additional known vectors captured from the Python reference —
    /// pin down the empty-input and single-byte edge cases too.
    #[test]
    fn vmp_hash_edge_cases() {
        assert_eq!(vmp_hash(b""), 0x0);
        assert_eq!(vmp_hash(b"a"), 0x61);
        assert_eq!(vmp_hash(b"AndroidManifest.xml"), 0x406b3a3eb6e389a1);
    }

    /// XOR cipher: encrypting twice with the same parameters returns
    /// the original buffer.
    #[test]
    fn neon_decrypt_round_trip() {
        let pt = b"Hello, Virbox SENS round-trip test buffer";
        let x8 = 0x1234u32;
        let ct = neon_decrypt(pt, x8, 100);
        // Ensure we actually mutated something.
        assert_ne!(&ct[..], &pt[..]);
        let pt2 = neon_decrypt(&ct, x8, 100);
        assert_eq!(&pt2[..], &pt[..]);
    }

    /// Captured from the Python reference:
    /// `derive_x8(bytes(range(1, 17))) == 0x602`.
    #[test]
    fn derive_x8_known_vector() {
        let key: Vec<u8> = (1..=16u8).collect();
        assert_eq!(derive_x8(&key), 0x602);
    }

    /// And the exact byte sequence of `neon_decrypt(b"Hello World")`
    /// with `x8=0x1234, base=100` — captured from the Python reference
    /// so a regression in the keystream formula surfaces immediately.
    #[test]
    fn neon_decrypt_byte_for_byte() {
        let ct = neon_decrypt(b"Hello World", 0x1234, 100);
        let expected = [
            0x18, 0xe1, 0xd4, 0x80, 0x4f, 0x74, 0xdf, 0xd3, 0x82, 0x48, 0x3c,
        ];
        assert_eq!(&ct[..], &expected[..]);
    }
}
