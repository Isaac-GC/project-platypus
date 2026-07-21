//! Best-effort AXML (Android binary XML) string-pool reader.
//!
//! Mirrors `unpacker/packer_backends/detector.py::_parse_axml_strings`
//! exactly. We DO NOT parse the full AXML — only the string pool, which
//! is what the packer detector and `_common.read_manifest_strings`
//! consume.
//!
//! Returns an empty vec on any structural error (truncation, bad
//! header, etc.) so callers can treat "no strings" identically to
//! "couldn't parse".

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;

/// Magic header for the AXML chunk: `0x00080003` little-endian =
/// `[0x03, 0x00, 0x08, 0x00]`. The first 4 bytes of every well-formed
/// AndroidManifest.xml binary.
const AXML_MAGIC: [u8; 4] = [0x03, 0x00, 0x08, 0x00];

/// Parse the AXML string pool. Returns one `String` per pool entry, in
/// pool order (matches Python `_parse_axml_strings` 1:1).
pub fn parse_axml_strings(data: &[u8]) -> Vec<String> {
    if data.len() < 36 || data[..4] != AXML_MAGIC {
        return Vec::new();
    }
    let try_parse = |data: &[u8]| -> Option<Vec<String>> {
        let mut cur = Cursor::new(&data[16..]);
        let n_strings = cur.read_u32::<LittleEndian>().ok()? as usize;
        let mut cur = Cursor::new(&data[24..]);
        let flags = cur.read_u32::<LittleEndian>().ok()?;
        let str_pool_off = cur.read_u32::<LittleEndian>().ok()? as usize + 8;
        let utf8 = (flags & 0x100) != 0;

        let mut offs = Vec::with_capacity(n_strings);
        for i in 0..n_strings {
            let base = 36 + i * 4;
            if base + 4 > data.len() {
                return None;
            }
            offs.push(u32::from_le_bytes([
                data[base],
                data[base + 1],
                data[base + 2],
                data[base + 3],
            ]) as usize);
        }

        let mut out = Vec::with_capacity(n_strings);
        for o in offs {
            let mut base = str_pool_off.checked_add(o)?;
            if utf8 {
                // UTF-8: skipped u16-length byte, then u8 byte-length, then bytes.
                if base + 2 > data.len() {
                    out.push(String::new());
                    continue;
                }
                let lo = data[base];
                base += if lo & 0x80 != 0 { 2 } else { 1 };
                if base >= data.len() {
                    out.push(String::new());
                    continue;
                }
                let mut ln = data[base] as usize;
                if ln & 0x80 != 0 {
                    if base + 1 >= data.len() {
                        out.push(String::new());
                        continue;
                    }
                    ln = ((ln & 0x7F) << 8) | data[base + 1] as usize;
                    base += 2;
                } else {
                    base += 1;
                }
                let end = base.saturating_add(ln).min(data.len());
                out.push(String::from_utf8_lossy(&data[base..end]).into_owned());
            } else {
                // UTF-16LE: u16 char-length, then chars * 2 bytes.
                if base + 2 > data.len() {
                    out.push(String::new());
                    continue;
                }
                let mut ln = u16::from_le_bytes([data[base], data[base + 1]]) as usize;
                if ln & 0x8000 != 0 {
                    if base + 4 > data.len() {
                        out.push(String::new());
                        continue;
                    }
                    let hi = u16::from_le_bytes([data[base + 2], data[base + 3]]) as usize;
                    ln = ((ln & 0x7FFF) << 16) | hi;
                    base += 4;
                } else {
                    base += 2;
                }
                let byte_len = ln.checked_mul(2)?;
                let end = base.saturating_add(byte_len).min(data.len());
                let u16s: Vec<u16> = data[base..end]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                out.push(String::from_utf16_lossy(&u16s));
            }
        }
        Some(out)
    };

    try_parse(data).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_empty() {
        assert!(parse_axml_strings(&[]).is_empty());
    }

    #[test]
    fn bad_magic_returns_empty() {
        assert!(parse_axml_strings(&vec![0u8; 64]).is_empty());
    }

    #[test]
    fn too_short_returns_empty() {
        let mut data = vec![0u8; 16];
        data[..4].copy_from_slice(&AXML_MAGIC);
        assert!(parse_axml_strings(&data).is_empty());
    }
}
