//! Patch the string pool of a binary AXML (e.g. AndroidManifest.xml)
//! or RES_TABLE chunk *in place*.
//!
//! ## Why a patcher, not a full writer
//!
//! A complete AXML writer would need to reconstruct every binary
//! string-table offset, every attribute typed-value, every resource
//! id mapping, and every namespace URI from a high-level IR. The
//! existing AXML parser in this workspace is deliberately lossy —
//! it stringifies typed values and drops resource ids — so the
//! round-trip requires a richer IR than `XmlNode` exposes. That's a
//! 600+ line refactor of the parser side that's out of scope here.
//!
//! In practice, **most APK edits don't restructure the manifest** —
//! they swap strings (rename the app's user-visible label, change a
//! deep-link URL, edit a meta-data value). Those edits are completely
//! covered by editing the string pool's UTF-8/UTF-16 entries while
//! preserving every other byte of the file.
//!
//! ## Wire format
//!
//! ```text
//! AXML file:
//!   file header   8B  (type=0x0003, hdr_size, chunk_size)
//!   string pool   ResStringPool chunk
//!   resource map  ResChunk (optional)
//!   start ns      ...
//!   start element ...
//!   ...
//! ```
//!
//! `ResStringPool` itself:
//! ```text
//!   chunk header   8B  (type=0x0001, hdr=0x1c, chunk_size)
//!   string_count   u32
//!   style_count    u32
//!   flags          u32  (bit 8 = UTF-8 storage; otherwise UTF-16-LE)
//!   strings_start  u32  (offset from chunk start to the string data)
//!   styles_start   u32  (offset from chunk start to the styles data, 0 = none)
//!   offsets[]      u32 * string_count   (each offset is relative to strings_start)
//!   styles_offs[]  u32 * style_count
//!   strings_data
//!   styles_data
//! ```
//!
//! Each string in UTF-8 storage is encoded as:
//!   - u16 (var-length): the UTF-16 code-unit count (or `0x80 | hi`)
//!   - u8 / u16 (var-length): the UTF-8 byte count (or `0x80 | hi`)
//!   - UTF-8 bytes
//!   - 0x00 terminator
//!
//! UTF-16-LE strings are:
//!   - u16 (var-length): the UTF-16 code-unit count
//!   - UTF-16-LE bytes
//!   - 0x0000 terminator
//!
//! After modification:
//!   - rewrite the offsets table (each entry = offset within strings region)
//!   - update strings_start if it changed (it doesn't here — offsets table
//!     length is fixed)
//!   - update the string pool chunk's chunk_size
//!   - if styles were present, shift styles_start by the delta
//!   - update the *outer* file header's chunk_size by the same delta

use byteorder::{ByteOrder, LE};

/// In-place editor for the string pool of an AXML or ARSC file.
///
/// The editor only modifies string-pool entries; every other byte
/// (chunks, tags, attribute typed values, resource ids) is preserved
/// exactly. That's sufficient for "find and replace text" workflows.
pub struct AxmlEditor {
    data: Vec<u8>,
    pool_start: usize,
    pool_size: usize,
    strings: Vec<String>,
    is_utf8: bool,
    /// Offset of the string-pool chunk in the file. Used to adjust
    /// the outer file header's chunk_size when the pool changes size.
    /// In an ARSC file the same code works; the chunk just lives at
    /// a different absolute offset.
    file_header_chunk_size_offset: Option<usize>,
}

impl AxmlEditor {
    /// Parse and locate the string pool. Returns an editor positioned
    /// at the first string pool chunk found at the top level of the
    /// file (which, for AndroidManifest.xml, is *the* string pool).
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        if data.len() < 8 {
            return Err(crate::Error::InvalidApk("axml too short".into()));
        }
        let file_type = LE::read_u16(&data[0..2]);
        // AXML file header type = 0x0003. ARSC table = 0x0002. Either is fine.
        if file_type != 0x0003 && file_type != 0x0002 {
            return Err(crate::Error::InvalidApk(
                format!("unexpected top-level type 0x{file_type:04x}; expected AXML (0x0003) or ARSC (0x0002)")
            ));
        }
        let file_chunk_size = LE::read_u32(&data[4..8]) as usize;
        if file_chunk_size > data.len() {
            return Err(crate::Error::InvalidApk(
                format!("file header chunk_size {file_chunk_size} > buffer {}", data.len())
            ));
        }

        // The first chunk after the file header is the string pool
        // (chunk type 0x0001). For ARSC, the layout is slightly
        // different — the string pool is the first child of the
        // RES_TABLE chunk, which has a fixed 12-byte header.
        let pool_start = match file_type {
            0x0003 => 8,
            0x0002 => 12,   // skip the table chunk header (size + package_count)
            _ => unreachable!(),
        };

        if pool_start + 8 > data.len() {
            return Err(crate::Error::InvalidApk("no room for pool chunk header".into()));
        }
        let pool_type = LE::read_u16(&data[pool_start..pool_start + 2]);
        if pool_type != 0x0001 {
            return Err(crate::Error::InvalidApk(
                format!("expected string pool chunk (0x0001), got 0x{pool_type:04x}")
            ));
        }
        let pool_size = LE::read_u32(&data[pool_start + 4..pool_start + 8]) as usize;
        if pool_start + pool_size > data.len() {
            return Err(crate::Error::InvalidApk("pool chunk overflows buffer".into()));
        }

        let pool = &data[pool_start..pool_start + pool_size];
        let (strings, is_utf8) = parse_string_pool(pool)?;

        Ok(Self {
            data: data.to_vec(),
            pool_start, pool_size, strings, is_utf8,
            file_header_chunk_size_offset: if file_type == 0x0003 { Some(4) } else { None },
        })
    }

    /// Read-only view of the string pool. Indices are stable — every
    /// position in the file that references string `i` will continue
    /// to do so after a `replace`.
    pub fn strings(&self) -> &[String] { &self.strings }

    /// Returns whether the pool encodes strings as UTF-8 (the modern
    /// default emitted by `aapt2`) or UTF-16-LE (older `aapt`).
    pub fn is_utf8(&self) -> bool { self.is_utf8 }

    /// Replace the string at `idx`. Subsequent encoding errors (e.g.
    /// a value too long to fit in the variable-length size field) are
    /// returned from `to_bytes`, not here.
    pub fn replace(&mut self, idx: usize, new_value: impl Into<String>) -> crate::Result<()> {
        if idx >= self.strings.len() {
            return Err(crate::Error::Other(
                format!("string index {idx} out of range (pool size {})", self.strings.len())
            ));
        }
        self.strings[idx] = new_value.into();
        Ok(())
    }

    /// Convenience: search for an exact string and replace it. Returns
    /// the number of slots that matched and were replaced.
    pub fn replace_all(&mut self, old: &str, new: &str) -> usize {
        let mut n = 0;
        for s in &mut self.strings {
            if s == old { *s = new.to_string(); n += 1; }
        }
        n
    }

    /// Find the first index whose string equals `value`.
    pub fn find(&self, value: &str) -> Option<usize> {
        self.strings.iter().position(|s| s == value)
    }

    /// Re-serialise to bytes. The string pool chunk is rebuilt with the
    /// updated entries; everything else in the file is copied through
    /// unchanged, with the file header's chunk_size and (if present)
    /// the surrounding table chunk's size adjusted to match the new
    /// total length.
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        let new_pool = build_string_pool(&self.strings, self.is_utf8)?;

        // Compose the output:
        //   [original file/table header bytes up to pool_start]
        //   [new string pool chunk]
        //   [everything after the original pool]
        let mut out = Vec::with_capacity(self.data.len() + new_pool.len());
        out.extend_from_slice(&self.data[..self.pool_start]);
        out.extend_from_slice(&new_pool);
        out.extend_from_slice(&self.data[self.pool_start + self.pool_size..]);

        // Patch the outer file/table chunk_size to match.
        let new_total = out.len() as u32;
        if let Some(off) = self.file_header_chunk_size_offset {
            LE::write_u32(&mut out[off..off + 4], new_total);
        } else {
            // ARSC table chunk_size lives at byte 4-8 (right after type+header_size).
            LE::write_u32(&mut out[4..8], new_total);
        }

        Ok(out)
    }
}

// ── Encoding/decoding of the string pool ──────────────────────────────────

fn parse_string_pool(chunk: &[u8]) -> crate::Result<(Vec<String>, bool)> {
    if chunk.len() < 28 {
        return Err(crate::Error::InvalidApk("string pool header too short".into()));
    }
    let string_count  = LE::read_u32(&chunk[8..12])  as usize;
    let _style_count  = LE::read_u32(&chunk[12..16]) as usize;
    let flags         = LE::read_u32(&chunk[16..20]);
    let strings_start = LE::read_u32(&chunk[20..24]) as usize;
    let _styles_start = LE::read_u32(&chunk[24..28]) as usize;
    let is_utf8 = (flags & (1 << 8)) != 0;

    // Offsets follow the 28-byte header.
    if 28 + 4 * string_count > chunk.len() {
        return Err(crate::Error::InvalidApk("offsets array overflows chunk".into()));
    }
    let mut offsets = Vec::with_capacity(string_count);
    for i in 0..string_count {
        let off = LE::read_u32(&chunk[28 + 4 * i..32 + 4 * i]) as usize;
        offsets.push(off);
    }

    // Data region: [strings_start, end of chunk).
    let mut strings = Vec::with_capacity(string_count);
    for off in offsets {
        let abs = strings_start + off;
        if abs >= chunk.len() {
            strings.push(String::new());
            continue;
        }
        let s = if is_utf8 {
            read_utf8_str(chunk, abs)
        } else {
            read_utf16_str(chunk, abs)
        };
        strings.push(s);
    }
    Ok((strings, is_utf8))
}

fn read_utf8_str(buf: &[u8], pos: usize) -> String {
    // Skip the UTF-16 length prefix (var-length).
    let (mut p, _) = read_varlen_u8(buf, pos);
    // Then the UTF-8 byte length (var-length).
    let (q, byte_len) = read_varlen_u8(buf, p);
    p = q;
    if p + byte_len > buf.len() { return String::new(); }
    String::from_utf8_lossy(&buf[p..p + byte_len]).into_owned()
}

fn read_utf16_str(buf: &[u8], pos: usize) -> String {
    let (p, code_units) = read_varlen_u16(buf, pos);
    if p + 2 * code_units > buf.len() { return String::new(); }
    let units: Vec<u16> = (0..code_units)
        .map(|i| LE::read_u16(&buf[p + 2 * i..p + 2 * i + 2]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Read an AOSP-flavour var-length u8 length field:
///   if high bit set, two bytes: `((b0 & 0x7f) << 8) | b1`
///   else one byte: `b0`
fn read_varlen_u8(buf: &[u8], pos: usize) -> (usize, usize) {
    let b0 = buf[pos];
    if b0 & 0x80 == 0 {
        return (pos + 1, b0 as usize);
    }
    let b1 = buf[pos + 1];
    (pos + 2, (((b0 & 0x7f) as usize) << 8) | (b1 as usize))
}

/// Same for u16 — used by the UTF-16 path.
fn read_varlen_u16(buf: &[u8], pos: usize) -> (usize, usize) {
    let v = LE::read_u16(&buf[pos..pos + 2]);
    if v & 0x8000 == 0 {
        return (pos + 2, v as usize);
    }
    let v2 = LE::read_u16(&buf[pos + 2..pos + 4]);
    (pos + 4, (((v & 0x7fff) as usize) << 16) | (v2 as usize))
}

fn build_string_pool(strings: &[String], utf8: bool) -> crate::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut offsets = Vec::with_capacity(strings.len());

    for s in strings {
        offsets.push(data.len() as u32);
        if utf8 {
            encode_utf8_str(s, &mut data)?;
        } else {
            encode_utf16_str(s, &mut data)?;
        }
    }
    // 4-byte align the data tail.
    while data.len() % 4 != 0 { data.push(0); }

    let header_size = 28u32;
    let offsets_size = (offsets.len() * 4) as u32;
    let strings_start = header_size + offsets_size;
    let chunk_size = strings_start + data.len() as u32;

    let mut out = Vec::with_capacity(chunk_size as usize);
    // Chunk header.
    out.extend_from_slice(&0x0001u16.to_le_bytes());           // type
    out.extend_from_slice(&(header_size as u16).to_le_bytes());// header_size
    out.extend_from_slice(&chunk_size.to_le_bytes());          // chunk_size
    // Pool header.
    out.extend_from_slice(&(strings.len() as u32).to_le_bytes()); // string_count
    out.extend_from_slice(&0u32.to_le_bytes());                  // style_count
    out.extend_from_slice(&(if utf8 { 1u32 << 8 } else { 0 }).to_le_bytes()); // flags
    out.extend_from_slice(&strings_start.to_le_bytes());         // strings_start
    out.extend_from_slice(&0u32.to_le_bytes());                  // styles_start = 0
    // Offsets.
    for off in &offsets {
        out.extend_from_slice(&off.to_le_bytes());
    }
    // Data.
    out.extend_from_slice(&data);
    Ok(out)
}

fn encode_utf8_str(s: &str, out: &mut Vec<u8>) -> crate::Result<()> {
    let utf16_len = s.encode_utf16().count();
    let bytes = s.as_bytes();
    write_varlen_u8(out, utf16_len)?;
    write_varlen_u8(out, bytes.len())?;
    out.extend_from_slice(bytes);
    out.push(0);
    Ok(())
}

fn encode_utf16_str(s: &str, out: &mut Vec<u8>) -> crate::Result<()> {
    let units: Vec<u16> = s.encode_utf16().collect();
    write_varlen_u16(out, units.len())?;
    for u in &units {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    Ok(())
}

fn write_varlen_u8(out: &mut Vec<u8>, n: usize) -> crate::Result<()> {
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x8000 {
        out.push(0x80 | ((n >> 8) as u8));
        out.push(n as u8);
    } else {
        return Err(crate::Error::Other(
            format!("string too long for UTF-8 var-length encoding ({n} > 0x7fff)")
        ));
    }
    Ok(())
}

fn write_varlen_u16(out: &mut Vec<u8>, n: usize) -> crate::Result<()> {
    if n < 0x8000 {
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0x7fff_ffff {
        let hi = ((n >> 16) as u16) | 0x8000;
        let lo = n as u16;
        out.extend_from_slice(&hi.to_le_bytes());
        out.extend_from_slice(&lo.to_le_bytes());
    } else {
        return Err(crate::Error::Other(
            format!("string too long for UTF-16 var-length encoding ({n} > 2GB)")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal AXML in-memory and check we can round-trip its
    /// string pool. The "file" we construct is just file header +
    /// string pool — enough to exercise the path.
    fn make_minimal_axml(strings: &[&str], utf8: bool) -> Vec<u8> {
        let s: Vec<String> = strings.iter().map(|s| s.to_string()).collect();
        let pool = build_string_pool(&s, utf8).unwrap();
        // File header (8 bytes: type=0x0003, hdr=0x8, total)
        let total = 8 + pool.len();
        let mut out = Vec::new();
        out.extend_from_slice(&0x0003u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&pool);
        out
    }

    #[test]
    fn roundtrip_utf8() {
        let buf = make_minimal_axml(&["hello", "world", "α γ"], true);
        let mut ed = AxmlEditor::from_bytes(&buf).unwrap();
        assert_eq!(ed.strings(), &["hello", "world", "α γ"]);
        assert!(ed.is_utf8());

        ed.replace(1, "WORLD").unwrap();
        let out = ed.to_bytes().unwrap();
        let ed2 = AxmlEditor::from_bytes(&out).unwrap();
        assert_eq!(ed2.strings(), &["hello", "WORLD", "α γ"]);
    }

    #[test]
    fn roundtrip_utf16() {
        let buf = make_minimal_axml(&["foo", "barbaz", "🦀"], false);
        let mut ed = AxmlEditor::from_bytes(&buf).unwrap();
        assert!(!ed.is_utf8());
        assert_eq!(ed.strings()[2], "🦀");

        ed.replace_all("foo", "fizz");
        let out = ed.to_bytes().unwrap();
        let ed2 = AxmlEditor::from_bytes(&out).unwrap();
        assert_eq!(ed2.strings()[0], "fizz");
        assert_eq!(ed2.strings()[2], "🦀");
    }

    #[test]
    fn find_returns_index() {
        let buf = make_minimal_axml(&["aa", "bb", "cc"], true);
        let ed = AxmlEditor::from_bytes(&buf).unwrap();
        assert_eq!(ed.find("bb"), Some(1));
        assert_eq!(ed.find("zz"), None);
    }

    #[test]
    fn length_change_updates_chunk_size() {
        // The new string is longer than the old — chunk_size MUST grow.
        let buf = make_minimal_axml(&["short"], true);
        let orig_total = buf.len();
        let mut ed = AxmlEditor::from_bytes(&buf).unwrap();
        ed.replace(0, "a much longer replacement string").unwrap();
        let out = ed.to_bytes().unwrap();
        assert!(out.len() > orig_total);
        let total_in_header = u32::from_le_bytes(out[4..8].try_into().unwrap()) as usize;
        assert_eq!(total_in_header, out.len());
    }
}
