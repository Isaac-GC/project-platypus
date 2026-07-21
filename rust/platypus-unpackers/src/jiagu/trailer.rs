//! Jiagu `qh\x00\x01` trailer parser.
//!
//! Every Jiagu-packed sample in this corpus carries an extra trailer
//! appended to its tiny stub `classes.dex`. The trailer begins at the
//! DEX's `file_size` (so ART ignores it during loading) and has this
//! structure:
//!
//! ```text
//!     +0  magic   = b'qh\x00\x01'         # u32 little-endian
//!     +4  size    = trailer total length  # u32, includes the 12-byte header
//!     +8  data_off                        # u32, offset within the body
//!                                          # where the encrypted-data section starts
//!     +12 body[size-12]                    # variable-length body
//! ```
//!
//! The body splits at `data_off`:
//!
//! - `body[0..data_off]` — metadata section (XOR-0xa6-encoded key/value
//!   entries, each preceded by an XOR-0xc6-encoded 12-byte marker).
//! - `body[data_off..]` — encrypted data section (bulk DEX payload).
//!
//! For the full byte-level format (chunk markers, key normalisation,
//! entry-0 classification, plaintext code-items tail detection) see the
//! original Python module `unpacker/packer_backends/jiagu_trailer.py`.
//! This Rust port keeps the semantics 1:1.

use serde::{Deserialize, Serialize};

/// `qh\x00\x01` trailer magic.
pub const JIAGU_TRAILER_MAGIC: &[u8; 4] = b"qh\x00\x01";

/// One key/value pair from the trailer's metadata section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiaguMetaEntry {
    /// Raw key bytes (may include 0xa0..0xaf "shift" markers).
    pub key: Vec<u8>,
    /// Best-effort ASCII rendering of the key.
    pub key_str: String,
    /// Single u8 grouping/sort hint.
    pub type_byte: u8,
    /// Raw value bytes.
    pub value: Vec<u8>,
    /// Best-effort ASCII rendering of the value.
    pub value_str: String,
}

/// Parsed Jiagu trailer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiaguTrailer {
    /// File offset of the `qh\x00\x01` magic within the stub DEX.
    pub trailer_off: usize,
    /// `size` field — total trailer length (including the 12-byte header).
    pub trailer_size: u32,
    /// `data_off` field — offset within body where the data section starts.
    pub data_off: u32,
    /// Full body length.
    pub body_len: usize,
    /// Recovered metadata key/value entries.
    pub metadata: Vec<JiaguMetaEntry>,
    /// Encrypted data-section bytes (entry table + payloads).
    pub data_section: Vec<u8>,

    // ---- Convenience views ------------------------------------------------
    pub n_entries: u32,
    pub entry0_size: u32,
    pub entry0_off: u32,

    /// Raw encrypted entry-table bytes for entries 1..n-1. Each pair is
    /// an opaque 8-byte slot — `(size, off)` encrypted under the
    /// per-build runtime key.
    pub encrypted_table: Vec<u8>,
}

impl JiaguTrailer {
    /// Look up a metadata value by Jiagu-normalised key.
    ///
    /// Jiagu's config strings are CamelCase-with-markers (high-bit
    /// bytes 0xa1..0xba expand to `A..Z`; 0x0d/0x0e/0x0f/0x00 are
    /// `_`/`.`/`/`/space separators). We normalise both sides to
    /// lowercase ASCII with all separators elided and compare.
    pub fn get(&self, key: &str) -> Option<String> {
        let target = normalise_key(key.as_bytes());
        self.metadata
            .iter()
            .find(|m| normalise_key(&m.key) == target)
            .map(|m| render_value(&m.value))
    }

    /// Like [`get`] but returns the raw value bytes (pre-rendering).
    pub fn get_raw(&self, key: &str) -> Option<&[u8]> {
        let target = normalise_key(key.as_bytes());
        self.metadata
            .iter()
            .find(|m| normalise_key(&m.key) == target)
            .map(|m| m.value.as_slice())
    }
}

/// Expand Jiagu's high-bit single-letter markers in place. Byte
/// `0xa0 + N` (N in 1..=26) stands in for uppercase letter N — e.g.
/// `0xa1` -> `'A'`, `0xae` -> `'N'`, `0xba` -> `'Z'`.
fn expand_letter_markers(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    for &c in b {
        if (0xa1..=0xba).contains(&c) {
            out.push(c - 0xa0 + 0x40); // 'A'..'Z'
        } else {
            out.push(c);
        }
    }
    out
}

/// Lowercase, drop all non-alphanumeric bytes (after expanding Jiagu's
/// letter markers).
fn normalise_key(b: &[u8]) -> Vec<u8> {
    let expanded = expand_letter_markers(b);
    let mut out = Vec::with_capacity(expanded.len());
    for c in expanded {
        if (0x41..=0x5a).contains(&c) {
            out.push(c + 0x20); // uppercase -> lowercase
        } else if (0x61..=0x7a).contains(&c) || (0x30..=0x39).contains(&c) {
            out.push(c);
        }
        // else drop
    }
    out
}

/// Render a value byte string back to a likely-intended ASCII form.
/// Maps known control-byte separators to their semantic equivalents,
/// expands the letter-marker bytes, and keeps printable ASCII as-is.
fn render_value(b: &[u8]) -> String {
    let expanded = expand_letter_markers(b);
    let mut out = String::with_capacity(expanded.len());
    for c in expanded {
        match c {
            0x0d => out.push('_'),
            0x0e => out.push('.'),
            0x0f => out.push('/'),
            0x00 => out.push(' '),
            0x20..=0x7e => out.push(c as char),
            other => out.push_str(&format!("\\x{:02x}", other)),
        }
    }
    out
}

/// Diagnostic-friendly rendering — keeps separators as raw escape
/// sequences so the underlying structure is visible in JSON dumps.
fn render_ascii(b: &[u8]) -> String {
    // latin-1: just one-to-one byte→char mapping.
    b.iter().map(|&c| c as char).collect()
}

/// Find every byte offset in `body[..end]` where the 12-byte chunk
/// marker pattern `d6 ed c6 c6 ?? c6 c6 c6 ?? c6 c6 c6` matches.
///
/// This is a direct equivalent of the Python `CHUNK_MARKER_RE` finditer.
fn find_chunk_markers(body: &[u8], end: usize) -> Vec<usize> {
    let mut hits = Vec::new();
    let limit = end.min(body.len());
    if limit < 12 {
        return hits;
    }
    let mut i = 0usize;
    while i + 12 <= limit {
        let s = &body[i..i + 12];
        if s[0] == 0xd6
            && s[1] == 0xed
            && s[2] == 0xc6
            && s[3] == 0xc6
            && s[5] == 0xc6
            && s[6] == 0xc6
            && s[7] == 0xc6
            && s[9] == 0xc6
            && s[10] == 0xc6
            && s[11] == 0xc6
        {
            hits.push(i);
            i += 1;
        } else {
            i += 1;
        }
    }
    hits
}

/// Parse a Jiagu trailer if present in a `classes.dex`.
///
/// Returns `None` if no `qh\x00\x01` magic is found or the structure
/// is malformed.
pub fn parse_trailer(dex_bytes: &[u8]) -> Option<JiaguTrailer> {
    let pos = find_subseq(dex_bytes, JIAGU_TRAILER_MAGIC)?;
    if pos + 12 > dex_bytes.len() {
        return None;
    }
    let size = u32::from_le_bytes(dex_bytes[pos + 4..pos + 8].try_into().ok()?);
    let data_off = u32::from_le_bytes(dex_bytes[pos + 8..pos + 12].try_into().ok()?);
    let body = &dex_bytes[pos + 12..];
    if data_off as usize > body.len() {
        return None;
    }
    let data_off_usz = data_off as usize;

    // Scan metadata section for chunk markers.
    let mut metadata = Vec::new();
    let matches = find_chunk_markers(body, data_off_usz);
    for i in 0..matches.len() {
        let off = matches[i];
        let nxt = if i + 1 < matches.len() {
            matches[i + 1]
        } else {
            data_off_usz
        };
        if off + 12 > body.len() {
            break;
        }
        let marker = &body[off..off + 12];
        let klen = (marker[4] ^ 0xc6) as usize;
        let type_byte = marker[8] ^ 0xc6;
        let payload_enc = &body[off + 12..nxt.min(body.len())];
        let payload: Vec<u8> = payload_enc.iter().map(|b| b ^ 0xa6).collect();
        let (key, value) = if klen > 0 && klen <= payload.len() {
            (payload[..klen].to_vec(), payload[klen..].to_vec())
        } else {
            (payload.clone(), Vec::new())
        };
        let key_str = render_ascii(&key);
        let value_str = render_ascii(&value);
        metadata.push(JiaguMetaEntry {
            key,
            key_str,
            type_byte,
            value,
            value_str,
        });
    }

    let data_section = body[data_off_usz..].to_vec();

    let mut n_entries = 0u32;
    let mut entry0_size = 0u32;
    let mut entry0_off = 0u32;
    let mut encrypted_table = Vec::new();
    if data_section.len() >= 12 {
        n_entries = u32::from_le_bytes(data_section[0..4].try_into().ok()?);
        entry0_size = u32::from_le_bytes(data_section[4..8].try_into().ok()?);
        entry0_off = u32::from_le_bytes(data_section[8..12].try_into().ok()?);
        if n_entries >= 2 {
            let tbl_end = 12usize + (n_entries as usize - 1) * 8;
            if tbl_end <= data_section.len() {
                encrypted_table = data_section[12..tbl_end].to_vec();
            }
        }
    }

    Some(JiaguTrailer {
        trailer_off: pos,
        trailer_size: size,
        data_off,
        body_len: body.len(),
        metadata,
        data_section,
        n_entries,
        entry0_size,
        entry0_off,
        encrypted_table,
    })
}

/// Find the first occurrence of `needle` in `haystack` (byte-level
/// substring search). Mirrors Python `bytes.find` — returns the
/// starting index, or `None` if not found.
fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    let last = haystack.len() - needle.len();
    for i in 0..=last {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Entry-0 content classification.
//
// `classify_entry0_format` returns one of:
//   "v1_plaintext_codeitems"  — older builds, entry 0 is recoverable
//   "v2_nibble_obfuscated"    — newer builds, entry 0 is not recoverable
//   "unknown"                 — heuristic could not decide
// ---------------------------------------------------------------------------

const NIBBLE_OBF_SET: [u8; 5] = [0x00, 0x0f, 0x1e, 0x2d, 0x3c];

/// Classify entry-0 protection style heuristically. Skips the first
/// 16 bytes (always opaque) and inspects ~2 KiB of the immediately-
/// following region.
pub fn classify_entry0_format(entry0_bytes: &[u8]) -> &'static str {
    if entry0_bytes.len() < 32 {
        return "unknown";
    }
    let end = (16 + 2048).min(entry0_bytes.len());
    let sample = &entry0_bytes[16..end];
    if sample.is_empty() {
        return "unknown";
    }
    let nibble_obf_count = sample.iter().filter(|b| NIBBLE_OBF_SET.contains(b)).count();
    let zero_count = sample.iter().filter(|&&b| b == 0).count();
    if nibble_obf_count as f64 / sample.len() as f64 > 0.70 {
        return "v2_nibble_obfuscated";
    }
    if zero_count as f64 / sample.len() as f64 > 0.05 {
        return "v1_plaintext_codeitems";
    }
    "unknown"
}

fn version_to_tuple(v: &str) -> Option<Vec<u32>> {
    if v.is_empty() {
        return None;
    }
    v.split('.')
        .map(|x| x.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>()
}

/// Map `JiaguVersion` → expected entry-0 format. Falls back to
/// `"unknown"` when the heuristic can't decide. Pass an empty string to
/// model the Python "None" case.
pub fn classify_by_version(jiagu_version: &str) -> &'static str {
    let Some(t) = version_to_tuple(jiagu_version) else {
        return "unknown";
    };
    // Python compares first 3 components as a tuple of ints.
    let head: Vec<u32> = t.iter().take(3).copied().collect();
    if head <= vec![1, 3, 9] {
        return "v1_plaintext_codeitems";
    }
    // 1.4.x → nibble-obfuscated
    if t.len() >= 2 && t[0] == 1 && t[1] == 4 {
        return "v2_nibble_obfuscated";
    }
    "unknown"
}

// ---------------------------------------------------------------------------
// Plaintext code-item tail detection (works on BOTH v1 and v2 entry0).
// ---------------------------------------------------------------------------

/// Full "multiples of 15" alphabet (`0x0f * k mod 256` for k in 0..17),
/// plus 0. Adjacent bytes (0x01, 0x02) that show up in the nibble
/// prefix interspersed are NOT in this set — matches the Python.
fn nibble_alphabet_contains(b: u8) -> bool {
    // {0x0f * k % 256 for k in 0..17} | {0}
    // 0, 15, 30, 45, 60, 75, 90, 105, 120, 135, 150, 165, 180, 195,
    // 210, 225, 240, (255 from k=17? — k goes 0..17 inclusive of 0
    // exclusive of 17; (0x0f * 16) % 256 = 240, so highest is 240).
    matches!(
        b,
        0x00 | 0x0f
            | 0x1e
            | 0x2d
            | 0x3c
            | 0x4b
            | 0x5a
            | 0x69
            | 0x78
            | 0x87
            | 0x96
            | 0xa5
            | 0xb4
            | 0xc3
            | 0xd2
            | 0xe1
            | 0xf0
    )
}

/// Return the byte offset within `entry0_body` after which we believe
/// the data is plaintext Dalvik `code_item`s.
///
/// For v1 builds this returns 0 (whole body is plaintext after the
/// 16-byte header already stripped by the caller).
///
/// For v2 builds this returns the end of the last sustained
/// ≥ `min_run` byte run of "nibble alphabet" bytes.
///
/// Returns `entry0_body.len()` if no plaintext tail was found.
pub fn find_codeitems_tail_offset(entry0_body: &[u8], min_run: usize) -> usize {
    let n = entry0_body.len();
    if n == 0 {
        return 0;
    }
    // Early-out: if first 64 bytes are not dominated by the nibble
    // alphabet, we're already in plaintext territory.
    let first64 = &entry0_body[..64.min(n)];
    if !first64.is_empty() {
        let hits = first64.iter().filter(|&&b| nibble_alphabet_contains(b)).count();
        if hits * 2 < first64.len() {
            return 0;
        }
    }
    let mut last_run_end = 0usize;
    let mut i = 0usize;
    while i < n {
        if nibble_alphabet_contains(entry0_body[i]) {
            let mut j = i;
            while j < n && nibble_alphabet_contains(entry0_body[j]) {
                j += 1;
            }
            if j - i >= min_run {
                last_run_end = j;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    last_run_end
}

/// Compact, JSON-serialisable summary of a parsed trailer — suitable
/// for the per-sample manifest. The full raw data section is NOT
/// included (it can be many MB) — only its length and the recovered
/// metadata.
pub fn summarise_trailer(tr: &JiaguTrailer) -> serde_json::Value {
    let mut flat_meta = Vec::with_capacity(tr.metadata.len());
    for m in &tr.metadata {
        let mut o = serde_json::Map::new();
        o.insert(
            "key_ascii".into(),
            serde_json::Value::String(m.key_str.clone()),
        );
        o.insert(
            "key_hex".into(),
            serde_json::Value::String(hex_lower(&m.key)),
        );
        o.insert(
            "type_byte".into(),
            serde_json::Value::from(m.type_byte as u32),
        );
        o.insert(
            "value_ascii".into(),
            serde_json::Value::String(m.value_str.clone()),
        );
        o.insert("value_len".into(), serde_json::Value::from(m.value.len()));
        flat_meta.push(serde_json::Value::Object(o));
    }

    let jiagu_version = tr.get("JiaguVersion").unwrap_or_default();

    // Slice entry-0's content for classification — limited to the
    // first 16+4096 bytes.
    let mut e0_slice: Vec<u8> = Vec::new();
    let e0_off = tr.entry0_off as usize;
    let e0_size = tr.entry0_size as usize;
    if e0_size > 0 && e0_off + e0_size.min(0x1000) <= tr.data_section.len() {
        let take = e0_size.min(0x1000);
        e0_slice = tr.data_section[e0_off..e0_off + take].to_vec();
    }
    let cls_by_data = if !e0_slice.is_empty() {
        classify_entry0_format(&e0_slice)
    } else {
        "unknown"
    };
    let cls_by_ver = classify_by_version(&jiagu_version);

    // Compute the plaintext-tail offset within entry-0's body
    // (post the 16-byte opaque header).
    let mut pt_tail_offset: usize = 0;
    let mut pt_tail_size: usize = 0;
    if e0_size > 16 && e0_off + e0_size <= tr.data_section.len() {
        let body = &tr.data_section[e0_off + 16..e0_off + e0_size];
        // Bounded prefix (16 MB cap) — alphabet-density scan is O(n)
        // but we don't want pathological behaviour on huge entries.
        let cap = 16 * 1024 * 1024;
        let scan = &body[..body.len().min(cap)];
        if scan.len() >= body.len() {
            pt_tail_offset = find_codeitems_tail_offset(scan, 32);
            pt_tail_size = body.len() - pt_tail_offset;
        } else {
            pt_tail_offset = 0;
            pt_tail_size = 0;
        }
    }

    let mut out = serde_json::Map::new();
    out.insert("trailer_off".into(), serde_json::Value::from(tr.trailer_off));
    out.insert("trailer_size".into(), serde_json::Value::from(tr.trailer_size));
    out.insert("data_off".into(), serde_json::Value::from(tr.data_off));
    out.insert("body_len".into(), serde_json::Value::from(tr.body_len));
    out.insert(
        "data_section_len".into(),
        serde_json::Value::from(tr.data_section.len()),
    );
    out.insert("n_entries".into(), serde_json::Value::from(tr.n_entries));
    out.insert("entry0_size".into(), serde_json::Value::from(tr.entry0_size));
    out.insert("entry0_off".into(), serde_json::Value::from(tr.entry0_off));
    out.insert(
        "encrypted_table_len".into(),
        serde_json::Value::from(tr.encrypted_table.len()),
    );
    out.insert("metadata".into(), serde_json::Value::Array(flat_meta));
    insert_opt(&mut out, "original_app", tr.get("AppName"));
    insert_opt(&mut out, "activity_name", tr.get("ActivityName"));
    insert_opt(&mut out, "apk_md5", tr.get("ApkMD5"));
    insert_opt(&mut out, "apk_sign", tr.get("Sign"));
    insert_opt(&mut out, "stub_class", tr.get("StubAppName"));
    insert_opt(&mut out, "package", tr.get("pkg"));
    insert_opt(&mut out, "version_code", tr.get("VersionCode"));
    insert_opt(&mut out, "version_name", tr.get("VersionName"));
    insert_opt(
        &mut out,
        "jiagu_version",
        if jiagu_version.is_empty() {
            None
        } else {
            Some(jiagu_version.clone())
        },
    );
    insert_opt(&mut out, "protect_time", tr.get("ProtectTime"));
    insert_opt(&mut out, "allowed_sig", tr.get("AllowedSig"));
    insert_opt(&mut out, "checksum", tr.get("Checksum"));
    insert_opt(&mut out, "sig_serial", tr.get("sig"));
    out.insert(
        "entry0_format_by_data".into(),
        serde_json::Value::String(cls_by_data.into()),
    );
    out.insert(
        "entry0_format_by_version".into(),
        serde_json::Value::String(cls_by_ver.into()),
    );
    let combined = if cls_by_data != "unknown" {
        cls_by_data
    } else {
        cls_by_ver
    };
    out.insert(
        "entry0_format".into(),
        serde_json::Value::String(combined.into()),
    );
    out.insert(
        "plaintext_tail_offset".into(),
        serde_json::Value::from(pt_tail_offset),
    );
    out.insert(
        "plaintext_tail_size".into(),
        serde_json::Value::from(pt_tail_size),
    );

    serde_json::Value::Object(out)
}

fn insert_opt(out: &mut serde_json::Map<String, serde_json::Value>, k: &str, v: Option<String>) {
    out.insert(
        k.into(),
        match v {
            Some(s) => serde_json::Value::String(s),
            None => serde_json::Value::Null,
        },
    );
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nibble_alphabet_basic() {
        for k in 0..17u32 {
            let b = ((0x0f * k) & 0xff) as u8;
            assert!(nibble_alphabet_contains(b), "missing 0x{:02x}", b);
        }
        assert!(nibble_alphabet_contains(0));
        assert!(!nibble_alphabet_contains(0x01));
        assert!(!nibble_alphabet_contains(0x10));
        assert!(!nibble_alphabet_contains(0xfe));
    }

    #[test]
    fn classify_by_version_matches_python() {
        assert_eq!(classify_by_version("1.3.9.9"), "v1_plaintext_codeitems");
        assert_eq!(classify_by_version("1.3.9"), "v1_plaintext_codeitems");
        assert_eq!(classify_by_version("1.2.0.0"), "v1_plaintext_codeitems");
        assert_eq!(classify_by_version("1.4.0.4"), "v2_nibble_obfuscated");
        assert_eq!(classify_by_version("1.4.5"), "v2_nibble_obfuscated");
        assert_eq!(classify_by_version("2.0.0"), "unknown");
        assert_eq!(classify_by_version(""), "unknown");
        assert_eq!(classify_by_version("bogus"), "unknown");
    }

    #[test]
    fn normalise_key_strips_separators_and_expands_markers() {
        // 0xa1 = 'A', 0xa3 = 'C'
        let input = b"\xa1ct_NAME";
        let out = normalise_key(input);
        // Expanded: 'A' 'c' 't' '_' 'N' 'A' 'M' 'E' → lowercased, sep dropped:
        // 'a' 'c' 't' 'n' 'a' 'm' 'e'
        assert_eq!(&out, b"actname");
    }

    #[test]
    fn render_value_handles_separators() {
        let s = render_value(b"foo\x0dbar\x0ebaz");
        assert_eq!(s, "foo_bar.baz");
    }

    #[test]
    fn parse_trailer_roundtrip() {
        // Build a minimal trailer:
        //   magic | size | data_off | body
        // Body: one chunk marker for key="x", value="y" plus the data section.
        // marker: d6 ed c6 c6 LL c6 c6 c6 TT c6 c6 c6 — LL=key_len^0xc6, TT=type^0xc6
        let key_len: u8 = 1;
        let type_byte: u8 = b'p';
        let marker: [u8; 12] = [
            0xd6,
            0xed,
            0xc6,
            0xc6,
            key_len ^ 0xc6,
            0xc6,
            0xc6,
            0xc6,
            type_byte ^ 0xc6,
            0xc6,
            0xc6,
            0xc6,
        ];
        // Payload encoded with XOR 0xa6: key + value
        let key: &[u8] = b"x";
        let value: &[u8] = b"y";
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(key);
        payload.extend_from_slice(value);
        let payload_enc: Vec<u8> = payload.iter().map(|b| b ^ 0xa6u8).collect();
        let mut body = Vec::new();
        body.extend_from_slice(&marker);
        body.extend_from_slice(&payload_enc);
        let data_off = body.len() as u32;
        // Data section: n_entries=1, entry0_size=0, entry0_off=0
        let mut data_section = Vec::new();
        data_section.extend_from_slice(&1u32.to_le_bytes()); // n_entries
        data_section.extend_from_slice(&0u32.to_le_bytes()); // entry0_size
        data_section.extend_from_slice(&0u32.to_le_bytes()); // entry0_off
        body.extend_from_slice(&data_section);

        let mut dex_bytes: Vec<u8> = vec![0u8; 16]; // prefix garbage
        dex_bytes.extend_from_slice(JIAGU_TRAILER_MAGIC);
        dex_bytes.extend_from_slice(&((body.len() + 12) as u32).to_le_bytes());
        dex_bytes.extend_from_slice(&data_off.to_le_bytes());
        dex_bytes.extend_from_slice(&body);

        let tr = parse_trailer(&dex_bytes).expect("trailer parses");
        assert_eq!(tr.trailer_off, 16);
        assert_eq!(tr.data_off as usize, data_off as usize);
        assert_eq!(tr.metadata.len(), 1);
        assert_eq!(&tr.metadata[0].key, b"x");
        assert_eq!(&tr.metadata[0].value, b"y");
        assert_eq!(tr.n_entries, 1);
    }

    #[test]
    fn find_codeitems_tail_v1_is_zero() {
        // 64-byte high-bit-poor sample → returns 0 immediately.
        let mut v = vec![0x01u8; 256];
        v[0] = 0x70;
        v[1] = 0x10;
        assert_eq!(find_codeitems_tail_offset(&v, 32), 0);
    }

    #[test]
    fn find_codeitems_tail_v2_locates_boundary() {
        // First 200 bytes are nibble alphabet, then plaintext-ish.
        let mut v: Vec<u8> = (0..200).map(|i| if i % 2 == 0 { 0x0f } else { 0x1e }).collect();
        v.extend(std::iter::repeat(0x02u8).take(100));
        let off = find_codeitems_tail_offset(&v, 32);
        // Expect a boundary near 200.
        assert!(off >= 32 && off <= 200, "got {}", off);
    }
}
