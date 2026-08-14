//! VBPD container extraction (Report §6 — legacy DEX-body container).
//!
//! Older Virbox builds wrap a private-format encrypted-bytecode container
//! inside the DEX's `data` section. The container's `VBPD` magic sits at
//! a fixed offset (`0x13c`) from the container start; a 20-byte
//! "r21e prologue" appears at one of four canonical offsets inside the
//! first 0x80 bytes after the magic.
//!
//! This module only carves the container blob — bytecode translation
//! lives in the Python `virbox_bundle/scripts/vbpd_lifter/` tree and is
//! out of scope here (see TODO in UNRECOVERED.md).

use serde::{Deserialize, Serialize};

/// `VBPD` magic marker.
pub const VBPD_MAGIC: &[u8; 4] = b"VBPD";

/// The container header is always at this offset behind the `VBPD`
/// magic — the magic is at `container_start + 0x13c`.
pub const VBPD_MAGIC_OFFSET_IN_CONTAINER: usize = 0x13c;

/// 20-byte invariant that appears in every Virbox VBPD container we
/// have observed (224 of 235 Virbox samples in this corpus). The
/// trailing 0xf0 byte that was originally documented as part of an
/// r21e prologue is sample-dependent and is stripped from the
/// canonical signature.
///
/// Placement table observed in this corpus:
///
/// ```text
///     position (from VBPD magic)  | n samples | label
///     +0x40 (body+0)              |    24     | r21e-body0
///     +0x44 (body+4)              |     4     | r21e-classic
///     +0x38 (header[14..15]+body) |   196     | r22-split
///     +0x28 (header[10..14])      |    ~5     | r22-deep-split
/// ```
pub const VBPD_R21E_REF: [u8; 20] = [
    0x02, 0x7c, 0x4c, 0x55, 0xab, 0xd5, 0x40, 0x76, 0x41, 0xdf, 0x4c, 0x8a, 0x9d, 0x72, 0xca, 0x02,
    0x67, 0x5b, 0xac, 0xdc,
];

/// Recovered VBPD container metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbpdContainer {
    pub dex_name: String,
    /// Byte offset of the container start within the host DEX.
    pub container_offset: usize,
    /// Byte offset of the `VBPD` magic within the host DEX
    /// (always `container_offset + 0x13c`).
    pub magic_offset: usize,
    /// Container payload length: `len(dex) - container_offset`.
    pub container_size: usize,
    /// `size` field claimed in the container header (bytes 4..8 after magic).
    pub header_size: u32,
    /// `ver` field claimed in the container header.
    pub ver: u32,
    /// `count` field claimed in the container header.
    pub count: u32,
    /// True iff the 20-byte invariant matched at any of the canonical
    /// offsets within the first 0x80 bytes after the magic.
    pub has_r21e_prologue: bool,
    /// `"r21e-classic" | "r21e-body0" | "r22-split" | "r22-deep-split"
    /// | "other@+0x.." | ""` (empty when no invariant present).
    pub prologue_layout: String,
    /// Hex of the 20-byte invariant slot (canonicalised). When no match
    /// is found we still emit the bytes at +0x40 as a debugging aid.
    pub prologue: String,
    /// Filesystem path of the carved container blob (filled by the
    /// orchestrator after `write_bytes`).
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub blob_path: String,
}

/// Locate the VBPD container inside `dex_bytes`. Returns `None` if the
/// `VBPD` magic isn't present anywhere.
///
/// Accepts all four observed prologue layouts (see [`VBPD_R21E_REF`]).
/// Any prologue match confirms a "real" VBPD-encrypted body — useful
/// to filter false-positive `b"VBPD"` matches in unrelated DEX content.
pub fn find_vbpd_container(dex_bytes: &[u8], dex_name: &str) -> Option<VbpdContainer> {
    let p = find_subsequence(dex_bytes, VBPD_MAGIC)?;
    let container_start = p.saturating_sub(VBPD_MAGIC_OFFSET_IN_CONTAINER);
    if p + 16 > dex_bytes.len() {
        return None;
    }
    let header_size = u32::from_le_bytes(dex_bytes[p + 4..p + 8].try_into().unwrap());
    let ver = u32::from_le_bytes(dex_bytes[p + 8..p + 12].try_into().unwrap());
    let count = u32::from_le_bytes(dex_bytes[p + 12..p + 16].try_into().unwrap());

    // Search the first 0x80 bytes after the magic for the 20-byte invariant.
    let head_end = (p + 0x80).min(dex_bytes.len());
    let head = &dex_bytes[p..head_end];
    let (pos, has_prologue) = match find_subsequence(head, &VBPD_R21E_REF) {
        Some(idx) => (idx as isize, true),
        None => (-1, false),
    };

    let layout = match pos {
        0x40 => "r21e-body0".to_string(),
        0x44 => "r21e-classic".to_string(),
        0x38 => "r22-split".to_string(),
        0x28 => "r22-deep-split".to_string(),
        x if x > 0 => format!("other@+0x{:x}", x),
        _ => String::new(),
    };

    // Canonical prologue rendering: if matched, the 20 bytes at the
    // match offset; otherwise the bytes at the default +0x40 slot (so
    // operators can eyeball what the candidate looked like).
    let prologue_hex = if pos >= 0 {
        let pos = pos as usize;
        let end = (pos + 20).min(head.len());
        hex(&head[pos..end])
    } else {
        let off = 0x40usize;
        let end = (off + 20).min(head.len());
        if off < head.len() {
            hex(&head[off..end])
        } else {
            String::new()
        }
    };

    Some(VbpdContainer {
        dex_name: dex_name.to_string(),
        container_offset: container_start,
        magic_offset: p,
        container_size: dex_bytes.len() - container_start,
        header_size,
        ver,
        count,
        has_r21e_prologue: has_prologue,
        prologue_layout: layout,
        prologue: prologue_hex,
        blob_path: String::new(),
    })
}

/// Naive byte-substring search. The needle is at most 20 bytes
/// throughout this module, so the n*m worst case is fine.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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

    /// Build a synthetic DEX-like buffer that places the `VBPD` magic at
    /// `0x13c` from a chosen container start, and the 20-byte invariant
    /// at `+0x40` from the magic (r21e-body0 layout). Verify detection.
    #[test]
    fn container_locates_in_synthetic_buffer() {
        let container_start = 0x1000usize;
        let magic_offset = container_start + VBPD_MAGIC_OFFSET_IN_CONTAINER;
        let prologue_offset = magic_offset + 0x40;
        let total_len = prologue_offset + 32; // some tail bytes after the prologue
        let mut buf = vec![0u8; total_len];

        // Magic + 12-byte header (size=0x1234, ver=1, count=2)
        buf[magic_offset..magic_offset + 4].copy_from_slice(VBPD_MAGIC);
        buf[magic_offset + 4..magic_offset + 8].copy_from_slice(&0x1234u32.to_le_bytes());
        buf[magic_offset + 8..magic_offset + 12].copy_from_slice(&1u32.to_le_bytes());
        buf[magic_offset + 12..magic_offset + 16].copy_from_slice(&2u32.to_le_bytes());

        // The 20-byte invariant at +0x40
        buf[prologue_offset..prologue_offset + VBPD_R21E_REF.len()].copy_from_slice(&VBPD_R21E_REF);

        let vc = find_vbpd_container(&buf, "synthetic.dex").expect("container detected");
        assert_eq!(vc.dex_name, "synthetic.dex");
        assert_eq!(vc.magic_offset, magic_offset);
        assert_eq!(vc.container_offset, container_start);
        assert_eq!(vc.container_size, total_len - container_start);
        assert_eq!(vc.header_size, 0x1234);
        assert_eq!(vc.ver, 1);
        assert_eq!(vc.count, 2);
        assert!(vc.has_r21e_prologue);
        assert_eq!(vc.prologue_layout, "r21e-body0");
        // 20 bytes hex = 40 chars
        assert_eq!(vc.prologue.len(), 40);
    }

    /// No `VBPD` magic anywhere — should cleanly return None.
    #[test]
    fn container_absent_returns_none() {
        let buf = vec![0u8; 4096];
        assert!(find_vbpd_container(&buf, "empty.dex").is_none());
    }

    /// Magic present but no prologue at any canonical offset — still
    /// returns Some with `has_r21e_prologue=false`.
    #[test]
    fn container_without_prologue_still_returns() {
        let mut buf = vec![0u8; 4096];
        let magic_offset = 0x500;
        buf[magic_offset..magic_offset + 4].copy_from_slice(VBPD_MAGIC);
        let vc = find_vbpd_container(&buf, "noprologue.dex").expect("magic still locates");
        assert!(!vc.has_r21e_prologue);
        assert_eq!(vc.prologue_layout, "");
    }
}
