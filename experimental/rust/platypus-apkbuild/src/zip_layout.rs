//! Minimal ZIP introspection: locate the central directory + End of
//! Central Directory record in a byte buffer.
//!
//! Used by the signing path which needs exact offsets to:
//!   - hash the file contents (offset 0..central_dir_start)
//!   - hash the central directory (central_dir_start..central_dir_end)
//!   - hash a *modified* EOCD where the central-directory-offset field
//!     points past the inserted signing block
//!   - insert the signing block between contents and central directory
//!
//! Spec: APPNOTE.TXT 6.3.10. Zip64 is partially handled (we read the
//! Zip64 EOCD locator if present) — enough for typical signed APKs,
//! not for >4GB archives.

use byteorder::{ByteOrder, LittleEndian as LE};

/// Signature bytes for the End of Central Directory record.
const EOCD_MAGIC:        u32 = 0x06054b50;
/// Zip64 locator magic (right before the regular EOCD, when present).
const ZIP64_EOCDL_MAGIC: u32 = 0x07064b50;
/// Zip64 EOCD magic (referenced by the locator).
const ZIP64_EOCD_MAGIC:  u32 = 0x06064b50;

/// Decoded ZIP layout — byte ranges within an in-memory APK buffer.
#[derive(Debug, Clone)]
pub struct ZipLayout {
    /// Where the file-entry data starts. Always 0 for a normal APK.
    pub contents_start: u64,
    /// Where the central directory begins. Everything between
    /// `contents_start` and `cd_start` is file entries.
    pub cd_start: u64,
    /// Size of the central directory.
    pub cd_size: u64,
    /// Where the End of Central Directory record (or Zip64 locator +
    /// EOCD when the archive uses Zip64) starts. The EOCD itself runs
    /// from here to the end of the buffer.
    pub eocd_start: u64,
    /// True if a Zip64 EOCD + locator are present. v2 signing handles
    /// both the regular and Zip64 EOCD shapes.
    pub is_zip64: bool,
}

impl ZipLayout {
    /// Locate the EOCD by scanning backward from the buffer end for
    /// the [`EOCD_MAGIC`] marker. The marker is followed by 18 bytes
    /// of fixed fields and a variable-length comment; the spec allows
    /// the comment to be up to 64K, so we cap our scan at the last 64K
    /// + 22 bytes of buffer.
    pub fn parse(buf: &[u8]) -> crate::Result<Self> {
        if buf.len() < 22 {
            return Err(crate::Error::InvalidApk("apk smaller than empty EOCD".into()));
        }
        let max_eocd_offset = buf.len().saturating_sub(22);
        let scan_floor = max_eocd_offset.saturating_sub(0x10000);
        let mut eocd_off: Option<usize> = None;
        for off in (scan_floor..=max_eocd_offset).rev() {
            if LE::read_u32(&buf[off..]) == EOCD_MAGIC {
                eocd_off = Some(off);
                break;
            }
        }
        let eocd_off = eocd_off.ok_or_else(||
            crate::Error::InvalidApk("EOCD not found (apk truncated?)".into()))?;

        let mut cd_size_32  = LE::read_u32(&buf[eocd_off + 12..]) as u64;
        let mut cd_off_32   = LE::read_u32(&buf[eocd_off + 16..]) as u64;

        // Detect Zip64. If either of those fields is 0xFFFFFFFF, the
        // real value lives in the Zip64 EOCD.
        let mut is_zip64 = false;
        let mut eocd_start = eocd_off as u64;

        if cd_size_32 == 0xFFFF_FFFF || cd_off_32 == 0xFFFF_FFFF {
            is_zip64 = true;
            // Look for the Zip64 EOCD locator right before the regular EOCD.
            if eocd_off < 20 {
                return Err(crate::Error::InvalidApk(
                    "zip64 marker present but no room for EOCD locator".into()));
            }
            let locator_off = eocd_off - 20;
            if LE::read_u32(&buf[locator_off..]) != ZIP64_EOCDL_MAGIC {
                return Err(crate::Error::InvalidApk(
                    "zip64 EOCD locator missing".into()));
            }
            let zip64_eocd_off = LE::read_u64(&buf[locator_off + 8..]) as usize;
            if zip64_eocd_off + 4 > buf.len() {
                return Err(crate::Error::InvalidApk(
                    "zip64 EOCD offset out of bounds".into()));
            }
            if LE::read_u32(&buf[zip64_eocd_off..]) != ZIP64_EOCD_MAGIC {
                return Err(crate::Error::InvalidApk(
                    "zip64 EOCD magic missing".into()));
            }
            cd_size_32 = LE::read_u64(&buf[zip64_eocd_off + 40..]);
            cd_off_32  = LE::read_u64(&buf[zip64_eocd_off + 48..]);
            // The EOCD region starts at the Zip64 EOCD, not the
            // regular one — the signing block lives between contents
            // and the Zip64 EOCD.
            eocd_start = zip64_eocd_off as u64;
        }

        Ok(ZipLayout {
            contents_start: 0,
            cd_start: cd_off_32,
            cd_size: cd_size_32,
            eocd_start,
            is_zip64,
        })
    }

    /// End byte (exclusive) of the central directory.
    pub fn cd_end(&self) -> u64 { self.cd_start + self.cd_size }

    /// Rewrite the EOCD's "offset of central directory" field in
    /// place to point at `new_cd_offset`. Used after inserting the
    /// signing block so the EOCD continues to refer to the central
    /// directory at its new location.
    pub fn patch_eocd_cd_offset(buf: &mut [u8], new_cd_offset: u64) -> crate::Result<()> {
        // Scan for the EOCD marker same as `parse`.
        if buf.len() < 22 {
            return Err(crate::Error::InvalidApk("buffer too small for EOCD".into()));
        }
        let max_eocd_offset = buf.len() - 22;
        let scan_floor = max_eocd_offset.saturating_sub(0x10000);
        let mut eocd_off: Option<usize> = None;
        for off in (scan_floor..=max_eocd_offset).rev() {
            if LE::read_u32(&buf[off..]) == EOCD_MAGIC {
                eocd_off = Some(off);
                break;
            }
        }
        let eocd_off = eocd_off.ok_or_else(||
            crate::Error::InvalidApk("EOCD not found while patching".into()))?;
        if new_cd_offset > u32::MAX as u64 {
            // Zip64 — write the sentinel here and update the Zip64 EOCD too.
            LE::write_u32(&mut buf[eocd_off + 16..eocd_off + 20], 0xFFFF_FFFF);
            // Find the Zip64 locator + EOCD.
            if eocd_off < 20 {
                return Err(crate::Error::InvalidApk(
                    "expected Zip64 locator but EOCD too close to start".into()));
            }
            let loc_off = eocd_off - 20;
            if LE::read_u32(&buf[loc_off..]) != ZIP64_EOCDL_MAGIC {
                return Err(crate::Error::InvalidApk(
                    "Zip64 sentinel in EOCD but locator missing".into()));
            }
            let z64_eocd_off = LE::read_u64(&buf[loc_off + 8..]) as usize;
            LE::write_u64(&mut buf[z64_eocd_off + 48..z64_eocd_off + 56], new_cd_offset);
            // Also patch the locator's relative offset (it points at the
            // Zip64 EOCD, which we're NOT moving — the locator stays valid).
        } else {
            LE::write_u32(&mut buf[eocd_off + 16..eocd_off + 20], new_cd_offset as u32);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct an empty-but-valid ZIP: no entries, EOCD only.
    fn empty_zip() -> Vec<u8> {
        let mut out = Vec::new();
        // EOCD: magic + disk_no(0) + cd_disk(0) + cd_entries_this_disk(0)
        //       + cd_entries_total(0) + cd_size(0) + cd_off(0) + comment_len(0)
        out.extend_from_slice(&EOCD_MAGIC.to_le_bytes());
        out.extend_from_slice(&[0u8; 18]);  // 18 bytes of zero
        out
    }

    #[test]
    fn parses_empty_zip() {
        let buf = empty_zip();
        let l = ZipLayout::parse(&buf).unwrap();
        assert_eq!(l.contents_start, 0);
        assert_eq!(l.cd_start, 0);
        assert_eq!(l.cd_size, 0);
        assert_eq!(l.eocd_start, 0);
        assert!(!l.is_zip64);
    }

    #[test]
    fn rejects_truncated() {
        assert!(ZipLayout::parse(&[]).is_err());
        assert!(ZipLayout::parse(b"PK\x05\x06").is_err());
    }

    #[test]
    fn patches_cd_offset_32bit() {
        let mut buf = empty_zip();
        ZipLayout::patch_eocd_cd_offset(&mut buf, 1234).unwrap();
        let after = ZipLayout::parse(&buf).unwrap();
        assert_eq!(after.cd_start, 1234);
    }
}
