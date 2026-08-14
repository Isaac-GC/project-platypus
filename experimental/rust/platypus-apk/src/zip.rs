use std::io::{Cursor, Read};
use zip::{CompressionMethod, ZipArchive};

pub struct ApkZip {
    raw: Vec<u8>,
}

/// Inflate a raw (still-compressed) ZIP entry by its compression method.
///
/// We read entries via `by_index_raw` + this helper instead of the `zip`
/// crate's normal decoding path because some Android malware (Godfather and
/// friends) sets the ZIP "encrypted" general-purpose bit on `classes*.dex`
/// *without actually encrypting the data*. Android's loader ignores that bit
/// and runs the app, but a strict reader refuses the entry with "Password
/// required to decrypt file", which used to make the whole APK look like it had
/// no DEX. The bytes are plain Stored/Deflated, so we decode them directly.
///
/// Returns `None` for compression methods we don't handle (APK entries are only
/// ever Stored or Deflated).
fn inflate_raw(method: CompressionMethod, raw: Vec<u8>) -> Option<Vec<u8>> {
    match method {
        CompressionMethod::Stored => Some(raw),
        CompressionMethod::Deflated => {
            let mut out = Vec::new();
            flate2::read::DeflateDecoder::new(Cursor::new(raw))
                .read_to_end(&mut out)
                .ok()?;
            Some(out)
        }
        _ => None,
    }
}

impl ApkZip {
    /// Open an APK/ZIP from a file path.
    pub fn open(path: &str) -> Result<Self, super::ApkError> {
        let raw = std::fs::read(path)?;
        Self::from_bytes(raw)
    }

    /// Open from raw bytes (validates that it is a valid ZIP).
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, super::ApkError> {
        // Validate by opening once.
        let cursor = Cursor::new(&data);
        ZipArchive::new(cursor)?;
        Ok(ApkZip { raw: data })
    }

    /// Returns a fresh ZipArchive over the stored bytes.
    fn archive(&self) -> Result<ZipArchive<Cursor<&[u8]>>, super::ApkError> {
        let cursor = Cursor::new(self.raw.as_slice());
        Ok(ZipArchive::new(cursor)?)
    }

    /// List all entry names.
    pub fn list_entries(&self) -> Vec<String> {
        let Ok(mut archive) = self.archive() else { return Vec::new() };
        // Single archive — iterate all entries without re-opening for each one.
        // Use `by_index_raw`: names live in the central directory, so we don't
        // need to decode (and thus don't trip over the fake-encryption bit some
        // malware sets — see `inflate_raw`).
        let count = archive.len();
        let mut names = Vec::with_capacity(count);
        for i in 0..count {
            if let Ok(file) = archive.by_index_raw(i) {
                names.push(file.name().to_string());
            }
        }
        names
    }

    /// Read a named entry's bytes, tolerating the deceptive "encrypted" bit
    /// (see [`inflate_raw`]). Scans by raw index because `by_name` consults the
    /// `zip` crate's decode path, which the bit also poisons.
    pub fn read_entry(&self, name: &str) -> Result<Vec<u8>, super::ApkError> {
        let mut archive = self.archive()?;
        for i in 0..archive.len() {
            let mut file = match archive.by_index_raw(i) {
                Ok(f) => f,
                Err(_) => continue,
            };
            if file.name() != name {
                continue;
            }
            let method = file.compression();
            let mut raw = Vec::new();
            file.read_to_end(&mut raw)?;
            return inflate_raw(method, raw).ok_or_else(|| {
                super::ApkError::Zip(format!("unsupported compression for entry {name}"))
            });
        }
        Err(super::ApkError::NotFound(name.to_string()))
    }

    /// Check if an entry exists.
    pub fn has_entry(&self, name: &str) -> bool {
        self.list_entries().iter().any(|n| n == name)
    }

    /// Raw bytes of the APK.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Extract all DEX files: classes.dex, classes2.dex, ..., classesN.dex
    /// Returns (filename, bytes) pairs sorted by name.
    pub fn dex_files(&self) -> Vec<(String, Vec<u8>)> {
        let Ok(mut archive) = self.archive() else { return Vec::new() };
        // Single pass via `by_index_raw` so we decode each entry ourselves with
        // `inflate_raw`. This is what lets us read `classes*.dex` from APKs that
        // set the bogus "encrypted" bit; the normal `by_index` path refuses
        // those with "Password required to decrypt file" and the APK looks
        // empty of DEX. Only DEX entries are inflated — others are skipped
        // before any decompression.
        let count = archive.len();
        let mut result: Vec<(String, Vec<u8>)> = Vec::new();
        for i in 0..count {
            let mut file = match archive.by_index_raw(i) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let name = file.name().to_string();
            let is_dex = name == "classes.dex"
                || (name.starts_with("classes")
                    && name.ends_with(".dex")
                    && name.len() > 11
                    && name[7..name.len() - 4].chars().all(|c| c.is_ascii_digit()));
            if !is_dex {
                continue;
            }
            let method = file.compression();
            let mut raw = Vec::with_capacity(file.compressed_size() as usize);
            if file.read_to_end(&mut raw).is_err() {
                continue;
            }
            if let Some(bytes) = inflate_raw(method, raw) {
                result.push((name, bytes));
            }
        }
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal single-entry ZIP holding `data` Stored under `name`,
    /// with the ZIP **"encrypted" general-purpose bit (bit 0) set** even though
    /// the bytes are plain. This reproduces the Godfather/Android anti-analysis
    /// trick: Android's loader ignores the bit, but strict desktop readers
    /// refuse the entry with "Password required to decrypt file".
    fn fake_encrypted_zip(name: &str, data: &[u8]) -> Vec<u8> {
        let nb = name.as_bytes();
        let (nlen, dlen) = (nb.len() as u16, data.len() as u32);
        let mut z = Vec::new();
        // ── Local file header ──
        z.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // sig
        z.extend_from_slice(&20u16.to_le_bytes()); // version needed
        z.extend_from_slice(&0x0001u16.to_le_bytes()); // GP flags: encrypted bit
        z.extend_from_slice(&0u16.to_le_bytes()); // method: Stored
        z.extend_from_slice(&0u16.to_le_bytes()); // mod time
        z.extend_from_slice(&0u16.to_le_bytes()); // mod date
        z.extend_from_slice(&0u32.to_le_bytes()); // crc32 (unchecked on raw read)
        z.extend_from_slice(&dlen.to_le_bytes()); // compressed size
        z.extend_from_slice(&dlen.to_le_bytes()); // uncompressed size
        z.extend_from_slice(&nlen.to_le_bytes()); // name length
        z.extend_from_slice(&0u16.to_le_bytes()); // extra length
        z.extend_from_slice(nb);
        z.extend_from_slice(data);
        // ── Central directory header ──
        let cd_off = z.len() as u32;
        z.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]); // sig
        z.extend_from_slice(&20u16.to_le_bytes()); // version made by
        z.extend_from_slice(&20u16.to_le_bytes()); // version needed
        z.extend_from_slice(&0x0001u16.to_le_bytes()); // GP flags: encrypted bit
        z.extend_from_slice(&0u16.to_le_bytes()); // method: Stored
        z.extend_from_slice(&0u16.to_le_bytes()); // mod time
        z.extend_from_slice(&0u16.to_le_bytes()); // mod date
        z.extend_from_slice(&0u32.to_le_bytes()); // crc32
        z.extend_from_slice(&dlen.to_le_bytes()); // compressed size
        z.extend_from_slice(&dlen.to_le_bytes()); // uncompressed size
        z.extend_from_slice(&nlen.to_le_bytes()); // name length
        z.extend_from_slice(&0u16.to_le_bytes()); // extra length
        z.extend_from_slice(&0u16.to_le_bytes()); // comment length
        z.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        z.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        z.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        z.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        z.extend_from_slice(nb);
        // ── End of central directory ──
        let cd_size = z.len() as u32 - cd_off;
        z.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // sig
        z.extend_from_slice(&0u16.to_le_bytes()); // disk number
        z.extend_from_slice(&0u16.to_le_bytes()); // disk w/ cd start
        z.extend_from_slice(&1u16.to_le_bytes()); // cd records this disk
        z.extend_from_slice(&1u16.to_le_bytes()); // total cd records
        z.extend_from_slice(&cd_size.to_le_bytes()); // cd size
        z.extend_from_slice(&cd_off.to_le_bytes()); // cd offset
        z.extend_from_slice(&0u16.to_le_bytes()); // comment length
        z
    }

    #[test]
    fn reads_dex_despite_fake_encryption_bit() {
        let dex = b"dex\n035\0\x01\x02\x03\x04 fake but plausible";
        let bytes = fake_encrypted_zip("classes.dex", dex);

        // Sanity: the trick actually defeats the strict path the way the real
        // sample does — the zip crate refuses the entry.
        let mut strict = ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();
        assert!(strict.by_index(0).is_err(), "encryption bit should block the strict path");

        // Our tolerant path recovers it.
        let apk = ApkZip::from_bytes(bytes).expect("opens");
        let dexes = apk.dex_files();
        assert_eq!(dexes.len(), 1, "should recover the DEX");
        assert_eq!(dexes[0].0, "classes.dex");
        assert_eq!(dexes[0].1, dex, "DEX bytes must round-trip");
        assert!(apk.has_entry("classes.dex"));
        assert!(apk.list_entries().contains(&"classes.dex".to_string()));
    }

    #[test]
    fn decoy_directory_entries_do_not_masquerade_as_dex() {
        // A `classes.dex/...` decoy (the other half of the trick) must not be
        // picked up as a DEX, and the real one still is.
        let zip = fake_encrypted_zip("classes.dex/res/foo.xml", b"<not a dex>");
        let apk = ApkZip::from_bytes(zip).expect("opens");
        assert_eq!(apk.dex_files().len(), 0, "decoy must not count as DEX");
    }
}
