//! Build a new APK out of an existing one + a set of in-memory edits.
//!
//! Edits are file-level: replace an entry, add a new one, or delete an
//! existing one. The output is a fresh ZIP — we never mutate the input
//! buffer or file. Edits are applied in this priority order:
//!
//!   1. Deletions (entries not emitted)
//!   2. Replacements (entry bytes overridden, attributes inherited)
//!   3. Additions (new entries appended)
//!
//! The output is **zipaligned**: every STORED (uncompressed) entry's
//! local-header `extra` field is padded so the entry's data starts at
//! a 4-byte boundary inside the archive. `zipalign` is a hard
//! requirement for APKs that contain `.so` libraries on some Android
//! versions, and harmless otherwise.
//!
//! What this module deliberately does *not* do:
//!   - Emit `META-INF/MANIFEST.MF` etc. — that's [`crate::signing::v1`]
//!   - Compute or insert the APK Signing Block — that's
//!     [`crate::signing::v2`]
//! Run the builder *first*, then hand its output to the signing layer.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::collections::BTreeMap;

use zip::write::{SimpleFileOptions, ZipWriter};
use zip::{CompressionMethod, ZipArchive};

/// One source for an entry going into the output APK.
pub enum BuildEntry {
    /// Inherit the entry verbatim from the input APK at `name`.
    /// Lets us pass through most entries unchanged.
    Inherit { name: String },
    /// Replace the entry at `name` with `bytes`. Compression mirrors
    /// what the input used unless [`Self::Add::stored`] is set.
    Replace { name: String, bytes: Vec<u8> },
    /// Add a brand-new entry. `stored` controls whether the entry is
    /// uncompressed (STORED) — required for `.so` files inside APKs
    /// or anything you want zipaligned. Default is DEFLATE.
    Add { name: String, bytes: Vec<u8>, stored: bool },
}

/// Outcome reported back to the caller, useful for CLI summaries.
#[derive(Debug, Clone, Default)]
pub struct BuildOutcome {
    pub entries_inherited: usize,
    pub entries_replaced:  usize,
    pub entries_added:     usize,
    pub entries_deleted:   usize,
    pub bytes_written:     usize,
}

/// The repack orchestrator.
pub struct ApkBuilder {
    /// Original APK bytes. Kept around so `BuildEntry::Inherit` can pull
    /// from it without re-opening the file.
    original: Vec<u8>,
    /// Override map: file path → operation. `None` = delete.
    overrides: BTreeMap<String, Option<EntryOverride>>,
    /// Brand-new entries to append after inherited ones.
    additions: Vec<NewEntry>,
    /// Whether to strip the input's existing `META-INF/*.{MF,SF,RSA,EC,DSA}`
    /// — true by default since you almost always want to re-sign.
    strip_existing_meta_inf_signatures: bool,
    zipalign: bool,
}

struct EntryOverride {
    bytes: Vec<u8>,
    /// `None` = inherit input's compression, `Some(method)` = override.
    method: Option<CompressionMethod>,
}

struct NewEntry {
    name: String,
    bytes: Vec<u8>,
    method: CompressionMethod,
}

impl ApkBuilder {
    /// Open an existing APK from disk.
    pub fn from_apk(path: &std::path::Path) -> crate::Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(bytes)
    }

    /// Open an APK already in memory.
    pub fn from_bytes(bytes: Vec<u8>) -> crate::Result<Self> {
        // Sanity-check it's a valid ZIP.
        let _ = ZipArchive::new(Cursor::new(&bytes))?;
        Ok(Self {
            original: bytes,
            overrides: BTreeMap::new(),
            additions: Vec::new(),
            strip_existing_meta_inf_signatures: true,
            zipalign: true,
        })
    }

    /// Apply a replacement. The new bytes will inherit the input's
    /// compression method.
    pub fn replace(&mut self, name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> &mut Self {
        self.overrides.insert(name.into(), Some(EntryOverride {
            bytes: bytes.into(), method: None,
        }));
        self
    }

    /// Replace AND force a specific compression. Useful for `.so` files
    /// that must be STORED for system loaders.
    pub fn replace_with_method(
        &mut self, name: impl Into<String>, bytes: impl Into<Vec<u8>>,
        method: CompressionMethod,
    ) -> &mut Self {
        self.overrides.insert(name.into(), Some(EntryOverride {
            bytes: bytes.into(), method: Some(method),
        }));
        self
    }

    /// Add a brand-new entry. Pass `stored=true` for files the OS
    /// loader needs to mmap (`.so`).
    pub fn add(&mut self, name: impl Into<String>, bytes: impl Into<Vec<u8>>, stored: bool) -> &mut Self {
        self.additions.push(NewEntry {
            name: name.into(),
            bytes: bytes.into(),
            method: if stored { CompressionMethod::Stored } else { CompressionMethod::Deflated },
        });
        self
    }

    pub fn delete(&mut self, name: impl Into<String>) -> &mut Self {
        self.overrides.insert(name.into(), None);
        self
    }

    /// Turn off automatic stripping of META-INF signatures. Default is on
    /// because you almost always want to re-sign rather than carry stale
    /// signature blobs.
    pub fn keep_existing_signatures(&mut self) -> &mut Self {
        self.strip_existing_meta_inf_signatures = false;
        self
    }

    pub fn no_zipalign(&mut self) -> &mut Self {
        self.zipalign = false;
        self
    }

    /// Materialise the new APK bytes.
    pub fn build(&self) -> crate::Result<(Vec<u8>, BuildOutcome)> {
        let mut outcome = BuildOutcome::default();

        let mut out = Cursor::new(Vec::with_capacity(self.original.len()));
        let mut writer = ZipWriter::new(&mut out);

        let mut input = ZipArchive::new(Cursor::new(&self.original))?;
        let names: Vec<String> = (0..input.len())
            .map(|i| input.by_index(i).map(|e| e.name().to_string()))
            .collect::<Result<Vec<_>, _>>()?;

        // ── Inherited / replaced entries ──
        for name in &names {
            // Strip old signatures unless the caller opted out.
            if self.strip_existing_meta_inf_signatures && is_meta_inf_signature(name) {
                outcome.entries_deleted += 1;
                continue;
            }
            match self.overrides.get(name) {
                Some(None) => {
                    outcome.entries_deleted += 1;
                    continue;
                }
                Some(Some(override_)) => {
                    let method = override_.method.unwrap_or_else(|| {
                        // Inherit method from the source entry.
                        input.by_name(name).map(|e| e.compression())
                             .unwrap_or(CompressionMethod::Deflated)
                    });
                    write_entry(&mut writer, name, &override_.bytes, method, self.zipalign)?;
                    outcome.entries_replaced += 1;
                }
                None => {
                    // Inherit.
                    let mut source = input.by_name(name)?;
                    let method = source.compression();
                    let mut buf = Vec::with_capacity(source.size() as usize);
                    source.read_to_end(&mut buf)?;
                    write_entry(&mut writer, name, &buf, method, self.zipalign)?;
                    outcome.entries_inherited += 1;
                }
            }
        }

        // ── Brand-new entries ──
        for add in &self.additions {
            if names.iter().any(|n| n == &add.name) {
                // The output already has this name (inherited or
                // replaced). Skip the add to avoid duplicate entries.
                continue;
            }
            write_entry(&mut writer, &add.name, &add.bytes, add.method, self.zipalign)?;
            outcome.entries_added += 1;
        }

        writer.finish()?;
        let bytes = out.into_inner();
        outcome.bytes_written = bytes.len();
        Ok((bytes, outcome))
    }
}

fn write_entry<W: Write + Seek>(
    writer: &mut ZipWriter<W>,
    name: &str,
    bytes: &[u8],
    method: CompressionMethod,
    zipalign: bool,
) -> crate::Result<()> {
    // Zipalign: for STORED entries, pad the local-file-header's `extra`
    // field so the entry's *data* starts on a 4-byte boundary inside
    // the output archive. zip 2.x exposes this via `with_alignment`.
    // 4-byte alignment is the conventional choice for APKs; some APKs
    // bump native libs (`lib/*/*.so`) to 4096 (page alignment).
    let alignment: u16 = if zipalign && method == CompressionMethod::Stored {
        if is_native_lib(name) { 4096 } else { 4 }
    } else { 1 };
    let opts = SimpleFileOptions::default()
        .compression_method(method)
        .with_alignment(alignment);
    writer.start_file(name, opts)?;
    writer.write_all(bytes)?;
    Ok(())
}

/// Native libraries inside `lib/<abi>/*.so` need 4K page alignment for
/// modern Android linkers (Android 6+) to mmap them directly out of the
/// APK without copying. All other STORED entries are fine with 4-byte
/// alignment.
fn is_native_lib(name: &str) -> bool {
    name.starts_with("lib/") && name.ends_with(".so")
}

/// True for the META-INF entries that hold v1 (JAR) signature blobs.
/// These get stripped during repack because the new signing pass will
/// emit fresh ones (and stale ones would fail verification).
fn is_meta_inf_signature(name: &str) -> bool {
    if !name.starts_with("META-INF/") { return false; }
    let upper = name.to_ascii_uppercase();
    upper.ends_with(".SF") || upper.ends_with(".RSA") || upper.ends_with(".EC")
        || upper.ends_with(".DSA") || upper == "META-INF/MANIFEST.MF"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_apk() -> Vec<u8> {
        let mut out = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut out);
            w.start_file("AndroidManifest.xml", SimpleFileOptions::default()).unwrap();
            w.write_all(b"<fake manifest>").unwrap();
            w.start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default()).unwrap();
            w.write_all(b"old signature").unwrap();
            w.start_file("classes.dex",
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored)).unwrap();
            w.write_all(b"deadbeef").unwrap();
            w.finish().unwrap();
        }
        out.into_inner()
    }

    #[test]
    fn inherit_passthrough() {
        let apk = make_test_apk();
        let mut b = ApkBuilder::from_bytes(apk).unwrap();
        b.keep_existing_signatures(); // don't strip
        let (out, summary) = b.build().unwrap();
        // The output is a valid zip with the same 3 entries.
        let zr = ZipArchive::new(Cursor::new(&out)).unwrap();
        assert_eq!(zr.len(), 3);
        assert_eq!(summary.entries_inherited, 3);
    }

    #[test]
    fn strips_old_signatures_by_default() {
        let apk = make_test_apk();
        let b = ApkBuilder::from_bytes(apk).unwrap();
        let (out, summary) = b.build().unwrap();
        let zr = ZipArchive::new(Cursor::new(&out)).unwrap();
        assert_eq!(zr.len(), 2);
        assert_eq!(summary.entries_deleted, 1);
    }

    #[test]
    fn replace_overrides_bytes() {
        let apk = make_test_apk();
        let mut b = ApkBuilder::from_bytes(apk).unwrap();
        b.replace("classes.dex", b"replaced!".to_vec());
        let (out, _) = b.build().unwrap();
        let mut zr = ZipArchive::new(Cursor::new(&out)).unwrap();
        let mut buf = Vec::new();
        zr.by_name("classes.dex").unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"replaced!");
    }

    #[test]
    fn add_new_entry() {
        let apk = make_test_apk();
        let mut b = ApkBuilder::from_bytes(apk).unwrap();
        b.add("assets/new.bin", b"hello".to_vec(), true);
        let (out, summary) = b.build().unwrap();
        let mut zr = ZipArchive::new(Cursor::new(&out)).unwrap();
        let mut buf = Vec::new();
        zr.by_name("assets/new.bin").unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello");
        assert_eq!(summary.entries_added, 1);
    }

    #[test]
    fn delete_drops_entry() {
        let apk = make_test_apk();
        let mut b = ApkBuilder::from_bytes(apk).unwrap();
        b.delete("AndroidManifest.xml");
        let (out, _) = b.build().unwrap();
        let zr = ZipArchive::new(Cursor::new(&out)).unwrap();
        assert!(zr.file_names().all(|n| n != "AndroidManifest.xml"));
    }
}
