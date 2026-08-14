//! APK Signature Scheme v4 — `.idsig` sidecar file for incremental
//! install on Android 11+.
//!
//! Spec: <https://source.android.com/docs/security/features/apksigning/v4>
//!
//! v4 is fundamentally different from v2/v3:
//!
//!   * The signature lives in a **separate `.idsig` file** alongside
//!     the APK, never inside the APK itself.
//!   * The integrity-protected data is a **Merkle tree** over the APK
//!     bytes in 4 KB chunks (fs-verity compatible). This is what lets
//!     Android's `installd` start running the app *before* the full
//!     download finishes — only the page-sized chunks the app actually
//!     touches need to be downloaded + verified.
//!   * The root hash of that Merkle tree is what gets RSA-signed.
//!
//! Wire format of the `.idsig` file (length-prefixed sequence):
//!
//! ```text
//!   version          u32         = 2 (we emit "V4 with signing-info-v2")
//!   hashing_info     blob {
//!       hash_algo            u32  = 1 (SHA-256)
//!       log2_block_size      u8   = 12 (4 KB chunks)
//!       salt_size            u32  = 0
//!       raw_root_hash_size   u32  = 32
//!       raw_root_hash        bytes[32]
//!   }
//!   signing_info     blob {
//!       apk_digest                   length-prefixed bytes  (master v3 digest)
//!       x509_certificate             length-prefixed bytes  (DER)
//!       additional_data              length-prefixed bytes  (empty)
//!       public_key                   length-prefixed bytes  (SPKI DER)
//!       signature_algorithm_id       u32                    (0x0103)
//!       signature                    length-prefixed bytes  (sign(signed_data))
//!   }
//!   merkle_tree      blob {
//!       length            u32
//!       hash_tree_levels  bytes  (full hash tree concatenated)
//!   }
//! ```
//!
//! What `signed_data` is over: the concatenation of
//! `hashing_info` + `signing_info_without_signature` + the apk digest.
//! We follow the v4 signer impl in apksig — the canonical signing
//! payload is the same bytes verifyers would reconstruct.

use byteorder::{ByteOrder, LE};
use sha2::{Digest, Sha256};

use crate::keys::KeyPair;
use crate::zip_layout::ZipLayout;

/// 4 KB chunks for the Merkle tree leaves. fs-verity's standard.
const PAGE_SIZE: usize = 4096;
/// log2(4096) = 12.
const LOG2_PAGE_SIZE: u8 = 12;
/// SHA-256 in fs-verity's algorithm enum.
const HASH_ALGO_SHA256: u32 = 1;
/// Same algo ID v2/v3 use — RSA-PKCS#1-v1.5 with SHA-256.
const SIGNATURE_ALGO: u32 = 0x0103;
/// fs-verity-style version field.
const V4_FILE_VERSION: u32 = 2;

/// Build the `.idsig` sidecar for a fully-signed APK.
///
/// The input `apk` should already carry its v2 / v3 signing block —
/// v4 references the v3 master digest from inside it. If neither v2
/// nor v3 is present, we synthesize an apk_digest from a fresh chunked
/// hash of the APK contents (this lets v4-only signing work, though
/// the standard pattern is v3 + v4 together).
pub fn build_idsig(apk: &[u8], key: &KeyPair) -> crate::Result<Vec<u8>> {
    // ── 1. Merkle tree + root hash over the entire APK file. ──
    let (merkle_tree, root_hash) = compute_merkle_tree(apk);

    // ── 2. apk_digest — for our purposes, the same chunked-SHA-256
    //       digest used by v2/v3 (since we run before/alongside them).
    //       v4's verifier in Android uses this to bind the .idsig to
    //       the in-band signature; it doesn't have to be the same as
    //       the root hash. We compute the v2/v3 master digest over
    //       (contents | CD | EOCD with cd-offset patched to
    //       signing-block-start). ──
    let layout = ZipLayout::parse(apk)?;
    let signing_block_start =
        super::detect_signing_block_start(apk, &layout).unwrap_or(layout.cd_start);
    let apk_digest = super::v2::digest_with_eocd_offset(apk, &layout, signing_block_start)?;

    // ── 3. hashing_info blob. ──
    let hashing_info = build_hashing_info(&root_hash);

    // ── 4. signing_info blob (without the signature first, so we can
    //       hash it, then append the signature). ──
    let mut signing_info_no_sig = build_signing_info_no_sig(
        &apk_digest, key.cert_der(), &key.public_key_spki_der()?,
    );

    // ── 5. Compute the signature over (hashing_info || signing_info_no_sig). ──
    let mut signed_blob = Vec::new();
    signed_blob.extend_from_slice(&hashing_info);
    signed_blob.extend_from_slice(&signing_info_no_sig);
    let signature = key.sign_sha256(&signed_blob)?;

    // ── 6. Append signature_algorithm_id + signature to signing_info. ──
    write_u32_le(&mut signing_info_no_sig, SIGNATURE_ALGO);
    write_length_prefixed(&mut signing_info_no_sig, &signature);
    let signing_info = signing_info_no_sig;

    // ── 7. Assemble the .idsig file. ──
    let mut out = Vec::new();
    write_u32_le(&mut out, V4_FILE_VERSION);
    write_length_prefixed(&mut out, &hashing_info);
    write_length_prefixed(&mut out, &signing_info);
    write_length_prefixed(&mut out, &merkle_tree);
    Ok(out)
}

/// Build the hashing_info blob from a root hash.
fn build_hashing_info(root_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 4 + 4 + 32);
    write_u32_le(&mut out, HASH_ALGO_SHA256);
    out.push(LOG2_PAGE_SIZE);
    write_u32_le(&mut out, 0);                // salt_size
    write_u32_le(&mut out, root_hash.len() as u32);
    out.extend_from_slice(root_hash);
    out
}

/// Build the signing_info blob up to (but not including) the signature
/// field — the spec defines this exact prefix as the bytes the
/// signature is computed over (after concatenating the hashing_info).
fn build_signing_info_no_sig(
    apk_digest: &[u8],
    cert_der: &[u8],
    public_key_spki: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    write_length_prefixed(&mut out, apk_digest);
    write_length_prefixed(&mut out, cert_der);
    write_length_prefixed(&mut out, &[]);       // additional_data — empty
    write_length_prefixed(&mut out, public_key_spki);
    out
}

/// Compute a SHA-256 Merkle tree over `data` with 4 KB leaves. Returns
/// `(serialized_tree, root_hash)`.
///
/// Layout: each level's hashes are stored concatenated, leaves first.
/// Each internal node hashes the SHA-256 of `PAGE_SIZE` bytes of its
/// children's digests (one PAGE_SIZE slice of digest area, zero-padded
/// when a level has fewer than PAGE_SIZE/HASH_SIZE = 128 children).
///
/// The serialization order matches what `mkbootimage` / `fsverity-utils`
/// emit and what Android's verifier expects: root hash is *not*
/// included in the tree blob itself (it's stored in `hashing_info`).
fn compute_merkle_tree(data: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let hash_size = 32usize;
    let hashes_per_page = PAGE_SIZE / hash_size;     // = 128

    // ── Level 0 — leaf hashes over 4 KB chunks of the input. ──
    let leaf_count = (data.len() + PAGE_SIZE - 1) / PAGE_SIZE;
    let mut levels: Vec<Vec<u8>> = Vec::new();
    let mut level0 = Vec::with_capacity(leaf_count.next_multiple_of(hashes_per_page) * hash_size);
    let mut buf = [0u8; PAGE_SIZE];
    for i in 0..leaf_count {
        let start = i * PAGE_SIZE;
        let end   = (start + PAGE_SIZE).min(data.len());
        let chunk = &data[start..end];
        // Zero-pad the last chunk up to PAGE_SIZE so every leaf hashes
        // a fixed-size input — fs-verity / v4 contract.
        buf[..chunk.len()].copy_from_slice(chunk);
        for b in &mut buf[chunk.len()..] { *b = 0; }
        let mut h = Sha256::new();
        h.update(&buf);
        level0.extend_from_slice(&h.finalize());
    }
    // Pad level0 up to a PAGE_SIZE multiple so the next level can hash
    // full pages of hashes (the unused tail is zero-padded).
    let level0_padded_len = level0.len().next_multiple_of(PAGE_SIZE);
    level0.resize(level0_padded_len, 0);
    levels.push(level0);

    // ── Roll up. Each level's hashes are over PAGE_SIZE-byte pages of
    //    the previous level. Stop when a level fits in one page. ──
    loop {
        let prev = levels.last().unwrap();
        if prev.len() <= PAGE_SIZE { break; }
        let page_count = prev.len() / PAGE_SIZE;
        let mut next = Vec::with_capacity(page_count.next_multiple_of(hashes_per_page) * hash_size);
        for i in 0..page_count {
            let mut h = Sha256::new();
            h.update(&prev[i * PAGE_SIZE..(i + 1) * PAGE_SIZE]);
            next.extend_from_slice(&h.finalize());
        }
        let padded_len = next.len().next_multiple_of(PAGE_SIZE);
        next.resize(padded_len, 0);
        levels.push(next);
    }

    // ── Root: SHA-256 of the topmost level's single page. ──
    let top = levels.last().unwrap();
    let mut top_page = [0u8; PAGE_SIZE];
    top_page[..top.len().min(PAGE_SIZE)].copy_from_slice(&top[..top.len().min(PAGE_SIZE)]);
    let mut h = Sha256::new();
    h.update(&top_page);
    let root: [u8; 32] = h.finalize().into();

    // ── Serialize the tree: top level first, then down to leaves
    //    (Android's expected order — emit higher levels first). ──
    let mut serialized = Vec::new();
    for level in levels.iter().rev() {
        serialized.extend_from_slice(level);
    }
    (serialized, root)
}

/// Length-prefixed write: u32 LE length, then bytes.
fn write_length_prefixed(out: &mut Vec<u8>, data: &[u8]) {
    write_u32_le(out, data.len() as u32);
    out.extend_from_slice(data);
}

fn write_u32_le(out: &mut Vec<u8>, v: u32) {
    let mut buf = [0u8; 4];
    LE::write_u32(&mut buf, v);
    out.extend_from_slice(&buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_self_signed;

    #[test]
    fn merkle_root_stable() {
        // Same input → same root, every time.
        let data = b"hello world".repeat(1000);
        let (_, r1) = compute_merkle_tree(&data);
        let (_, r2) = compute_merkle_tree(&data);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_changes_with_data() {
        let (_, ra) = compute_merkle_tree(b"hello A");
        let (_, rb) = compute_merkle_tree(b"hello B");
        assert_ne!(ra, rb);
    }

    #[test]
    fn idsig_builds_with_valid_apk() {
        use std::io::{Cursor, Write};
        use zip::write::{SimpleFileOptions, ZipWriter};
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            w.start_file("AndroidManifest.xml", SimpleFileOptions::default()).unwrap();
            w.write_all(b"<fake>").unwrap();
            w.start_file("classes.dex", SimpleFileOptions::default()).unwrap();
            w.write_all(b"\xca\xfe\xba\xbe").unwrap();
            w.finish().unwrap();
        }
        let apk = buf.into_inner();
        let key = generate_self_signed("CN=V4Test", 1).unwrap();
        let idsig = build_idsig(&apk, &key).unwrap();
        // Sanity: starts with version field = 2.
        let ver = u32::from_le_bytes(idsig[..4].try_into().unwrap());
        assert_eq!(ver, V4_FILE_VERSION);
        // And the file is non-trivial (tree + sig + cert).
        assert!(idsig.len() > 500);
    }
}
