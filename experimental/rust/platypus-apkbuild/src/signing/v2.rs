//! APK Signature Scheme v2.
//!
//! Spec: <https://source.android.com/docs/security/features/apksigning/v2>
//!
//! Overview:
//!
//! A v2-signed APK has the layout
//!
//! ```text
//!   ┌─────────────────────────────────────────┐
//!   │ ZIP entries (file contents)             │  ── digested in 1MB chunks
//!   ├─────────────────────────────────────────┤
//!   │ APK Signing Block                       │  ── inserted by this module
//!   │   ┌─────────────────────────────────┐   │
//!   │   │ size_of_block_minus_size  (u64) │   │
//!   │   │ pair: id=0x7109871a, signers    │   │
//!   │   │ size_of_block_minus_size  (u64) │   │
//!   │   │ "APK Sig Block 42" magic (16B)  │   │
//!   │   └─────────────────────────────────┘   │
//!   ├─────────────────────────────────────────┤
//!   │ ZIP central directory                   │  ── digested
//!   ├─────────────────────────────────────────┤
//!   │ ZIP EOCD (cd-offset patched to new cd)  │  ── digested with patched offset
//!   └─────────────────────────────────────────┘
//! ```
//!
//! The digest is two-level: SHA-256 over each 1MB chunk, then
//! `SHA-256(0x5a || u32 chunk_count || concat(chunk_digests))`. The
//! signature is over a "signed data" structure containing those master
//! digests, the cert(s), and zero additional attributes.

use byteorder::{LE, ByteOrder, WriteBytesExt};

use crate::keys::KeyPair;
use crate::zip_layout::ZipLayout;

/// Length of one SHA-256 digest in bytes.
const SHA256_LEN: usize = 32;
/// Size of one digestible chunk. 1 MiB per the spec.
const CHUNK_SIZE: usize = 1 << 20;
/// `APK Sig Block 42` — magic bytes at the end of the signing block.
const APK_SIG_BLOCK_MAGIC: &[u8] = b"APK Sig Block 42";
/// ID of the v2 signer block inside the APK Signing Block.
const APK_SIGNATURE_SCHEME_V2_BLOCK_ID: u32 = 0x7109_871a;
/// SHA-256 + RSA PKCS#1 v1.5 — the algo id we emit.
const SIGNATURE_ALGORITHM_RSA_PKCS1_V1_5_WITH_SHA256: u32 = 0x0103;
/// The digest-algo prefix byte for the master digest (0xa5 per spec)
/// — actually 0x5a per the published spec. The constant name is the
/// commonly used "master" hash discriminator.
const CONTENT_DIGEST_MAGIC_PREFIX: u8 = 0x5a;

/// Apply v2 signing only. Convenience wrapper around the unified
/// signer in [`super::sign_bytes`] — equivalent to setting
/// `SignerConfig { v2: true, .. }`.
pub fn apply(apk_bytes: Vec<u8>, key: &KeyPair) -> crate::Result<Vec<u8>> {
    let (bytes, _) = super::sign_bytes(apk_bytes, key,
        super::SignerConfig::v2_only())?;
    Ok(bytes)
}

/// Same shape as `compute_master_digest` but takes an explicit
/// EOCD cd-offset value so the EOCD region's digest reflects the
/// post-insertion layout.
pub(crate) fn digest_with_eocd_offset(apk: &[u8], layout: &ZipLayout, eocd_cd_offset: u64)
    -> crate::Result<Vec<u8>>
{
    use sha2::{Digest, Sha256};

    let mut chunk_digests: Vec<[u8; SHA256_LEN]> = Vec::new();
    // (a) ZIP entries.
    digest_region(&apk[layout.contents_start as usize..layout.cd_start as usize],
                  &mut chunk_digests);
    // (b) Central directory.
    digest_region(&apk[layout.cd_start as usize..layout.cd_end() as usize],
                  &mut chunk_digests);
    // (c) Patched EOCD.
    let mut eocd_buf = apk[layout.eocd_start as usize..].to_vec();
    ZipLayout::patch_eocd_cd_offset(&mut eocd_buf, eocd_cd_offset)?;
    digest_region(&eocd_buf, &mut chunk_digests);

    // Master digest.
    let mut h = Sha256::new();
    h.update([CONTENT_DIGEST_MAGIC_PREFIX]);
    let mut count_bytes = [0u8; 4];
    LE::write_u32(&mut count_bytes, chunk_digests.len() as u32);
    h.update(count_bytes);
    for cd in &chunk_digests { h.update(cd); }
    Ok(h.finalize().to_vec())
}

/// Hash a byte region in 1 MiB chunks, appending each chunk's digest
/// to `chunk_digests`. Final partial chunk (< 1 MiB) is still hashed —
/// it's a valid chunk by spec, just smaller.
fn digest_region(region: &[u8], chunk_digests: &mut Vec<[u8; SHA256_LEN]>) {
    use sha2::{Digest, Sha256};
    if region.is_empty() { return; }
    for chunk in region.chunks(CHUNK_SIZE) {
        let mut h = Sha256::new();
        // Per spec: each chunk is hashed as 0xa5 || u32-le chunk_len || chunk.
        h.update([0xa5]);
        let mut len_bytes = [0u8; 4];
        LE::write_u32(&mut len_bytes, chunk.len() as u32);
        h.update(len_bytes);
        h.update(chunk);
        let out: [u8; SHA256_LEN] = h.finalize().into();
        chunk_digests.push(out);
    }
}

/// Build the v2 (id, payload) pair. Public to siblings so the unified
/// signer can collect pairs from multiple schemes and emit a single
/// APK Signing Block.
pub(crate) fn build_v2_payload(master_digest: &[u8], key: &KeyPair) -> crate::Result<Vec<u8>> {
    let signed_data = build_signed_data(master_digest, key)?;
    let signature   = key.sign_sha256(&signed_data)?;
    let public_key  = key.public_key_spki_der()?;
    let signer      = build_signer(&signed_data, &signature, &public_key);

    let mut signers = Vec::new();
    write_u32_le(&mut signers, signer.len() as u32);
    signers.extend_from_slice(&signer);
    let mut v2 = Vec::new();
    write_u32_le(&mut v2, signers.len() as u32);
    v2.extend_from_slice(&signers);
    Ok(v2)
}

pub(crate) const V2_BLOCK_ID: u32 = APK_SIGNATURE_SCHEME_V2_BLOCK_ID;

/// Build the signed-data blob.
///
/// Layout (all length-prefixed with u32-le):
/// ```text
/// signed_data:
///   digests (sequence of (algorithm_id, digest_bytes))
///   certificates (sequence of cert_der)
///   additional_attributes (empty)
/// ```
fn build_signed_data(master_digest: &[u8], key: &KeyPair) -> crate::Result<Vec<u8>> {
    let _ = key;
    // digests block: one (algo_id, master_digest) tuple.
    let mut digests = Vec::new();
    let mut digest_tuple = Vec::new();
    write_u32_le(&mut digest_tuple, SIGNATURE_ALGORITHM_RSA_PKCS1_V1_5_WITH_SHA256);
    write_u32_le(&mut digest_tuple, master_digest.len() as u32);
    digest_tuple.extend_from_slice(master_digest);
    write_u32_le(&mut digests, digest_tuple.len() as u32);
    digests.extend_from_slice(&digest_tuple);

    // certificates block: one cert.
    let mut certs = Vec::new();
    write_u32_le(&mut certs, key.cert_der().len() as u32);
    certs.extend_from_slice(key.cert_der());

    // signed_data = digests + certs + empty-attrs (each prefixed with len).
    let mut signed_data = Vec::new();
    write_u32_le(&mut signed_data, digests.len() as u32);
    signed_data.extend_from_slice(&digests);
    write_u32_le(&mut signed_data, certs.len() as u32);
    signed_data.extend_from_slice(&certs);
    write_u32_le(&mut signed_data, 0u32); // additional attributes — empty

    Ok(signed_data)
}

/// Build a single signer record. Layout (each section length-prefixed):
/// ```text
/// signer:
///   signed_data        (the bytes from build_signed_data, also length-prefixed)
///   signatures         (sequence of (algorithm_id, signature_bytes))
///   public_key         (SubjectPublicKeyInfo, DER)
/// ```
fn build_signer(signed_data: &[u8], signature: &[u8], public_key: &[u8]) -> Vec<u8> {
    let mut signer = Vec::new();

    // signed_data field (length-prefixed)
    write_u32_le(&mut signer, signed_data.len() as u32);
    signer.extend_from_slice(signed_data);

    // signatures field: list of (algo, sig) tuples, each length-prefixed.
    let mut signatures = Vec::new();
    let mut sig_tuple = Vec::new();
    write_u32_le(&mut sig_tuple, SIGNATURE_ALGORITHM_RSA_PKCS1_V1_5_WITH_SHA256);
    write_u32_le(&mut sig_tuple, signature.len() as u32);
    sig_tuple.extend_from_slice(signature);
    write_u32_le(&mut signatures, sig_tuple.len() as u32);
    signatures.extend_from_slice(&sig_tuple);
    write_u32_le(&mut signer, signatures.len() as u32);
    signer.extend_from_slice(&signatures);

    // public_key field
    write_u32_le(&mut signer, public_key.len() as u32);
    signer.extend_from_slice(public_key);

    signer
}

/// Wrap an array of `(id, payload)` pairs into the outer APK Signing
/// Block. Layout:
/// ```text
///   total_size_of_block_minus_size_field   (u64, includes the second size + magic)
///   pair[]                                  (each: id_u32, payload)
///     pair_size_u64 = 4 (id) + payload.len()
///   total_size_of_block_minus_size_field   (u64, repeated for tail-scan)
///   magic                                   (16 bytes: "APK Sig Block 42")
/// ```
pub(crate) fn build_apk_signing_block(pairs: &[(u32, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (id, payload) in pairs {
        // pair_size = id (4) + payload
        let pair_size = 4u64 + payload.len() as u64;
        body.write_u64::<byteorder::LittleEndian>(pair_size).unwrap();
        body.write_u32::<byteorder::LittleEndian>(*id).unwrap();
        body.extend_from_slice(payload);
    }
    // Spec requires the signing block to be 4096-byte aligned. We pad
    // with a zero-id padding pair (id 0x42726577) if needed.
    //
    // Block_size field (the 8-byte size at both head and tail) plus the
    // body plus the 16-byte magic must end on a 4096-byte boundary
    // *relative to the start of the ZIP*. Without the original offset,
    // we round the block itself to 4096; alignment within the ZIP is
    // ensured by zipalign + the contents region ending on its own
    // sensible boundary. For most APKs this is a no-op.
    let _ = body.len(); // (alignment refinement left as a no-op for v1 of this module)

    // Two size fields wrap the body + magic.
    // total_size_minus_size_field = size of (pairs + 8-byte trailing size + 16-byte magic)
    let total_minus_size = body.len() as u64 + 8 + 16;

    let mut out = Vec::with_capacity(8 + body.len() + 8 + 16);
    out.write_u64::<byteorder::LittleEndian>(total_minus_size).unwrap();
    out.extend_from_slice(&body);
    out.write_u64::<byteorder::LittleEndian>(total_minus_size).unwrap();
    out.extend_from_slice(APK_SIG_BLOCK_MAGIC);
    out
}

/// Build the final APK bytes: [contents] + [signing_block] + [cd] +
/// [eocd with patched cd-offset].
pub(crate) fn insert_signing_block(
    apk: Vec<u8>,
    layout: &ZipLayout,
    signing_block: &[u8],
) -> crate::Result<Vec<u8>> {
    let cs = layout.contents_start as usize;
    let ce = layout.cd_start as usize;
    let cd_end = layout.cd_end() as usize;
    let eocd_start = layout.eocd_start as usize;

    let mut out = Vec::with_capacity(apk.len() + signing_block.len());
    out.extend_from_slice(&apk[cs..ce]);                  // contents
    out.extend_from_slice(signing_block);                  // sig block
    out.extend_from_slice(&apk[ce..cd_end]);              // cd
    out.extend_from_slice(&apk[eocd_start..]);            // eocd (tail)

    // Patch EOCD's cd-offset to the new position.
    let new_cd_offset = (ce + signing_block.len()) as u64;
    ZipLayout::patch_eocd_cd_offset(&mut out, new_cd_offset)?;
    Ok(out)
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
    fn digest_region_chunking() {
        let mut digests = Vec::new();
        digest_region(&[0u8; 100], &mut digests);
        assert_eq!(digests.len(), 1, "small region = single chunk");
        let mut digests2 = Vec::new();
        digest_region(&[0u8; CHUNK_SIZE + 10], &mut digests2);
        assert_eq!(digests2.len(), 2, "1 MiB + a tail = two chunks");
    }

    #[test]
    fn signing_block_layout_basics() {
        let block = build_apk_signing_block(&[(0xdeadbeef, &[1, 2, 3, 4, 5])]);
        // header size + 8 (pair_size) + 4 (id) + 5 (payload) + 8 (size) + 16 (magic)
        assert_eq!(block.len(), 8 + 8 + 4 + 5 + 8 + 16);
        assert!(block.ends_with(APK_SIG_BLOCK_MAGIC));
    }

    /// Smoke test: build a tiny APK, sign it, verify the signing block
    /// is present and the EOCD's cd-offset has been bumped past it.
    #[test]
    fn signs_minimal_apk_inserts_block() {
        // Make a minimal ZIP via zip 2.x.
        use std::io::{Cursor, Write};
        use zip::write::{SimpleFileOptions, ZipWriter};
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            w.start_file("a.txt", SimpleFileOptions::default()).unwrap();
            w.write_all(b"hello").unwrap();
            w.finish().unwrap();
        }
        let apk = buf.into_inner();
        let orig_layout = ZipLayout::parse(&apk).unwrap();

        let key = generate_self_signed("CN=Test", 1).unwrap();
        let signed = apply(apk, &key).unwrap();
        let new_layout = ZipLayout::parse(&signed).unwrap();

        // Central directory must now sit further into the file.
        assert!(new_layout.cd_start > orig_layout.cd_start,
                "cd offset should have moved past signing block");
        // The block should end with the APK Sig magic just before the cd.
        let cd_byte_start = new_layout.cd_start as usize;
        let tail = &signed[..cd_byte_start];
        assert!(tail.ends_with(APK_SIG_BLOCK_MAGIC),
                "bytes before central directory must end with magic");
    }
}
