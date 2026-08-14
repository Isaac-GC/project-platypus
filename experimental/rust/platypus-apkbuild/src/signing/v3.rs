//! APK Signature Scheme v3.
//!
//! Spec: <https://source.android.com/docs/security/features/apksigning/v3>
//!
//! v3 is structurally a superset of v2:
//!
//! * Same chunked-SHA-256 master digest over the same three regions
//!   (contents / central directory / EOCD-with-cd-offset-patched).
//! * Same outer APK Signing Block format, but a **different pair ID**
//!   (`0xf05368c0`) so v3 verifiers find a v3 block and v2 verifiers
//!   ignore it.
//! * Signer block adds **min-SDK / max-SDK** integers around the
//!   `signed_data` and an `additional_attributes` slot used for the
//!   proof-of-rotation lineage. The Android verifier checks the
//!   running OS's API level against `[min_sdk, max_sdk]` and only
//!   trusts a signer's block if the device falls in that window —
//!   this is what lets a single APK hold *multiple* v3 blocks for a
//!   rotation chain, each scoped to a different SDK range.
//!
//! This implementation:
//!   - Single signer, no lineage. `attributes` is emitted as the
//!     length-prefixed empty sequence required by the spec.
//!   - Min SDK = 28 (Android P, the first OS to honour v3), Max SDK =
//!     i32::MAX (no upper limit, the canonical "everywhere") — both
//!     overridable via [`SignerV3Config`].
//!   - Both v2 + v3 are recommended together; the public
//!     [`crate::signing::SignerConfig`] toggles each independently.
//!
//! For key rotation (proof-of-rotation), the spec defines an
//! `additional_attributes` entry with attribute ID `0x3ba06f8c` whose
//! payload is the lineage chain. That's a separate (multi-week) effort
//! covering lineage signing, validation, and the surrounding policy.
//! Out of scope here — see the spec section "Proof-of-rotation
//! attribute" for the wire format when you're ready to add it.

use byteorder::{ByteOrder, LE};

use crate::keys::KeyPair;
use crate::zip_layout::ZipLayout;

/// Pair ID for v3 inside the APK Signing Block.
pub(crate) const APK_SIGNATURE_SCHEME_V3_BLOCK_ID: u32 = 0xf05368c0;
/// Same algorithm ID v2 uses — the chunked-SHA-256 + RSA-PKCS#1-v1.5 combo.
const SIGNATURE_ALGORITHM_RSA_PKCS1_V1_5_WITH_SHA256: u32 = 0x0103;

/// Per-signer config knobs. Defaults are right for "I want a v3 signer
/// on everything Android P+" — the most common case for a new app.
#[derive(Debug, Clone, Copy)]
pub struct SignerV3Config {
    /// Minimum API level that should trust this signer block. The
    /// Android verifier rejects a v3 signer that doesn't cover the
    /// current device's level.
    pub min_sdk: i32,
    /// Maximum API level. Use `i32::MAX` (the default) for no upper
    /// bound; a finite value is only meaningful in a key-rotation
    /// chain where each block covers a slice of the SDK range.
    pub max_sdk: i32,
}

impl Default for SignerV3Config {
    fn default() -> Self {
        Self { min_sdk: 28, max_sdk: i32::MAX }
    }
}

/// Build the v3 (id, payload) pair for a single signer. Combined with
/// the v2 pair into one signing block by
/// [`super::sign_with_block_schemes`].
pub(crate) fn build_v3_payload(
    master_digest: &[u8],
    key: &KeyPair,
    cfg: &SignerV3Config,
) -> crate::Result<Vec<u8>> {
    let signed_data = build_v3_signed_data(master_digest, key, cfg)?;
    let signature   = key.sign_sha256(&signed_data)?;
    let public_key  = key.public_key_spki_der()?;
    let signer      = build_v3_signer(&signed_data, &signature, &public_key, cfg);

    let mut signers = Vec::new();
    write_u32_le(&mut signers, signer.len() as u32);
    signers.extend_from_slice(&signer);
    let mut v3 = Vec::new();
    write_u32_le(&mut v3, signers.len() as u32);
    v3.extend_from_slice(&signers);
    Ok(v3)
}

pub(crate) const V3_BLOCK_ID: u32 = APK_SIGNATURE_SCHEME_V3_BLOCK_ID;

/// v3's signed_data sequence:
/// ```text
///   digests                  (same shape as v2)
///   certificates             (same shape as v2)
///   min_sdk     i32
///   max_sdk     i32
///   additional_attributes    (empty by default — would hold lineage)
/// ```
fn build_v3_signed_data(
    master_digest: &[u8],
    key: &KeyPair,
    cfg: &SignerV3Config,
) -> crate::Result<Vec<u8>> {
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

    let mut signed_data = Vec::new();
    // digests (length-prefixed)
    write_u32_le(&mut signed_data, digests.len() as u32);
    signed_data.extend_from_slice(&digests);
    // certificates (length-prefixed)
    write_u32_le(&mut signed_data, certs.len() as u32);
    signed_data.extend_from_slice(&certs);
    // min_sdk / max_sdk (raw i32 LE — NOT length-prefixed)
    write_i32_le(&mut signed_data, cfg.min_sdk);
    write_i32_le(&mut signed_data, cfg.max_sdk);
    // additional_attributes (empty sequence)
    write_u32_le(&mut signed_data, 0);

    Ok(signed_data)
}

/// v3 signer block:
/// ```text
///   signed_data        (length-prefixed)
///   min_sdk    i32     (NOT length-prefixed; same as inside signed_data)
///   max_sdk    i32
///   signatures         (length-prefixed sequence of (algo, sig))
///   public_key         (length-prefixed SPKI DER)
/// ```
fn build_v3_signer(
    signed_data: &[u8],
    signature: &[u8],
    public_key: &[u8],
    cfg: &SignerV3Config,
) -> Vec<u8> {
    let mut signer = Vec::new();

    // signed_data field (length-prefixed)
    write_u32_le(&mut signer, signed_data.len() as u32);
    signer.extend_from_slice(signed_data);

    // The outer min_sdk / max_sdk fields are repeated outside signed_data
    // so a verifier can short-circuit on SDK mismatch without parsing
    // the signed-data structure.
    write_i32_le(&mut signer, cfg.min_sdk);
    write_i32_le(&mut signer, cfg.max_sdk);

    // signatures field
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

fn write_u32_le(out: &mut Vec<u8>, v: u32) {
    let mut buf = [0u8; 4];
    LE::write_u32(&mut buf, v);
    out.extend_from_slice(&buf);
}
fn write_i32_le(out: &mut Vec<u8>, v: i32) {
    let mut buf = [0u8; 4];
    LE::write_i32(&mut buf, v);
    out.extend_from_slice(&buf);
}
