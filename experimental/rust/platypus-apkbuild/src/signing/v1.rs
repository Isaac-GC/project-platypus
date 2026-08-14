//! Placeholder — v1 (JAR) signing is not yet implemented.
//!
//! v1 signing needs a small PKCS#7 SignedData blob in `META-INF/CERT.RSA`
//! plus a `MANIFEST.MF` + `CERT.SF` text pair. The text side is trivial;
//! the PKCS#7 encoding (CMS — Cryptographic Message Syntax) is the
//! non-trivial piece. Two viable implementation paths:
//!
//!   1. Pull in the `cms` crate (RustCrypto) to assemble SignedData and
//!      let it handle DER canonicalisation. ~30 extra lines on this side.
//!   2. Hand-roll the DER bytes for the specific shape Android accepts.
//!      ~150 lines of careful ASN.1; no extra deps.
//!
//! For now this module returns the input unchanged when the caller asks
//! for v1 signing, so the surrounding plumbing keeps compiling. v2-only
//! signing produces install-able APKs on Android 7+ (Nougat, 2016) —
//! the only scenario where v1 alone is required is Android 6.0 and
//! earlier, which are well below the practical support floor in 2026.

use crate::keys::KeyPair;

pub fn apply(apk_bytes: Vec<u8>, _key: &KeyPair) -> crate::Result<Vec<u8>> {
    // No-op for now. See module docs.
    Ok(apk_bytes)
}
