//! Private-key signing path — vendor side only, gated behind the `sign` feature
//! so it never compiles into the shipped client.

use crate::{Claims, TOKEN_PREFIX};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

/// Sign `claims` with the raw 32-byte Ed25519 `seed`, producing a `PLT1` token.
///
/// The signed message is `"PLT1." + base64url(payload)` — identical to what
/// [`crate::verify`] reconstructs — so the version prefix is authenticated.
pub fn sign(claims: &Claims, seed: &[u8]) -> Result<String, String> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| "seed must be 32 bytes".to_string())?;
    let sk = SigningKey::from_bytes(&seed);

    let payload = serde_json::to_vec(claims).map_err(|e| e.to_string())?;
    let payload_seg = URL_SAFE_NO_PAD.encode(&payload);
    let signing_input = format!("{TOKEN_PREFIX}.{payload_seg}");
    let sig = sk.sign(signing_input.as_bytes());
    let sig_seg = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(format!("{TOKEN_PREFIX}.{payload_seg}.{sig_seg}"))
}
