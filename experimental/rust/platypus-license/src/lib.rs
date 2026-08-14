//! Offline, node-locked license verification for Project Platypus.
//!
//! # Licensing model
//!
//! Platypus ships as a desktop reverse-engineering tool that is frequently run
//! on **air-gapped analysis VMs** — so the model is *offline node-locked* with
//! short-lived signed tokens, not an online "phone-home" check:
//!
//! * The vendor holds an Ed25519 **private** key offline and signs a license
//!   token per customer ([`sign`], or the Python `licensing.keygen` CLI).
//! * Every client (this Tauri app and the `platypus` Python module) embeds the
//!   matching Ed25519 **public** key ([`VENDOR_PUBLIC_KEY_HEX`]) and verifies
//!   tokens locally with no network access.
//! * A token may be **node-locked** to one machine via [`Claims::machine`]
//!   (a fingerprint from [`fingerprint::machine_fingerprint`]) and may carry an
//!   **expiry** ([`Claims::expires`], `None` = perpetual), a **tier**, and a set
//!   of **feature** entitlements that gate individual tools.
//!
//! # Token wire format — `PLT1`
//!
//! ```text
//! PLT1.<base64url(payload_json)>.<base64url(ed25519_sig)>
//! ```
//!
//! * `PLT1` pins the version *and* the algorithm (Ed25519). There is no `alg`
//!   field inside the payload, so algorithm-substitution attacks are impossible.
//! * The signature covers the ASCII bytes `"PLT1." + base64url(payload)` — the
//!   version prefix is part of the signed message, so it can't be stripped or
//!   downgraded.
//! * Verifying over the *encoded* payload segment (not re-serialized JSON) means
//!   the Rust and Python verifiers never have to agree on JSON canonicalisation.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub mod fingerprint;

#[cfg(feature = "sign")]
mod sign;
#[cfg(feature = "sign")]
pub use sign::sign;

/// Wire-format version + algorithm tag. Also the first signed byte-run.
pub const TOKEN_PREFIX: &str = "PLT1";

/// Vendor Ed25519 public key (raw 32 bytes, hex). The matching private key is
/// held offline by the issuer and never ships. Replace this constant to rotate
/// the signing key — clients built against the old key reject the new tokens.
pub const VENDOR_PUBLIC_KEY_HEX: &str =
    "6537a4e05e9a341bc80cdc18b5134c030bc89e1cacc640d88c0a43f6b719eb0b";

/// Allowed clock skew (seconds) when checking `issued`, so a token signed a few
/// seconds in the future on a faster vendor clock is not rejected as `NotYetValid`.
pub const CLOCK_SKEW_SECS: i64 = 300;

/// The signed claim set carried by a license token.
///
/// Kept deliberately flat and string-typed (`plan`/`tier`) so the Rust, Python,
/// and any future verifier agree on the JSON without sharing an enum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Unique license id, e.g. `PLAT-DEMO-0001`.
    pub id: String,
    /// Licensee display name.
    pub name: String,
    /// Licensee email.
    pub email: String,
    /// `perpetual` | `subscription` | `trial`.
    pub plan: String,
    /// `community` | `pro` | `enterprise`.
    pub tier: String,
    /// Max concurrent activations (informational on the client).
    pub seats: u32,
    /// Entitlement keys gating individual tools, e.g. `["unpacker","taint"]`.
    pub features: Vec<String>,
    /// Issued-at, unix seconds.
    pub issued: i64,
    /// Expiry, unix seconds. `None` = perpetual.
    pub expires: Option<i64>,
    /// Bound machine fingerprint for node-locking. `None` = floating.
    pub machine: Option<String>,
}

impl Claims {
    /// Whether this license grants `feature`. An `"*"` entitlement grants all.
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == "*" || f == feature)
    }
}

/// Outcome of verifying a token. Anything other than [`Status::Valid`] means the
/// client should treat the install as unlicensed (optionally surfacing *why*).
///
/// Signature / structural failures take precedence over policy failures: if the
/// signature is bad the [`Claims`] are never trusted, so `Expired` is only
/// returned for an *authentic* but out-of-date token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Authentic, in-date, and (if node-locked) on the right machine.
    Valid,
    /// Authentic signature but `expires` is in the past.
    Expired,
    /// Authentic signature but `issued` is in the future beyond [`CLOCK_SKEW_SECS`].
    NotYetValid,
    /// Authentic signature but bound to a different machine.
    MachineMismatch,
    /// Signature did not verify against the vendor key.
    BadSignature,
    /// Token was structurally invalid (bad prefix / base64 / JSON).
    Malformed,
    /// No token was supplied.
    Missing,
}

impl Status {
    /// Only `Valid` should unlock paid functionality.
    pub fn is_valid(self) -> bool {
        matches!(self, Status::Valid)
    }

    /// Stable snake_case wire string, shared by the Tauri and PyO3 layers so
    /// the frontend sees one vocabulary regardless of which client produced it.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Valid => "valid",
            Status::Expired => "expired",
            Status::NotYetValid => "not_yet_valid",
            Status::MachineMismatch => "machine_mismatch",
            Status::BadSignature => "bad_signature",
            Status::Malformed => "malformed",
            Status::Missing => "missing",
        }
    }
}

/// A token after verification: its decoded [`Claims`] (when the signature was
/// authentic) and the policy [`Status`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verified {
    pub status: Status,
    /// Present whenever the signature verified — even for `Expired` /
    /// `MachineMismatch`, so the UI can show *whose* license it is.
    pub claims: Option<Claims>,
}

impl Verified {
    fn fail(status: Status) -> Self {
        Verified { status, claims: None }
    }
}

/// Parse + cryptographically verify a token against `public_key` (raw 32 bytes),
/// **without** applying time/machine policy. On success the returned [`Claims`]
/// are authentic. Use [`evaluate`] for the full check.
pub fn verify(token: &str, public_key: &[u8]) -> Result<Claims, Status> {
    let vk_bytes: [u8; 32] = public_key.try_into().map_err(|_| Status::Malformed)?;
    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| Status::Malformed)?;

    // PLT1.<payload>.<sig>
    let mut parts = token.trim().splitn(3, '.');
    let prefix = parts.next().ok_or(Status::Malformed)?;
    let payload_seg = parts.next().ok_or(Status::Malformed)?;
    let sig_seg = parts.next().ok_or(Status::Malformed)?;
    if prefix != TOKEN_PREFIX || payload_seg.is_empty() || sig_seg.is_empty() {
        return Err(Status::Malformed);
    }

    let payload = URL_SAFE_NO_PAD
        .decode(payload_seg)
        .map_err(|_| Status::Malformed)?;
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(sig_seg)
        .map_err(|_| Status::Malformed)?
        .try_into()
        .map_err(|_| Status::Malformed)?;
    let signature = Signature::from_bytes(&sig_bytes);

    // Signed message = the prefix and the *encoded* payload segment.
    let signing_input = format!("{TOKEN_PREFIX}.{payload_seg}");
    vk.verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| Status::BadSignature)?;

    serde_json::from_slice::<Claims>(&payload).map_err(|_| Status::Malformed)
}

/// Full verification: signature, then expiry/not-yet-valid against `now_unix`,
/// then node-lock against `machine_fp` (when the token is bound). `public_key`
/// is the raw 32-byte vendor key; pass [`VENDOR_PUBLIC_KEY_HEX`] decoded, or use
/// [`evaluate_now`] to default everything.
pub fn evaluate(
    token: &str,
    now_unix: i64,
    machine_fp: Option<&str>,
    public_key: &[u8],
) -> Verified {
    let claims = match verify(token, public_key) {
        Ok(c) => c,
        Err(status) => return Verified::fail(status),
    };

    let status = if claims.issued > now_unix + CLOCK_SKEW_SECS {
        Status::NotYetValid
    } else if claims.expires.is_some_and(|exp| exp < now_unix) {
        Status::Expired
    } else if let Some(bound) = claims.machine.as_deref() {
        match machine_fp {
            Some(fp) if fp == bound => Status::Valid,
            _ => Status::MachineMismatch,
        }
    } else {
        Status::Valid
    };

    Verified { status, claims: Some(claims) }
}

/// Convenience wrapper around [`evaluate`] using the current system clock, this
/// machine's [`fingerprint::machine_fingerprint`], and the embedded
/// [`VENDOR_PUBLIC_KEY_HEX`]. `None`/empty token → [`Status::Missing`].
pub fn evaluate_now(token: Option<&str>) -> Verified {
    let token = match token {
        Some(t) if !t.trim().is_empty() => t,
        _ => return Verified::fail(Status::Missing),
    };
    let key = match hex::decode(VENDOR_PUBLIC_KEY_HEX) {
        Ok(k) => k,
        Err(_) => return Verified::fail(Status::Malformed),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let fp = fingerprint::machine_fingerprint();
    evaluate(token, now, fp.as_deref(), &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical demo keypair (matches VENDOR_PUBLIC_KEY_HEX).
    const SEED_HEX: &str = "95eb2fd278459607b3be7b147d2e0f6660410270e7279b55811ecc790d54b692";

    // Token vectors produced out-of-band (Python `cryptography`), proving the
    // wire format verifies across independent Ed25519 implementations.
    const DEMO_TOKEN: &str = "PLT1.eyJpZCI6IlBMQVQtREVNTy0wMDAxIiwibmFtZSI6IlBsYXR5cHVzIERlbW8iLCJlbWFpbCI6ImRlbW9AcGxhdHlwdXMubG9jYWwiLCJwbGFuIjoicGVycGV0dWFsIiwidGllciI6InBybyIsInNlYXRzIjoxLCJmZWF0dXJlcyI6WyJ1bnBhY2tlciIsInRhaW50IiwiY29kZWdlbiIsImRlb2JmIl0sImlzc3VlZCI6MTcwMDAwMDAwMCwiZXhwaXJlcyI6bnVsbCwibWFjaGluZSI6bnVsbH0.D1imCCTPVqy3dG1ncNPAYnQynxl-zm6SO-fQFmcl0Y8OkkuSOPCehzCXMdQJzfrSlEDNBoOr0-36om4r7bCsAg";
    const EXPIRED_TOKEN: &str = "PLT1.eyJpZCI6IlBMQVQtRVhQLTAwMDIiLCJuYW1lIjoiUGxhdHlwdXMgRGVtbyIsImVtYWlsIjoiZGVtb0BwbGF0eXB1cy5sb2NhbCIsInBsYW4iOiJzdWJzY3JpcHRpb24iLCJ0aWVyIjoicHJvIiwic2VhdHMiOjEsImZlYXR1cmVzIjpbInVucGFja2VyIiwidGFpbnQiLCJjb2RlZ2VuIiwiZGVvYmYiXSwiaXNzdWVkIjoxNzAwMDAwMDAwLCJleHBpcmVzIjoxNzAwMDAxMDAwLCJtYWNoaW5lIjpudWxsfQ.HjrqKSQFI_ZdHkGO_FOecZ9Xi2MkiskvyTHdTTURmgCC9PLJn5m1SBAFonDwvstYVzgm1J4LCRd9Rpp10QDrDA";

    fn pubkey() -> Vec<u8> {
        hex::decode(VENDOR_PUBLIC_KEY_HEX).unwrap()
    }

    #[test]
    fn demo_token_verifies_against_embedded_key() {
        let claims = verify(DEMO_TOKEN, &pubkey()).expect("authentic");
        assert_eq!(claims.id, "PLAT-DEMO-0001");
        assert_eq!(claims.tier, "pro");
        assert!(claims.has_feature("unpacker"));
        assert!(!claims.has_feature("nope"));
        assert_eq!(claims.expires, None);
    }

    #[test]
    fn perpetual_token_is_valid_now() {
        let v = evaluate(DEMO_TOKEN, 1_900_000_000, None, &pubkey());
        assert_eq!(v.status, Status::Valid);
    }

    #[test]
    fn expired_token_reports_expired_but_keeps_claims() {
        let v = evaluate(EXPIRED_TOKEN, 1_900_000_000, None, &pubkey());
        assert_eq!(v.status, Status::Expired);
        assert_eq!(v.claims.unwrap().id, "PLAT-EXP-0002");
    }

    #[test]
    fn tampered_payload_is_bad_signature() {
        // Flip a byte inside the payload segment.
        let mut t: Vec<char> = DEMO_TOKEN.chars().collect();
        let i = 10;
        t[i] = if t[i] == 'A' { 'B' } else { 'A' };
        let tampered: String = t.into_iter().collect();
        assert!(matches!(
            verify(&tampered, &pubkey()),
            Err(Status::BadSignature) | Err(Status::Malformed)
        ));
    }

    #[test]
    fn wrong_prefix_is_malformed() {
        let bad = DEMO_TOKEN.replacen("PLT1", "PLT9", 1);
        assert_eq!(verify(&bad, &pubkey()).unwrap_err(), Status::Malformed);
    }

    #[test]
    fn missing_token_is_missing() {
        assert_eq!(evaluate_now(None).status, Status::Missing);
        assert_eq!(evaluate_now(Some("   ")).status, Status::Missing);
    }

    #[cfg(feature = "sign")]
    #[test]
    fn node_lock_round_trip() {
        let seed: [u8; 32] = hex::decode(SEED_HEX).unwrap().try_into().unwrap();
        let claims = Claims {
            id: "PLAT-LOCK-0003".into(),
            name: "Locked".into(),
            email: "lock@platypus.local".into(),
            plan: "perpetual".into(),
            tier: "enterprise".into(),
            seats: 1,
            features: vec!["*".into()],
            issued: 1_700_000_000,
            expires: None,
            machine: Some("deadbeefdeadbeefdeadbeefdeadbeef".into()),
        };
        let token = sign(&claims, &seed).unwrap();

        // Right machine → Valid; wrong/absent machine → MachineMismatch.
        let ok = evaluate(&token, 1_900_000_000, Some("deadbeefdeadbeefdeadbeefdeadbeef"), &pubkey());
        assert_eq!(ok.status, Status::Valid);
        let bad = evaluate(&token, 1_900_000_000, Some("00000000000000000000000000000000"), &pubkey());
        assert_eq!(bad.status, Status::MachineMismatch);
        let none = evaluate(&token, 1_900_000_000, None, &pubkey());
        assert_eq!(none.status, Status::MachineMismatch);
    }
}
