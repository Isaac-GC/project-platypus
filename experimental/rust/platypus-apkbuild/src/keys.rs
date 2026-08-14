//! Generate or load signing keypairs + certificates.
//!
//! Two paths:
//!
//!   1. **Generate** a fresh self-signed RSA-2048 keypair via
//!      [`generate_self_signed`]. Outputs key + cert as PEM. Use this
//!      for debug builds, CI fixtures, etc.
//!   2. **Load** an existing key + cert from PEM files via
//!      [`KeyPair::from_pem_files`]. Use this for release builds where
//!      the cert was issued externally (e.g. by `apksigner` or `keytool`).
//!
//! PKCS#12 / JKS keystores aren't directly supported yet; the conversion
//! is a one-liner with `openssl`:
//!
//! ```text
//! openssl pkcs12 -in keystore.p12 -nokeys -out cert.pem
//! openssl pkcs12 -in keystore.p12 -nocerts -nodes -out key.pem
//! ```

use std::path::Path;

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;

/// Public-key algorithm. Only RSA is currently surfaced; ECDSA is
/// supported by the v2 spec but is a follow-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPairAlgo {
    /// RSA with PKCS#1-v1.5 padding + SHA-256. Standard Android default.
    Rsa2048Sha256,
}

/// A loaded private key + matching X.509 certificate, ready to sign.
pub struct KeyPair {
    pub algo: KeyPairAlgo,
    /// PEM-encoded private key (PKCS#8).
    pub key_pem: String,
    /// PEM-encoded X.509 certificate.
    pub cert_pem: String,
    /// Parsed private key for signing operations.
    pub(crate) private_key: RsaPrivateKey,
    /// Cert as raw DER for direct inclusion in the v1 SignedData /
    /// v2 SignerInfo.certificates field.
    pub(crate) cert_der: Vec<u8>,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("algo", &self.algo)
            .field("key_bits", &(self.private_key.size() * 8))
            .field("cert_der_len", &self.cert_der.len())
            .finish()
    }
}

impl KeyPair {
    /// Load from on-disk PEM files. Both arguments may point at the
    /// *same* file — some workflows concatenate key + cert.
    pub fn from_pem_files(key_path: &Path, cert_path: &Path) -> crate::Result<Self> {
        let key_pem = std::fs::read_to_string(key_path)?;
        let cert_pem = std::fs::read_to_string(cert_path)?;
        Self::from_pem(&key_pem, &cert_pem)
    }

    /// Load from a PKCS#12 keystore (`.p12` / `.pfx`). This is the
    /// format `apksigner` and `keytool -genkeypair` produce; it bundles
    /// the private key and the matching certificate chain in one
    /// password-protected file.
    ///
    /// Use `alias = None` to pick the single private-key entry in the
    /// keystore (the common case — most signing keystores hold exactly
    /// one). Pass `Some(name)` to pick by alias when the keystore has
    /// multiple entries.
    ///
    /// For `.jks` (Java KeyStore) input, convert once with `keytool`:
    /// ```text
    /// keytool -importkeystore -srckeystore foo.jks -destkeystore foo.p12 \
    ///         -deststoretype PKCS12
    /// ```
    pub fn from_pkcs12_file(
        path: &Path,
        password: &str,
        alias: Option<&str>,
    ) -> crate::Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_pkcs12_bytes(&bytes, password, alias)
    }

    pub fn from_pkcs12_bytes(
        data: &[u8],
        password: &str,
        alias: Option<&str>,
    ) -> crate::Result<Self> {
        use p12_keystore::KeyStore;
        let ks = KeyStore::from_pkcs12(data, password)
            .map_err(|e| crate::Error::Signing(format!("pkcs12 decode: {e}")))?;

        // Pick the entry: by alias if provided, else the only private-key entry.
        let (key_der, cert_der) = match alias {
            Some(name) => {
                let entry = ks.entry(name).ok_or_else(|| crate::Error::Signing(
                    format!("alias '{name}' not found in keystore")))?;
                extract_private_key_chain(entry)?
            }
            None => {
                let (_alias, chain) = ks.private_key_chain()
                    .ok_or_else(|| crate::Error::Signing(
                        "no private key entry in keystore (use --alias to pick a specific one if multiple)".into()))?;
                let cert_der = chain.chain().first().ok_or_else(|| crate::Error::Signing(
                    "private key entry has no certificate chain".into()))?
                    .as_der().to_vec();
                (chain.key().to_vec(), cert_der)
            }
        };

        // The PKCS#12 stores the private key as PKCS#8 DER. Re-encode
        // as PEM so the rest of the crate (which works in PEM) is happy.
        let key_pem = pkcs8_der_to_pem(&key_der)?;
        let cert_pem = cert_der_to_pem(&cert_der);
        Self::from_pem(&key_pem, &cert_pem)
    }

    /// Load from already-decoded PEM strings.
    pub fn from_pem(key_pem: &str, cert_pem: &str) -> crate::Result<Self> {
        let private_key = parse_private_key_pem(key_pem)?;
        let cert_der = single_cert_der(cert_pem)?;
        Ok(KeyPair {
            algo: KeyPairAlgo::Rsa2048Sha256,
            key_pem: key_pem.to_string(),
            cert_pem: cert_pem.to_string(),
            private_key, cert_der,
        })
    }

    /// Compute the signature over `data` using this key + the algo's
    /// canonical hash. Used by both the v1 and v2 signing paths.
    pub fn sign_sha256(&self, data: &[u8]) -> crate::Result<Vec<u8>> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::sha2::Sha256;
        use rsa::signature::{SignatureEncoding, Signer};
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let sig = signing_key.try_sign(data)
            .map_err(|e| crate::Error::Signing(format!("rsa sign: {e}")))?;
        Ok(sig.to_bytes().to_vec())
    }

    /// Raw DER of the cert — used as-is in signing payloads.
    pub fn cert_der(&self) -> &[u8] { &self.cert_der }

    /// SubjectPublicKeyInfo (SPKI) of the cert's public key, DER-encoded.
    /// v2 signing embeds this in the signer block.
    pub fn public_key_spki_der(&self) -> crate::Result<Vec<u8>> {
        use rsa::pkcs8::EncodePublicKey;
        let pub_key = self.private_key.to_public_key();
        let doc = pub_key.to_public_key_der()
            .map_err(|e| crate::Error::Signing(format!("spki encode: {e}")))?;
        Ok(doc.as_bytes().to_vec())
    }
}

/// Extract `(key_der, leaf_cert_der)` from one of two p12-keystore entry
/// flavours (private-key chain vs. trusted-cert). Returns an error when
/// the alias points at a trusted-cert entry (we can't sign with it).
fn extract_private_key_chain(
    entry: &p12_keystore::KeyStoreEntry,
) -> crate::Result<(Vec<u8>, Vec<u8>)> {
    use p12_keystore::KeyStoreEntry;
    match entry {
        KeyStoreEntry::PrivateKeyChain(chain) => {
            let cert = chain.chain().first().ok_or_else(|| crate::Error::Signing(
                "private key entry has no certificate chain".into()))?;
            Ok((chain.key().to_vec(), cert.as_der().to_vec()))
        }
        KeyStoreEntry::Certificate(_) => Err(crate::Error::Signing(
            "selected alias is a trusted certificate, not a private key".into())),
        _ => Err(crate::Error::Signing(
            "selected alias is not a private-key entry".into())),
    }
}

/// Convert a PKCS#8 DER private key into a PEM-encoded string with the
/// `-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----` armor.
fn pkcs8_der_to_pem(der: &[u8]) -> crate::Result<String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let body = B64.encode(der);
    Ok(format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        wrap_pem_lines(&body)
    ))
}

fn cert_der_to_pem(der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let body = B64.encode(der);
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        wrap_pem_lines(&body)
    )
}

fn wrap_pem_lines(b64: &str) -> String {
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 1);
    let mut i = 0;
    while i < b64.len() {
        let end = (i + 64).min(b64.len());
        out.push_str(&b64[i..end]);
        if end < b64.len() { out.push('\n'); }
        i = end;
    }
    out
}

fn parse_private_key_pem(pem: &str) -> crate::Result<RsaPrivateKey> {
    // Try PKCS#8 first (`-----BEGIN PRIVATE KEY-----`), then PKCS#1
    // (`-----BEGIN RSA PRIVATE KEY-----`).
    if let Ok(k) = RsaPrivateKey::from_pkcs8_pem(pem) { return Ok(k); }
    if let Ok(k) = RsaPrivateKey::from_pkcs1_pem(pem) { return Ok(k); }
    Err(crate::Error::Signing(
        "could not parse PEM private key (expected PKCS#8 or PKCS#1)".into()))
}

/// Extract the DER bytes from a single-cert PEM file. We don't support
/// chains yet — v1 + v2 work fine with a single self-signed cert.
fn single_cert_der(pem: &str) -> crate::Result<Vec<u8>> {
    use der::pem::PemLabel;
    use x509_cert::Certificate;
    use der::DecodePem;
    let cert = Certificate::from_pem(pem)?;
    use der::Encode;
    let der = cert.to_der()?;
    let _ = Certificate::PEM_LABEL; // touch the import so it stays useful
    Ok(der)
}

/// Generate a fresh self-signed RSA-2048 keypair + cert.
///
/// `subject_cn`  is the Common Name (`CN=`) baked into the certificate's
/// Subject + Issuer (it's self-signed so they match). Use something
/// distinctive — Android tools surface it in logcat when an install
/// fails verification.
///
/// `validity_years` controls the cert lifetime. Default 30 to mirror
/// `keytool -genkeypair`'s standard debug cert.
///
/// Returns PEM strings for the private key (PKCS#8) and the cert.
pub fn generate_self_signed(
    subject_cn: &str,
    validity_years: u32,
) -> crate::Result<KeyPair> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair as RcgenKeyPair, PKCS_RSA_SHA256};
    use time::{Duration, OffsetDateTime};

    // Distinguished Name. Only CN; Android doesn't care about the rest.
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, subject_cn);

    let mut params = CertificateParams::new(Vec::new())?;
    params.distinguished_name = dn;
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after  = now + Duration::days(365 * validity_years as i64);

    // rcgen 0.13: explicitly choose the alg + bring our own RSA key
    // because rcgen's default builder won't emit RSA without help.
    // Generate the RSA key via the `rsa` crate so we can later use
    // the same key for signing operations.
    let mut rng = rand::thread_rng();
    let rsa_key = RsaPrivateKey::new(&mut rng, 2048)?;

    let key_pem = {
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::pkcs8::LineEnding;
        rsa_key.to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| crate::Error::Signing(format!("encode pkcs8: {e}")))?
            .to_string()
    };

    let kp = RcgenKeyPair::from_pem_and_sign_algo(&key_pem, &PKCS_RSA_SHA256)?;
    let cert = params.self_signed(&kp)?;
    let cert_pem = cert.pem();

    KeyPair::from_pem(&key_pem, &cert_pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign_roundtrip() {
        let kp = generate_self_signed("CN=PlatypusTest", 1).unwrap();
        assert_eq!(kp.algo, KeyPairAlgo::Rsa2048Sha256);
        assert!(!kp.cert_der.is_empty());
        let sig = kp.sign_sha256(b"hello world").unwrap();
        assert!(!sig.is_empty());
        // SPKI is well-formed.
        let spki = kp.public_key_spki_der().unwrap();
        assert!(spki.len() > 100);  // RSA-2048 SPKI is ~270 bytes
    }

    #[test]
    fn load_what_we_just_generated() {
        let kp1 = generate_self_signed("CN=RoundTrip", 1).unwrap();
        let kp2 = KeyPair::from_pem(&kp1.key_pem, &kp1.cert_pem).unwrap();
        let sig1 = kp1.sign_sha256(b"data").unwrap();
        let sig2 = kp2.sign_sha256(b"data").unwrap();
        // PKCS#1 v1.5 sigs are deterministic — they should be identical.
        assert_eq!(sig1, sig2);
    }
}
