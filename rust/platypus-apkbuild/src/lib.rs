//! Repack and sign Android APKs.
//!
//! ## Pipeline
//!
//! ```text
//! input.apk ──▶ ApkBuilder ──▶ apply replacements / additions / deletions
//!                          ──▶ zipalign uncompressed entries
//!                          ──▶ write contents + central dir + EOCD
//!                          ──▶ insert APK Signing Block (v2 / v3)
//!                          ──▶ optionally embed META-INF v1 sigs
//!                          ──▶ output.apk (install-ready)
//! ```
//!
//! ## What ships
//!
//! * Repack with file-level replacements, additions, deletions
//! * 4-byte zipalign of uncompressed entries (required by some
//!   Android versions; harmless on all)
//! * Key generation — self-signed RSA-2048 cert, PEM output
//! * **v2** (APK Signature Scheme v2) — the modern required scheme
//!   for Android 7+ (Nougat)
//! * **v1** (JAR signing) — META-INF/MANIFEST.MF + CERT.SF + CERT.RSA,
//!   needed for KitKat/older or for apps that opt in to both.
//!
//! ## What's *not* here yet (and why)
//!
//! * **v3** signing + key rotation lineage — useful but niche
//! * **v4** (`.idsig` files) — only for incremental install in dev
//!   workflows on Android 11+
//! * **PKCS#12 keystore loading** — supply PEM directly for now; one
//!   `openssl pkcs12 -in foo.p12 -out foo.pem` converts
//! * **DEX / AXML / resources.arsc writers** — supply replacement
//!   bytes via `ApkBuilder::replace`. The matching writer crates in
//!   the workspace produce parsers only.

pub mod builder;
pub mod keys;
pub mod signing;
pub mod zip_layout;
/// String-pool patcher for binary AXML (`AndroidManifest.xml`,
/// `res/layout/*.xml`) and ARSC (`resources.arsc`). Covers the
/// "change app name, rename a string resource, swap a URL" workflow
/// without a full binary writer.
pub mod axml_patch;
/// String-table patcher for `classes.dex`. Same-length-or-shorter
/// replacement only; the surrounding tables (proto/type/method/field
/// ids, class defs, code items) are passed through unchanged. Adler-32
/// + SHA-1 header signatures are refreshed on emit. Adequate for
/// swapping hard-coded URLs / tokens / strings. A full DEX writer is
/// out of scope — see [`dex_patch`]'s module docs.
pub mod dex_patch;

pub use builder::{ApkBuilder, BuildEntry, BuildOutcome};
pub use keys::{generate_self_signed, KeyPair, KeyPairAlgo};
pub use signing::{SignerConfig, SigningOutcome};
pub use axml_patch::AxmlEditor;
pub use dex_patch::DexStringEditor;

/// Top-level error type for the crate. Mostly transparent wrappers so
/// the caller can `?` through pretty error reporting without losing
/// the underlying type.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("der: {0}")]
    Der(#[from] der::Error),
    #[error("rsa: {0}")]
    Rsa(#[from] rsa::Error),
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("invalid apk: {0}")]
    InvalidApk(String),
    #[error("signing: {0}")]
    Signing(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
