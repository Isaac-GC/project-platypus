//! Dependency-free symmetric crypto for project-platypus.
//!
//! Implements AES (FIPS-197) for 128- and 256-bit keys plus CBC mode
//! with two padding policies (PKCS#7 and NoPadding), in both directions.
//! This is what the deobfuscation VM's `javax.crypto.Cipher` mock and
//! the static unpackers (e.g. Fengyue's AES-CBC-NoPadding DEX blob) need
//! — and it lets the whole workspace drop the `aes` + `cbc` crates.
//!
//! Scope is intentionally small and constant-time-agnostic: this code
//! runs on attacker-supplied APK blobs during *analysis*, never to
//! protect live secrets, so side-channel hardening isn't a goal. Speed
//! is fine for the megabyte-scale blobs these paths see.
//!
//! Correctness is pinned to the FIPS-197 and NIST SP 800-38A known
//! answers in the unit tests.

pub mod aes;

pub use aes::{
    aes_cbc_nopad_decrypt, aes_cbc_nopad_encrypt, aes_cbc_pkcs7_decrypt,
    aes_cbc_pkcs7_encrypt, Aes,
};
