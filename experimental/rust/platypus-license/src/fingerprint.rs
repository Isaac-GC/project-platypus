//! Stable per-machine fingerprint used to node-lock a license.
//!
//! The raw id comes from `machine-uid` (IOPlatformUUID on macOS,
//! `/etc/machine-id` on Linux, the `MachineGuid` registry value on Windows).
//! We hash it rather than store it raw so the token never embeds a value that
//! could be correlated back to the host, and we truncate to 16 bytes (32 hex
//! chars) — ample collision resistance for a node-lock.
//!
//! The Python verifier (`licensing.machine`) reads the *same* OS sources and
//! applies the *same* normalisation + hash, so a token locked here verifies
//! there and vice-versa.

use sha2::{Digest, Sha256};

/// `sha256(normalise(raw_machine_id))[..16]` as lowercase hex.
///
/// Normalisation = trim surrounding whitespace, strip `{}` (Windows wraps the
/// GUID in braces), then lowercase — so every platform feeds the hash the same
/// shape regardless of how the OS formats its id.
pub fn fingerprint_from_raw(raw: &str) -> String {
    let norm = raw.trim().trim_matches(|c| c == '{' || c == '}').to_lowercase();
    let mut h = Sha256::new();
    h.update(norm.as_bytes());
    hex::encode(&h.finalize()[..16])
}

/// This machine's fingerprint, or `None` if the OS id is unavailable (rare —
/// e.g. a hardened container with no machine-id). A `None` here means a
/// node-locked token can't be matched, so it will read as `MachineMismatch`.
pub fn machine_fingerprint() -> Option<String> {
    machine_uid::get().ok().map(|raw| fingerprint_from_raw(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_braces_and_case() {
        // Windows-style braced GUID and the bare lowercase form must agree.
        let a = fingerprint_from_raw("{ABCD-1234}");
        let b = fingerprint_from_raw("abcd-1234");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn local_fingerprint_is_stable() {
        // Two reads in a row are identical (it's deterministic from the OS id).
        assert_eq!(machine_fingerprint(), machine_fingerprint());
    }
}
