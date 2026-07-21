//! Sign an unsigned (or v2-only) APK.
//!
//! Single APK Signing Block contains a list of (scheme_id, payload)
//! pairs. The pipeline:
//!
//!   1. Parse the input's ZIP layout — find contents end / CD start.
//!   2. Compute the v2/v3 master digest once (chunked SHA-256 over
//!      contents + central directory + EOCD-with-patched-cd-offset).
//!   3. For each enabled scheme (v2 / v3), build the (id, payload)
//!      pair using the master digest + key.
//!   4. Emit one APK Signing Block carrying all the pairs.
//!   5. Insert before the central directory, patch the EOCD's
//!      cd-offset to the new position, write out.
//!   6. (v4) Compute the Merkle tree over the *final* signed bytes,
//!      emit the .idsig sidecar file.
//!   7. (v1) Stub — see [`v1`] for the deferred implementation.

use std::path::Path;

use crate::keys::KeyPair;
use crate::zip_layout::ZipLayout;

pub mod v1;
pub mod v2;
pub mod v3;
pub mod v4;

pub use v3::SignerV3Config;

/// Which signing schemes to apply.
///
/// **Recommended default**: v2 + v3 together. v2 is required for
/// Android 7-8 install paths, v3 is required for Android 9+ key
/// rotation support and is also what newer verifiers prefer.
#[derive(Debug, Clone, Default)]
pub struct SignerConfig {
    pub v1: bool,
    pub v2: bool,
    pub v3: bool,
    /// When `Some(path)`, also produce a `.idsig` (v4) sidecar at the
    /// given path after the in-band signing block is written.
    pub v4_sidecar_path: Option<std::path::PathBuf>,
    /// v3 per-signer config — SDK range, lineage (when supported).
    /// Ignored when `v3 == false`.
    pub v3_config: SignerV3Config,
}

impl SignerConfig {
    /// Recommended modern combo: v2 + v3. Covers Android 7+. Skips v1
    /// (which is stubbed) and v4 (use [`Self::with_v4`] to enable).
    pub fn modern() -> Self {
        Self { v1: false, v2: true, v3: true, v4_sidecar_path: None,
               v3_config: SignerV3Config::default() }
    }

    /// v2-only — older default. Use [`Self::modern`] for new projects.
    pub fn v2_only() -> Self {
        Self { v1: false, v2: true, v3: false, v4_sidecar_path: None,
               v3_config: SignerV3Config::default() }
    }

    pub fn with_v4(mut self, sidecar_path: impl Into<std::path::PathBuf>) -> Self {
        self.v4_sidecar_path = Some(sidecar_path.into());
        self
    }
}

/// Summary returned after signing.
#[derive(Debug, Clone, Default)]
pub struct SigningOutcome {
    pub v1_applied: bool,
    pub v2_applied: bool,
    pub v3_applied: bool,
    pub v4_applied: bool,
    /// Filesystem path of the .idsig file when v4 was emitted.
    pub v4_sidecar_path: Option<std::path::PathBuf>,
    pub output_size: usize,
}

/// Sign on-disk APK at `input`, write to `output`.
pub fn sign_apk(
    input: &Path,
    output: &Path,
    key: &KeyPair,
    config: SignerConfig,
) -> crate::Result<SigningOutcome> {
    let bytes = std::fs::read(input)?;
    let (signed, mut outcome) = sign_bytes(bytes, key, config)?;
    std::fs::write(output, &signed)?;
    outcome.output_size = signed.len();
    Ok(outcome)
}

/// In-memory variant — convenient for tests and library callers.
pub fn sign_bytes(
    input: Vec<u8>,
    key: &KeyPair,
    config: SignerConfig,
) -> crate::Result<(Vec<u8>, SigningOutcome)> {
    let mut bytes = input;
    let mut outcome = SigningOutcome::default();

    // ── v2 + v3: single signing block carrying both pairs. ──
    if config.v2 || config.v3 {
        bytes = sign_with_block_schemes(bytes, key, &config)?;
        outcome.v2_applied = config.v2;
        outcome.v3_applied = config.v3;
    }

    // ── v1: still a stub. ──
    if config.v1 {
        bytes = v1::apply(bytes, key)?;
        outcome.v1_applied = true;
    }

    // ── v4: external .idsig sidecar over the final signed bytes. ──
    if let Some(sidecar_path) = &config.v4_sidecar_path {
        let sidecar_bytes = v4::build_idsig(&bytes, key)?;
        std::fs::write(sidecar_path, sidecar_bytes)?;
        outcome.v4_applied = true;
        outcome.v4_sidecar_path = Some(sidecar_path.clone());
    }

    outcome.output_size = bytes.len();
    Ok((bytes, outcome))
}

/// Build the v2 / v3 pairs against one master digest, emit one signing
/// block, splice it in. This is the unified driver used by `sign_bytes`
/// for everything that lives *inside* the APK Signing Block.
fn sign_with_block_schemes(
    apk_bytes: Vec<u8>,
    key: &KeyPair,
    config: &SignerConfig,
) -> crate::Result<Vec<u8>> {
    let layout = ZipLayout::parse(&apk_bytes)?;

    // The signing block goes between contents and CD. If the input
    // already has a signing block (e.g. user re-signed), strip it and
    // start fresh. Detection: 16 bytes before the CD == magic.
    let (cleaned_bytes, cleaned_layout) = strip_existing_signing_block(apk_bytes, &layout)?;
    let signing_block_start = cleaned_layout.cd_start;

    let master_digest = v2::digest_with_eocd_offset(
        &cleaned_bytes, &cleaned_layout, signing_block_start,
    )?;

    let mut pairs_owned: Vec<(u32, Vec<u8>)> = Vec::new();
    if config.v2 {
        let payload = v2::build_v2_payload(&master_digest, key)?;
        pairs_owned.push((v2::V2_BLOCK_ID, payload));
    }
    if config.v3 {
        let payload = v3::build_v3_payload(&master_digest, key, &config.v3_config)?;
        pairs_owned.push((v3::V3_BLOCK_ID, payload));
    }

    let pair_refs: Vec<(u32, &[u8])> = pairs_owned.iter()
        .map(|(id, p)| (*id, p.as_slice())).collect();
    let signing_block = v2::build_apk_signing_block(&pair_refs);

    v2::insert_signing_block(cleaned_bytes, &cleaned_layout, &signing_block)
}

/// If `apk` already has an APK Signing Block, return a copy with it
/// stripped (contents + CD + EOCD with cd-offset reset) plus the
/// updated layout for the cleaned bytes. If no block is present,
/// return the input untouched.
pub(crate) fn strip_existing_signing_block(
    apk: Vec<u8>,
    layout: &ZipLayout,
) -> crate::Result<(Vec<u8>, ZipLayout)> {
    const MAGIC: &[u8] = b"APK Sig Block 42";
    let cd = layout.cd_start as usize;
    if cd < MAGIC.len() || &apk[cd - MAGIC.len()..cd] != MAGIC {
        return Ok((apk, layout.clone()));
    }
    // Find the block's leading-size field (= trailing-size field).
    let trailing_size = { use byteorder::ByteOrder; byteorder::LE::read_u64 }(&apk[cd - 24..cd - 16]);
    let block_size = (8 + trailing_size) as usize;  // leading u64 + body + trailing u64 + magic
    let block_start = cd - block_size;

    let mut out = Vec::with_capacity(apk.len() - block_size);
    out.extend_from_slice(&apk[..block_start]);                 // contents
    out.extend_from_slice(&apk[cd..]);                          // cd + eocd

    // Patch the EOCD's cd-offset down by block_size.
    let new_cd_offset = block_start as u64;
    ZipLayout::patch_eocd_cd_offset(&mut out, new_cd_offset)?;

    // Re-parse layout from the cleaned bytes.
    let new_layout = ZipLayout::parse(&out)?;
    Ok((out, new_layout))
}

/// Detect whether `apk` already carries an APK Signing Block and, if
/// so, return its start offset (= input's CD start minus block size).
/// Returns `None` when there's no block — caller treats the CD start
/// as the new block start.
pub(crate) fn detect_signing_block_start(apk: &[u8], layout: &ZipLayout) -> Option<u64> {
    const MAGIC: &[u8] = b"APK Sig Block 42";
    let cd = layout.cd_start as usize;
    if cd < MAGIC.len() || &apk[cd - MAGIC.len()..cd] != MAGIC { return None; }
    let trailing_size = { use byteorder::ByteOrder; byteorder::LE::read_u64 }(&apk[cd - 24..cd - 16]);
    let block_size = (8 + trailing_size) as usize;
    Some((cd - block_size) as u64)
}
