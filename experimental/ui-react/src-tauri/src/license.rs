//! Tauri command surface for offline, node-locked license verification.
//!
//! The verifier itself lives in the `platypus-license` crate (shared with the
//! `platypus` Python module); this module only adds the desktop concerns:
//! where the token is stored, how it's activated from the UI, and the backend
//! feature gate.
//!
//! Storage: the activated token is written verbatim to `<cache>/license.plt`
//! (the same `cache_dir` the project uses). It's a signed, tamper-evident blob,
//! so plain-text-on-disk is fine — editing it just makes it fail verification.

use std::path::PathBuf;

use serde::Serialize;
use tauri::State;

use platypus_license as lic;

use crate::state::AppState;

const LICENSE_FILE: &str = "license.plt";

fn license_path(state: &AppState) -> PathBuf {
    state.cache_dir.join(LICENSE_FILE)
}

/// The stored token, trimmed; `None` if absent or blank.
fn read_token(state: &AppState) -> Option<String> {
    std::fs::read_to_string(license_path(state))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Flattened license view for the frontend (camelCase to match the TS layer).
/// Claim fields are `null` when the token didn't verify.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LicenseInfo {
    pub status: String,
    pub valid: bool,
    pub id: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub plan: Option<String>,
    pub tier: Option<String>,
    pub seats: Option<u32>,
    pub features: Vec<String>,
    pub expires: Option<i64>,
    pub machine: Option<String>,
}

impl From<lic::Verified> for LicenseInfo {
    fn from(v: lic::Verified) -> Self {
        let c = v.claims;
        LicenseInfo {
            status: v.status.as_str().to_string(),
            valid: v.status.is_valid(),
            id: c.as_ref().map(|c| c.id.clone()),
            name: c.as_ref().map(|c| c.name.clone()),
            email: c.as_ref().map(|c| c.email.clone()),
            plan: c.as_ref().map(|c| c.plan.clone()),
            tier: c.as_ref().map(|c| c.tier.clone()),
            seats: c.as_ref().map(|c| c.seats),
            features: c.as_ref().map(|c| c.features.clone()).unwrap_or_default(),
            expires: c.as_ref().and_then(|c| c.expires),
            machine: c.as_ref().and_then(|c| c.machine.clone()),
        }
    }
}

/// Human-readable reason an activation was refused.
fn activation_error(status: lic::Status) -> String {
    match status {
        lic::Status::Expired => "This license has expired.".into(),
        lic::Status::NotYetValid => "This license is not valid yet (check your clock).".into(),
        lic::Status::MachineMismatch => {
            "This license is locked to a different machine.".into()
        }
        lic::Status::BadSignature => "Invalid license: signature check failed.".into(),
        lic::Status::Malformed => "That doesn't look like a Platypus license key.".into(),
        lic::Status::Missing => "No license key was provided.".into(),
        lic::Status::Valid => "License is valid.".into(),
    }
}

// ── Commands ─────────────────────────────────────────────────────────────────

/// Current license status, read from disk. Never errors — an absent/blank file
/// is reported as `missing`.
#[tauri::command]
pub fn license_status(state: State<'_, AppState>) -> LicenseInfo {
    lic::evaluate_now(read_token(&state).as_deref()).into()
}

/// This machine's node-lock fingerprint (32 hex chars), to paste into a license
/// request. Matches the Python `platypus.license.machine_fingerprint()` output.
#[tauri::command]
pub fn machine_fingerprint() -> Option<String> {
    lic::fingerprint::machine_fingerprint()
}

/// Verify `token`; on a `valid` outcome persist it and return the info. Any
/// non-valid outcome writes nothing and returns the reason as an error.
#[tauri::command]
pub fn license_activate(
    token: String,
    state: State<'_, AppState>,
) -> Result<LicenseInfo, String> {
    let verified = lic::evaluate_now(Some(&token));
    if !verified.status.is_valid() {
        return Err(activation_error(verified.status));
    }
    std::fs::write(license_path(&state), token.trim())
        .map_err(|e| format!("could not save license: {e}"))?;
    Ok(verified.into())
}

/// Remove the stored license (revert to unlicensed). Idempotent.
#[tauri::command]
pub fn license_deactivate(state: State<'_, AppState>) -> Result<(), String> {
    match std::fs::remove_file(license_path(&state)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not remove license: {e}")),
    }
}

// ── Backend feature gate ─────────────────────────────────────────────────────

/// Reject a command unless the stored license is `valid` *and* grants `feature`.
/// Call at the top of any paywalled command, e.g.:
///
/// ```ignore
/// crate::license::require_feature(&state, "taint")?;
/// ```
///
/// Enforcement is **release-only**: debug builds (`cargo run`/`tauri dev`) skip
/// the check so day-to-day development isn't gated, while shipped binaries
/// (`cargo build --release`) require a license. This is defense-in-depth behind
/// the frontend gate, not the primary UX.
pub fn require_feature(state: &AppState, feature: &str) -> Result<(), String> {
    if cfg!(debug_assertions) {
        return Ok(());
    }
    let verified = lic::evaluate_now(read_token(state).as_deref());
    if !verified.status.is_valid() {
        return Err(format!(
            "A valid license is required for this feature ({}). Add one in Settings → License.",
            verified.status.as_str()
        ));
    }
    if !verified.claims.as_ref().is_some_and(|c| c.has_feature(feature)) {
        return Err(format!("Your license does not include the '{feature}' feature."));
    }
    Ok(())
}
