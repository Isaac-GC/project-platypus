//! Tauri commands backing the standalone-shell ViewerApi.
//!
//! Commands:
//!   - `open_apk`               — APK file dialog, set state.apk_path
//!   - `set_apk_path(path)`     — set without dialog (used by --cli arg)
//!   - `app_label()`            — UI title bar
//!   - `activity_list()`        — picker data
//!   - `activity_rehydrate()`   — full IR for one activity (deobfuscated
//!                                in-place if a mapping is loaded)
//!   - `activity_theme()`       — effective theme for an activity
//!   - `load_mapping_dialog()`  — pick a dexmapper mapping (JSON or
//!                                ProGuard) via the OS dialog
//!   - `load_mapping(path)`     — load a mapping from an explicit path
//!   - `current_mapping()`      — info about the currently-loaded mapping
//!   - `clear_mapping()`        — drop the loaded mapping
//!
//! Implementation mirrors the Project Platypus integration's commands —
//! both end up calling into platypus_rehydrate. The standalone shell
//! re-opens the APK + parses resources fresh per call (cheap; no shared
//! project model to maintain).

use std::path::PathBuf;

use serde::Serialize;
use tauri::State;
use tauri_plugin_dialog::{DialogExt, FilePath};

use project_platypus_native::apk::arsc;
use project_platypus_native::apk::axml;
use project_platypus_native::apk::zip::ApkZip;
use project_platypus_native::dex::parser::DexFileWithRaw;
use project_platypus_native::resources::{Manifest, Resources};

use platypus_dexmapper::{Deobfuscator, MappingInfo};

use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivitySummary {
    pub name: String,
    pub label: Option<String>,
    pub is_launcher: bool,
    pub exported: bool,
}

// ── File picker / state setter ─────────────────────────────────────────────

/// Show the OS file-open dialog and store the chosen path. Returns the
/// selected path (or `None` if the user cancelled).
#[tauri::command]
pub async fn open_apk(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<FilePath>>();
    app.dialog()
        .file()
        .add_filter("Android packages",
                    &["apk", "xapk", "apkm", "apks", "aab"])
        .pick_file(move |selected| {
            let _ = tx.send(selected);
        });
    let selected = rx.await.map_err(|e| e.to_string())?;
    let path = selected.and_then(|fp| fp.into_path().ok());

    if let Some(p) = &path {
        let s = p.to_string_lossy().into_owned();
        *state.apk_path.write().unwrap() = Some(s.clone());
        return Ok(Some(s));
    }
    Ok(None)
}

/// Set the APK path directly without showing the dialog. Used on app
/// startup when the user passed a path on the command line.
#[tauri::command]
pub fn set_apk_path(path: String, state: State<'_, AppState>) -> Result<(), String> {
    // Validate the path exists and is openable as an APK before accepting.
    PathBuf::from(&path).canonicalize()
        .map_err(|e| format!("path not found: {e}"))?;
    ApkZip::open(&path)
        .map_err(|e| format!("not a valid APK: {e}"))?;
    *state.apk_path.write().unwrap() = Some(path);
    Ok(())
}

/// Current APK path (or `None` if the user hasn't opened one yet).
#[tauri::command]
pub fn current_apk_path(state: State<'_, AppState>) -> Option<String> {
    state.apk_path.read().unwrap().clone()
}

// ── ViewerApi backend ──────────────────────────────────────────────────────

#[tauri::command]
pub fn app_label(state: State<'_, AppState>) -> String {
    let path = state.apk_path.read().unwrap().clone();
    let Some(path) = path else { return "Activity Viewer".into() };

    // Best-effort label: package name from the manifest, else file name.
    if let Ok(apk) = ApkZip::open(&path) {
        if let Ok(bytes) = apk.read_entry("AndroidManifest.xml") {
            if let Ok(root) = axml::parse(&bytes) {
                if let Some(pkg) = root.attr("package") {
                    return format!("{pkg} — {}", basename(&path));
                }
            }
        }
    }
    basename(&path)
}

#[tauri::command]
pub fn activity_list(state: State<'_, AppState>) -> Result<Vec<ActivitySummary>, String> {
    let path = current_path(&state)?;
    let apk = ApkZip::open(&path)
        .map_err(|e| format!("Could not open {path}: {e}"))?;
    let resources = open_resources(&apk).ok();
    let manifest = open_typed_manifest(&apk, resources.as_ref())?;

    let pkg = manifest.package().unwrap_or("").to_string();
    Ok(manifest.activities().into_iter()
        .map(|a| ActivitySummary {
            name: a.resolve_name(&pkg),
            label: a.label.clone(),
            is_launcher: a.is_launcher(),
            exported: a.exported.unwrap_or(false),
        })
        .collect())
}

#[tauri::command]
pub fn activity_rehydrate(
    activity_name: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let path = current_path(&state)?;
    let apk = ApkZip::open(&path)
        .map_err(|e| format!("Could not open {path}: {e}"))?;
    let resources = open_resources(&apk)?;

    // Parse every dex in the APK. The standalone shell doesn't keep a
    // pre-parsed cache (unlike Project Platypus's slot model) — it parses
    // fresh per request. Cost is one-shot per activity-rehydrate call;
    // typical APKs parse in ~50-200ms.
    let dex_files: Vec<DexFileWithRaw> = apk.dex_files().into_iter()
        .filter_map(|(name, bytes)| DexFileWithRaw::from_bytes(bytes, name).ok())
        .collect();

    let mut view = project_platypus_native::rehydrate::rehydrate_activity(
        &apk, &activity_name, &resources, &dex_files,
    );
    // Apply the loaded dexmapper mapping (if any) before serialising.
    // Pure string rewrite — preserves every IR shape; unknown names pass
    // through unchanged so the frontend's renderers don't care whether a
    // mapping was loaded.
    if let Some(deob) = state.deobfuscator.read().unwrap().as_ref() {
        deob.apply_to_activity_view(&mut view);
    }
    serde_json::to_value(&view)
        .map_err(|e| format!("Could not serialise rehydration result: {e}"))
}

/// Effective theme for an activity. Backs `ViewerApi.theme()` for the R1
/// renderer. Resolution order:
///   1. activity-level `android:theme` (most specific)
///   2. `<application android:theme>` (app-wide default)
///   3. bundled Material 3 defaults (always present as fallback)
/// Returns the JSON-serialised `Theme`.
#[tauri::command]
pub fn activity_theme(
    activity_name: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let path = current_path(&state)?;
    let apk = ApkZip::open(&path)
        .map_err(|e| format!("Could not open {path}: {e}"))?;
    let resources = open_resources(&apk)?;
    let manifest = open_typed_manifest(&apk, Some(&resources))?;
    let pkg = manifest.package().unwrap_or("").to_string();

    // Find the explicit theme name, falling back through the chain.
    let theme_ref = manifest.activities().into_iter()
        .find(|a| a.resolve_name(&pkg) == activity_name)
        .and_then(|a| a.theme.clone())
        .or_else(|| manifest.application().and_then(|app| app.theme.clone()));

    let theme = match theme_ref {
        Some(r) => resolve_theme_ref(&r, &resources),
        None => resources.theme(0), // bundled defaults only
    };

    serde_json::to_value(&theme)
        .map_err(|e| format!("Could not serialise theme: {e}"))
}

/// Take whatever the manifest had as the `android:theme` value
/// (`@style/Theme.MyApp`, `@android:style/Theme.Material.Light`, or a
/// resolved `@0x...` id) and return the effective `Theme`. Falls back to
/// bundled defaults if the reference can't be resolved.
fn resolve_theme_ref(
    raw: &str,
    resources: &Resources,
) -> project_platypus_native::resources::theme::Theme {
    use project_platypus_native::resources::refs::{parse_reference, Reference};
    if let Some(r) = parse_reference(raw) {
        match r {
            Reference::Id(id) => return resources.theme(id),
            Reference::Named { type_name, name, package } => {
                // Framework themes (`@android:style/...`) aren't in the app's
                // arsc — fall through to defaults.
                if package.as_deref() != Some("android") && type_name == "style" {
                    if let Some(t) = resources.theme_by_name(&name) {
                        return t;
                    }
                }
            }
            _ => {}
        }
    }
    resources.theme(0)
}

// ── Dexmapper integration ─────────────────────────────────────────────────

/// Show the OS file dialog to pick a dexmapper mapping file. Auto-detects
/// JSON vs. ProGuard format. Returns the loaded mapping's info, or
/// `Ok(None)` if the user cancelled.
#[tauri::command]
pub async fn load_mapping_dialog(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<MappingInfo>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<FilePath>>();
    app.dialog()
        .file()
        .add_filter("Dexmapper mappings", &["json", "txt", "map", "proguard"])
        .pick_file(move |selected| { let _ = tx.send(selected); });
    let selected = rx.await.map_err(|e| e.to_string())?;
    let Some(p) = selected.and_then(|fp| fp.into_path().ok()) else {
        return Ok(None);
    };
    let deob = Deobfuscator::load(&p)?;
    let info = deob.info();
    *state.deobfuscator.write().unwrap() = Some(deob);
    Ok(Some(info))
}

/// Load a mapping from an explicit path (drag-and-drop, CLI arg, scripted
/// integrations). Returns the new mapping's info.
#[tauri::command]
pub fn load_mapping(path: String, state: State<'_, AppState>) -> Result<MappingInfo, String> {
    let deob = Deobfuscator::load(&path)?;
    let info = deob.info();
    *state.deobfuscator.write().unwrap() = Some(deob);
    Ok(info)
}

/// Summary of the currently-loaded mapping. `None` when no mapping is
/// loaded — used by the frontend to render the toolbar pill.
#[tauri::command]
pub fn current_mapping(state: State<'_, AppState>) -> Option<MappingInfo> {
    state.deobfuscator.read().unwrap().as_ref().map(|d| d.info())
}

/// Drop the loaded mapping. After this call `activity_rehydrate` reverts
/// to returning raw (obfuscated) names.
#[tauri::command]
pub fn clear_mapping(state: State<'_, AppState>) {
    *state.deobfuscator.write().unwrap() = None;
}

// ── Asset loading ─────────────────────────────────────────────────────────
//
// The web frontend needs raw bytes for `<img>` sources, font loading,
// and any direct binary parsing. These two commands mirror the
// `get_asset_bytes` / `get_asset_info` pair in the Project Platypus
// shell so a `ViewerApi` extension can call into either host.

/// Categorise an APK entry by extension. Returns `(content_type, kind)`
/// where `kind` is a UI-facing classification (`image` / `font` /
/// `axml` / `arsc` / `dex` / `elf` / `text` / `binary`).
fn asset_category(name: &str) -> (&'static str, &'static str) {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".png")  { return ("image/png",     "image"); }
    if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        return ("image/jpeg", "image");
    }
    if lower.ends_with(".webp") { return ("image/webp",    "image"); }
    if lower.ends_with(".gif")  { return ("image/gif",     "image"); }
    if lower.ends_with(".svg")  { return ("image/svg+xml", "image"); }
    if lower.ends_with(".ttf") || lower.ends_with(".otf") {
        return ("font/ttf", "font");
    }
    if lower.ends_with(".woff") { return ("font/woff",  "font"); }
    if lower.ends_with(".woff2"){ return ("font/woff2", "font"); }
    if lower.ends_with(".json") { return ("application/json", "text"); }
    if lower.ends_with(".xml")  { return ("application/xml",  "axml"); }
    if lower.ends_with(".arsc") { return ("application/octet-stream", "arsc"); }
    if lower.ends_with(".dex")  { return ("application/octet-stream", "dex"); }
    if lower.ends_with(".so")   { return ("application/octet-stream", "elf"); }
    ("application/octet-stream", "binary")
}

/// Raw bytes for an APK entry. AXML (binary `res/*.xml`) is decoded to
/// text-XML on the way out so consumers can pass the bytes directly to
/// a regular XML parser.
#[tauri::command]
pub fn get_asset_bytes(
    entry_path: String,
    state: State<'_, AppState>,
) -> Result<Vec<u8>, String> {
    let path = current_path(&state)?;
    let apk = ApkZip::open(&path).map_err(|e| e.to_string())?;
    let bytes = apk.read_entry(&entry_path).map_err(|e| e.to_string())?;

    let (_, kind) = asset_category(&entry_path);
    if kind == "axml" {
        if let Ok(root) = axml::parse(&bytes) {
            return Ok(root.to_xml_string().into_bytes());
        }
    }
    Ok(bytes)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetInfo {
    pub path: String,
    pub size: usize,
    pub content_type: String,
    pub decoded_kind: String,
}

#[tauri::command]
pub fn get_asset_info(
    entry_path: String,
    state: State<'_, AppState>,
) -> Result<AssetInfo, String> {
    let path = current_path(&state)?;
    let apk = ApkZip::open(&path).map_err(|e| e.to_string())?;
    let bytes = apk.read_entry(&entry_path).map_err(|e| e.to_string())?;

    let (ct, kind) = asset_category(&entry_path);
    Ok(AssetInfo {
        path: entry_path,
        size: bytes.len(),
        content_type: ct.to_string(),
        decoded_kind: kind.to_string(),
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn current_path(state: &AppState) -> Result<String, String> {
    state.apk_path.read().unwrap().clone()
        .ok_or_else(|| "No APK loaded — use File → Open or pass a path on the command line".into())
}

fn open_resources(apk: &ApkZip) -> Result<Resources, String> {
    let bytes = apk.read_entry("resources.arsc")
        .map_err(|e| format!("read resources.arsc: {e}"))?;
    let table = arsc::parse(&bytes)
        .map_err(|e| format!("resources.arsc parse failed: {e}"))?;
    Ok(Resources::new(table))
}

fn open_typed_manifest(apk: &ApkZip, resources: Option<&Resources>) -> Result<Manifest, String> {
    let bytes = apk.read_entry("AndroidManifest.xml")
        .map_err(|e| format!("read AndroidManifest.xml: {e}"))?;
    let root = match resources {
        Some(r) => axml::parse_with_resources(&bytes, r.table()),
        None    => axml::parse(&bytes),
    }.map_err(|e| format!("Manifest parse failed: {e}"))?;
    let m = Manifest::from_xml(root);
    Ok(match resources {
        Some(r) => m.resolved(r),
        None    => m,
    })
}

fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string()
}
