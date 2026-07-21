//! Standalone platypus-viewer Tauri app entrypoint.
//!
//! Tiny shell — file picker + the activity-viewer Tauri commands. CLI
//! support: pass an APK path as the first argument and the app starts
//! with that APK already loaded. Drag-and-drop also wires through the
//! same `set_apk_path` command from the frontend.

mod commands;
mod state;

use state::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // CLI: positional args. First positional → APK path. A `--mapping <path>`
    // (or `-m <path>`) flag preloads a dexmapper mapping so the user sees
    // real names from the moment the first activity renders.
    let mut cli_apk: Option<String> = None;
    let mut cli_mapping: Option<String> = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-m" | "--mapping" => { cli_mapping = it.next(); }
            s if !s.starts_with('-') && cli_apk.is_none() => { cli_apk = Some(s.to_string()); }
            _ => {} // ignore unrecognised flags — Tauri may inject its own
        }
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        // ── Self-update plugins ────────────────────────────────────────
        // `updater` checks the configured endpoint and downloads/installs
        // signed bundles. `process` is required for the post-install
        // `relaunch()` call. Both are inert until the frontend invokes
        // them — see `src/updater.ts`.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(move |app| {
            let st = AppState::new();
            if let Some(p) = &cli_apk {
                match std::fs::canonicalize(p) {
                    Ok(canon) => {
                        let s = canon.to_string_lossy().into_owned();
                        *st.apk_path.write().unwrap() = Some(s.clone());
                        eprintln!("[platypus-viewer] preloaded apk {s}");
                    }
                    Err(e) => eprintln!("[platypus-viewer] CLI apk '{p}' rejected: {e}"),
                }
            }
            if let Some(p) = &cli_mapping {
                match platypus_dexmapper::Deobfuscator::load(p) {
                    Ok(d) => {
                        let info = d.info();
                        *st.deobfuscator.write().unwrap() = Some(d);
                        eprintln!("[platypus-viewer] preloaded mapping {p} ({} classes)",
                                  info.class_count);
                    }
                    Err(e) => eprintln!("[platypus-viewer] CLI mapping '{p}' rejected: {e}"),
                }
            }
            app.manage(st);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::open_apk,
            commands::set_apk_path,
            commands::current_apk_path,
            commands::app_label,
            commands::activity_list,
            commands::activity_rehydrate,
            commands::activity_theme,
            commands::load_mapping_dialog,
            commands::load_mapping,
            commands::current_mapping,
            commands::clear_mapping,
            commands::get_asset_bytes,
            commands::get_asset_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running platypus-viewer");
}
