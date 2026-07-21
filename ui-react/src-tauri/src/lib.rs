mod commands;
mod license;
mod project;
mod state;

use state::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        // ── Self-update plugins ────────────────────────────────────────
        // `updater` checks the configured endpoint and downloads/installs
        // signed bundles. `process` is required for the post-install
        // `relaunch()` call. Both are inert until the frontend invokes
        // them — see `src/utils/updater.ts`. Sub-windows (search, taint,
        // activity-viewer) don't get the updater capability; only the
        // main window can trigger updates.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            // Resolve `<os cache>/project_platypus/` and ensure it exists.
            let base = app.path()
                .cache_dir()
                .expect("OS cache directory unavailable");
            let cache_dir = base.join("project_platypus");
            std::fs::create_dir_all(&cache_dir)
                .expect("could not create project_platypus cache dir");

            // Construct AppState from disk (restores any persisted slots).
            let state = AppState::with_cache_dir(cache_dir);
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // ── Existing single-file commands ────────────────────────────
            commands::load_file,
            commands::get_class_smali,
            commands::get_class_java,
            commands::get_manifest,
            commands::get_xrefs,
            commands::get_call_graph,
            commands::get_method_cfg,
            commands::run_method,
            commands::find_exec,
            commands::search_code,
            commands::open_file_dialog,
            commands::get_resources,
            commands::get_entry,
            commands::get_asset_bytes,
            commands::get_asset_info,
            commands::load_file_b,
            commands::get_class_smali_b,
            commands::get_class_java_b,
            commands::run_script,
            commands::kill_script,
            commands::lint_script,
            commands::open_search_window,
            commands::open_taint_window,
            commands::run_taint_analysis,
            commands::taint_build_root,
            commands::taint_expand_forward,
            commands::taint_expand_backward,
            commands::taint_reanalyze,
            // ── Multi-APK project commands ───────────────────────────────
            commands::project_init,
            commands::project_list_slots,
            commands::project_add_apk,
            commands::project_add_split,
            commands::project_remove_slot,
            commands::project_set_active_slot,
            commands::project_set_compare_slot,
            commands::project_force_reload_slot,
            commands::project_clear_extracted,
            commands::project_cache_dir,
            commands::project_load_embedded,
            commands::project_load_embedded_nested,
            commands::analyze_dex_loaders,
            commands::script_get_completions,
            commands::script_list,
            commands::script_load,
            commands::script_save,
            commands::script_create,
            commands::script_delete,
            commands::script_rename,
            commands::script_dir,
            // ── UI-state persistence (durable on Linux/WebKitGTK) ────────
            commands::ui_state_get,
            commands::ui_state_set,
            commands::ui_state_remove,
            // ── Activity viewer ─────────────────────────────────────────
            commands::activity_list,
            commands::activity_rehydrate,
            commands::activity_theme,
            commands::open_activity_viewer_window,
            // ── Dexmapper deobfuscation ─────────────────────────────────
            commands::load_mapping_dialog,
            commands::load_mapping,
            commands::current_mapping,
            commands::clear_mapping,
            // ── Deobfuscation-mark tab ───────────────────────────────────
            commands::deobf_mark_method,
            commands::deobf_unmark_method,
            commands::deobf_list_marks,
            commands::deobf_scan_sites,
            commands::deobf_run_all_marks,
            commands::deobf_run_specific_sites,
            // ── Offline licensing ────────────────────────────────────────
            license::license_status,
            license::license_activate,
            license::license_deactivate,
            license::machine_fingerprint,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
