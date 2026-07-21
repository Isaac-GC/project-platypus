//! Python bindings for the platypus-rehydrate crate.
//!
//! Exposes the UnifiedView IR + the per-activity rehydration entry points
//! to scripts. The IR is bridged through `json.loads` over a single
//! `serde_json::to_string`, which produces the same camelCase shape the
//! Tauri commands return — keeping the Python and frontend views of the
//! data identical (no per-shell snake/camel drift).

#![cfg(feature = "python")]

use pyo3::prelude::*;
use pyo3::types::PyList;
use pyo3::exceptions::PyValueError;
use pyo3::types::PyAnyMethods;

use platypus_rehydrate as pr;

use super::apk::PyApk;

/// `apk.rehydrate_activity("com.example.MainActivity")` → dict.
///
/// Returns the JSON-shaped UnifiedView for the named activity (camelCase
/// keys, matching the Tauri command shape and the TS `ActivityView` type).
/// Wrapped as a free function so callers can also pass an arbitrary class
/// name (e.g. from a script that walked the manifest themselves).
#[pyfunction]
pub fn rehydrate_activity(
    py: Python<'_>,
    apk: &PyApk,
    activity_name: &str,
) -> PyResult<Py<PyAny>> {
    let (zip, dex_files, resources) = unpack_apk(apk)?;
    let view = pr::rehydrate_activity(&zip, activity_name, &resources, &dex_files);
    serde_to_py(py, &view)
}

/// `apk.rehydrate_all()` → list of dicts.
///
/// Rehydrate every activity declared in the manifest. Faster than calling
/// `rehydrate_activity` in a loop because the resources/manifest/DEX
/// parsing happens once.
#[pyfunction]
pub fn rehydrate_all(py: Python<'_>, apk: &PyApk) -> PyResult<Py<PyAny>> {
    let (zip, dex_files, resources) = unpack_apk(apk)?;
    // Re-parse the manifest with reference resolution so activity names
    // are clean.
    let manifest_bytes = zip.read_entry("AndroidManifest.xml")
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let manifest_root = platypus_apk::axml::parse_with_resources(
        &manifest_bytes,
        resources.table(),
    ).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let manifest = platypus_resources::Manifest::from_xml(manifest_root)
        .resolved(&resources);

    let views = pr::rehydrate_all(&zip, &manifest, &resources, &dex_files);
    let list = PyList::empty(py);
    for v in &views {
        list.append(serde_to_py(py, v)?)?;
    }
    Ok(list.into())
}

// ── Conversion helpers ──────────────────────────────────────────────────────

fn unpack_apk(apk: &PyApk) -> PyResult<(
    platypus_apk::zip::ApkZip,
    Vec<platypus_dex::parser::DexFileWithRaw>,
    platypus_resources::Resources,
)> {
    // Reopen the zip. The PyApk wraps an ApkZip but doesn't expose it
    // directly; we read its base path via the resources lookup. For now,
    // reopen via list_files+from_bytes by collecting all bytes.
    //
    // (Cleaner long-term: add a `pub fn raw_zip(&self) -> &ApkZip` accessor
    // on PyApk. Doing it here keeps the bindings self-contained.)
    let inner = apk.zip_handle();
    let dex_pairs: Vec<(String, Vec<u8>)> = inner.dex_files();
    let dex_files: Vec<_> = dex_pairs.into_iter()
        .filter_map(|(n, b)| platypus_dex::parser::DexFileWithRaw::from_bytes(b, n).ok())
        .collect();
    let res_bytes = inner.read_entry("resources.arsc")
        .map_err(|e| PyValueError::new_err(format!("read resources.arsc: {e}")))?;
    let table = platypus_apk::arsc::parse(&res_bytes)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let resources = platypus_resources::Resources::new(table);
    Ok((inner, dex_files, resources))
}

/// Generic serde → Python bridge. Goes through `json.dumps`/`json.loads`
/// so the result is a plain dict / list / scalar tree — no PyO3-specific
/// wrappers leak into user-land. Every nested struct serialises with the
/// same camelCase shape as the Tauri JSON commands return.
fn serde_to_py<T: serde::Serialize>(py: Python<'_>, value: &T) -> PyResult<Py<PyAny>> {
    let json = serde_json::to_string(value)
        .map_err(|e| PyValueError::new_err(format!("serialise: {e}")))?;
    let json_module = py.import("json")?;
    let parsed = json_module.call_method1("loads", (json,))?;
    Ok(parsed.into())
}
