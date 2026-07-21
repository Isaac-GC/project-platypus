#[cfg(feature = "python")]
pub mod apk;
#[cfg(feature = "python")]
pub mod dex;
#[cfg(feature = "python")]
pub mod manifest;
#[cfg(feature = "python")]
pub mod resources;
#[cfg(feature = "python")]
pub mod vm;
#[cfg(feature = "python")]
pub mod typed;
#[cfg(feature = "python")]
pub mod rehydrate;
#[cfg(feature = "python")]
pub mod license;

#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::wrap_pyfunction;

#[cfg(feature = "python")]
pub use apk::{PyApk, PyApkSet};
#[cfg(feature = "python")]
pub use dex::{PyDex, PyCallSite, PyExecResult};
#[cfg(feature = "python")]
pub use manifest::PyManifestNode;
#[cfg(feature = "python")]
pub use resources::{PyResource, PyResourceTable};
#[cfg(feature = "python")]
pub use vm::PyVm;
#[cfg(feature = "python")]
pub use typed::{
    PyManifest, PyApplication, PyActivity, PyActivityAlias, PyService, PyReceiver, PyProvider,
    PyIntentFilter, PyIntentData, PyMetaData, PyUsesPermission, PyPermission,
    PyUsesFeature, PyUsesLibrary, PyResources, PyLayout, PyView,
};

#[cfg(feature = "python")]
#[pymodule]
pub fn platypus(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Existing low-level wrappers (kept for back-compat).
    m.add_class::<PyApk>()?;
    m.add_class::<PyApkSet>()?;
    m.add_class::<PyDex>()?;
    m.add_class::<PyManifestNode>()?;
    m.add_class::<PyResource>()?;
    m.add_class::<PyResourceTable>()?;
    m.add_class::<PyCallSite>()?;
    m.add_class::<PyExecResult>()?;
    m.add_class::<PyVm>()?;

    // ── Rich Androguard-style query layer (platypus_resources) ─────────
    m.add_class::<PyManifest>()?;
    m.add_class::<PyApplication>()?;
    m.add_class::<PyActivity>()?;
    m.add_class::<PyActivityAlias>()?;
    m.add_class::<PyService>()?;
    m.add_class::<PyReceiver>()?;
    m.add_class::<PyProvider>()?;
    m.add_class::<PyIntentFilter>()?;
    m.add_class::<PyIntentData>()?;
    m.add_class::<PyMetaData>()?;
    m.add_class::<PyUsesPermission>()?;
    m.add_class::<PyPermission>()?;
    m.add_class::<PyUsesFeature>()?;
    m.add_class::<PyUsesLibrary>()?;
    m.add_class::<PyResources>()?;
    m.add_class::<PyLayout>()?;
    m.add_class::<PyView>()?;

    // Module-level convenience functions.
    m.add_function(wrap_pyfunction!(typed::parse_resources, m)?)?;
    m.add_function(wrap_pyfunction!(typed::parse_manifest, m)?)?;
    m.add_function(wrap_pyfunction!(typed::parse_manifest_with_resources, m)?)?;

    // ── Rehydrate (activity-viewer backend) ───────────────────────────
    m.add_function(wrap_pyfunction!(rehydrate::rehydrate_activity, m)?)?;
    m.add_function(wrap_pyfunction!(rehydrate::rehydrate_all, m)?)?;

    // ── Offline license verification (platypus.license) ───────────────
    license::register(m)?;

    Ok(())
}
