//! Python bindings for the rich `platypus_resources` query layer.
//!
//! Exposes the typed Manifest / Resources / Layout types as PyO3 classes.
//! These complement the existing `PyManifestNode` / `PyResourceTable`
//! (which stay for backward compat) — the names here are `Manifest`,
//! `Resources`, `Layout`, plus typed component classes (`Activity`,
//! `Service`, etc.) so Python users get autocomplete and structured access
//! instead of stringly-typed XmlNode walking.

#![cfg(feature = "python")]

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

use platypus_resources as pr;

use super::manifest::PyManifestNode;
use super::resources::PyResourceTable;

// ── Resources (indexed) ─────────────────────────────────────────────────────

#[pyclass(name = "Resources")]
pub struct PyResources {
    pub(crate) inner: pr::Resources,
}

#[pymethods]
impl PyResources {
    /// Build from raw resources.arsc bytes.
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let table = platypus_apk::arsc::parse(data)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner: pr::Resources::new(table) })
    }

    /// Total entry count.
    pub fn __len__(&self) -> usize { self.inner.len() }

    /// Distinct type names — `["string", "drawable", "layout", ...]`.
    pub fn types(&self) -> Vec<String> { self.inner.types() }

    /// Lookup the id for `(type, name)` — e.g. `R.string.app_name`.
    pub fn id_by_name(&self, type_name: &str, name: &str) -> Option<u32> {
        self.inner.id_by_name(type_name, name)
    }

    /// Resolve an id to its final string value (chases @-references).
    pub fn resolve(&self, res_id: u32) -> Option<String> {
        self.inner.resolve(res_id)
    }

    /// Get the string value of `R.string.<name>` directly.
    pub fn string_by_name(&self, name: &str) -> Option<String> {
        self.inner.string_by_name(name)
    }

    /// Get the layout file path of `R.layout.<name>` (e.g. "res/layout/activity_main.xml").
    pub fn layout_path(&self, name: &str) -> Option<String> {
        self.inner.layout_path(name)
    }

    /// Get the drawable path of `R.drawable.<name>`.
    pub fn drawable_path(&self, name: &str) -> Option<String> {
        self.inner.drawable_path(name)
    }

    /// Get the mipmap path of `R.mipmap.<name>` (launcher icons live here).
    pub fn mipmap_path(&self, name: &str) -> Option<String> {
        self.inner.mipmap_path(name)
    }

    /// Generic resolver — value of any `(type, name)` pair.
    pub fn value_by_name(&self, type_name: &str, name: &str) -> Option<String> {
        self.inner.value_by_name(type_name, name)
    }

    /// All entries of one type, as `(id, name, value)` tuples.
    pub fn by_type(&self, type_name: &str) -> Vec<(u32, String, String)> {
        self.inner.by_type(type_name).iter()
            .map(|e| (e.id, e.name.clone(), e.value.clone()))
            .collect()
    }

    /// Every string resource as `(id, name, value)`.
    pub fn all_strings(&self) -> Vec<(u32, String, String)> {
        self.inner.all_strings().into_iter()
            .map(|(id, n, v)| (id, n.to_string(), v))
            .collect()
    }

    /// Substring search by name across all types — `(type, name, id)` tuples.
    pub fn search(&self, query: &str) -> Vec<(String, String, u32)> {
        self.inner.search(query).into_iter()
            .map(|(t, n, id)| (t.to_string(), n.to_string(), id))
            .collect()
    }

    /// Resolve an arbitrary attribute string. `@string/foo` → `"Hello"`,
    /// literal strings pass through unchanged. Used by Manifest /
    /// Layout for cross-referencing.
    pub fn resolve_value(&self, value: &str) -> String {
        self.inner.resolve_value(value)
    }

    // ── Drawable resolution ─────────────────────────────────────────────

    /// Resolve `R.drawable.<name>` (or mipmap) to a structured drawable
    /// dict — see [`crate::resources::drawable::Drawable`] for the shape.
    /// `apk` is the same `Apk` instance the Resources came from.
    pub fn resolve_drawable_by_name(
        &self,
        py: pyo3::Python<'_>,
        apk: &super::apk::PyApk,
        name: &str,
    ) -> PyResult<pyo3::Py<pyo3::PyAny>> {
        let zip = apk.zip_handle();
        let drawable = self.inner.resolve_drawable_by_name(&zip, name);
        match drawable {
            Some(d) => drawable_to_py(py, &d),
            None => Ok(py.None()),
        }
    }

    /// Resolve a drawable by resource id (e.g. `0x7f080001`).
    pub fn resolve_drawable_by_id(
        &self,
        py: pyo3::Python<'_>,
        apk: &super::apk::PyApk,
        res_id: u32,
    ) -> PyResult<pyo3::Py<pyo3::PyAny>> {
        let zip = apk.zip_handle();
        let drawable = self.inner.resolve_drawable(&zip, res_id);
        drawable_to_py(py, &drawable)
    }

    /// Resolve any attribute value (color literal, `@drawable/foo`, path)
    /// to a structured drawable. Use for `android:background` / `src` /
    /// `drawable` attributes.
    pub fn resolve_drawable_value(
        &self,
        py: pyo3::Python<'_>,
        apk: &super::apk::PyApk,
        value: &str,
    ) -> PyResult<pyo3::Py<pyo3::PyAny>> {
        let zip = apk.zip_handle();
        let drawable = self.inner.resolve_drawable_value(&zip, value);
        drawable_to_py(py, &drawable)
    }

    // ── Style + theme resolution ────────────────────────────────────────

    /// Look up `R.style.<name>` and return the flattened style (parent
    /// chain merged in). `None` if not a style or doesn't exist.
    pub fn style_by_name(
        &self,
        py: pyo3::Python<'_>,
        name: &str,
    ) -> PyResult<pyo3::Py<pyo3::PyAny>> {
        match self.inner.style_by_name(name) {
            Some(s) => json_to_py(py, &s),
            None => Ok(py.None()),
        }
    }

    /// Look up a style by resource id and return the flattened form.
    pub fn style_by_id(
        &self,
        py: pyo3::Python<'_>,
        res_id: u32,
    ) -> PyResult<pyo3::Py<pyo3::PyAny>> {
        match self.inner.style(res_id) {
            Some(s) => json_to_py(py, &s),
            None => Ok(py.None()),
        }
    }

    /// Build the effective theme dict for a theme id (typically the value of
    /// `<application android:theme>`). Falls back to bundled Material 3
    /// defaults for any attribute the theme chain doesn't define.
    pub fn theme_by_id(
        &self,
        py: pyo3::Python<'_>,
        theme_id: u32,
    ) -> PyResult<pyo3::Py<pyo3::PyAny>> {
        let theme = self.inner.theme(theme_id);
        json_to_py(py, &theme)
    }

    /// Same as [`theme_by_id`] but takes a style name like
    /// `"Theme.MyApp.NoActionBar"`.
    pub fn theme_by_name(
        &self,
        py: pyo3::Python<'_>,
        name: &str,
    ) -> PyResult<pyo3::Py<pyo3::PyAny>> {
        match self.inner.theme_by_name(name) {
            Some(t) => json_to_py(py, &t),
            None => Ok(py.None()),
        }
    }

    /// Bundled defaults — useful when the app doesn't declare a theme or
    /// when previewing a layout in isolation.
    #[staticmethod]
    pub fn default_theme(py: pyo3::Python<'_>) -> PyResult<pyo3::Py<pyo3::PyAny>> {
        let theme = platypus_resources::theme::default_theme();
        json_to_py(py, &theme)
    }
}

/// Serde-roundtrip a Drawable to a plain Python dict so the frontend
/// doesn't need to deal with PyO3-specific classes for every variant.
fn drawable_to_py(
    py: pyo3::Python<'_>,
    drawable: &platypus_resources::Drawable,
) -> PyResult<pyo3::Py<pyo3::PyAny>> {
    json_to_py(py, drawable)
}

/// Generic serde → Python dict bridge via `json.loads`. Used for Drawable,
/// Style, Theme — anything implementing `Serialize`. Slower than direct
/// PyO3 conversion but zero-maintenance as types evolve.
fn json_to_py<T: serde::Serialize>(
    py: pyo3::Python<'_>,
    value: &T,
) -> PyResult<pyo3::Py<pyo3::PyAny>> {
    use pyo3::types::PyAnyMethods;
    let json = serde_json::to_string(value)
        .map_err(|e| PyValueError::new_err(format!("serialise: {e}")))?;
    let json_module = py.import("json")?;
    let parsed = json_module.call_method1("loads", (json,))?;
    Ok(parsed.into())
}

// ── Manifest (typed) ────────────────────────────────────────────────────────

#[pyclass(name = "Manifest")]
pub struct PyManifest {
    pub(crate) inner: pr::Manifest,
}

#[pymethods]
impl PyManifest {
    /// Build from raw AndroidManifest.xml bytes.
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let node = platypus_apk::axml::parse(data)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner: pr::Manifest::from_xml(node) })
    }

    /// Build from raw bytes AND a Resources index — every `@-reference` in
    /// attribute values is resolved during parse.
    #[staticmethod]
    pub fn from_bytes_with_resources(data: &[u8], resources: &PyResources) -> PyResult<Self> {
        let node = platypus_apk::axml::parse_with_resources(data, resources.inner.table())
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let m = pr::Manifest::from_xml(node);
        Ok(Self { inner: m.with_resources(&resources.inner) })
    }

    /// Wrap an already-parsed `ManifestNode`.
    #[staticmethod]
    pub fn from_node(node: &PyManifestNode) -> Self {
        Self { inner: pr::Manifest::from_xml(node.inner.clone()) }
    }

    /// Build a new Manifest with `@-references` resolved against `resources`.
    /// Original is untouched.
    pub fn with_resources(&self, resources: &PyResources) -> Self {
        Self { inner: self.inner.resolved(&resources.inner) }
    }

    /// Resolve a single attribute string in this manifest's context.
    pub fn resolve(&self, value: &str, resources: &PyResources) -> String {
        self.inner.resolve(value, &resources.inner)
    }

    // ── Top-level attributes ────────────────────────────────────────────

    #[getter] pub fn package(&self) -> Option<String> { self.inner.package().map(String::from) }
    #[getter] pub fn version_name(&self) -> Option<String> { self.inner.version_name().map(String::from) }
    #[getter] pub fn version_code(&self) -> Option<i64> { self.inner.version_code() }
    #[getter] pub fn min_sdk(&self) -> Option<i32> { self.inner.min_sdk() }
    #[getter] pub fn target_sdk(&self) -> Option<i32> { self.inner.target_sdk() }
    #[getter] pub fn max_sdk(&self) -> Option<i32> { self.inner.max_sdk() }

    // ── Permissions ─────────────────────────────────────────────────────

    /// `<uses-permission>` entries as PyUsesPermission.
    pub fn uses_permissions(&self) -> Vec<PyUsesPermission> {
        self.inner.uses_permissions().into_iter()
            .map(|p| PyUsesPermission { inner: p }).collect()
    }

    /// Bare permission name strings (with `android.permission.` stripped).
    #[getter] pub fn permission_names(&self) -> Vec<String> { self.inner.permission_names() }

    /// `<permission>` declarations (apps that *expose* permissions).
    pub fn permissions(&self) -> Vec<PyPermission> {
        self.inner.permissions().into_iter()
            .map(|p| PyPermission { inner: p }).collect()
    }

    // ── Component listings ──────────────────────────────────────────────

    pub fn activities(&self) -> Vec<PyActivity> {
        self.inner.activities().into_iter()
            .map(|a| PyActivity { inner: a }).collect()
    }

    pub fn activity_aliases(&self) -> Vec<PyActivityAlias> {
        self.inner.activity_aliases().into_iter()
            .map(|a| PyActivityAlias { inner: a }).collect()
    }

    pub fn services(&self) -> Vec<PyService> {
        self.inner.services().into_iter()
            .map(|s| PyService { inner: s }).collect()
    }

    pub fn receivers(&self) -> Vec<PyReceiver> {
        self.inner.receivers().into_iter()
            .map(|r| PyReceiver { inner: r }).collect()
    }

    pub fn providers(&self) -> Vec<PyProvider> {
        self.inner.providers().into_iter()
            .map(|p| PyProvider { inner: p }).collect()
    }

    /// Activities whose intent-filter has MAIN + LAUNCHER (the home-screen icon).
    pub fn launcher_activities(&self) -> Vec<PyActivity> {
        self.inner.launcher_activities().into_iter()
            .map(|a| PyActivity { inner: a }).collect()
    }

    /// Find an activity by its FQ class name.
    pub fn activity_by_name(&self, fq_name: &str) -> Option<PyActivity> {
        self.inner.activity_by_name(fq_name).map(|a| PyActivity { inner: a })
    }

    pub fn application(&self) -> Option<PyApplication> {
        self.inner.application().map(|a| PyApplication { inner: a })
    }

    pub fn uses_features(&self) -> Vec<PyUsesFeature> {
        self.inner.uses_features().into_iter()
            .map(|f| PyUsesFeature { inner: f }).collect()
    }

    pub fn uses_libraries(&self) -> Vec<PyUsesLibrary> {
        self.inner.uses_libraries().into_iter()
            .map(|l| PyUsesLibrary { inner: l }).collect()
    }

    /// Underlying generic XmlNode — for raw access.
    pub fn raw(&self) -> PyManifestNode {
        PyManifestNode::new(self.inner.root.clone())
    }
}

// ── Component Python classes ─────────────────────────────────────────────────

#[pyclass(name = "Application")]
#[derive(Clone)]
pub struct PyApplication { inner: pr::Application }

#[pymethods]
impl PyApplication {
    #[getter] pub fn name(&self)                    -> Option<String> { self.inner.name.clone() }
    #[getter] pub fn label(&self)                   -> Option<String> { self.inner.label.clone() }
    #[getter] pub fn icon(&self)                    -> Option<String> { self.inner.icon.clone() }
    #[getter] pub fn theme(&self)                   -> Option<String> { self.inner.theme.clone() }
    #[getter] pub fn debuggable(&self)              -> Option<bool>   { self.inner.debuggable }
    #[getter] pub fn allow_backup(&self)            -> Option<bool>   { self.inner.allow_backup }
    #[getter] pub fn uses_cleartext_traffic(&self)  -> Option<bool>   { self.inner.uses_cleartext_traffic }
    #[getter] pub fn network_security_config(&self) -> Option<String> { self.inner.network_security_config.clone() }
    #[getter] pub fn extract_native_libs(&self)     -> Option<bool>   { self.inner.extract_native_libs }
    #[getter] pub fn large_heap(&self)              -> Option<bool>   { self.inner.large_heap }

    /// Every `<meta-data>` directly inside `<application>`.
    pub fn meta_data(&self) -> Vec<PyMetaData> {
        self.inner.meta_data.iter().cloned()
            .map(|m| PyMetaData { inner: m }).collect()
    }

    /// All other `android:foo` attributes not explicitly modelled above.
    #[getter] pub fn other_attrs(&self) -> Vec<(String, String)> { self.inner.other_attrs.clone() }
}

#[pyclass(name = "Activity")]
#[derive(Clone)]
pub struct PyActivity { inner: pr::Activity }

#[pymethods]
impl PyActivity {
    #[getter] pub fn name(&self)                    -> String         { self.inner.name.clone() }
    #[getter] pub fn label(&self)                   -> Option<String> { self.inner.label.clone() }
    #[getter] pub fn icon(&self)                    -> Option<String> { self.inner.icon.clone() }
    #[getter] pub fn theme(&self)                   -> Option<String> { self.inner.theme.clone() }
    #[getter] pub fn exported(&self)                -> Option<bool>   { self.inner.exported }
    #[getter] pub fn launch_mode(&self)             -> Option<String> { self.inner.launch_mode.clone() }
    #[getter] pub fn task_affinity(&self)           -> Option<String> { self.inner.task_affinity.clone() }
    #[getter] pub fn permission(&self)              -> Option<String> { self.inner.permission.clone() }
    #[getter] pub fn config_changes(&self)          -> Option<String> { self.inner.config_changes.clone() }
    #[getter] pub fn screen_orientation(&self)      -> Option<String> { self.inner.screen_orientation.clone() }
    #[getter] pub fn parent_activity_name(&self)    -> Option<String> { self.inner.parent_activity_name.clone() }

    /// Resolve relative `.Foo` / bare `Foo` to a fully-qualified name.
    pub fn resolve_name(&self, package: &str) -> String { self.inner.resolve_name(package) }

    /// True if this activity has an intent-filter with both MAIN + LAUNCHER.
    #[getter] pub fn is_launcher(&self) -> bool { self.inner.is_launcher() }

    /// True if this activity has any MAIN action.
    #[getter] pub fn is_main(&self) -> bool { self.inner.is_main() }

    pub fn intent_filters(&self) -> Vec<PyIntentFilter> {
        self.inner.intent_filters.iter().cloned()
            .map(|f| PyIntentFilter { inner: f }).collect()
    }
    pub fn meta_data(&self) -> Vec<PyMetaData> {
        self.inner.meta_data.iter().cloned()
            .map(|m| PyMetaData { inner: m }).collect()
    }
}

#[pyclass(name = "ActivityAlias")]
#[derive(Clone)]
pub struct PyActivityAlias { inner: pr::ActivityAlias }

#[pymethods]
impl PyActivityAlias {
    #[getter] pub fn name(&self)             -> String         { self.inner.name.clone() }
    #[getter] pub fn target_activity(&self)  -> Option<String> { self.inner.target_activity.clone() }
    #[getter] pub fn label(&self)            -> Option<String> { self.inner.label.clone() }
    #[getter] pub fn exported(&self)         -> Option<bool>   { self.inner.exported }
    #[getter] pub fn permission(&self)       -> Option<String> { self.inner.permission.clone() }

    pub fn intent_filters(&self) -> Vec<PyIntentFilter> {
        self.inner.intent_filters.iter().cloned()
            .map(|f| PyIntentFilter { inner: f }).collect()
    }
}

#[pyclass(name = "Service")]
#[derive(Clone)]
pub struct PyService { inner: pr::Service }

#[pymethods]
impl PyService {
    #[getter] pub fn name(&self)                      -> String         { self.inner.name.clone() }
    #[getter] pub fn label(&self)                     -> Option<String> { self.inner.label.clone() }
    #[getter] pub fn exported(&self)                  -> Option<bool>   { self.inner.exported }
    #[getter] pub fn permission(&self)                -> Option<String> { self.inner.permission.clone() }
    #[getter] pub fn process(&self)                   -> Option<String> { self.inner.process.clone() }
    #[getter] pub fn foreground_service_type(&self)   -> Option<String> { self.inner.foreground_service_type.clone() }
    #[getter] pub fn isolated_process(&self)          -> Option<bool>   { self.inner.isolated_process }
    #[getter] pub fn is_accessibility_service(&self)  -> bool           { self.inner.is_accessibility_service() }

    pub fn intent_filters(&self) -> Vec<PyIntentFilter> {
        self.inner.intent_filters.iter().cloned()
            .map(|f| PyIntentFilter { inner: f }).collect()
    }
}

#[pyclass(name = "Receiver")]
#[derive(Clone)]
pub struct PyReceiver { inner: pr::Receiver }

#[pymethods]
impl PyReceiver {
    #[getter] pub fn name(&self)             -> String         { self.inner.name.clone() }
    #[getter] pub fn exported(&self)         -> Option<bool>   { self.inner.exported }
    #[getter] pub fn permission(&self)       -> Option<String> { self.inner.permission.clone() }
    #[getter] pub fn enabled(&self)          -> Option<bool>   { self.inner.enabled }
    #[getter] pub fn is_device_admin(&self)  -> bool           { self.inner.is_device_admin() }

    pub fn intent_filters(&self) -> Vec<PyIntentFilter> {
        self.inner.intent_filters.iter().cloned()
            .map(|f| PyIntentFilter { inner: f }).collect()
    }
}

#[pyclass(name = "Provider")]
#[derive(Clone)]
pub struct PyProvider { inner: pr::Provider }

#[pymethods]
impl PyProvider {
    #[getter] pub fn name(&self)                  -> String         { self.inner.name.clone() }
    #[getter] pub fn authorities(&self)           -> Vec<String>    { self.inner.authorities.clone() }
    #[getter] pub fn exported(&self)              -> Option<bool>   { self.inner.exported }
    #[getter] pub fn grant_uri_permissions(&self) -> Option<bool>   { self.inner.grant_uri_permissions }
    #[getter] pub fn permission(&self)            -> Option<String> { self.inner.permission.clone() }
    #[getter] pub fn read_permission(&self)       -> Option<String> { self.inner.read_permission.clone() }
    #[getter] pub fn write_permission(&self)      -> Option<String> { self.inner.write_permission.clone() }
}

#[pyclass(name = "IntentFilter")]
#[derive(Clone)]
pub struct PyIntentFilter { inner: pr::IntentFilter }

#[pymethods]
impl PyIntentFilter {
    #[getter] pub fn priority(&self)    -> Option<i32>     { self.inner.priority }
    #[getter] pub fn auto_verify(&self) -> Option<bool>    { self.inner.auto_verify }
    #[getter] pub fn actions(&self)     -> Vec<String>     { self.inner.actions.clone() }
    #[getter] pub fn categories(&self)  -> Vec<String>     { self.inner.categories.clone() }
    #[getter] pub fn is_deep_link(&self) -> bool           { self.inner.is_deep_link() }

    pub fn data(&self) -> Vec<PyIntentData> {
        self.inner.data.iter().cloned()
            .map(|d| PyIntentData { inner: d }).collect()
    }
}

#[pyclass(name = "IntentData")]
#[derive(Clone)]
pub struct PyIntentData { inner: pr::IntentData }

#[pymethods]
impl PyIntentData {
    #[getter] pub fn scheme(&self)        -> Option<String> { self.inner.scheme.clone() }
    #[getter] pub fn host(&self)          -> Option<String> { self.inner.host.clone() }
    #[getter] pub fn port(&self)          -> Option<String> { self.inner.port.clone() }
    #[getter] pub fn path(&self)          -> Option<String> { self.inner.path.clone() }
    #[getter] pub fn path_pattern(&self)  -> Option<String> { self.inner.path_pattern.clone() }
    #[getter] pub fn path_prefix(&self)   -> Option<String> { self.inner.path_prefix.clone() }
    #[getter] pub fn mime_type(&self)     -> Option<String> { self.inner.mime_type.clone() }
}

#[pyclass(name = "MetaData")]
#[derive(Clone)]
pub struct PyMetaData { inner: pr::MetaData }

#[pymethods]
impl PyMetaData {
    #[getter] pub fn name(&self)     -> String         { self.inner.name.clone() }
    #[getter] pub fn value(&self)    -> Option<String> { self.inner.value.clone() }
    #[getter] pub fn resource(&self) -> Option<String> { self.inner.resource.clone() }
}

#[pyclass(name = "UsesPermission")]
#[derive(Clone)]
pub struct PyUsesPermission { inner: pr::UsesPermission }

#[pymethods]
impl PyUsesPermission {
    #[getter] pub fn name(&self)            -> String       { self.inner.name.clone() }
    #[getter] pub fn max_sdk_version(&self) -> Option<i32>  { self.inner.max_sdk_version }
    #[getter] pub fn sdk_23_only(&self)     -> bool         { self.inner.sdk_23_only }
}

#[pyclass(name = "Permission")]
#[derive(Clone)]
pub struct PyPermission { inner: pr::Permission }

#[pymethods]
impl PyPermission {
    #[getter] pub fn name(&self)             -> String         { self.inner.name.clone() }
    #[getter] pub fn label(&self)            -> Option<String> { self.inner.label.clone() }
    #[getter] pub fn description(&self)      -> Option<String> { self.inner.description.clone() }
    #[getter] pub fn permission_group(&self) -> Option<String> { self.inner.permission_group.clone() }
    #[getter] pub fn protection_level(&self) -> Option<String> { self.inner.protection_level.clone() }
}

#[pyclass(name = "UsesFeature")]
#[derive(Clone)]
pub struct PyUsesFeature { inner: pr::UsesFeature }

#[pymethods]
impl PyUsesFeature {
    #[getter] pub fn name(&self)          -> Option<String> { self.inner.name.clone() }
    #[getter] pub fn gl_es_version(&self) -> Option<String> { self.inner.gl_es_version.clone() }
    #[getter] pub fn required(&self)      -> Option<bool>   { self.inner.required }
}

#[pyclass(name = "UsesLibrary")]
#[derive(Clone)]
pub struct PyUsesLibrary { inner: pr::UsesLibrary }

#[pymethods]
impl PyUsesLibrary {
    #[getter] pub fn name(&self)     -> String       { self.inner.name.clone() }
    #[getter] pub fn required(&self) -> Option<bool> { self.inner.required }
}

// ── Layout (with optional reference resolution) ─────────────────────────────

#[pyclass(name = "Layout")]
pub struct PyLayout { pub(crate) inner: pr::Layout }

#[pymethods]
impl PyLayout {
    /// Parse binary AXML bytes (no reference resolution).
    #[staticmethod]
    pub fn parse(data: &[u8]) -> PyResult<Self> {
        let l = pr::Layout::parse(data).map_err(PyValueError::new_err)?;
        Ok(Self { inner: l })
    }

    /// Parse + resolve every `@-reference` against the supplied Resources.
    #[staticmethod]
    pub fn parse_with_resources(data: &[u8], resources: &PyResources) -> PyResult<Self> {
        let l = pr::Layout::parse_with_resources(data, &resources.inner)
            .map_err(PyValueError::new_err)?;
        Ok(Self { inner: l })
    }

    #[getter] pub fn resolved(&self) -> bool { self.inner.resolved }
    #[getter] pub fn view_count(&self) -> usize { self.inner.view_count() }

    /// The root view of the layout tree.
    pub fn root(&self) -> PyView { PyView { inner: self.inner.root.clone() } }

    /// First view (DFS) with `android:id="@id/<id>"`.
    pub fn find_by_id(&self, id: &str) -> Option<PyView> {
        self.inner.find_by_id(id).cloned().map(|v| PyView { inner: v })
    }

    /// Every view (recursively) with the given XML tag.
    pub fn find_by_tag(&self, tag: &str) -> Vec<PyView> {
        self.inner.find_by_tag(tag).into_iter().cloned()
            .map(|v| PyView { inner: v }).collect()
    }

    /// Render the tree back to readable XML.
    pub fn to_xml(&self) -> String { self.inner.to_xml_string() }
}

#[pyclass(name = "View")]
#[derive(Clone)]
pub struct PyView { inner: pr::View }

#[pymethods]
impl PyView {
    #[getter] pub fn tag(&self)                 -> String         { self.inner.tag.clone() }
    #[getter] pub fn id(&self)                  -> Option<String> { self.inner.id() }
    #[getter] pub fn text(&self)                -> Option<String> { self.inner.text().map(String::from) }
    #[getter] pub fn content_description(&self) -> Option<String> { self.inner.content_description().map(String::from) }
    #[getter] pub fn on_click(&self)            -> Option<String> { self.inner.on_click().map(String::from) }
    #[getter] pub fn attrs(&self)               -> Vec<(String, String)> { self.inner.attrs.clone() }

    pub fn attr(&self, name: &str) -> Option<String> {
        self.inner.attr(name).map(String::from)
    }

    pub fn children(&self) -> Vec<PyView> {
        self.inner.children.iter().cloned()
            .map(|v| PyView { inner: v }).collect()
    }

    /// Recursive id-search starting at this view.
    pub fn find_by_id(&self, id: &str) -> Option<PyView> {
        self.inner.find_by_id(id).cloned().map(|v| PyView { inner: v })
    }

    /// Render this subtree as XML.
    pub fn to_xml(&self) -> String { self.inner.raw.to_xml_string() }
}

// ── Bridge from PyApk / PyApkSet to the rich types ──────────────────────────
//
// We don't modify the existing PyApk/PyApkSet impls (that file already exists);
// instead we expose helper free functions accessible via the module.

/// `platypus.parse_resources(bytes)` — convenience top-level for callers
/// who already have raw arsc bytes.
#[pyfunction]
pub fn parse_resources(data: &[u8]) -> PyResult<PyResources> {
    PyResources::from_bytes(data)
}

/// `platypus.parse_manifest(bytes)` — convenience top-level for callers
/// who already have raw AndroidManifest.xml bytes.
#[pyfunction]
pub fn parse_manifest(data: &[u8]) -> PyResult<PyManifest> {
    PyManifest::from_bytes(data)
}

/// `platypus.parse_manifest_with_resources(manifest_bytes, resources_bytes)` —
/// one-shot parse+resolve from raw bytes.
#[pyfunction]
pub fn parse_manifest_with_resources(
    manifest_bytes: &[u8],
    resources_bytes: &[u8],
) -> PyResult<(PyManifest, PyResources)> {
    let res = PyResources::from_bytes(resources_bytes)?;
    let m = PyManifest::from_bytes_with_resources(manifest_bytes, &res)?;
    Ok((m, res))
}

// Silence unused-import warning for PyResourceTable when the legacy types
// aren't used elsewhere here — they're still needed for cross-module use.
#[allow(dead_code)]
fn _resource_table_typecheck(t: PyResourceTable) -> PyResourceTable { t }
