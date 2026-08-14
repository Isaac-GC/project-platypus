#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::exceptions::PyValueError;

#[cfg(feature = "python")]
use crate::apk::zip::ApkZip;
#[cfg(feature = "python")]
use crate::apk::axml;
#[cfg(feature = "python")]
use crate::apk::arsc;
#[cfg(feature = "python")]
use crate::apk::split::SplitApk;
#[cfg(feature = "python")]
use crate::dex::parser::DexFileWithRaw;

#[cfg(feature = "python")]
use super::dex::PyDex;
#[cfg(feature = "python")]
use super::manifest::PyManifestNode;
#[cfg(feature = "python")]
use super::resources::PyResourceTable;

#[cfg(feature = "python")]
#[pyclass(name = "Apk")]
pub struct PyApk {
    inner: ApkZip,
}

#[cfg(feature = "python")]
impl PyApk {
    /// Crate-internal accessor — gives the rehydrate bindings (and any
    /// future Rust-side consumer) a fresh ApkZip handle backed by the
    /// same bytes. Not exposed to Python.
    pub(crate) fn zip_handle(&self) -> ApkZip {
        // ApkZip::from_bytes is cheap — it just rebuilds the central
        // directory; raw_bytes() is a borrow so no copy on the input side.
        ApkZip::from_bytes(self.inner.raw_bytes().to_vec())
            .expect("PyApk::zip_handle: source bytes already validated by inner ApkZip")
    }
}

#[cfg(feature = "python")]
#[pymethods]
impl PyApk {
    #[new]
    pub fn open(path: &str) -> PyResult<Self> {
        ApkZip::open(path)
            .map(|z| PyApk { inner: z })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        ApkZip::from_bytes(data.to_vec())
            .map(|z| PyApk { inner: z })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// List all files in the APK.
    pub fn list_files(&self) -> Vec<String> {
        self.inner.list_entries()
    }

    /// Extract DEX files as PyDex objects.
    pub fn dex_files(&self) -> PyResult<Vec<PyDex>> {
        self.inner
            .dex_files()
            .into_iter()
            .map(|(name, bytes)| {
                DexFileWithRaw::from_bytes(bytes, name)
                    .map(|d| PyDex { inner: d })
                    .map_err(|e| PyValueError::new_err(e.to_string()))
            })
            .collect()
    }

    /// Read any file from the APK as bytes.
    pub fn read_file(&self, name: &str) -> PyResult<Vec<u8>> {
        self.inner
            .read_entry(name)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Check if a file exists.
    pub fn has_file(&self, name: &str) -> bool {
        self.inner.has_entry(name)
    }

    /// Parse AndroidManifest.xml and return the root node.
    pub fn manifest(&self) -> PyResult<PyManifestNode> {
        let data = self
            .inner
            .read_entry("AndroidManifest.xml")
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let root = axml::parse(&data)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyManifestNode::new(root))
    }

    /// Parse resources.arsc and return a ResourceTable.
    pub fn resources(&self) -> PyResult<PyResourceTable> {
        let data = self
            .inner
            .read_entry("resources.arsc")
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let table = arsc::parse(&data)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyResourceTable { inner: table })
    }

    /// List drawable file names.
    pub fn drawables(&self) -> Vec<String> {
        self.inner
            .list_entries()
            .into_iter()
            .filter(|name| name.starts_with("res/drawable"))
            .collect()
    }

    /// List layout file names.
    pub fn layouts(&self) -> Vec<String> {
        self.inner
            .list_entries()
            .into_iter()
            .filter(|name| name.starts_with("res/layout"))
            .collect()
    }

    /// Get package name from manifest.
    #[getter]
    pub fn package_name(&self) -> PyResult<Option<String>> {
        let data = match self.inner.read_entry("AndroidManifest.xml") {
            Ok(d)  => d,
            Err(_) => return Ok(None),
        };
        let root = axml::parse(&data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(root.attr("package").map(|s| s.to_string()))
    }

    /// Get version name from manifest.
    #[getter]
    pub fn version_name(&self) -> PyResult<Option<String>> {
        let data = match self.inner.read_entry("AndroidManifest.xml") {
            Ok(d)  => d,
            Err(_) => return Ok(None),
        };
        let root = axml::parse(&data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(root.attr("android:versionName").map(|s| s.to_string()))
    }

    /// Get app label (resource reference or string).
    #[getter]
    pub fn label(&self) -> PyResult<Option<String>> {
        let data = match self.inner.read_entry("AndroidManifest.xml") {
            Ok(d)  => d,
            Err(_) => return Ok(None),
        };
        let root = axml::parse(&data).map_err(|e| PyValueError::new_err(e.to_string()))?;

        // Look for <application android:label="...">
        let label = root
            .find_first("application")
            .and_then(|app| app.attr("android:label"))
            .map(|s| s.to_string());
        Ok(label)
    }

    /// Parse and resolve AndroidManifest.xml references against resources.arsc.
    pub fn manifest_resolved(&self) -> PyResult<PyManifestNode> {
        let manifest_data = self.inner
            .read_entry("AndroidManifest.xml")
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let resources = match self.inner.read_entry("resources.arsc") {
            Ok(data) => Some(arsc::parse(&data).map_err(|e| PyValueError::new_err(e.to_string()))?),
            Err(_) => None,
        };
        let root = if let Some(res) = resources {
            axml::parse_with_resources(&manifest_data, &res)
        } else {
            axml::parse(&manifest_data)
        }.map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyManifestNode::new(root))
    }

    // ── Rich query layer (platypus_resources) ─────────────────────────

    /// Indexed [`Resources`] view of resources.arsc, with fast by-name and
    /// reference-resolution helpers.
    pub fn resources_typed(&self) -> PyResult<super::typed::PyResources> {
        let data = self.inner.read_entry("resources.arsc")
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        super::typed::PyResources::from_bytes(&data)
    }

    /// Typed [`Manifest`] (Activity / Service / IntentFilter etc. as classes,
    /// not generic XmlNode). Reference values are NOT resolved — use
    /// `manifest_typed_resolved()` for that.
    pub fn manifest_typed(&self) -> PyResult<super::typed::PyManifest> {
        let data = self.inner.read_entry("AndroidManifest.xml")
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        super::typed::PyManifest::from_bytes(&data)
    }

    /// Typed [`Manifest`] with every `@-reference` in attribute values
    /// resolved against the app's resources.arsc — `@string/app_name` becomes
    /// `"My App"` etc. This is the typical "I want everything wired up"
    /// entry point.
    pub fn manifest_typed_resolved(&self) -> PyResult<super::typed::PyManifest> {
        let manifest_data = self.inner.read_entry("AndroidManifest.xml")
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let res_data = self.inner.read_entry("resources.arsc")
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let resources = super::typed::PyResources::from_bytes(&res_data)?;
        super::typed::PyManifest::from_bytes_with_resources(&manifest_data, &resources)
    }

    /// Parse a layout XML file from this APK. Returns a typed [`Layout`]
    /// with `@-references` resolved against the app's resources.arsc.
    ///
    /// `entry_path` is typically `"res/layout/activity_main.xml"` — find it
    /// via `apk.resources_typed().layout_path("activity_main")` first if you
    /// only have the layout name.
    pub fn layout(&self, entry_path: &str) -> PyResult<super::typed::PyLayout> {
        let data = self.inner.read_entry(entry_path)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        // Best-effort: load resources for cross-referencing if available.
        if let Ok(res_bytes) = self.inner.read_entry("resources.arsc") {
            let res = super::typed::PyResources::from_bytes(&res_bytes)?;
            return super::typed::PyLayout::parse_with_resources(&data, &res);
        }
        super::typed::PyLayout::parse(&data)
    }
}

#[cfg(feature = "python")]
#[pyclass(name = "ApkSet")]
pub struct PyApkSet {
    inner: SplitApk,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyApkSet {
    /// Load all APK files from a directory.
    #[staticmethod]
    pub fn from_dir(dir: &str) -> PyResult<Self> {
        SplitApk::from_dir(dir)
            .map(|s| PyApkSet { inner: s })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Load from an explicit list of APK file paths.
    #[staticmethod]
    pub fn from_files(paths: Vec<String>) -> PyResult<Self> {
        let paths_str: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
        SplitApk::from_files(&paths_str)
            .map(|s| PyApkSet { inner: s })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Load from bytes: list of (filename, bytes) tuples.
    #[staticmethod]
    pub fn from_bytes_list(list: Vec<(String, Vec<u8>)>) -> PyResult<Self> {
        SplitApk::from_bytes_list(list)
            .map(|s| PyApkSet { inner: s })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Number of splits.
    #[getter]
    pub fn split_count(&self) -> usize {
        self.inner.split_count()
    }

    /// Names of all splits.
    pub fn split_names(&self) -> Vec<String> {
        self.inner.split_names()
    }

    /// List all files across splits as (split_name, filename) tuples.
    pub fn list_all_files(&self) -> Vec<(String, String)> {
        self.inner.list_all_files()
    }

    /// Aggregate all DEX files from all splits as PyDex objects.
    pub fn dex_files(&self) -> PyResult<Vec<PyDex>> {
        self.inner
            .dex_files()
            .into_iter()
            .map(|(name, bytes)| {
                DexFileWithRaw::from_bytes(bytes, name)
                    .map(|d| PyDex { inner: d })
                    .map_err(|e| PyValueError::new_err(e.to_string()))
            })
            .collect()
    }

    /// Read a file from any split (base first).
    pub fn read_file(&self, name: &str) -> PyResult<Vec<u8>> {
        self.inner
            .read_file(name)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Check if a file exists in any split.
    pub fn has_file(&self, name: &str) -> bool {
        self.inner.has_file(name)
    }

    /// Parse AndroidManifest.xml from the base APK.
    pub fn manifest(&self) -> PyResult<PyManifestNode> {
        let root = self.inner.manifest()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyManifestNode::new(root))
    }

    /// Parse AndroidManifest.xml with resource reference resolution.
    pub fn manifest_resolved(&self) -> PyResult<PyManifestNode> {
        let root = self.inner.manifest_resolved()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyManifestNode::new(root))
    }

    /// Parse resources.arsc from the base APK.
    pub fn resources(&self) -> PyResult<PyResourceTable> {
        self.inner
            .resources()
            .map(|r| PyResourceTable { inner: r })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Package name from base manifest.
    #[getter]
    pub fn package_name(&self) -> Option<String> {
        self.inner.package_name()
    }

    /// Version name from base manifest.
    #[getter]
    pub fn version_name(&self) -> Option<String> {
        self.inner.version_name()
    }

    /// Drawable paths from all splits as (split_name, path) tuples.
    pub fn drawables(&self) -> Vec<(String, String)> {
        self.inner.drawables()
    }

    /// Layout paths from all splits as (split_name, path) tuples.
    pub fn layouts(&self) -> Vec<(String, String)> {
        self.inner.layouts()
    }
}
