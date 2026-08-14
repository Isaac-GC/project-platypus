#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
use crate::apk::arsc::ResourceTable;

#[cfg(feature = "python")]
#[pyclass(name = "Resource")]
#[derive(Clone)]
pub struct PyResource {
    #[pyo3(get)]
    pub id: u32,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub type_name: String,
    #[pyo3(get)]
    pub value: String,
}

#[cfg(feature = "python")]
impl PyResource {
    pub fn from_entry(e: &crate::apk::arsc::ResourceEntry) -> Self {
        PyResource {
            id:        e.id,
            name:      e.name.clone(),
            type_name: e.type_name.clone(),
            value:     e.value.clone(),
        }
    }
}

#[cfg(feature = "python")]
#[pyclass(name = "ResourceTable")]
pub struct PyResourceTable {
    pub(crate) inner: ResourceTable,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyResourceTable {
    pub fn get_string(&self, res_id: u32) -> Option<String> {
        self.inner.get_string(res_id).map(|s| s.to_string())
    }

    pub fn get(&self, res_id: u32) -> Option<PyResource> {
        self.inner.get(res_id).map(PyResource::from_entry)
    }

    pub fn all_resources(&self) -> Vec<PyResource> {
        self.inner.entries().iter().map(PyResource::from_entry).collect()
    }

    pub fn by_type(&self, type_name: &str) -> Vec<PyResource> {
        self.inner
            .by_type(type_name)
            .into_iter()
            .map(PyResource::from_entry)
            .collect()
    }

    pub fn strings(&self) -> Vec<PyResource> {
        self.by_type("string")
    }

    /// Resolve a resource ID to its final string value, following reference chains.
    /// For example, resolves @string/app_name → "My App".
    pub fn resolve(&self, res_id: u32) -> Option<String> {
        self.inner.resolve(res_id)
    }

    /// Get a string resource by name (e.g. "app_name").
    pub fn string_by_name(&self, name: &str) -> Option<String> {
        self.inner.string_by_name(name).map(|s| s.to_string())
    }
}
