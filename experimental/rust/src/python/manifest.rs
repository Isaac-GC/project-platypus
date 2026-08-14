#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use std::collections::HashMap;

#[cfg(feature = "python")]
use crate::apk::axml::XmlNode;

#[cfg(feature = "python")]
#[pyclass(name = "ManifestNode")]
#[derive(Clone)]
pub struct PyManifestNode {
    pub(crate) inner: XmlNode,
}

#[cfg(feature = "python")]
impl PyManifestNode {
    pub fn new(node: XmlNode) -> Self {
        PyManifestNode { inner: node }
    }
}

#[cfg(feature = "python")]
#[pymethods]
impl PyManifestNode {
    #[getter]
    pub fn tag(&self) -> &str {
        &self.inner.tag
    }

    pub fn attr(&self, name: &str) -> Option<String> {
        self.inner.attr(name).map(|s| s.to_string())
    }

    pub fn attrs(&self) -> HashMap<String, String> {
        self.inner
            .attrs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn children(&self) -> Vec<PyManifestNode> {
        self.inner
            .children
            .iter()
            .map(|c| PyManifestNode::new(c.clone()))
            .collect()
    }

    pub fn to_xml(&self) -> String {
        self.inner.to_xml_string()
    }

    pub fn find_all(&self, tag: &str) -> Vec<PyManifestNode> {
        self.inner
            .find_all(tag)
            .into_iter()
            .map(|n| PyManifestNode::new(n.clone()))
            .collect()
    }

    pub fn find_first(&self, tag: &str) -> Option<PyManifestNode> {
        self.inner
            .find_first(tag)
            .map(|n| PyManifestNode::new(n.clone()))
    }
}
