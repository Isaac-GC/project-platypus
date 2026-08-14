//! `platypus.license` — the same offline Ed25519 verifier the Tauri app uses,
//! surfaced to Python through PyO3. Native callers (the `platypus` extension)
//! get verification for free; the pure-Python `licensing` package mirrors this
//! API with PyNaCl for environments where the compiled module isn't loaded.

use platypus_license as lic;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::wrap_pyfunction;

/// Result of verifying a license token. `valid` is the only field most callers
/// need; the claim getters are `None` when the signature didn't verify.
#[pyclass(name = "License", module = "platypus.license")]
pub struct PyLicense {
    inner: lic::Verified,
}

#[pymethods]
impl PyLicense {
    /// `valid` | `expired` | `machine_mismatch` | `bad_signature` | `malformed` | `missing` | `not_yet_valid`.
    #[getter]
    fn status(&self) -> &'static str {
        self.inner.status.as_str()
    }

    /// True only when the token is authentic, in-date, and on the right machine.
    #[getter]
    fn valid(&self) -> bool {
        self.inner.status.is_valid()
    }

    #[getter]
    fn id(&self) -> Option<String> {
        self.inner.claims.as_ref().map(|c| c.id.clone())
    }
    #[getter]
    fn name(&self) -> Option<String> {
        self.inner.claims.as_ref().map(|c| c.name.clone())
    }
    #[getter]
    fn email(&self) -> Option<String> {
        self.inner.claims.as_ref().map(|c| c.email.clone())
    }
    #[getter]
    fn plan(&self) -> Option<String> {
        self.inner.claims.as_ref().map(|c| c.plan.clone())
    }
    #[getter]
    fn tier(&self) -> Option<String> {
        self.inner.claims.as_ref().map(|c| c.tier.clone())
    }
    #[getter]
    fn seats(&self) -> Option<u32> {
        self.inner.claims.as_ref().map(|c| c.seats)
    }
    #[getter]
    fn features(&self) -> Vec<String> {
        self.inner
            .claims
            .as_ref()
            .map(|c| c.features.clone())
            .unwrap_or_default()
    }
    #[getter]
    fn expires(&self) -> Option<i64> {
        self.inner.claims.as_ref().and_then(|c| c.expires)
    }
    #[getter]
    fn machine(&self) -> Option<String> {
        self.inner.claims.as_ref().and_then(|c| c.machine.clone())
    }

    /// Whether this license entitles `feature` (an `"*"` entitlement grants all).
    /// Always false for an invalid token.
    fn has_feature(&self, feature: &str) -> bool {
        self.inner
            .claims
            .as_ref()
            .is_some_and(|c| c.has_feature(feature))
    }

    fn __repr__(&self) -> String {
        let id = self.id().unwrap_or_else(|| "-".into());
        format!("<License {id} status={}>", self.status())
    }
}

/// Verify `token` against the embedded vendor key, the current clock, and this
/// machine's fingerprint. `None`/empty → a `missing` result.
#[pyfunction]
#[pyo3(signature = (token=None))]
fn verify(token: Option<&str>) -> PyLicense {
    PyLicense { inner: lic::evaluate_now(token) }
}

/// This machine's node-lock fingerprint (32 hex chars), or `None` if the OS
/// machine id is unavailable. Matches the Tauri `machine_fingerprint` command
/// and the Rust [`platypus_license::fingerprint`] output.
#[pyfunction]
fn machine_fingerprint() -> Option<String> {
    lic::fingerprint::machine_fingerprint()
}

/// Build the `platypus.license` submodule and register it under the parent.
pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = parent.py();
    let m = PyModule::new(py, "license")?;
    m.add_class::<PyLicense>()?;
    m.add_function(wrap_pyfunction!(verify, &m)?)?;
    m.add_function(wrap_pyfunction!(machine_fingerprint, &m)?)?;
    m.add("TOKEN_PREFIX", lic::TOKEN_PREFIX)?;
    m.add("VENDOR_PUBLIC_KEY_HEX", lic::VENDOR_PUBLIC_KEY_HEX)?;
    parent.add_submodule(&m)?;
    // Make `from platypus.license import verify` work, not just attribute access.
    py.import("sys")?
        .getattr("modules")?
        .set_item("platypus.license", &m)?;
    Ok(())
}
