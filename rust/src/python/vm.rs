#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::exceptions::PyValueError;
#[cfg(feature = "python")]
use pyo3::types::{PyBytes, PyList, PyTuple};

#[cfg(feature = "python")]
use crate::dex::clazz::Clazz;
#[cfg(feature = "python")]
use crate::dex::parser::DexFileWithRaw;
#[cfg(feature = "python")]
use crate::vm::vm::Vm;
#[cfg(feature = "python")]
use crate::vm::value::Value;
#[cfg(feature = "python")]
use crate::vm::mock_handler::MockRegistry;
#[cfg(feature = "python")]
use crate::vm::logger::format_value;

#[cfg(feature = "python")]
use super::resources::PyResourceTable;

// ── Value ↔ Python conversions ────────────────────────────────────────────────

/// Convert a `Value` to an owned Python object (`Py<PyAny>`).
#[cfg(feature = "python")]
fn value_to_pyobject(py: Python<'_>, v: Value) -> Py<PyAny> {
    match v {
        Value::Null      => py.None(),
        Value::Bool(b)   => b.into_pyobject(py).unwrap().to_owned().into_any().unbind(),
        Value::Int(n)    => n.into_pyobject(py).unwrap().into_any().unbind(),
        Value::Float(f)  => f.into_pyobject(py).unwrap().into_any().unbind(),
        Value::Str(s)    => s.into_pyobject(py).unwrap().into_any().unbind(),
        Value::Bytes(b)  => PyBytes::new(py, &b).into_any().unbind(),
        v @ Value::Array(_)  => {
            let snapshot = v.array_snapshot().unwrap_or_default();
            let items: Vec<Py<PyAny>> = snapshot.into_iter()
                .map(|item| value_to_pyobject(py, item))
                .collect();
            // PyList::new can only fail on allocation errors; unwrap is fine here.
            PyList::new(py, items).unwrap().into_any().unbind()
        }
    }
}

/// Convert a Python object back to a `Value`.
///
/// Returns `None` when the Python object is `None` or when no suitable
/// mapping exists — in both cases the mock is treated as returning void.
#[cfg(feature = "python")]
fn pyobject_to_value(py: Python<'_>, obj: Py<PyAny>) -> Option<Value> {
    let bound = obj.bind(py);
    if bound.is_none() {
        return None;
    }
    // Test bool *before* int — Python's bool is a subclass of int.
    if let Ok(b) = bound.extract::<bool>() {
        return Some(Value::Bool(b));
    }
    if let Ok(n) = bound.extract::<i64>() {
        return Some(Value::Int(n));
    }
    if let Ok(f) = bound.extract::<f64>() {
        return Some(Value::Float(f));
    }
    if let Ok(s) = bound.extract::<String>() {
        return Some(Value::Str(s));
    }
    if let Ok(b) = bound.extract::<Vec<u8>>() {
        return Some(Value::Bytes(b));
    }
    // Recursively convert list elements.
    if let Ok(list) = bound.downcast::<PyList>() {
        let items = list.iter()
            .filter_map(|item| pyobject_to_value(py, item.unbind()))
            .collect();
        return Some(Value::new_array(items));
    }
    None
}

// ── PyVm ──────────────────────────────────────────────────────────────────────

/// A Dalvik VM instance with support for custom Python mock methods.
///
/// # Quick start
///
/// ```python
/// import platypus
///
/// vm = platypus.Vm()
/// vm.load_dex_file("classes.dex")
///
/// # Register a Python callable as a mock for any DEX method.
/// vm.register_mock(
///     "Landroid/content/Context;->getString",
///     lambda res_id: "mocked string",
/// )
///
/// result = vm.exec_method("Lcom/example/Foo;->bar", [])
/// print(result)  # "mocked string" if bar() calls getString(...)
/// ```
#[cfg(feature = "python")]
#[pyclass(name = "Vm")]
pub struct PyVm {
    inner: Vm,
    /// The most recently user-requested per-call instruction budget. Used to
    /// **refill** `inner.instr_budget` at the start of every `exec_method` so
    /// each call gets a fresh budget rather than draining a shared pool.
    /// `None` means the user has never called `vm.reset()` and `exec_method`
    /// should fall back to its built-in default.
    configured_budget: Option<u64>,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyVm {
    /// Create a new, empty VM instance.
    #[new]
    pub fn new() -> Self {
        PyVm { inner: Vm::new(), configured_budget: None }
    }

    /// Load a DEX file from a filesystem path.
    pub fn load_dex_file(&mut self, path: &str) -> PyResult<()> {
        DexFileWithRaw::from_file(path)
            .map(|d| self.inner.add_dex_file(&d))
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Load a DEX file from raw bytes.
    ///
    /// `name` is used only for display / error messages.
    pub fn load_dex_bytes(&mut self, data: Vec<u8>, name: &str) -> PyResult<()> {
        DexFileWithRaw::from_bytes(data, name.to_string())
            .map(|d| self.inner.add_dex_file(&d))
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Preload string resources from a `ResourceTable` so that
    /// `Context.getString(int)` calls inside executed methods are resolved
    /// automatically.
    pub fn load_resources(&mut self, resources: &PyResourceTable) {
        self.inner.load_resources(
            resources.inner.entries().iter()
                .filter(|e| e.type_name == "string")
                .filter_map(|e| resources.inner.resolve(e.id).map(|v| (e.id, v)))
        );
    }

    /// Register a Python callable as a mock implementation for a DEX method.
    ///
    /// `method_fqn` must use the DEX method reference format:
    /// `"Lpackage/ClassName;->methodName"`.
    ///
    /// The callable receives the method's arguments converted to Python values:
    /// - `int` / `long`  → Python `int`
    /// - `float`         → Python `float`
    /// - `boolean`       → Python `bool`
    /// - `String`        → Python `str`
    /// - `byte[]`        → Python `bytes`
    /// - arrays          → Python `list`
    /// - `null` / other  → Python `None`
    ///
    /// The callable should return a Python value (using the same mapping), or
    /// `None` to indicate a void return.
    ///
    /// Registered mocks take **priority** over the built-in Rust mocks, so you
    /// can also use `register_mock` to **override** an existing built-in mock
    /// (e.g. replace the default `String.charAt` behaviour).
    ///
    /// # Example
    /// ```python
    /// vm.register_mock(
    ///     "Lcom/example/Crypto;->decrypt",
    ///     lambda ciphertext: "decrypted: " + ciphertext.decode(),
    /// )
    /// # Override the built-in Base64 mock:
    /// import base64
    /// vm.register_mock(
    ///     "Landroid/util/Base64;->decode",
    ///     lambda data, flags: base64.b64decode(data),
    /// )
    /// ```
    pub fn register_mock(&mut self, method_fqn: &str, callable: Py<PyAny>) {
        // If `method_fqn` includes a parameter signature `(...)`, use the
        // full key so the mock fires only for that specific overload.
        // Without a signature, the mock acts as a catch-all for every overload
        // of the given method name.
        //
        // Examples:
        //   "Ljava/lang/String;->valueOf"               — all overloads
        //   "Ljava/lang/String;->valueOf(I)Ljava/lang/String;" — int overload only
        let key = if method_fqn.contains('(') {
            MockRegistry::method_fqn_to_full_key(method_fqn)
        } else {
            MockRegistry::method_fqn_to_key(method_fqn)
        };
        self.inner.mocks.register_dynamic(key, Box::new(move |args, _state| {
            // `Python::attach` is re-entrant — safe to call even if the
            // current thread already holds the GIL (as is the case when
            // exec_method is invoked from Python).
            Python::attach(|py| {
                let py_args: Vec<Py<PyAny>> = args.into_iter()
                    .map(|v| value_to_pyobject(py, v))
                    .collect();
                let py_tuple = PyTuple::new(py, py_args).ok()?;
                let result = callable.call1(py, py_tuple).ok()?;
                pyobject_to_value(py, result)
            })
        }));
    }

    /// Execute a method by its DEX reference and return the formatted result.
    ///
    /// `target` format: `"Lpackage/ClassName;->methodName"`
    ///
    /// `args` is a list of string-encoded arguments:
    /// - Plain integers (`"42"`, `"0x7f040001"`)
    /// - Quoted strings (`'"hello"'`)
    /// - Resource encodings from `find_exec` (`"@sget:..."`, `"@invoke!..."`)
    ///
    /// Returns the formatted return value, or `None` if the method returns
    /// void, is not found, or exhausts the instruction budget.
    pub fn exec_method(
        &mut self,
        target: &str,
        args: Vec<String>,
    ) -> PyResult<Option<String>> {
        use crate::analysis::resolve_arg_encoding;

        let mut parts = target.splitn(2, "->");
        let class_raw = parts.next()
            .ok_or_else(|| PyValueError::new_err("target must be 'Lclass;->method'"))?;
        let method_raw = parts.next()
            .ok_or_else(|| PyValueError::new_err("target must be 'Lclass;->method'"))?;

        let class_norm  = class_raw.trim_start_matches('L').trim_end_matches(';');
        let method_name = method_raw.split('(').next().unwrap_or(method_raw).trim();

        // Find the method across all loaded DEX files.
        let method = self.inner.dex_files.iter().find_map(|dex| {
            dex.parsed.class_defs.iter()
                .find(|cd| {
                    cd.type_name.trim_start_matches('L').trim_end_matches(';') == class_norm
                })
                .and_then(|cd| Clazz::new(cd, dex).ok())
                .and_then(|clazz| {
                    clazz.methods.into_iter().find(|m| m.method_name == method_name)
                })
        });

        let method = match method {
            Some(m) => m,
            None    => return Ok(None),
        };

        // Resolve string-encoded args before resetting the call state so any
        // resource-table lookups use the loaded resource state.
        let values: Vec<Value> = args.iter()
            .map(|s| resolve_arg_encoding(s, None, &mut self.inner))
            .collect();

        // Clear transient call state and **refill** the instruction budget to
        // the user's configured value (or 5M default if they've never called
        // vm.reset()). This is critical: `call_method` decrements the budget
        // per-instruction, so without refilling, the second exec_method call
        // would inherit a depleted budget from the first.
        self.inner.call_stack.clear();
        self.inner.memory.last_return = None;
        self.inner.mock_state.clear();
        self.inner.instr_budget = Some(self.configured_budget.unwrap_or(5_000_000));

        let result = self.inner.call_method(&method, values);
        Ok(result.as_ref().map(format_value))
    }

    /// Reset transient VM state (call stack, last return value, mock state)
    /// and set the per-call instruction budget. Every subsequent `exec_method`
    /// call refills its budget to this value (rather than draining from a
    /// shared pool), so you only need to call `reset()` once at the top of a
    /// session — not before each individual `exec_method`.
    pub fn reset(&mut self, instr_limit: u64) {
        self.configured_budget = Some(instr_limit);
        self.inner.reset_for_call(instr_limit);
    }
}
