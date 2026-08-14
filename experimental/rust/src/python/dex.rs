#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::exceptions::PyValueError;

#[cfg(feature = "python")]
use crate::dex::clazz::Clazz;
#[cfg(feature = "python")]
use crate::dex::parser::DexFileWithRaw;
#[cfg(feature = "python")]
use crate::codegen::smali::smali_generator::SmaliClassCodeGen;
#[cfg(feature = "python")]
use crate::codegen::java::analysis::AnalysisConfig;
#[cfg(feature = "python")]
use crate::codegen::java::decompiler::JavaDecompiler;
#[cfg(feature = "python")]
use crate::codegen::java::dominator_tree::DominatorTree;
#[cfg(feature = "python")]
use crate::codegen::java::java_generator::{JavaGenerator, class_package};
#[cfg(feature = "python")]
use crate::codegen::java::ssa_builder::SsaBuilder;

#[cfg(feature = "python")]
use crate::analysis::CallSite;
#[cfg(feature = "python")]
use super::resources::PyResourceTable;

/// A single call site where a target method is invoked.
#[cfg(feature = "python")]
#[pyclass(name = "CallSite")]
#[derive(Clone)]
pub struct PyCallSite {
    #[pyo3(get)] pub caller_class:  String,
    #[pyo3(get)] pub caller_method: String,
    #[pyo3(get)] pub source_file:   String,
    #[pyo3(get)] pub line_number:   Option<u32>,
    #[pyo3(get)] pub invoke_str:    String,
    /// List of (register_index, value_or_None) pairs.
    #[pyo3(get)] pub static_args:   Vec<(u32, Option<String>)>,
}

#[cfg(feature = "python")]
impl From<CallSite> for PyCallSite {
    fn from(s: CallSite) -> Self {
        PyCallSite {
            caller_class:  s.caller_class,
            caller_method: s.caller_method,
            source_file:   s.source_file,
            line_number:   s.line_number,
            invoke_str:    s.invoke_str,
            static_args:   s.static_args,
        }
    }
}

/// Result of executing a call site via the VM.
#[cfg(feature = "python")]
#[pyclass(name = "ExecResult")]
#[derive(Clone)]
pub struct PyExecResult {
    #[pyo3(get)] pub site:   PyCallSite,
    /// Formatted return value, or `None` if void.
    #[pyo3(get)] pub result: Option<String>,
}

#[cfg(feature = "python")]
#[pyclass(name = "Dex")]
pub struct PyDex {
    pub(crate) inner: DexFileWithRaw,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyDex {
    #[staticmethod]
    pub fn from_file(path: &str) -> PyResult<Self> {
        DexFileWithRaw::from_file(path)
            .map(|d| PyDex { inner: d })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[staticmethod]
    pub fn from_bytes(data: Vec<u8>, name: &str) -> PyResult<Self> {
        DexFileWithRaw::from_bytes(data, name.to_string())
            .map(|d| PyDex { inner: d })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[getter]
    pub fn filename(&self) -> &str {
        &self.inner.parsed.filename
    }

    #[getter]
    pub fn sha256(&self) -> &str {
        &self.inner.parsed.digest
    }

    #[getter]
    pub fn version(&self) -> &str {
        &self.inner.parsed.header.version_str
    }

    #[getter]
    pub fn class_count(&self) -> usize {
        self.inner.parsed.class_defs.len()
    }

    pub fn class_names(&self) -> Vec<String> {
        self.inner
            .parsed
            .class_defs
            .iter()
            .map(|cd| cd.type_name.clone())
            .collect()
    }

    /// Decompile a class to Java-like source.
    pub fn decompile_class(&self, class_name: &str) -> PyResult<String> {
        let cd = self
            .inner
            .parsed
            .class_defs
            .iter()
            .find(|cd| cd.type_name == class_name)
            .ok_or_else(|| PyValueError::new_err(format!("class not found: {}", class_name)))?;

        let clazz = Clazz::new(cd, &self.inner)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        let config = AnalysisConfig::default();
        let decompiler = JavaDecompiler::new(Some(config.clone()));

        let mut method_texts: Vec<String> = Vec::new();
        let mut all_imports: std::collections::HashSet<String> = std::collections::HashSet::new();

        for method in &clazz.methods {
            if method.instructions.is_empty() {
                method_texts.push(String::new());
                continue;
            }

            let ast = decompiler.decompile(method);

            let mut cfg_clone = method.cfg.clone();
            if let Some(ref mut cfg) = cfg_clone {
                DominatorTree::compute(cfg);
            }
            let ssa = cfg_clone
                .as_ref()
                .map(|cfg| {
                    SsaBuilder::new().build(
                        cfg,
                        &method.instructions,
                        method.registers_size,
                        method.ins_size,
                    )
                })
                .unwrap_or_else(SsaBuilder::empty_ssa);

            let mut gen = JavaGenerator::new(method, &self.inner.parsed, &ssa);
            let text = gen.gen_class_method(&ast);
            for imp in gen.import_statements() {
                all_imports.insert(imp);
            }
            method_texts.push(text);
        }

        let mut out = Vec::new();
        let pkg = class_package(&clazz.class_name);
        if !pkg.is_empty() {
            out.push(format!("package {};", pkg));
            out.push(String::new());
        }
        let mut sorted_imports: Vec<String> = all_imports.into_iter().collect();
        sorted_imports.sort();
        for imp in sorted_imports {
            out.push(imp);
        }
        if !method_texts.is_empty() {
            out.push(String::new());
        }
        for t in method_texts {
            if !t.is_empty() {
                out.push(t);
            }
        }

        Ok(out.join("\n"))
    }

    /// Get Smali disassembly for a class.
    pub fn disassemble_class(&self, class_name: &str) -> PyResult<String> {
        let cd = self
            .inner
            .parsed
            .class_defs
            .iter()
            .find(|cd| cd.type_name == class_name)
            .ok_or_else(|| PyValueError::new_err(format!("class not found: {}", class_name)))?;

        let clazz = Clazz::new(cd, &self.inner)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        let gen = SmaliClassCodeGen::new(&clazz, &self.inner.parsed);
        Ok(gen.format())
    }

    /// Find all call sites in this DEX that invoke `target`.
    /// `target` format: `"Lclass;->method"` (e.g. `"Lhivhi/wfg;->bihvbhi"`).
    /// Returns a list of `CallSite` objects.
    pub fn find_calls(&self, target: &str) -> Vec<PyCallSite> {
        crate::analysis::find_calls(&self.inner, target)
            .into_iter()
            .map(PyCallSite::from)
            .collect()
    }

    /// Execute a single method call via the Dalvik VM interpreter.
    ///
    /// `target`    — `"Lclass;->method"`
    /// `args`      — string-encoded arguments (integers parsed automatically)
    /// `resources` — optional ResourceTable for resolving `getString(int)` calls
    ///
    /// Returns the formatted result string, or `None` if void / not found.
    pub fn exec_method(
        &self,
        target: &str,
        args: Vec<String>,
        resources: Option<&PyResourceTable>,
    ) -> PyResult<Option<String>> {
        use crate::vm::vm::Vm;
        use crate::vm::value::Value;
        use crate::vm::logger::format_value;
        use crate::analysis::resolve_arg_encoding;

        let mut target_parts = target.splitn(2, "->");
        let class_raw = target_parts.next()
            .ok_or_else(|| PyValueError::new_err("target must be 'Lclass;->method'"))?
            .to_string();
        let method_name_full = target_parts.next()
            .ok_or_else(|| PyValueError::new_err("target must be 'Lclass;->method'"))?
            .to_string();

        // Find the method.
        let class_norm = class_raw.trim_start_matches('L').trim_end_matches(';');
        let method_name_clean = method_name_full.split('(').next().unwrap_or(&method_name_full).trim();
        let method = self.inner.parsed.class_defs.iter()
            .find(|cd| cd.type_name.trim_start_matches('L').trim_end_matches(';') == class_norm)
            .and_then(|cd| {
                Clazz::new(cd, &self.inner).ok()
            })
            .and_then(|clazz| clazz.methods.into_iter()
                .find(|m| m.method_name == method_name_clean));

        let method = match method {
            Some(m) => m,
            None    => return Ok(None),
        };

        // Build the VM.
        let vm_dex = DexFileWithRaw::from_bytes(
            self.inner.raw_bytes().to_vec(),
            self.inner.parsed.filename.clone(),
        ).map_err(|e| PyValueError::new_err(e.to_string()))?;

        let mut vm = Vm::new();
        vm.add_dex_file(&vm_dex);

        if let Some(res_table) = resources {
            vm.load_resources(
                res_table.inner.entries().iter()
                    .filter(|e| e.type_name == "string")
                    .filter_map(|e| res_table.inner.resolve(e.id).map(|v| (e.id, v)))
            );
        }

        // Parse args.
        let resource_table = resources.map(|r| &r.inner);
        let values: Vec<Value> = args.iter().map(|s| {
            resolve_arg_encoding(s, resource_table, &mut vm)
        }).collect();

        vm.reset_for_call(50_000);
        let result = vm.call_method(&method, values);
        Ok(result.as_ref().map(format_value))
    }

    /// Find all call sites for `target` and execute each one.
    /// Returns a list of `ExecResult` objects.
    ///
    /// `resources` — optional ResourceTable; when provided, `getString(int)` calls
    ///   inside the executed method are resolved automatically, and R$string field
    ///   references in static args are resolved via the resource table.
    /// `instr_limit` — optional per-call instruction budget. `None` uses the
    /// `analysis::exec_calls` default (5_000_000).
    pub fn find_exec(
        &self,
        target: &str,
        resources: Option<&PyResourceTable>,
        instr_limit: Option<u64>,
    ) -> Vec<PyExecResult> {
        let resource_table = resources.map(|r| &r.inner);
        crate::analysis::find_and_exec(&self.inner, target, resource_table, instr_limit)
            .into_iter()
            .map(|(site, result)| PyExecResult {
                site: PyCallSite::from(site),
                result: result.map(|v| crate::vm::logger::format_value(&v)),
            })
            .collect()
    }
}
