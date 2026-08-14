/// Java pseudo-code generator — produces JADX-style Java output.
///
/// Two-pass approach:
///   Pass 1 (type inference): scan instructions to build `reg → Java type` map,
///            collect imports, seed JADX namer with param types.
///   Pass 2 (code generation): emit Java using JADX naming conventions,
///            collapse `new-instance` + `invoke-direct/<init>` pairs,
///            use `pending_call` for typed move-result declarations.

use std::collections::{HashMap, HashSet};

use platypus_dex::access_flags::MethodAccessFlag;
use platypus_dex::instructions::{Instruction, InstructionKind};
use platypus_dex::method::Method;
use platypus_dex::parser::ParsedDex;

use super::ast::AstNode;
use super::ssa_builder::SsaForm;

// ── MethodFilter — dynamic call-suppression registry ─────────────────────────

/// A registry of (class, method) pairs whose call sites should be suppressed
/// from the decompiled output (e.g. Kotlin runtime boilerplate).
///
/// Entries can be added at runtime via [`MethodFilter::suppress_method`] and
/// [`MethodFilter::suppress_class`].  The default instance is pre-populated
/// with well-known Kotlin/JVM boilerplate.
#[derive(Clone)]
pub struct MethodFilter {
    /// Dalvik class descriptors whose *every* method call should be suppressed.
    suppressed_classes: HashSet<String>,
    /// class_desc → set of method names to suppress within that class.
    suppressed_methods: HashMap<String, HashSet<String>>,
}

impl Default for MethodFilter {
    fn default() -> Self {
        let mut f = MethodFilter {
            suppressed_classes: HashSet::new(),
            suppressed_methods: HashMap::new(),
        };
        // Kotlin null-check / assertion boilerplate.
        let intrinsics = "Lkotlin/jvm/internal/Intrinsics;";
        for m in &[
            "checkNotNullParameter",
            "checkNotNull",
            "checkParameterIsNotNull",
            "checkExpressionValueIsNotNull",
            "checkNotNullExpressionValue",
            "checkReturnedValueIsNotNull",
            "throwNpe",
            "throwUninitializedPropertyAccessException",
            "areEqual",
            "stringPlus",
        ] {
            f.suppress_method(intrinsics, m);
        }
        // Kotlin synthetic constructor marker.
        f.suppress_class("Lkotlin/jvm/internal/DefaultConstructorMarker;");
        f
    }
}

impl MethodFilter {
    /// Create an empty filter with no rules.
    pub fn empty() -> Self {
        MethodFilter {
            suppressed_classes: HashSet::new(),
            suppressed_methods: HashMap::new(),
        }
    }

    /// Suppress every method call on the given class (Dalvik descriptor).
    pub fn suppress_class(&mut self, class_desc: &str) {
        self.suppressed_classes.insert(class_desc.to_string());
    }

    /// Suppress calls to a specific method on a class.
    pub fn suppress_method(&mut self, class_desc: &str, method_name: &str) {
        self.suppressed_methods
            .entry(class_desc.to_string())
            .or_default()
            .insert(method_name.to_string());
    }

    /// Returns `true` if the given (class, method) call should be dropped.
    pub fn is_suppressed(&self, class_desc: &str, method_name: &str) -> bool {
        if self.suppressed_classes.contains(class_desc) {
            return true;
        }
        if let Some(methods) = self.suppressed_methods.get(class_desc) {
            return methods.contains(method_name);
        }
        false
    }
}

// ── JADX naming helpers ───────────────────────────────────────────────────────

/// Map a Java type name (simple, not a descriptor) to its JADX base name.
fn jadx_base(java_type: &str) -> &str {
    match java_type {
        "String"      => "str",
        "byte[]"      => "bArr",
        "int[]"       => "iArr",
        "char[]"      => "cArr",
        "long[]"      => "jArr",
        "boolean[]"   => "zArr",
        "short[]"     => "sArr",
        "float[]"     => "fArr",
        "double[]"    => "dArr",
        "Object[]"    => "objArr",
        "int"         => "i",
        "long"        => "j",
        "boolean"     => "z",
        "byte"        => "b",
        "char"        => "c",
        "float"       => "f",
        "double"      => "d",
        "short"       => "s",
        "Object"      => "obj",
        "Exception"   => "e",
        "Throwable"   => "th",
        _             => "",    // falls through to camelCase of simple class name
    }
}

/// Convert a Java class type name ("SecretKeySpec",
/// "MediaBrowserCompat.MediaItem", "Foo[]") to a camelCase variable
/// identifier ("secretKeySpec", "mediaItem", "foo"). The output is always
/// a legal Java identifier — array brackets and qualifying dots are
/// stripped so the result can be used as a local variable name.
fn class_to_var(java_type: &str) -> String {
    let trimmed = java_type.trim_end_matches("[]");
    let simple = trimmed.rsplit('.').next().unwrap_or(trimmed);
    if simple.is_empty() { return "obj".to_string(); }
    let mut chars = simple.chars();
    let first = chars.next().unwrap().to_lowercase().next().unwrap();
    format!("{}{}", first, chars.as_str())
}

// ── JadxNamer ─────────────────────────────────────────────────────────────────

struct JadxNamer {
    /// reg → assigned JADX name
    names:    HashMap<i64, String>,
    /// base_name → how many times it has been assigned
    counters: HashMap<String, u32>,
}

impl JadxNamer {
    fn new() -> Self {
        JadxNamer { names: HashMap::new(), counters: HashMap::new() }
    }

    /// Assign a JADX name to `reg` based on its Java type.
    /// If already assigned, returns the existing name without allocating a new one.
    fn assign(&mut self, reg: i64, java_type: &str) -> String {
        if let Some(n) = self.names.get(&reg) {
            return n.clone();
        }
        let base_str;
        let base = {
            let b = jadx_base(java_type);
            if b.is_empty() {
                base_str = class_to_var(java_type);
                base_str.as_str()
            } else {
                b
            }
        };
        let count = self.counters.entry(base.to_string()).or_insert(0);
        let name = if *count == 0 {
            base.to_string()
        } else {
            format!("{}{}", base, *count + 1)
        };
        *count += 1;
        self.names.insert(reg, name.clone());
        name
    }

    fn get(&self, reg: i64) -> Option<&str> {
        self.names.get(&reg).map(|s| s.as_str())
    }

    /// Remove the existing name for `reg` and assign a fresh one based on
    /// `java_type`.  Used when a register is reused with a different type.
    fn reassign(&mut self, reg: i64, java_type: &str) -> String {
        self.names.remove(&reg);
        self.assign(reg, java_type)
    }
}

// ── JavaGenerator ─────────────────────────────────────────────────────────────

pub struct JavaGenerator<'a> {
    pub method:  &'a Method,
    pub dex:     &'a ParsedDex,
    pub ssa:     &'a SsaForm,

    /// reg → inferred Java type (e.g. "String", "byte[]", "int").
    reg_types:    HashMap<i64, String>,
    /// JADX name assignments.
    namer:        JadxNamer,
    /// reg → pending new-instance type (waiting for invoke-direct/<init>).
    pending_new:  HashMap<i64, String>,
    /// Pending call from invoke: consumed by the next move-result.
    /// Tuple: (call_expr_string, return_type_desc).
    pending_call: Option<(String, String)>,
    /// Registers already declared to avoid duplicate `Type name` prefixes.
    declared:        HashSet<i64>,
    /// The Java type used at the most recent declaration of each register.
    /// When a register is reused with a different type we force a fresh name
    /// and re-declaration so we don't emit `boolean x = new Intent(...)`.
    declared_types:  HashMap<i64, String>,
    /// Fully-qualified class names to import (dotted, e.g. "android.util.Base64").
    imports:         HashSet<String>,
    /// Simple class names (last path segment, e.g. "wfg") that are shared by
    /// more than one fully-qualified class referenced in this DEX. Such names
    /// can't be disambiguated by an `import` (only one import per simple name
    /// is legal), so every reference to an ambiguous class is rendered
    /// fully-qualified inline and no import is emitted for it. This is what
    /// fixes the obfuscated-APK bug where `wfg.bihvbhi(...)` resolved to the
    /// wrong `wfg` because the file imported a same-named class from another
    /// package.
    ambiguous_simple: HashSet<String>,
    /// reg → raw string value for const-string registers.
    /// These are inlined at point-of-use instead of being emitted as separate
    /// variable declarations.  Cleared whenever the register is overwritten.
    string_literals: HashMap<i64, String>,

    /// Dynamic filter controlling which method calls are suppressed.
    pub filter: MethodFilter,

    current_block: usize,

    /// Registers that currently hold `this` (via `move-object v, p0`, or a
    /// chain of such moves). Reads of these render as `this`, and the move
    /// itself emits nothing — instead of leaking an undeclared SSA name
    /// (`v0_1 = this; … v0_1.mState`). An entry is cleared the moment its
    /// register is overwritten with anything else (see the `declare_*` fns).
    this_aliases: HashSet<i64>,

    /// Branch-instruction index → the Java type of the compared register
    /// *as it stood at that instruction* (its reaching-def type), captured
    /// during the forward type scan. This is what makes the `== 0` → `== null`
    /// rewrite correct for *polymorphic* registers: a register reused as an
    /// `int` param and later as a `String` const collapses to one entry in
    /// `reg_types` (the last write wins), so a `if-eqz` on the int value would
    /// wrongly become `== null`. Keyed by the branch's instruction index so a
    /// register branched on more than once is resolved per-site.
    branch_operand_types: HashMap<usize, String>,
}

impl<'a> JavaGenerator<'a> {
    // ── Constructor ───────────────────────────────────────────────────────────

    pub fn new(method: &'a Method, dex: &'a ParsedDex, ssa: &'a SsaForm) -> Self {
        Self::new_with_filter(method, dex, ssa, MethodFilter::default())
    }

    /// Create a generator with a custom call-suppression filter.
    pub fn new_with_filter(
        method: &'a Method,
        dex:    &'a ParsedDex,
        ssa:    &'a SsaForm,
        filter: MethodFilter,
    ) -> Self {
        let ambiguous_simple = Self::compute_ambiguous_simple(dex);
        let mut gen = JavaGenerator {
            method,
            dex,
            ssa,
            reg_types:    HashMap::new(),
            namer:        JadxNamer::new(),
            pending_new:  HashMap::new(),
            pending_call:    None,
            declared:        HashSet::new(),
            declared_types:  HashMap::new(),
            imports:         HashSet::new(),
            ambiguous_simple,
            string_literals: HashMap::new(),
            filter,
            current_block: 0,
            branch_operand_types: HashMap::new(),
            this_aliases: HashSet::new(),
        };
        gen.infer_types_and_names();
        gen
    }

    /// Build the set of simple class names that map to more than one
    /// fully-qualified class among every type referenced by the DEX. These
    /// are the names that an `import` cannot disambiguate, so they must be
    /// rendered fully-qualified at every use site. Computed once per
    /// generator from `type_ids` (which enumerates every referenced type).
    fn compute_ambiguous_simple(dex: &ParsedDex) -> HashSet<String> {
        ambiguous_simple_names(dex.type_ids.iter().map(|t| t.type_name.as_str()))
    }

    /// Render a Dalvik type descriptor to its Java source form, fully
    /// qualifying any class whose simple name is ambiguous (see
    /// [`ambiguous_simple`]). Mirrors [`dalvik_type_to_java_owned`] for the
    /// unambiguous case so existing output is unchanged there.
    fn owned_type(&self, type_desc: &str) -> String {
        render_owned_type(type_desc, &self.ambiguous_simple)
    }

    // ── Type inference pass ───────────────────────────────────────────────────

    fn infer_types_and_names(&mut self) {
        let instrs_clone: Vec<Instruction> = self.method.instructions.clone();
        let (param_types, _) = parse_proto_desc(&self.method.proto_desc.clone());
        let is_static = self.method.is_static();
        let regs_size  = self.method.registers_size;
        let ins_size   = self.method.ins_size;
        let param_threshold = (regs_size as i64) - (ins_size as i64);

        // ── Seed parameter types ──────────────────────────────────────────────
        // p0 = `this` for instance methods (never printed as a typed local).
        // Wide types (long J, double D) occupy two consecutive registers.
        let param_start_offset: i64 = if is_static { 0 } else { 1 };
        let mut reg_offset = param_start_offset;
        for ty in &param_types {
            let reg = param_threshold + reg_offset;
            let java = self.owned_type(ty);
            self.collect_import(ty);
            self.reg_types.insert(reg, java.clone());
            self.namer.assign(reg, &java);
            // Mark the register as already-declared so subsequent
            // writes (e.g. check-cast in a bridge method) emit a
            // plain assignment instead of redeclaring the variable.
            // Without this, the bridge `evaluate(float, Object, Object)`
            // produces `Rect obj = (Rect) obj;` — invalid Java, since
            // `obj` is already a parameter name in the same scope.
            self.declared.insert(reg);
            self.declared_types.insert(reg, java.clone());
            // Wide types consume 2 registers.
            reg_offset += if ty == "J" || ty == "D" { 2 } else { 1 };
        }
        // The implicit `this` for instance methods sits at p0 (the
        // first param slot). Mark it declared too so any later
        // `move-object v, p0` etc. doesn't emit a `Foo this = …`.
        if !is_static {
            let this_reg = param_threshold;
            self.declared.insert(this_reg);
            // Type for `this` is the enclosing class; assigning to it
            // would be a no-op or a programmer error in Java source.
            self.declared_types.insert(this_reg,
                self.owned_type(&self.method.class_name));
        }

        // ── Forward scan ─────────────────────────────────────────────────────
        let mut idx = 0;
        while idx < instrs_clone.len() {
            let instr = &instrs_clone[idx];
            match instr.opcode {
                // const-string
                0x1a | 0x1b => {
                    if let Some(r) = instr.v_a {
                        self.reg_types.insert(r, "String".to_string());
                    }
                }
                // const/4..const-wide/high16
                0x12..=0x15 => {
                    if let Some(r) = instr.v_a {
                        self.reg_types.entry(r).or_insert_with(|| "int".to_string());
                    }
                }
                0x16..=0x19 => {
                    if let Some(r) = instr.v_a {
                        self.reg_types.entry(r).or_insert_with(|| "long".to_string());
                    }
                }
                // const-class
                0x1c => {
                    if let Some(r) = instr.v_a {
                        self.reg_types.insert(r, "Class".to_string());
                    }
                }
                // new-instance
                0x22 => {
                    if let Some(r) = instr.v_a {
                        if let Some(ti) = instr.v_b.and_then(|i| self.dex.type_ids.get(i as usize)) {
                            let java = self.owned_type(&ti.type_name.clone());
                            self.collect_import(&ti.type_name.clone());
                            self.reg_types.insert(r, java);
                        }
                    }
                }
                // new-array
                0x23 => {
                    if let Some(r) = instr.v_a {
                        if let Some(ti) = instr.v_c.and_then(|i| self.dex.type_ids.get(i as usize)) {
                            let java = self.owned_type(&ti.type_name.clone());
                            self.collect_import(&ti.type_name.clone());
                            self.reg_types.insert(r, java);
                        }
                    }
                }
                // check-cast
                0x1f => {
                    if let Some(r) = instr.v_a {
                        if let Some(ti) = instr.v_b.and_then(|i| self.dex.type_ids.get(i as usize)) {
                            let java = self.owned_type(&ti.type_name.clone());
                            self.collect_import(&ti.type_name.clone());
                            self.reg_types.insert(r, java);
                        }
                    }
                }
                // iget → field type
                0x52..=0x58 => {
                    if let Some(r) = instr.v_a {
                        if let Some(f) = instr.v_c.and_then(|fi| self.dex.field_ids.get(fi as usize)) {
                            let tn = f.type_name.clone();
                            let java = self.owned_type(&tn);
                            self.collect_import(&tn);
                            self.reg_types.insert(r, java);
                        }
                    }
                }
                // sget → field type
                0x60..=0x66 => {
                    if let Some(r) = instr.v_a {
                        if let Some(f) = instr.v_b.and_then(|fi| self.dex.field_ids.get(fi as usize)) {
                            let tn = f.type_name.clone();
                            let java = self.owned_type(&tn);
                            self.collect_import(&tn);
                            self.reg_types.insert(r, java);
                        }
                    }
                }
                // filled-new-array → look ahead for move-result-object
                0x24 | 0x25 => {
                    if idx + 1 < instrs_clone.len() {
                        let next = &instrs_clone[idx + 1];
                        if (0x0a..=0x0d).contains(&next.opcode) {
                            if let Some(dst) = next.v_a {
                                let type_idx = instr.v_b.unwrap_or(0) as usize;
                                if let Some(ti) = self.dex.type_ids.get(type_idx) {
                                    let java = self.owned_type(&ti.type_name.clone());
                                    self.collect_import(&ti.type_name.clone());
                                    self.reg_types.insert(dst, java);
                                }
                            }
                        }
                    }
                }
                // invoke → look ahead for move-result
                0x6e..=0x72 | 0x74..=0x78 => {
                    if idx + 1 < instrs_clone.len() {
                        let next = &instrs_clone[idx + 1];
                        if (0x0a..=0x0d).contains(&next.opcode) {
                            if let Some(dst) = next.v_a {
                                let m_idx = instr.v_b.unwrap_or(0) as usize;
                                if let Some(mi) = self.dex.method_ids.get(m_idx) {
                                    let pd = mi.proto_desc.clone();
                                    let (_, ret) = parse_proto_desc(&pd);
                                    if ret != "V" && !ret.is_empty() {
                                        let java = self.owned_type(&ret);
                                        self.collect_import(&ret);
                                        self.reg_types.insert(dst, java);
                                    }
                                }
                            }
                        }
                    }
                }
                // move — propagate source type to destination (if not already set)
                0x01..=0x09 => {
                    if let (Some(dst), Some(src)) = (instr.v_a, instr.v_b) {
                        if !self.reg_types.contains_key(&dst) {
                            if let Some(ty) = self.reg_types.get(&src).cloned() {
                                self.reg_types.insert(dst, ty);
                            }
                        }
                    }
                }
                // if-eqz / if-nez / if-ltz / … (one-register tests). Snapshot
                // the *current* (reaching-def) type of the compared register
                // here, before any later reuse of that register can overwrite
                // it. `translate_condition` consults this per-site type for the
                // `== 0` → `== null` / boolean rewrite. See `branch_operand_types`.
                0x38..=0x3d => {
                    if let Some(r) = instr.v_a {
                        if let Some(ty) = self.reg_types.get(&r) {
                            self.branch_operand_types.insert(idx, ty.clone());
                        }
                    }
                }
                _ => {}
            }
            idx += 1;
        }

        // ── Second propagation pass (handles move chains) ─────────────────────
        // Run a second pass so that chains like v0 = v1, v2 = v0 both get types.
        for instr in &instrs_clone {
            if (0x01..=0x09).contains(&instr.opcode) {
                if let (Some(dst), Some(src)) = (instr.v_a, instr.v_b) {
                    if !self.reg_types.contains_key(&dst) {
                        if let Some(ty) = self.reg_types.get(&src).cloned() {
                            self.reg_types.insert(dst, ty);
                        }
                    }
                }
            }
        }

        // ── Assign JADX names for locals in instruction order ─────────────────
        for instr in &instrs_clone {
            if let Some(r) = instr.v_a {
                if let Some(ty) = self.reg_types.get(&r).cloned() {
                    self.namer.assign(r, &ty);
                }
            }
        }
    }

    fn collect_import(&mut self, descriptor: &str) {
        // Find the base type (strip array prefix)
        let base = descriptor.trim_start_matches('[');
        if base.starts_with('L') && base.ends_with(';') {
            let inner = &base[1..base.len() - 1];
            if inner.starts_with("java/lang/") { return; } // auto-imported
            // Don't import the current class itself (self-references, e.g. a
            // static call `wfg.foo()` inside wfg.java).
            let self_inner = self.method.class_name
                .trim_start_matches('L').trim_end_matches(';');
            if inner == self_inner { return; }
            let simple = inner.rsplit('/').next().unwrap_or(inner);
            // Ambiguous simple names are rendered fully-qualified inline, so
            // importing one would be both redundant and (for the loser of the
            // collision) actively misleading. Skip them.
            if self.ambiguous_simple.contains(simple) { return; }
            self.imports.insert(inner.replace('/', "."));
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Sorted list of import statements collected during type inference.
    pub fn import_statements(&self) -> Vec<String> {
        let mut sorted: Vec<String> = self.imports.iter().cloned().collect();
        sorted.sort();
        sorted.iter().map(|s| format!("import {};", s)).collect()
    }

    /// Package name derived from the method's class descriptor.
    pub fn package_name(&self) -> String {
        class_package(&self.method.class_name)
    }

    /// Generate the complete method text (signature + `{` + body + `}`).
    pub fn gen_class_method(&mut self, ast: &AstNode) -> String {
        let sig  = self.format_method_signature();
        let body = self.gen_method_body(ast);
        format!("{} {{\n{}\n}}", sig, body)
    }

    /// Generate just the method body lines (handles try/catch wrapping).
    fn gen_method_body(&mut self, ast: &AstNode) -> String {
        // If the method has exception handlers, wrap body in try/catch.
        let has_try = !self.method.try_items.is_empty();

        if has_try {
            // Collect catch types from handlers.
            let mut catch_types: Vec<String> = Vec::new();
            for handler in &self.method.handlers {
                for h in &handler.handlers {
                    let ty = self.dex.type_ids
                        .get(h.type_idx as usize)
                        .map(|t| self.owned_type(&t.type_name))
                        .unwrap_or_else(|| "Exception".to_string());
                    if !catch_types.contains(&ty) {
                        catch_types.push(ty);
                    }
                }
                if handler.catch_all_addr.is_some() && !catch_types.iter().any(|t| t == "Exception") {
                    catch_types.push("Exception".to_string());
                }
            }
            if catch_types.is_empty() {
                catch_types.push("Exception".to_string());
            }

            // Body with indent 2
            let mut inner_lines = self.gen_node(ast, 2);
            compose_cast_chain(&mut inner_lines);
            collapse_return_of_temp(&mut inner_lines);
            let mut out = String::new();
            out.push_str("    try {");
            for line in &inner_lines {
                out.push('\n');
                out.push_str(line);
            }
            // Final pending_call flush
            if let Some((call_expr, _)) = self.pending_call.take() {
                out.push('\n');
                out.push_str(&format!("        {};", call_expr));
            }

            for catch_type in &catch_types {
                let var = catch_var_name(catch_type);
                out.push_str(&format!("\n    }} catch ({} {}) {{", catch_type, var));
                out.push_str(&format!("\n        {}.printStackTrace();", var));
            }
            out.push_str("\n    }");
            out
        } else {
            let mut lines = self.gen_node(ast, 1);
            compose_cast_chain(&mut lines);
            collapse_return_of_temp(&mut lines);
            strip_trailing_void_return(&mut lines, &self.method.proto_desc);
            lines.join("\n")
        }
    }

    /// Recursively generate indented lines for one AST node.
    pub fn gen_node(&mut self, node: &AstNode, indent: usize) -> Vec<String> {
        let pad = Self::pad(indent);
        match node {
            AstNode::Sequence(seq) => {
                let mut lines = Vec::new();
                let ids: Vec<usize> = if let Some(b) = seq.block {
                    vec![b]
                } else {
                    seq.blocks.clone()
                };
                for id in ids {
                    lines.extend(self.gen_block_instrs(id, indent));
                }
                lines
            }
            // A flat list of AST nodes: render each in order at the
            // same indent. This is what `prepend_ast` produces when an
            // if-statement (or while/loop) has a continuation that
            // follows the merge. The generator just concatenates;
            // there's no per-Compound chrome (braces, etc.) because
            // the constituent nodes already emit their own structure.
            AstNode::Compound(nodes) => {
                let mut lines = Vec::new();
                for n in nodes {
                    lines.extend(self.gen_node(n, indent));
                }
                lines
            }
            AstNode::If(if_node) => {
                let mut lines = Vec::new();
                lines.extend(self.gen_block_instrs(if_node.header, indent));
                let cond = self.translate_condition(&if_node.condition, Some(if_node.header));
                lines.push(format!("{}if ({}) {{", pad, cond));
                lines.extend(self.gen_node(&if_node.true_body, indent + 1));
                if let Some(false_body) = &if_node.false_body {
                    lines.push(format!("{}}} else {{", pad));
                    lines.extend(self.gen_node(false_body, indent + 1));
                }
                lines.push(format!("{}}}", pad));
                lines
            }
            AstNode::While(while_node) => {
                let mut lines = Vec::new();
                lines.extend(self.gen_block_instrs(while_node.header, indent));
                let cond = self.translate_condition(&while_node.condition, Some(while_node.header));
                lines.push(format!("{}while ({}) {{", pad, cond));
                lines.extend(self.gen_node(&while_node.body, indent + 1));
                lines.push(format!("{}}}", pad));
                lines
            }
            AstNode::DoWhile(do_while_node) => {
                let mut lines = Vec::new();
                lines.push(format!("{}do {{", pad));
                lines.extend(self.gen_node(&do_while_node.body, indent + 1));
                // DoWhileNode carries no header block, so we can't resolve a
                // per-site operand type — fall back to the reg_types cache.
                let cond = self.translate_condition(&do_while_node.condition, None);
                lines.push(format!("{}}} while ({});", pad, cond));
                lines
            }
            AstNode::Loop(loop_node) => {
                let mut lines = Vec::new();
                lines.extend(self.gen_block_instrs(loop_node.header, indent));
                lines.push(format!("{}while (true) {{", pad));
                lines.extend(self.gen_node(&loop_node.body, indent + 1));
                lines.push(format!("{}}}", pad));
                lines
            }
        }
    }

    /// Emit instructions for one basic block.
    pub fn gen_block_instrs(&mut self, block_id: usize, indent: usize) -> Vec<String> {
        self.current_block = block_id;
        let mut lines: Vec<String> = Vec::new();

        let cfg = match &self.method.cfg {
            Some(c) => c,
            None    => return lines,
        };
        let block = match cfg.blocks.get(block_id) {
            Some(b) => b,
            None    => return lines,
        };
        let indices: Vec<usize> = block.instr_indices.clone();

        for idx in indices {
            let instr = match self.method.instructions.get(idx) {
                Some(i) => i.clone(),
                None    => continue,
            };
            // Flush any pending call if this instruction is not a move-result.
            if !(0x0a..=0x0d).contains(&instr.opcode) {
                if let Some((call_expr, _)) = self.pending_call.take() {
                    lines.push(format!("{}{};", Self::pad(indent), call_expr));
                }
            }
            if let Some(line) = self.gen_instruction(&instr, indent) {
                lines.push(line);
            }
        }
        // Flush trailing pending_call (non-void invoke at end of block).
        if let Some((call_expr, _)) = self.pending_call.take() {
            lines.push(format!("{}{};", Self::pad(indent), call_expr));
        }

        lines
    }

    // ── Instruction generator ─────────────────────────────────────────────────

    pub fn gen_instruction(&mut self, instr: &Instruction, indent: usize) -> Option<String> {
        let pad = Self::pad(indent);

        match instr.opcode {
            0x00 => None,

            // ── move ──────────────────────────────────────────────────────────
            0x01..=0x09 => {
                let dst = instr.v_a?;
                // `move-object v, this` (or a move of an existing this-alias)
                // doesn't introduce a new variable — it just makes `v` another
                // name for `this`. Record the alias and emit nothing; reads of
                // `v` render as `this`. Without this the destination has no
                // inferred type and leaks an undeclared SSA name.
                let is_move_object = matches!(instr.opcode, 0x07 | 0x08 | 0x09);
                if is_move_object && !self.method.is_static() {
                    if let Some(src) = instr.v_b {
                        let this_reg = (self.method.registers_size as i64)
                            - (self.method.ins_size as i64);
                        if src == this_reg || self.this_aliases.contains(&src) {
                            self.string_literals.remove(&dst);
                            self.this_aliases.insert(dst);
                            return None;
                        }
                    }
                }
                let b = self.named_reg(instr.v_b);
                // If the destination has no inferred type, borrow the source's
                // (its current `reg_types`, else its last-declared type). This
                // keeps plain register-to-register moves from leaking an
                // undeclared SSA name (`v5_66 = f7;`).
                let a = if self.reg_types.contains_key(&dst) {
                    self.declare_dst(dst)
                } else {
                    let src_ty = instr.v_b.and_then(|s| {
                        self.reg_types.get(&s).cloned()
                            .or_else(|| self.declared_types.get(&s).cloned())
                    });
                    match src_ty {
                        Some(ty) => self.declare_dst_with_type(dst, &ty),
                        None     => self.declare_dst(dst),
                    }
                };
                Some(format!("{}{} = {};", pad, a, b))
            }

            // ── move-result — consumes pending_call ───────────────────────────
            0x0a..=0x0d => {
                let dst_reg = instr.v_a?;
                if let Some((call_expr, ret_type)) = self.pending_call.take() {
                    let java_type = self.owned_type(&ret_type);
                    let decl = self.declare_reg(dst_reg, &java_type);
                    Some(format!("{}{} = {};", pad, decl, call_expr))
                } else {
                    // pending_call was not set — the invoke was void, filtered, or
                    // the result was already flushed.  Use the inferred type so we
                    // at least get a typed variable declaration instead of a comment.
                    if let Some(ty) = self.reg_types.get(&dst_reg).cloned() {
                        let decl = self.declare_reg(dst_reg, &ty);
                        Some(format!("{}{}; // result unavailable", pad, decl))
                    } else {
                        None // nothing useful to emit
                    }
                }
            }

            // ── return ────────────────────────────────────────────────────────
            0x0e => Some(format!("{}return;", pad)),
            0x0f..=0x11 => {
                let a = self.named_reg(instr.v_a);
                Some(format!("{}return {};", pad, a))
            }

            // ── const ─────────────────────────────────────────────────────────
            0x12..=0x19 => {
                let dst = instr.v_a?;
                let val = instr.v_b.unwrap_or(0);
                let (ty, repr) = const_type_repr(instr.opcode, val);
                let decl = self.declare_reg(dst, ty);
                Some(format!("{}{} = {};", pad, decl, repr))
            }

            // ── const-string — stored for inline substitution ─────────────────
            // Instead of emitting `String str2 = "value";` we record the literal
            // and substitute it directly wherever the register is read.
            0x1a | 0x1b => {
                let dst = instr.v_a?;
                let idx = instr.v_b.unwrap_or(0) as usize;
                let s   = self.dex.strings.get(idx)
                    .map(|sd| sd.data.clone())
                    .unwrap_or_default();
                self.string_literals.insert(dst, s);
                None
            }

            // ── const-class ───────────────────────────────────────────────────
            0x1c => {
                let dst = instr.v_a?;
                let idx = instr.v_b.unwrap_or(0) as usize;
                let ty  = self.dex.type_ids.get(idx).map(|t| t.type_name.as_str()).unwrap_or("Object");
                let java = self.owned_type(ty);
                let decl = self.declare_reg(dst, "Class");
                Some(format!("{}{} = {}.class;", pad, decl, java))
            }

            // ── monitor ───────────────────────────────────────────────────────
            0x1d => Some(format!("{}// synchronized({})", pad, self.named_reg(instr.v_a))),
            0x1e => Some(format!("{}// end-synchronized", pad)),

            // ── check-cast ────────────────────────────────────────────────────
            0x1f => {
                let dst  = instr.v_a?;
                let idx  = instr.v_b.unwrap_or(0) as usize;
                let ty   = self.dex.type_ids.get(idx).map(|t| t.type_name.as_str()).unwrap_or("Object");
                let java = self.owned_type(ty);
                let orig = self.named_reg(Some(dst));
                let decl = self.declare_reg(dst, &java.clone());
                Some(format!("{}{} = ({}) {};", pad, decl, java, orig))
            }

            // ── instance-of ───────────────────────────────────────────────────
            0x20 => {
                let dst = instr.v_a?;
                let a   = self.declare_reg(dst, "boolean");
                let b   = self.named_reg(instr.v_b);
                let idx = instr.v_c.unwrap_or(0) as usize;
                let ty  = self.dex.type_ids.get(idx).map(|t| t.type_name.as_str()).unwrap_or("Object");
                let java = self.owned_type(ty);
                Some(format!("{}{} = {} instanceof {};", pad, a, b, java))
            }

            // ── array-length ──────────────────────────────────────────────────
            0x21 => {
                let dst = instr.v_a?;
                let a   = self.declare_reg(dst, "int");
                let b   = self.named_reg(instr.v_b);
                Some(format!("{}{} = {}.length;", pad, a, b))
            }

            // ── new-instance — deferred until invoke-direct/<init> ────────────
            0x22 => {
                let dst = instr.v_a?;
                let idx = instr.v_b.unwrap_or(0) as usize;
                if let Some(ti) = self.dex.type_ids.get(idx) {
                    let java = self.owned_type(&ti.type_name.clone());
                    self.pending_new.insert(dst, java);
                }
                None   // emitted when we see the matching <init>
            }

            // ── new-array ─────────────────────────────────────────────────────
            0x23 => {
                let dst     = instr.v_a?;
                let len_reg = self.named_reg(instr.v_b);
                let idx     = instr.v_c.unwrap_or(0) as usize;
                let ty      = self.dex.type_ids.get(idx).map(|t| t.type_name.as_str()).unwrap_or("[Object");
                let java    = self.owned_type(ty);
                let elem    = java.trim_end_matches("[]").to_string();
                let decl    = self.declare_reg(dst, &java.clone());
                Some(format!("{}{} = new {}[{}];", pad, decl, elem, len_reg))
            }

            // ── filled-new-array / filled-new-array-range ─────────────────────
            // Result is consumed by the next move-result-object, so we set
            // pending_call (same as a non-void invoke) and return None.
            0x24 | 0x25 => {
                let count    = instr.v_a.unwrap_or(0) as usize;
                let type_idx = instr.v_b.unwrap_or(0) as usize;
                let arr_desc = self.dex.type_ids.get(type_idx)
                    .map(|t| t.type_name.clone())
                    .unwrap_or_else(|| "[Ljava/lang/Object;".to_string());
                // Element type = strip one leading '[' from the array descriptor.
                let elem_desc = arr_desc.trim_start_matches('[');
                let elem_java = self.owned_type(elem_desc);
                self.collect_import(elem_desc);

                let args: Vec<String> = if instr.opcode == 0x24 {
                    // {vC, vD, vE, vF, vG}
                    let raw: &[Option<i64>] = &[
                        instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g,
                    ];
                    raw.iter().take(count)
                        .filter_map(|&r| r)
                        .map(|r| self.named_reg(Some(r)))
                        .collect()
                } else {
                    // range: vC .. vC+count-1
                    let first = instr.v_c.unwrap_or(0);
                    (0..count as i64)
                        .map(|i| self.named_reg(Some(first + i)))
                        .collect()
                };
                let expr = format!("new {}[]{{{}}}", elem_java, args.join(", "));
                self.pending_call = Some((expr, arr_desc));
                None
            }

            // ── fill-array-data ───────────────────────────────────────────────
            //
            // `fill-array-data vA, +off` fills the array in vA (from a preceding
            // `new-array`) with a payload table at `codepoint + off`. We resolve
            // the payload and re-assign the array with an initializer, e.g.
            // `bArr = new byte[]{1, 2, 3};`. The element type comes from the
            // array register's inferred type; the payload only carries the
            // element *width*.
            0x26 => {
                let dst = instr.v_a?;
                let name = self.named_reg(Some(dst));
                // Payload address = this instruction's codepoint + signed 32-bit
                // branch offset (the 31t format's B operand).
                let off = (instr.v_b.unwrap_or(0) as u32 as i32) as i64;
                let target = instr.codepoint as i64 + off;
                let payload = self.method.instructions.iter().find_map(|p| {
                    match &p.kind {
                        InstructionKind::FillArrayDataPayload { element_width, data, .. }
                            if p.codepoint as i64 == target =>
                            Some((*element_width as usize, data.clone())),
                        _ => None,
                    }
                });
                match payload {
                    Some((width, data)) => {
                        // The payload's element width is authoritative for the
                        // data layout. Trust the register's array type only when
                        // it's a genuine `T[]` whose element width matches —
                        // otherwise it's stale (a register reused for the array
                        // *and* a scalar collapses to e.g. "int"). Fall back to
                        // the width's natural type (1→byte, 2→short, 8→long,
                        // else int), which also keeps the assignment compiling
                        // against the `new-array`-declared variable.
                        let reg_elem = self.reg_types.get(&dst)
                            .filter(|t| t.ends_with("[]"))
                            .map(|t| t.trim_end_matches("[]").to_string());
                        let elem = match reg_elem {
                            Some(e) if java_prim_width(&e) == Some(width) => e,
                            _ => default_array_elem(width).to_string(),
                        };
                        let lits = array_data_literals(&elem, width, &data);
                        Some(format!("{}{} = new {}[]{{{}}};", pad, name, elem, lits.join(", ")))
                    }
                    None => Some(format!("{}// fill-array-data {} (payload not found)", pad, name)),
                }
            }

            // ── throw ─────────────────────────────────────────────────────────
            0x27 => {
                let a = self.named_reg(instr.v_a);
                Some(format!("{}throw {};", pad, a))
            }

            0x28..=0x2a => None,

            // ── switch ────────────────────────────────────────────────────────
            0x2b | 0x2c => {
                let a = self.named_reg(instr.v_a);
                Some(format!("{}switch ({}) {{ /* see table */ }}", pad, a))
            }

            // ── cmp ───────────────────────────────────────────────────────────
            0x2d..=0x31 => {
                let dst = instr.v_a?;
                let a   = self.declare_reg(dst, "int");
                let b   = self.named_reg(instr.v_b);
                let c   = self.named_reg(instr.v_c);
                let op  = match instr.opcode {
                    0x2d => "cmpl-float", 0x2e => "cmpg-float",
                    0x2f => "cmpl-double", 0x30 => "cmpg-double",
                    0x31 => "cmp-long", _ => "cmp",
                };
                Some(format!("{}{} = {} {} {} ? 1 : -1;", pad, a, b, op, c))
            }

            // ── if-* — absorbed by AST ────────────────────────────────────────
            0x32..=0x3d => None,

            // ── aget ──────────────────────────────────────────────────────────
            //
            // The destination holds an *element*, whose type is the array's
            // element type — not the array type. Crucially the array and the
            // destination are often the SAME register (`aget v0, v0, v1`), so
            // the array/index names are captured *before* declaring the
            // destination; declaring first would reassign that register's name
            // and corrupt the right-hand side (`int i = i[0];`).
            //
            // Declaring with the element type also fixes the polymorphic-param
            // case: an `int[]` parameter overwritten by its own element used to
            // emit `iArr = iArr[0];` (assigning an int to an int[] variable,
            // which doesn't compile). `declare_reg` mints a fresh int local
            // instead — `int i = iArr[0];`, later folded to `return iArr[0];`.
            0x44..=0x4a => {
                let dst  = instr.v_a?;
                let b    = self.named_reg(instr.v_b);
                let c    = self.named_reg(instr.v_c);
                let elem = self.aget_element_type(instr.opcode, instr.v_b);
                // When the destination *is* the array register (`aget v5, v5,
                // vN`), the element can never reuse the array's variable —
                // `x = x[i]` doesn't type-check for a 1-D array. `declare_reg`
                // only reassigns on a type *change*, which misses this case
                // when the recorded type already equals the element type, so
                // force a fresh local here.
                if instr.v_b == Some(dst) {
                    self.namer.reassign(dst, &elem);
                    self.declared.remove(&dst);
                }
                let a = self.declare_reg(dst, &elem);
                Some(format!("{}{} = {}[{}];", pad, a, b, c))
            }
            // ── aput ──────────────────────────────────────────────────────────
            0x4b..=0x51 => {
                let a = self.named_reg(instr.v_a);
                let b = self.named_reg(instr.v_b);
                let c = self.named_reg(instr.v_c);
                Some(format!("{}{}[{}] = {};", pad, b, c, a))
            }

            // ── iget ──────────────────────────────────────────────────────────
            //
            // We pull the field's actual type from the field_id table
            // and pass it to `declare_dst_with_type` so the declared
            // variable matches the *value* it holds, not whatever the
            // destination register happened to hold last. Without this,
            // a register that's later reused for a different-typed iget
            // (e.g. v4 holds an int from `iget v4, …, left:I` and later
            // an object from `iget-object v4, …, mRect:LRect;`) ends up
            // declaring the FIRST use with the LAST type — producing
            // `Rect rect3 = rect.left;` when `rect.left` is an int.
            0x52..=0x58 => {
                let dst   = instr.v_a?;
                let b     = self.named_reg(instr.v_b);
                let f_idx = instr.v_c.unwrap_or(0) as usize;
                let (fname, ftype) = self.dex.field_ids.get(f_idx)
                    .map(|f| (
                        f.field_name.clone(),
                        self.owned_type(&f.type_name),
                    ))
                    .unwrap_or_else(|| ("field".to_string(), "Object".to_string()));
                let a = self.declare_dst_with_type(dst, &ftype);
                Some(format!("{}{} = {}.{};", pad, a, b, fname))
            }
            // ── iput ──────────────────────────────────────────────────────────
            0x59..=0x5f => {
                let a     = self.named_reg(instr.v_a);
                let b     = self.named_reg(instr.v_b);
                let f_idx = instr.v_c.unwrap_or(0) as usize;
                let fname = self.dex.field_ids.get(f_idx)
                    .map(|f| f.field_name.as_str()).unwrap_or("field");
                Some(format!("{}{}.{} = {};", pad, b, fname, a))
            }

            // ── sget ──────────────────────────────────────────────────────────
            //
            // Same reasoning as iget: pull the field's actual type from
            // its FieldIdItem and declare the dest with that, not with
            // whatever reg_types happened to last record for this reg.
            0x60..=0x66 => {
                let dst   = instr.v_a?;
                let f_idx = instr.v_b.unwrap_or(0) as usize;
                let (class, fname, ftype) = self.dex.field_ids.get(f_idx)
                    .map(|f| (
                        self.owned_type(&f.class_name),
                        f.field_name.clone(),
                        self.owned_type(&f.type_name),
                    ))
                    .unwrap_or_else(|| ("Class".to_string(), "field".to_string(), "Object".to_string()));
                let a = self.declare_dst_with_type(dst, &ftype);
                Some(format!("{}{} = {}.{};", pad, a, class, fname))
            }
            // ── sput ──────────────────────────────────────────────────────────
            0x67..=0x6d => {
                let a     = self.named_reg(instr.v_a);
                let f_idx = instr.v_b.unwrap_or(0) as usize;
                let (class, fname) = self.dex.field_ids.get(f_idx)
                    .map(|f| (self.owned_type(&f.class_name), f.field_name.clone()))
                    .unwrap_or_else(|| ("Class".to_string(), "field".to_string()));
                Some(format!("{}{}.{} = {};", pad, class, fname, a))
            }

            // ── invoke ────────────────────────────────────────────────────────
            0x6e..=0x72 => {
                let arg_count = instr.v_a.unwrap_or(0) as usize;
                let m_idx     = instr.v_b.unwrap_or(0) as usize;
                let raw: &[Option<i64>] = &[instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g];
                let raw_regs: Vec<i64>  = raw.iter().take(arg_count).filter_map(|&r| r).collect();
                self.gen_invoke(instr.opcode, m_idx, &raw_regs, indent)
            }
            // ── invoke-range ──────────────────────────────────────────────────
            0x74..=0x78 => {
                let arg_count = instr.v_a.unwrap_or(0) as usize;
                let m_idx     = instr.v_b.unwrap_or(0) as usize;
                let first     = instr.v_c.unwrap_or(0);
                let raw_regs: Vec<i64> = (0..arg_count as i64).map(|i| first + i).collect();
                self.gen_invoke(instr.opcode, m_idx, &raw_regs, indent)
            }

            // ── unary ─────────────────────────────────────────────────────────
            //
            // neg/not and the numeric conversions (`int-to-long`, …) all have
            // a result type fixed by the opcode. Declare the destination with
            // it — otherwise `declare_dst` finds no type and leaks an
            // undeclared SSA name (`v0_2 = (long)i;`).
            0x7b..=0x8f => {
                let dst = instr.v_a?;
                let ty  = unary_result_type(instr.opcode);
                let a   = self.declare_dst_with_type(dst, ty);
                let b   = self.named_reg(instr.v_b);
                let op  = unary_op_str(instr.opcode);
                Some(format!("{}{} = {}{};", pad, a, op, b))
            }

            // ── binary 3-reg ──────────────────────────────────────────────────
            //
            // We explicitly declare with the type implied by the
            // opcode (e.g. `add-int` → `int`). Without this, binop
            // destinations land in `named_reg`'s SSA fallback and
            // leak names like `v1_11`, `v3_19` into the output
            // because nothing else in the forward scan typed them.
            0x90..=0xaf => {
                let dst = instr.v_a?;
                let ty  = binop_result_type(instr.opcode);
                let a   = self.declare_dst_with_type(dst, ty);
                let b   = self.named_reg(instr.v_b);
                let c   = self.named_reg(instr.v_c);
                let op  = binary_op_str(instr.opcode, false);
                Some(format!("{}{} = {} {} {};", pad, a, b, op, c))
            }

            // ── binary 2addr — in-place update, no new declaration needed ─────
            0xb0..=0xcf => {
                let a  = self.named_reg(instr.v_a);
                let b  = self.named_reg(instr.v_b);
                let op = binary_op_str(instr.opcode, true);
                Some(format!("{}{} {}= {};", pad, a, op, b))
            }

            // ── binary lit ────────────────────────────────────────────────────
            //
            // Every `*-int/lit{8,16}` op (add/rsub/mul/div/rem/and/or/xor/
            // shl/shr/ushr) yields an `int`. Declare the destination with that
            // type explicitly: `declare_dst` alone finds no `reg_types` entry
            // (the forward scan doesn't type arithmetic results) and falls
            // through to `named_reg`'s SSA fallback, leaking undeclared names
            // like `v1_5 = i & 1;` into the output.
            0xd0..=0xe2 => {
                let dst = instr.v_a?;
                let a   = self.declare_dst_with_type(dst, "int");
                let b   = self.named_reg(instr.v_b);
                let lit = instr.v_c.unwrap_or(0);
                let op  = binlit_op_str(instr.opcode);
                Some(format!("{}{} = {} {} {};", pad, a, b, op, lit))
            }

            _ => Some(format!("{}// unhandled opcode 0x{:02x}: {}",
                pad, instr.opcode, instr.instruction_str)),
        }
    }

    // ── Invoke helper ─────────────────────────────────────────────────────────

    /// Generate an invoke-* line.  Takes raw register numbers so that we can
    /// detect new-instance + `<init>` patterns before doing name lookups.
    fn gen_invoke(
        &mut self,
        opcode:   u8,
        m_idx:    usize,
        raw_regs: &[i64],
        indent:   usize,
    ) -> Option<String> {
        let pad = Self::pad(indent);

        let method_info = self.dex.method_ids.get(m_idx);
        let (class_name, method_name, proto_desc) = method_info
            .map(|mi| (mi.class_name.as_str(), mi.method_name.as_str(), mi.proto_desc.as_str()))
            .unwrap_or(("UnknownClass", "unknownMethod", "()V"));

        // ── Dynamic call-suppression filter ──────────────────────────────────
        if self.filter.is_suppressed(class_name, method_name) {
            return None;
        }

        // The invoke owner is printed for static calls (`Owner.method(...)`).
        // Collect its import so the simple name resolves — previously this was
        // skipped entirely, leaving cross-package static calls with no import
        // (and, when another same-named class was imported, pointing at the
        // wrong class). `collect_import` no-ops for java.lang and ambiguous
        // names (the latter are rendered fully-qualified by `owned_type`).
        let class_owner = class_name.to_string();
        self.collect_import(&class_owner);
        let java_class = self.owned_type(class_name);
        let (_, ret_desc) = parse_proto_desc(proto_desc);
        let is_void = ret_desc == "V" || ret_desc.is_empty();

        // ── Check for new-instance + <init> collapsing ────────────────────────
        if (opcode == 0x70 || opcode == 0x76) && method_name == "<init>" {
            if let Some(&recv_raw) = raw_regs.first() {
                if let Some(pending_type) = self.pending_new.remove(&recv_raw) {
                    let ctor_args = self.build_call_args(
                        raw_regs.get(1..).unwrap_or(&[]), proto_desc);
                    let decl = self.declare_reg(recv_raw, &pending_type.clone());
                    return Some(format!("{}{} = new {}({});",
                        pad, decl, pending_type, ctor_args.join(", ")));
                }
            }
        }

        // ── <init> as super() or this() ────────────────────────────────────
        //
        // An `invoke-direct <init>` that *isn't* paired with a fresh
        // new-instance is a constructor delegation: either a super
        // call (target class != this class) or a `this(...)` delegating
        // constructor (target class == this class). The pre-fix code
        // emitted `this.<init>(args)` literally, which is not valid
        // Java and confuses anyone reading the output.
        //
        // We compare by normalised class descriptor; we don't have the
        // resolved superclass at this layer, but the heuristic
        // "target != self ⇒ super" is correct for every Dalvik
        // constructor (the verifier rejects cross-class <init> calls
        // that aren't either super or this).
        if (opcode == 0x70 || opcode == 0x76) && method_name == "<init>" {
            let ctor_args = self.build_call_args(
                raw_regs.get(1..).unwrap_or(&[]), proto_desc);
            let kw = if class_name == self.method.class_name { "this" } else { "super" };
            return Some(format!("{}{}({});", pad, kw, ctor_args.join(", ")));
        }

        // ── Build call expression ─────────────────────────────────────────────
        let call_expr = match opcode {
            // invoke-static / invoke-static-range
            0x71 | 0x77 => {
                let args = self.build_call_args(raw_regs, proto_desc);
                format!("{}.{}({})", java_class, method_name, args.join(", "))
            }
            // invoke-direct / invoke-direct-range (non-<init> case)
            0x70 | 0x76 => {
                let recv = raw_regs.first()
                    .map(|&r| self.named_reg(Some(r)))
                    .unwrap_or_else(|| "this".to_string());
                let args = self.build_call_args(raw_regs.get(1..).unwrap_or(&[]), proto_desc);
                format!("{}.{}({})", recv, method_name, args.join(", "))
            }
            // invoke-super / invoke-super-range
            0x6f | 0x75 => {
                let args = self.build_call_args(raw_regs.get(1..).unwrap_or(&[]), proto_desc);
                format!("super.{}({})", method_name, args.join(", "))
            }
            // invoke-virtual / invoke-interface (and range variants)
            _ => {
                let recv = raw_regs.first()
                    .map(|&r| self.named_reg(Some(r)))
                    .unwrap_or_else(|| "this".to_string());
                let args = self.build_call_args(raw_regs.get(1..).unwrap_or(&[]), proto_desc);
                format!("{}.{}({})", recv, method_name, args.join(", "))
            }
        };

        if is_void {
            Some(format!("{}{};", pad, call_expr))
        } else {
            // Defer output: the following move-result will emit the typed declaration.
            self.pending_call = Some((call_expr, ret_desc));
            None
        }
    }

    // ── Register helpers ──────────────────────────────────────────────────────

    /// Build a call's argument list from the parameter registers and the
    /// callee's proto descriptor, collapsing wide (`long`/`double`) arguments.
    ///
    /// In a non-range `invoke`, a wide argument occupies *two* consecutive
    /// registers (the value's low and high halves), both listed explicitly in
    /// the instruction. Naively mapping each register to a name emits a phantom
    /// second argument from the high half (`Math.sqrt(d3, v5_66)`), which also
    /// leaks an undeclared SSA name. Walking the proto lets us consume two
    /// registers per wide param and emit only the low half.
    ///
    /// If the proto can't account for every register (parse failure or
    /// mismatch), the remaining registers are appended verbatim — degrading to
    /// the old one-name-per-register behaviour rather than dropping real args.
    fn build_call_args(&self, param_regs: &[i64], proto_desc: &str) -> Vec<String> {
        let (params, _) = parse_proto_desc(proto_desc);
        let mut args = Vec::with_capacity(param_regs.len());
        let mut i = 0;
        for p in &params {
            if i >= param_regs.len() { break; }
            args.push(self.named_reg(Some(param_regs[i])));
            i += if p == "J" || p == "D" { 2 } else { 1 };
        }
        while i < param_regs.len() {
            args.push(self.named_reg(Some(param_regs[i])));
            i += 1;
        }
        args
    }

    /// Return the value for a register:
    ///  • If it holds a const-string literal, returns the quoted string directly.
    ///  • Otherwise returns the JADX name (or SSA / raw fallback).
    fn named_reg(&self, r: Option<i64>) -> String {
        let reg = match r {
            Some(v) => v,
            None    => return "null".to_string(),
        };
        // Inline string literals at point of use.
        if let Some(s) = self.string_literals.get(&reg) {
            return format!("\"{}\"", escape_java_string(s));
        }
        // `this` for instance receiver (p0).
        if !self.method.is_static() && self.method.ins_size > 0 {
            let threshold = (self.method.registers_size as i64) - (self.method.ins_size as i64);
            if reg == threshold { return "this".to_string(); }
        }
        // A register aliased to `this` via `move-object` reads as `this`.
        if self.this_aliases.contains(&reg) {
            return "this".to_string();
        }
        if let Some(name) = self.namer.get(reg) {
            return name.to_string();
        }
        // SSA fallback.
        if let Some(&ver) = self.ssa.versions.get(&(self.current_block, reg)) {
            return SsaForm::compute_name(reg, ver, self.ssa.registers_size, self.ssa.ins_size);
        }
        // Raw fallback.
        let threshold = (self.ssa.registers_size as i64) - (self.ssa.ins_size as i64);
        if reg >= threshold {
            format!("p{}", reg - threshold)
        } else {
            format!("v{}", reg)
        }
    }

    /// Like [`declare_dst`] but takes an explicit type from the
    /// caller. Used by iget/sget where the field's actual type is
    /// known and trusted more than the per-register `reg_types`
    /// cache (which can be stale if the register was reused with a
    /// different type across the method body).
    ///
    /// Also overrides `reg_types[reg]` with the new type so any
    /// downstream code that reads it (e.g. the later namer pass)
    /// sees consistent information.
    fn declare_dst_with_type(&mut self, reg: i64, java_type: &str) -> String {
        self.string_literals.remove(&reg);
        // Overwriting the register breaks any `this` aliasing it held.
        self.this_aliases.remove(&reg);
        let param_threshold = (self.method.registers_size as i64) - (self.method.ins_size as i64);
        if reg >= param_threshold {
            self.declared.insert(reg);
            return self.named_reg(Some(reg));
        }
        // Force a name re-assignment when the pre-baked namer name
        // doesn't match `java_type`. The forward-scan namer pass
        // can pre-assign a register based on the LAST type it saw
        // (e.g. v4 ends up named "rect3" because a late
        // `iget-object v4, ..., mRect:LRect;` overwrote the earlier
        // int uses); without this we'd correctly declare the type
        // but still emit the misleading name ("int rect3 = …").
        // Comparison is by `jadx_base` prefix: "int" → "i", "Rect"
        // → "rect"; mismatch ⇒ reassign.
        if !self.declared.contains(&reg) {
            let new_base = jadx_base(java_type);
            if let Some(existing) = self.namer.get(reg) {
                let existing_base: String = existing.chars()
                    .take_while(|c| !c.is_ascii_digit())
                    .collect();
                let want_base = if new_base.is_empty() {
                    class_to_var(java_type)
                } else {
                    new_base.to_string()
                };
                if existing_base != want_base {
                    self.namer.reassign(reg, java_type);
                }
            }
        }
        // Refresh the cached type so subsequent declare_dst() calls
        // (without an explicit type) on the same register get the
        // right answer too.
        self.reg_types.insert(reg, java_type.to_string());
        self.declare_reg(reg, java_type)
    }

    /// Element type of an array-typed register, derived from its inferred Java
    /// type (`int[]` → `int`, `String[]` → `String`). Returns `None` when the
    /// register's type is unknown or isn't an array, so the caller can fall
    /// back to its default declaration path.
    fn array_element_type(&self, reg: Option<i64>) -> Option<String> {
        let r  = reg?;
        let ty = self.reg_types.get(&r)?;
        ty.strip_suffix("[]").map(|s| s.to_string())
    }

    /// The element type an `aget*` instruction reads, used to declare its
    /// destination. Prefers the precise element type of the array register
    /// when known (`int[]` → `int`, `String[]` → `String`); otherwise falls
    /// back to the category implied by the opcode variant. In real bytecode
    /// the array register's tracked type is frequently *not* an array (it came
    /// from a method return, field, or was reused), so the opcode-derived
    /// fallback is what fixes most `xArr = xArr[i];` (int-into-array-var) bugs.
    fn aget_element_type(&self, opcode: u8, array_reg: Option<i64>) -> String {
        if let Some(elem) = self.array_element_type(array_reg) {
            return elem;
        }
        match opcode {
            0x45 => "long",    // aget-wide   (long or double; long width is safe)
            0x46 => "Object",  // aget-object (element class unknown)
            0x47 => "boolean", // aget-boolean
            0x48 => "byte",    // aget-byte
            0x49 => "char",    // aget-char
            0x4a => "short",   // aget-short
            _    => "int",     // 0x44 aget   (int or float)
        }
        .to_string()
    }

    /// Declare the destination register using the type already inferred for it.
    /// Parameter registers (p0..pN in the method signature) are never re-declared
    /// inside the method body.  Falls back to `named_reg` if no type is known.
    fn declare_dst(&mut self, reg: i64) -> String {
        // A write to this register invalidates any previous string literal.
        self.string_literals.remove(&reg);
        // Overwriting the register breaks any `this` aliasing it held.
        self.this_aliases.remove(&reg);
        // Treat parameter registers as already declared.
        let param_threshold = (self.method.registers_size as i64) - (self.method.ins_size as i64);
        if reg >= param_threshold {
            // Mark as declared so subsequent writes also skip the type prefix.
            self.declared.insert(reg);
            return self.named_reg(Some(reg));
        }
        if let Some(ty) = self.reg_types.get(&reg).cloned() {
            self.declare_reg(reg, &ty)
        } else {
            self.named_reg(Some(reg))
        }
    }

    /// Emit `"JavaType name"` on first declaration, or just `"name"` afterwards.
    ///
    /// If the register was previously declared with a *different* type (register
    /// reuse), the old name is retired and a fresh JADX name is allocated for
    /// the new type so we never emit `boolean x = new Intent(...)`.
    fn declare_reg(&mut self, reg: i64, java_type: &str) -> String {
        // A write to this register invalidates any previous string literal.
        self.string_literals.remove(&reg);
        // Overwriting the register breaks any `this` aliasing it held.
        self.this_aliases.remove(&reg);

        // If the type changed since last declaration, force a fresh variable name.
        if let Some(prev) = self.declared_types.get(&reg) {
            if prev.as_str() != java_type {
                let name = self.namer.reassign(reg, java_type);
                self.declared.remove(&reg);
                self.declared.insert(reg);
                self.declared_types.insert(reg, java_type.to_string());
                return format!("{} {}", java_type, name);
            }
        }

        let name = if let Some(n) = self.namer.get(reg) {
            n.to_string()
        } else {
            self.namer.assign(reg, java_type)
        };
        if self.declared.insert(reg) {
            self.declared_types.insert(reg, java_type.to_string());
            format!("{} {}", java_type, name)
        } else {
            name
        }
    }

    // ── Type helpers ──────────────────────────────────────────────────────────

    pub fn dalvik_type_to_java(type_desc: &str) -> &str {
        match type_desc {
            "I" => "int",   "J" => "long",  "F" => "float",  "D" => "double",
            "Z" => "boolean","B" => "byte", "S" => "short",  "C" => "char",  "V" => "void",
            "[I" => "int[]","[J" => "long[]","[F" => "float[]","[D" => "double[]",
            "[Z" => "boolean[]","[B" => "byte[]","[S" => "short[]","[C" => "char[]",
            "Ljava/lang/String;" => "String",
            "Ljava/lang/Object;" => "Object",
            _ => type_desc,
        }
    }

    pub fn dalvik_type_to_java_owned(type_desc: &str) -> String {
        let quick = Self::dalvik_type_to_java(type_desc);
        if quick != type_desc { return quick.to_string(); }
        if let Some(rest) = type_desc.strip_prefix('[') {
            return format!("{}[]", Self::dalvik_type_to_java_owned(rest));
        }
        if type_desc.starts_with('L') && type_desc.ends_with(';') {
            let inner = &type_desc[1..type_desc.len() - 1];
            let simple = inner.rsplit('/').next().unwrap_or(inner);
            return simple.replace('$', ".");
        }
        type_desc.to_string()
    }

    // ── Signature ─────────────────────────────────────────────────────────────

    pub fn format_method_signature(&self) -> String {
        let m = self.method;
        let mut flags: Vec<&str> = Vec::new();
        for flag in &m.access_flags {
            let kw = match flag {
                MethodAccessFlag::Public    => "public",
                MethodAccessFlag::Private   => "private",
                MethodAccessFlag::Protected => "protected",
                MethodAccessFlag::Static    => "static",
                MethodAccessFlag::Final     => "final",
                MethodAccessFlag::Synchronized | MethodAccessFlag::DeclaredSynchronized => "synchronized",
                MethodAccessFlag::Native    => "native",
                MethodAccessFlag::Abstract  => "abstract",
                MethodAccessFlag::Strict    => "strictfp",
                MethodAccessFlag::Synthetic => "/* synthetic */",
                MethodAccessFlag::Bridge    => "/* bridge */",
                MethodAccessFlag::Varargs   => "/* varargs */",
                MethodAccessFlag::Constructor => "",
            };
            if !kw.is_empty() { flags.push(kw); }
        }
        flags.dedup();
        let access = flags.join(" ");

        let (param_types, ret_desc) = parse_proto_desc(&m.proto_desc);
        let ret_java = self.owned_type(&ret_desc);

        let is_constructor = m.method_name == "<init>"
            || m.access_flags.contains(&MethodAccessFlag::Constructor);
        let display_name = if is_constructor {
            // Constructor names are always the bare simple name, never
            // qualified — even when the class name is ambiguous file-wide.
            Self::dalvik_type_to_java_owned(&m.class_name)
        } else {
            m.method_name.clone()
        };

        let is_static      = m.access_flags.contains(&MethodAccessFlag::Static);
        let param_start_p  = if is_static { 0usize } else { 1usize };
        let param_threshold = (m.registers_size as i64) - (m.ins_size as i64);

        let mut params: Vec<String> = Vec::new();
        let mut sig_reg_offset = param_start_p as i64;
        for (param_idx, type_desc) in param_types.iter().enumerate() {
            let reg  = param_threshold + sig_reg_offset;
            let ty   = self.owned_type(type_desc);
            let name = self.namer.get(reg)
                .map(|n| n.to_string())
                .unwrap_or_else(|| format!("p{}", sig_reg_offset));
            // Inline parameter annotations (e.g. `@Nullable String x`).
            // The lookup is by *parameter position* (0-based), not by
            // register index — wide-param register offsets are
            // handled by the wide-arg-advance below.
            let ann_prefix = m.param_annotations.get(param_idx)
                .map(|anns| format_inline_param_annotations(anns))
                .unwrap_or_default();
            params.push(format!("{}{} {}", ann_prefix, ty, name));
            sig_reg_offset += if type_desc == "J" || type_desc == "D" { 2 } else { 1 };
        }
        let params_str = params.join(", ");

        if is_constructor {
            if access.is_empty() {
                format!("{}({})", display_name, params_str)
            } else {
                format!("{} {}({})", access, display_name, params_str)
            }
        } else if access.is_empty() {
            format!("{} {}({})", ret_java, display_name, params_str)
        } else {
            format!("{} {} {}({})", access, ret_java, display_name, params_str)
        }
    }

    fn pad(level: usize) -> String { "    ".repeat(level) }

    /// The reaching-def type of the register compared by the branch that
    /// terminates `header_block`, if that branch is a one-register `if-Xz`
    /// test. Prefers the per-site snapshot (`branch_operand_types`) which is
    /// correct for polymorphic registers; returns `None` when the header is
    /// unknown or its terminator isn't a zero-test.
    fn branch_operand_type(&self, header_block: Option<usize>) -> Option<&str> {
        let block = header_block?;
        let cfg = self.method.cfg.as_ref()?;
        let &last_idx = cfg.blocks.get(block)?.instr_indices.last()?;
        self.branch_operand_types.get(&last_idx).map(|s| s.as_str())
    }

    /// Translate raw register name tokens (`p0`, `v3`, `v3_1`) in a condition
    /// string to JADX names where possible.
    ///
    /// `header_block` is the CFG block whose terminator produced this
    /// condition (when known); it lets the `== 0` rewrite use the *reaching*
    /// type of the compared register rather than the last-write type cached
    /// in `reg_types`, which is wrong when the register is reused for a
    /// different type elsewhere in the method.
    fn translate_condition(&self, expr: &str, header_block: Option<usize>) -> String {
        let threshold = (self.method.registers_size as i64) - (self.method.ins_size as i64);
        let chars: Vec<char> = expr.chars().collect();
        let mut result = String::new();
        // Remember the LAST register we substituted; we use this for
        // the null-comparison post-pass below. (The string may contain
        // multiple register references for 2-arg ifs; we only care
        // about the LHS of a `== 0` / `!= 0` comparison, which is by
        // construction the only register in a 1-arg `if-Xz` condition.)
        let mut last_subst_reg: Option<i64> = None;
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            // A register token starts with 'p' or 'v', preceded by a non-identifier char
            // (or the start of string).
            let at_word_start = i == 0
                || (!chars[i - 1].is_alphanumeric() && chars[i - 1] != '_');
            if (c == 'p' || c == 'v') && at_word_start {
                // Collect the base digits.
                let mut j = i + 1;
                while j < chars.len() && chars[j].is_ascii_digit() { j += 1; }
                let base_end = j;
                // Optional SSA version suffix: _<digits>
                if j < chars.len() && chars[j] == '_' && j + 1 < chars.len()
                    && chars[j + 1].is_ascii_digit()
                {
                    j += 1;
                    while j < chars.len() && chars[j].is_ascii_digit() { j += 1; }
                }
                // Only treat it as a register token if it ends at a word boundary.
                let at_word_end = j >= chars.len()
                    || (!chars[j].is_alphanumeric() && chars[j] != '_');
                if base_end > i + 1 && at_word_end {
                    let num_str: String = chars[i + 1..base_end].iter().collect();
                    if let Ok(num) = num_str.parse::<i64>() {
                        let reg = if c == 'p' { threshold + num } else { num };
                        if let Some(name) = self.namer.get(reg) {
                            result.push_str(name);
                            last_subst_reg = Some(reg);
                            i = j;
                            continue;
                        }
                    }
                }
            }
            result.push(c);
            i += 1;
        }

        // Post-pass: rewrite the tail `... == 0` / `... != 0` based on the
        // type of the compared register. Prefer the per-site reaching-def
        // type captured at the branch (correct for polymorphic registers);
        // fall back to the last-write `reg_types` cache only when no snapshot
        // exists (e.g. the condition came from somewhere without a header).
        if let Some(ty) = self.branch_operand_type(header_block) {
            return rewrite_zero_comparison(&result, ty);
        }
        if let Some(reg) = last_subst_reg {
            if let Some(ty) = self.reg_types.get(&reg) {
                return rewrite_zero_comparison(&result, ty);
            }
        }

        result
    }
}

/// Rewrite the trailing zero-comparison in a condition expression based
/// on the type of the compared register.
///
/// * **Object types**: `name == 0` → `name == null`,
///   `name != 0` → `name != null`. Comparing a reference against the
///   integer literal `0` is not valid Java.
///
/// * **Boolean types**: `name != 0` → `name`,
///   `name == 0` → `!name`. The literal-zero form is technically legal
///   in Dalvik (booleans live in int registers) but reads as if someone
///   confused C and Java.
///
/// * **All other primitives**: leave alone — integer comparisons
///   against `0` are idiomatic.
///
/// The function does an exact suffix match against ` == 0` / ` != 0`;
/// nothing else is touched. The "stripped" portion is treated as a
/// single identifier (which it always is in practice — `extract_condition`
/// only emits `<reg> == 0` shape for one-arg `if-Xz` opcodes).
fn rewrite_zero_comparison(expr: &str, ty: &str) -> String {
    if is_object_type(ty) {
        for op in &[" == 0", " != 0"] {
            if let Some(stripped) = expr.strip_suffix(op) {
                return format!("{}{} null", stripped, &op[..3]);
            }
        }
    } else if ty == "boolean" {
        if let Some(stripped) = expr.strip_suffix(" != 0") {
            return stripped.to_string();
        }
        if let Some(stripped) = expr.strip_suffix(" == 0") {
            return format!("!{}", stripped);
        }
    }
    expr.to_string()
}

/// Render an annotation list as a single inline string suitable for
/// splatting before a parameter type in a method signature:
/// `@Nullable @Validated `  (trailing space so the caller can
/// concatenate directly with the type). Empty list returns empty
/// string.
///
/// The single-element-named-"value" shorthand is honoured here too —
/// `@SuppressWarnings("x")` instead of `@SuppressWarnings(value="x")`.
fn format_inline_param_annotations(
    anns: &[platypus_dex::parser::AnnotationItem],
) -> String {
    if anns.is_empty() { return String::new(); }
    let mut out = String::new();
    for ann in anns {
        // Use the same logical translation as
        // `JavaGenerator::dalvik_type_to_java_owned` so the rendered
        // annotation name matches the rest of the codegen.
        let name = JavaGenerator::dalvik_type_to_java_owned(&ann.type_name);
        if ann.elements.is_empty() {
            out.push_str(&format!("@{} ", name));
        } else if ann.elements.len() == 1 && ann.elements[0].0 == "value" {
            out.push_str(&format!("@{}({}) ", name, ann.elements[0].1));
        } else {
            let parts: Vec<String> = ann.elements.iter()
                .map(|(k, v)| format!("{} = {}", k, v))
                .collect();
            out.push_str(&format!("@{}({}) ", name, parts.join(", ")));
        }
    }
    out
}

/// Does this Java type represent a reference (object) rather than a primitive?
///
/// Used by `translate_condition` to substitute `null` for `0` in if-eqz / if-nez
/// comparisons. Primitives stay as `0`; arrays and class types become `null`.
fn is_object_type(java_type: &str) -> bool {
    !matches!(java_type,
        "int" | "long" | "float" | "double"
        | "boolean" | "byte" | "char" | "short"
        | "void"
    )
}

// ── Module-level helpers ──────────────────────────────────────────────────────

/// Given every type descriptor referenced by a DEX, return the set of simple
/// class names (last path segment) shared by more than one fully-qualified
/// class. These names cannot be disambiguated by an `import` (Java allows only
/// one import per simple name), so each reference to such a class must be
/// rendered fully-qualified. Array prefixes are stripped; primitives ignored.
pub fn ambiguous_simple_names<'a>(
    type_descriptors: impl Iterator<Item = &'a str>,
) -> HashSet<String> {
    let mut by_simple: HashMap<String, HashSet<String>> = HashMap::new();
    for desc in type_descriptors {
        let base = desc.trim_start_matches('[');
        if base.starts_with('L') && base.ends_with(';') {
            let inner = &base[1..base.len() - 1];
            let simple = inner.rsplit('/').next().unwrap_or(inner).to_string();
            by_simple.entry(simple).or_default().insert(inner.to_string());
        }
    }
    by_simple
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(simple, _)| simple)
        .collect()
}

/// Render a Dalvik type descriptor to Java source, fully-qualifying any class
/// whose simple name is in `ambiguous`. For unambiguous classes this returns
/// the bare simple name (matching the long-standing import-based rendering);
/// for ambiguous ones it emits the dotted fully-qualified name so the
/// reference is unmistakable even when several same-named classes coexist.
pub fn render_owned_type(type_desc: &str, ambiguous: &HashSet<String>) -> String {
    let quick = JavaGenerator::dalvik_type_to_java(type_desc);
    if quick != type_desc { return quick.to_string(); }
    if let Some(rest) = type_desc.strip_prefix('[') {
        return format!("{}[]", render_owned_type(rest, ambiguous));
    }
    if type_desc.starts_with('L') && type_desc.ends_with(';') {
        let inner = &type_desc[1..type_desc.len() - 1];
        let simple = inner.rsplit('/').next().unwrap_or(inner);
        if ambiguous.contains(simple) {
            // Fully-qualified; no import is emitted for ambiguous names.
            return inner.replace('/', ".").replace('$', ".");
        }
        return simple.replace('$', ".");
    }
    type_desc.to_string()
}

/// Extract the package from a Dalvik class descriptor.
/// "Lcom/example/foo/Bar;" → "com.example.foo"
pub fn class_package(class_desc: &str) -> String {
    let inner = if class_desc.starts_with('L') && class_desc.ends_with(';') {
        &class_desc[1..class_desc.len() - 1]
    } else {
        class_desc
    };
    let slash_pos = inner.rfind('/');
    match slash_pos {
        Some(pos) => inner[..pos].replace('/', "."),
        None      => String::new(),
    }
}

/// Extract the simple class name from a descriptor or dotted name.
pub fn simple_class_from_descriptor(class_desc: &str) -> &str {
    let inner = if class_desc.starts_with('L') && class_desc.ends_with(';') {
        &class_desc[1..class_desc.len() - 1]
    } else {
        class_desc
    };
    inner.rsplit('/').next().unwrap_or(inner)
}

/// Choose a catch variable name based on exception type.
fn catch_var_name(exc_type: &str) -> &str {
    match exc_type {
        "Exception" | "RuntimeException" | "IOException" => "e",
        "Throwable"                                       => "th",
        _                                                 => "e",
    }
}

/// Parse a Dalvik proto descriptor like `"(ILjava/lang/String;[B)V"`.
pub fn parse_proto_desc(proto: &str) -> (Vec<String>, String) {
    if let Some(close) = proto.find(')') {
        let params_str = &proto[1..close];
        let return_str = &proto[close + 1..];
        (parse_type_list(params_str), return_str.to_string())
    } else {
        (Vec::new(), proto.to_string())
    }
}

fn parse_type_list(s: &str) -> Vec<String> {
    let mut types = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '[' => {
                let start = i;
                i += 1;
                while i < chars.len() && chars[i] == '[' { i += 1; }
                if i < chars.len() && chars[i] == 'L' {
                    if let Some(end) = chars[i..].iter().position(|&c| c == ';') {
                        let end_abs = i + end;
                        types.push(chars[start..=end_abs].iter().collect());
                        i = end_abs + 1;
                    } else {
                        types.push(chars[start..].iter().collect());
                        break;
                    }
                } else {
                    types.push(chars[start..=i].iter().collect());
                    i += 1;
                }
            }
            'L' => {
                if let Some(end) = chars[i..].iter().position(|&c| c == ';') {
                    let end_abs = i + end;
                    types.push(chars[i..=end_abs].iter().collect());
                    i = end_abs + 1;
                } else {
                    types.push(chars[i..].iter().collect());
                    break;
                }
            }
            c => { types.push(c.to_string()); i += 1; }
        }
    }
    types
}

/// Strip the trailing implicit `return;` from a void method's body.
///
/// Dalvik always closes a method with a `return-void` (0x0e) even when
/// Java source would have nothing — the JVM and Dalvik runtimes both
/// require it but the Java *language* makes it implicit at the end of
/// a void method. Keeping the explicit `return;` in our output makes
/// every void method look two lines longer than its hand-written form,
/// which is especially loud for constructors and one-liners.
///
/// We only strip when:
///   * the method's proto descriptor ends in `V` (void return), AND
///   * the very last non-blank statement is exactly `return;` (modulo
///     any leading whitespace).
///
/// Returning a value, returning early from a branch, or anything else
/// nested deeper in the AST is left alone — we only touch the
/// final implicit close.
/// Collapse the cast-chain compound-op idiom that Dalvik emits whenever
/// an int-typed register is widened, mutated, then truncated back.
///
/// Triple (consecutive lines, same indent):
/// ```text
/// <pad>x = (T1)x;
/// <pad>x <op>= rhs;
/// <pad>x = (T2)x;
/// ```
/// collapses to:
/// ```text
/// <pad>x = (T2)((T1)x <op> rhs);
/// ```
///
/// **Why this exists.** RectEvaluator and similar numeric code goes through
/// register-typed conversions in dalvik (int → float → int), and the SSA
/// naming reuses the *same* user-facing name for each typed slice because
/// the dex variable table doesn't model it any differently. The straight
/// per-instruction translation produces:
/// ```text
/// i -= i2;
/// i = (float)i;
/// i *= f;
/// i = (int)i;
/// ```
/// which round-trips through a bogus `int = float` assignment. The peephole
/// folds the inner triple into a single sane expression.
///
/// **Conditions checked:**
/// * Three consecutive lines share the same leading indent.
/// * All three name the same identifier `x` on the LHS.
/// * Lines 1 and 3 are pure `<x> = (T) <x>` cast-from-self assignments.
/// * Line 2 is a compound-op assignment to `<x>` (`+=` `-=` `*=` `/=` `%=`
///   `&=` `|=` `^=` `<<=` `>>=` `>>>=`).
/// * `<x>` does not appear inside `rhs` (word-boundary check) — otherwise
///   inlining would change semantics, since both `<x>` references would
///   then refer to the post-cast value.
///
/// Loops over the line buffer until no further triple matches, so chained
/// cast pyramids collapse in a single pass.
fn compose_cast_chain(lines: &mut Vec<String>) {
    let mut i: usize = 0;
    while i + 2 < lines.len() {
        if let Some(replacement) =
            try_compose_cast_chain(&lines[i], &lines[i + 1], &lines[i + 2])
        {
            lines[i] = replacement;
            lines.remove(i + 1);
            lines.remove(i + 1); // index slid up after the previous remove
            // Don't advance — the rewritten line could itself form the head
            // of a new triple with the next two lines.
            continue;
        }
        i += 1;
    }
}

fn try_compose_cast_chain(a: &str, b: &str, c: &str) -> Option<String> {
    let (pad_a, body_a) = split_leading_indent(a);
    let (pad_b, body_b) = split_leading_indent(b);
    let (pad_c, body_c) = split_leading_indent(c);
    if pad_a != pad_b || pad_b != pad_c {
        return None;
    }

    let body_a = body_a.strip_suffix(';')?.trim_end();
    let body_b = body_b.strip_suffix(';')?.trim_end();
    let body_c = body_c.strip_suffix(';')?.trim_end();

    // ── Line A: "<x> = (T1)<x>" ─────────────────────────────────────────
    let (var_a, rhs_a) = body_a.split_once(" = ")?;
    let var_a = var_a.trim();
    if !is_valid_identifier(var_a) {
        return None;
    }
    let (t1, target_a) = parse_cast_of_ident(rhs_a)?;
    if target_a != var_a {
        return None;
    }

    // ── Line C: "<x> = (T2)<x>" ─────────────────────────────────────────
    let (var_c, rhs_c) = body_c.split_once(" = ")?;
    let var_c = var_c.trim();
    if var_c != var_a {
        return None;
    }
    let (t2, target_c) = parse_cast_of_ident(rhs_c)?;
    if target_c != var_a {
        return None;
    }

    // ── Line B: "<x> <op>= <rhs>" ──────────────────────────────────────
    let (var_b, op, rhs_b) = parse_compound_op(body_b)?;
    if var_b != var_a {
        return None;
    }

    // Bail if <x> recurs inside <rhs>. Inlining would change the value
    // that the inner reference reads (post-cast vs pre-cast).
    if contains_identifier_word(rhs_b, var_a) {
        return None;
    }

    Some(format!(
        "{}{} = ({})(({}){} {} {});",
        pad_a, var_a, t2, t1, var_a, op, rhs_b
    ))
}

/// Split a line into (leading whitespace, rest). Whitespace is only ' ' or '\t'.
fn split_leading_indent(s: &str) -> (&str, &str) {
    let n = s
        .bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count();
    (&s[..n], &s[n..])
}

/// Parse a trimmed `(T)ident` expression. Returns (T, ident).
///
/// Conservative: rejects anything that isn't exactly a parenthesized type
/// followed by a single identifier. Arrays/generics inside the cast are
/// permitted in the type slot since we treat it as an opaque substring.
fn parse_cast_of_ident(s: &str) -> Option<(&str, &str)> {
    let s = s.trim();
    let inner = s.strip_prefix('(')?;
    let close = inner.find(')')?;
    let ty = inner[..close].trim();
    let after = inner[close + 1..].trim_start();
    if ty.is_empty() || !is_valid_identifier(after) {
        return None;
    }
    Some((ty, after))
}

/// Parse `<ident> <op>= <rhs>` (whitespace-separated). Returns
/// `(ident, op_without_eq, rhs)`. The `<op>` set covers the Java compound
/// assignment operators that map to Dalvik 2addr arithmetic ops.
///
/// Longer operators are searched before shorter ones (`>>>=` before `>>=`
/// before `=`) to avoid spurious partial matches.
fn parse_compound_op(s: &str) -> Option<(&str, &str, &str)> {
    const OPS: &[&str] = &[
        ">>>=", ">>=", "<<=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
    ];
    for op_eq in OPS {
        let pat = format!(" {} ", op_eq);
        if let Some(at) = s.find(&pat) {
            let lhs = s[..at].trim();
            let rhs = s[at + pat.len()..].trim();
            if !is_valid_identifier(lhs) || rhs.is_empty() {
                return None;
            }
            return Some((lhs, &op_eq[..op_eq.len() - 1], rhs));
        }
    }
    None
}

fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Word-boundary substring check for an identifier within an expression.
/// Returns true iff `name` appears in `haystack` not flanked on either
/// side by another identifier character.
fn contains_identifier_word(haystack: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let hb = haystack.as_bytes();
    let nb = name.as_bytes();
    let n = nb.len();
    let mut i = 0usize;
    while i + n <= hb.len() {
        if &hb[i..i + n] == nb {
            let before_ok = i == 0 || !is_ident_byte(hb[i - 1]);
            let after_ok = i + n == hb.len() || !is_ident_byte(hb[i + n]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Collapse the trailing `Type t = expr; return t;` idiom into a single
/// `return expr;` line.
///
/// Bridge/synthetic methods in Java frequently end with a temp-then-return
/// shape because the dex source has a `move-result-object v0` followed by
/// `return-object v0`. The cleaner Java is the inline form.
///
/// **Conditions:**
/// * Two adjacent lines at the same indent.
/// * L1 matches `<Type> <ident> = <expr>;` — a *declaration* (must lead
///   with a type token), not a bare reassignment.
/// * L2 is exactly `return <ident>;`.
/// * `<ident>` does not appear anywhere else in the line buffer (word
///   boundary). This guards against subtle aliasing — if the same name
///   were reused elsewhere it's a hint our register-naming saw something
///   we don't fully model.
///
/// The peephole is intentionally narrow: it only fires on the very
/// specific declaration-then-return pair. General single-use-temp
/// inlining is left for a future SSA-based pass because text-level
/// lifetime tracking gets unreliable once temps are reassigned (the
/// RectEvaluator `i2` case).
fn collapse_return_of_temp(lines: &mut Vec<String>) {
    let mut i: usize = 0;
    while i + 1 < lines.len() {
        if let Some(replacement) = try_collapse_return_of_temp(&lines[i], &lines[i + 1], lines, i)
        {
            lines[i] = replacement;
            lines.remove(i + 1);
            // The combined line is `return ...;` — nothing else to fold
            // against it, so advance past.
            i += 1;
            continue;
        }
        i += 1;
    }
}

fn try_collapse_return_of_temp(
    l1: &str,
    l2: &str,
    all: &[String],
    i: usize,
) -> Option<String> {
    let (pad1, body1) = split_leading_indent(l1);
    let (pad2, body2) = split_leading_indent(l2);
    if pad1 != pad2 {
        return None;
    }

    let body1 = body1.strip_suffix(';')?.trim_end();
    let body2 = body2.strip_suffix(';')?.trim_end();

    // ── Line 2: "return <ident>" ────────────────────────────────────
    let ret_ident = body2.strip_prefix("return ")?.trim();
    if !is_valid_identifier(ret_ident) {
        return None;
    }

    // ── Line 1: "<Type> <ident> = <expr>" ──────────────────────────
    // Split on " = " (a declaration must contain that exact separator).
    let (lhs, expr) = body1.split_once(" = ")?;
    // The LHS is "<Type> <ident>" — split on the final whitespace so
    // generics / array brackets in the type are preserved verbatim.
    let lhs = lhs.trim();
    let last_ws = lhs.rfind(|c: char| c.is_whitespace())?;
    let ty = lhs[..last_ws].trim();
    let name = lhs[last_ws + 1..].trim();
    if ty.is_empty() || !is_valid_identifier(name) {
        return None;
    }
    // The "type" prefix should not itself contain a reserved keyword that
    // means this isn't a declaration. Realistically, splitting on " = "
    // and requiring a whitespace-separated leading word is enough for
    // the line shapes we emit.
    if name != ret_ident {
        return None;
    }

    let expr = expr.trim();
    if expr.is_empty() {
        return None;
    }

    // ── Lifetime check: `name` must not appear anywhere else in the
    //    method body. Walk every other line and look for a
    //    word-bounded occurrence.
    for (j, line) in all.iter().enumerate() {
        if j == i || j == i + 1 {
            continue;
        }
        if contains_identifier_word(line, name) {
            return None;
        }
    }

    Some(format!("{}return {};", pad1, expr))
}

fn strip_trailing_void_return(lines: &mut Vec<String>, proto_desc: &str) {
    if !proto_desc.ends_with(")V") {
        return;
    }
    // Walk backward past blank lines until we hit something meaningful.
    let mut last_idx: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().rev() {
        if !line.trim().is_empty() {
            last_idx = Some(i);
            break;
        }
    }
    if let Some(i) = last_idx {
        if lines[i].trim() == "return;" {
            lines.remove(i);
        }
    }
}

fn escape_java_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c    => out.push(c),
        }
    }
    out
}

/// Format the immediate for a `const*` opcode.
///
/// `raw` is the already-decoded immediate from the parser:
/// * `0x12` (const/4): sign-extended 4-bit value (-8..7), parsed as 11n.
/// * `0x13` (const/16): sign-extended 16-bit value.
/// * `0x14` (const):    32-bit value.
/// * `0x15` (const/high16): the high 16 bits of a 32-bit int; emit
///                          the result shifted into place.
/// * `0x16` / `0x17`:   sign-extended 16/32-bit long values.
/// * `0x18` (const-wide): 64-bit long value.
/// * `0x19` (const-wide/high16): high 16 bits of a 64-bit long.
///
/// **Bug-fix note:** the previous table did `(raw as i32) >> 4` for
/// const/4, which folded every small positive value (1..7) down to 0 —
/// breaking `mOrientation == 0` style return-conditions throughout the
/// decompiled output (LinearLayoutManager.canScrollHorizontally showed
/// `i = 0` on BOTH branches). The parser already sign-extends the
/// nibble into `v_b`, so the shift is wrong.
fn const_type_repr(opcode: u8, raw: i64) -> (&'static str, String) {
    match opcode {
        0x12 => ("int",  format!("{}", raw as i32)),
        0x13 => ("int",  format!("{}", raw as i32)),
        0x14 => ("int",  format!("{}", raw as i32)),
        0x15 => ("int",  format!("{}", (raw as i32) << 16)),
        0x16 => ("long", format!("{}L", raw as i64)),
        0x17 => ("long", format!("{}L", raw as i64)),
        0x18 => ("long", format!("{}L", raw)),
        0x19 => ("long", format!("{}L", (raw as i64) << 48)),
        _    => ("int",  format!("{}", raw)),
    }
}

fn unary_op_str(opcode: u8) -> &'static str {
    match opcode {
        0x7b => "-",
        0x7c => "~",
        0x7d => "-",
        0x7e => "~",
        0x7f => "-",
        0x80 => "-",
        0x81 => "(long)",
        0x82 => "(float)",
        0x83 => "(double)",
        0x84 => "(int)",
        0x85 => "(float)",
        0x86 => "(double)",
        0x87 => "(int)",
        0x88 => "(long)",
        0x89 => "(double)",
        0x8a => "(int)",
        0x8b => "(long)",
        0x8c => "(float)",
        0x8d => "(byte)",
        0x8e => "(char)",
        0x8f => "(short)",
        _ => "",
    }
}

/// Byte width of a Java primitive, or `None` for non-primitives.
fn java_prim_width(t: &str) -> Option<usize> {
    match t {
        "byte" | "boolean" => Some(1),
        "short" | "char" => Some(2),
        "int" | "float" => Some(4),
        "long" | "double" => Some(8),
        _ => None,
    }
}

/// Natural element type for a `fill-array-data` element width when the
/// register's own type is unavailable or stale.
fn default_array_elem(width: usize) -> &'static str {
    match width {
        1 => "byte",
        2 => "short",
        8 => "long",
        _ => "int",
    }
}

/// Decode a `fill-array-data` payload into Java literals for an array of
/// element type `elem`. Each element is `width` little-endian bytes; how those
/// bytes read back depends on the type (the payload itself is untyped).
fn array_data_literals(elem: &str, width: usize, data: &[u8]) -> Vec<String> {
    if width == 0 || width > 8 {
        return Vec::new();
    }
    data.chunks(width)
        .filter(|c| c.len() == width)
        .map(|c| {
            let mut raw: u64 = 0;
            for (i, &b) in c.iter().enumerate() {
                raw |= (b as u64) << (8 * i);
            }
            // Sign-extend to i64 for the signed integer types.
            let bits = (width * 8) as u32;
            let signed = if bits < 64 {
                let shift = 64 - bits;
                ((raw << shift) as i64) >> shift
            } else {
                raw as i64
            };
            match elem {
                "boolean" => (if raw != 0 { "true" } else { "false" }).to_string(),
                "char" => raw.to_string(), // unsigned 16-bit; a bare int literal is valid
                "long" => format!("{}L", signed),
                "float" => java_float_literal(f32::from_bits(raw as u32)),
                "double" => java_double_literal(f64::from_bits(raw)),
                _ => signed.to_string(), // byte / short / int
            }
        })
        .collect()
}

/// Render an `f32` as a valid Java `float` literal (handles NaN / infinities).
fn java_float_literal(f: f32) -> String {
    if f.is_nan() {
        "Float.NaN".to_string()
    } else if f.is_infinite() {
        if f > 0.0 { "Float.POSITIVE_INFINITY" } else { "Float.NEGATIVE_INFINITY" }.to_string()
    } else {
        format!("{:?}f", f)
    }
}

/// Render an `f64` as a valid Java `double` literal (handles NaN / infinities).
fn java_double_literal(d: f64) -> String {
    if d.is_nan() {
        "Double.NaN".to_string()
    } else if d.is_infinite() {
        if d > 0.0 { "Double.POSITIVE_INFINITY" } else { "Double.NEGATIVE_INFINITY" }.to_string()
    } else {
        format!("{:?}", d)
    }
}

/// Result type of a Dalvik unary opcode (neg/not and the numeric
/// conversions). Used to declare the destination so it doesn't fall through
/// to the SSA-name fallback. The conversions name their *target* type
/// (`int-to-long` → `long`); neg/not preserve their operand's width.
fn unary_result_type(opcode: u8) -> &'static str {
    match opcode {
        0x7b | 0x7c                      => "int",     // neg-int / not-int
        0x7d | 0x7e                      => "long",    // neg-long / not-long
        0x7f                             => "float",   // neg-float
        0x80                             => "double",  // neg-double
        0x81                             => "long",    // int-to-long
        0x82 | 0x85                      => "float",   // int/long-to-float
        0x83 | 0x86 | 0x89               => "double",  // int/long/float-to-double
        0x84 | 0x87 | 0x8a               => "int",     // long/float/double-to-int
        0x88 | 0x8b                      => "long",    // float/double-to-long
        0x8c                             => "float",   // double-to-float
        0x8d                             => "byte",    // int-to-byte
        0x8e                             => "char",    // int-to-char
        0x8f                             => "short",   // int-to-short
        _                                => "int",
    }
}

/// Map a Dalvik binary-op opcode to its Java source operator.
///
/// The 2-address forms (0xb0-0xcf) are folded onto the 3-operand
/// forms (0x90-0xaf) by subtracting 0x20 before lookup. The Dalvik
/// spec groups int ops at 0x90-0x9a and the *same* ops on longs at
/// 0x9b-0xa5; we pair int with long, NOT with the next int op.
///
/// **Bug-fix note:** the previous table paired adjacent opcodes
/// (e.g. `0x90 | 0x91 => "+"`), treating add-int and sub-int as both
/// "+". Every operator was off by one. That's why RectEvaluator's
/// `endValue.left - startValue.left` came out as `i + i2` followed
/// by `i -= f` instead of `i - i2` then `i *= f`.
///
/// References: dalvik bytecode spec §III, "Arithmetic and logic operations".
fn binary_op_str(opcode: u8, _two_addr: bool) -> &'static str {
    let base = if opcode >= 0xb0 { opcode - 0x20 } else { opcode };
    match base {
        // ── int + long ops (paired by operator across int/long) ─────
        0x90 | 0x9b => "+",      // add-int / add-long
        0x91 | 0x9c => "-",      // sub-int / sub-long
        0x92 | 0x9d => "*",      // mul-int / mul-long
        0x93 | 0x9e => "/",      // div-int / div-long
        0x94 | 0x9f => "%",      // rem-int / rem-long
        0x95 | 0xa0 => "&",      // and-int / and-long
        0x96 | 0xa1 => "|",      // or-int / or-long
        0x97 | 0xa2 => "^",      // xor-int / xor-long
        0x98 | 0xa3 => "<<",     // shl-int / shl-long
        0x99 | 0xa4 => ">>",     // shr-int / shr-long
        0x9a | 0xa5 => ">>>",    // ushr-int / ushr-long
        // ── float + double ops (paired the same way) ────────────────
        0xa6 | 0xab => "+",      // add-float / add-double
        0xa7 | 0xac => "-",      // sub-float / sub-double
        0xa8 | 0xad => "*",      // mul-float / mul-double
        0xa9 | 0xae => "/",      // div-float / div-double
        0xaa | 0xaf => "%",      // rem-float / rem-double
        _ => "?",
    }
}

/// The Java result type for a Dalvik binary-op opcode.
///
/// Dalvik groups its arithmetic ops by operand type:
///   0x90-0x9a  int      ops
///   0x9b-0xa5  long     ops
///   0xa6-0xaa  float    ops
///   0xab-0xaf  double   ops
///   0xb0-0xcf  same groupings, in their 2addr forms (offset +0x20)
///
/// Returning the correct type at this layer is load-bearing for naming:
/// without it, binop destinations land in `named_reg`'s SSA fallback
/// (e.g. `v1_11`) instead of getting a proper `int i3 = …` declaration.
pub fn binop_result_type(opcode: u8) -> &'static str {
    let base = if opcode >= 0xb0 { opcode - 0x20 } else { opcode };
    match base {
        0x90..=0x9a => "int",
        0x9b..=0xa5 => "long",
        0xa6..=0xaa => "float",
        0xab..=0xaf => "double",
        _           => "int", // safe fallback for unknown opcodes
    }
}

fn binlit_op_str(opcode: u8) -> &'static str {
    match opcode {
        0xd0 | 0xd8 => "+",
        0xd1 | 0xd9 => "-",
        0xd2 | 0xda => "*",
        0xd3 | 0xdb => "/",
        0xd4 | 0xdc => "%",
        0xd5 | 0xdd => "&",
        0xd6 | 0xde => "|",
        0xd7 | 0xdf => "^",
        0xe0        => "<<",
        0xe1        => ">>",
        0xe2        => ">>>",
        _ => "?",
    }
}

#[cfg(test)]
mod is_object_type_tests {
    use super::is_object_type;

    #[test]
    fn primitives_are_not_objects() {
        for p in &["int", "long", "float", "double",
                   "boolean", "byte", "char", "short", "void"] {
            assert!(!is_object_type(p), "{} should be a primitive", p);
        }
    }

    #[test]
    fn class_types_are_objects() {
        assert!(is_object_type("String"));
        assert!(is_object_type("Rect"));
        assert!(is_object_type("Object"));
        assert!(is_object_type("Map.Entry"));
    }

    #[test]
    fn array_types_are_objects() {
        // Arrays in Java are reference types — null is a valid value.
        assert!(is_object_type("int[]"));
        assert!(is_object_type("String[]"));
        assert!(is_object_type("byte[]"));
    }
}

#[cfg(test)]
mod binop_result_type_tests {
    use super::binop_result_type;

    #[test]
    fn int_ops_return_int() {
        for op in 0x90u8..=0x9au8 {
            assert_eq!(binop_result_type(op), "int", "opcode {:#x}", op);
        }
    }

    #[test]
    fn long_ops_return_long() {
        for op in 0x9bu8..=0xa5u8 {
            assert_eq!(binop_result_type(op), "long", "opcode {:#x}", op);
        }
    }

    #[test]
    fn float_ops_return_float() {
        for op in 0xa6u8..=0xaau8 {
            assert_eq!(binop_result_type(op), "float", "opcode {:#x}", op);
        }
    }

    #[test]
    fn double_ops_return_double() {
        for op in 0xabu8..=0xafu8 {
            assert_eq!(binop_result_type(op), "double", "opcode {:#x}", op);
        }
    }

    #[test]
    fn two_addr_ops_fold_onto_three_operand_classification() {
        // add-int/2addr (0xb0) → "int"; mul-float/2addr (0xc8) → "float"
        assert_eq!(binop_result_type(0xb0), "int");
        assert_eq!(binop_result_type(0xbb), "long");
        assert_eq!(binop_result_type(0xc8), "float");
        assert_eq!(binop_result_type(0xcb), "double");
    }
}

#[cfg(test)]
mod strip_return_tests {
    use super::strip_trailing_void_return;

    fn lines(ls: &[&str]) -> Vec<String> {
        ls.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn strips_trailing_return_from_void_method() {
        let mut v = lines(&["    foo();", "    return;"]);
        strip_trailing_void_return(&mut v, "()V");
        assert_eq!(v, vec!["    foo();".to_string()]);
    }

    #[test]
    fn leaves_value_return_alone_on_non_void() {
        let mut v = lines(&["    foo();", "    return x;"]);
        strip_trailing_void_return(&mut v, "()I");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn leaves_void_method_body_alone_when_no_trailing_return() {
        let mut v = lines(&["    foo();", "    bar();"]);
        strip_trailing_void_return(&mut v, "()V");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn ignores_returns_that_arent_the_final_statement() {
        // An early return inside a branch should NOT be stripped.
        let mut v = lines(&[
            "    if (x) {",
            "        return;",
            "    }",
            "    foo();",
        ]);
        strip_trailing_void_return(&mut v, "()V");
        assert_eq!(v.len(), 4);
    }
}

#[cfg(test)]
mod rewrite_zero_comparison_tests {
    use super::rewrite_zero_comparison;

    /// Object-typed registers: comparison against `0` is illegal Java; we
    /// substitute `null`.
    #[test]
    fn object_type_substitutes_null() {
        assert_eq!(rewrite_zero_comparison("rect4 != 0", "Rect"), "rect4 != null");
        assert_eq!(rewrite_zero_comparison("str == 0", "String"), "str == null");
        assert_eq!(
            rewrite_zero_comparison("arr != 0", "byte[]"),
            "arr != null",
            "arrays are reference types"
        );
    }

    /// Boolean-typed registers: drop the literal-zero compare to produce
    /// idiomatic Java.
    #[test]
    fn boolean_collapses_to_identifier() {
        assert_eq!(rewrite_zero_comparison("z != 0", "boolean"), "z");
        assert_eq!(rewrite_zero_comparison("z == 0", "boolean"), "!z");
    }

    /// Plain int-typed registers: `name != 0` is fine Java, leave alone.
    #[test]
    fn int_type_left_alone() {
        assert_eq!(rewrite_zero_comparison("i != 0", "int"), "i != 0");
        assert_eq!(rewrite_zero_comparison("i == 0", "int"), "i == 0");
        assert_eq!(rewrite_zero_comparison("i > 0", "int"), "i > 0");
    }

    /// Non-zero comparisons stay untouched even when the type would
    /// normally trigger a rewrite — we only fire on the exact
    /// `... == 0` / `... != 0` suffix.
    #[test]
    fn non_zero_comparisons_untouched() {
        assert_eq!(rewrite_zero_comparison("a > b", "int"), "a > b");
        assert_eq!(rewrite_zero_comparison("p != q", "String"), "p != q");
        assert_eq!(rewrite_zero_comparison("z == true", "boolean"), "z == true");
    }

    /// Other primitive types (byte, char, short, long, float, double):
    /// leave the zero comparison alone — those are valid integer compares
    /// in Java.
    #[test]
    fn other_primitives_left_alone() {
        for ty in &["byte", "char", "short", "long", "float", "double"] {
            assert_eq!(rewrite_zero_comparison("x != 0", ty), "x != 0",
                "type {} should not trigger rewrite", ty);
        }
    }
}

#[cfg(test)]
mod const_type_repr_tests {
    use super::const_type_repr;

    /// Regression for the const/4 `>> 4` bug: every small positive value
    /// (1..7) used to fold to 0 because the parser already sign-extended
    /// the nibble but the emitter then shifted it right again.
    #[test]
    fn const_4_renders_small_positives_correctly() {
        for v in 0..=7i64 {
            assert_eq!(const_type_repr(0x12, v), ("int", v.to_string()),
                "const/4 with value {} should render as {}", v, v);
        }
    }

    /// const/4 handles negative values (sign-extended nibble 0x8..0xf
    /// → -8..-1 after parsing).
    #[test]
    fn const_4_renders_negatives_correctly() {
        for v in -8i64..=-1i64 {
            assert_eq!(const_type_repr(0x12, v), ("int", v.to_string()));
        }
    }

    #[test]
    fn const_16_renders_directly() {
        assert_eq!(const_type_repr(0x13, 1234), ("int", "1234".to_string()));
        assert_eq!(const_type_repr(0x13, -1), ("int", "-1".to_string()));
    }

    /// const/high16 shifts the 16-bit immediate into the upper half of
    /// a 32-bit int — that's the whole point of the opcode.
    #[test]
    fn const_high16_shifts_into_upper_half() {
        // 0x1234 << 16 = 0x12340000 = 305397760
        assert_eq!(const_type_repr(0x15, 0x1234),
                   ("int", (0x1234i32 << 16).to_string()));
    }

    /// const-wide opcodes carry the `L` suffix so Java parses them as
    /// long literals, not as ints with implicit conversion.
    #[test]
    fn long_opcodes_emit_l_suffix() {
        assert_eq!(const_type_repr(0x16, 7), ("long", "7L".to_string()));
        assert_eq!(const_type_repr(0x18, 1_234_567_890_123),
                   ("long", "1234567890123L".to_string()));
    }
}

#[cfg(test)]
mod compose_cast_chain_tests {
    use super::compose_cast_chain;

    fn lines(ls: &[&str]) -> Vec<String> {
        ls.iter().map(|s| s.to_string()).collect()
    }

    /// The canonical RectEvaluator middle triple: `int` widened to `float`,
    /// multiplied, then truncated back to `int`. This is the motivating
    /// case for the peephole.
    #[test]
    fn collapses_int_float_int_compound_mul() {
        let mut v = lines(&[
            "        i = (float)i;",
            "        i *= f;",
            "        i = (int)i;",
        ]);
        compose_cast_chain(&mut v);
        assert_eq!(v, vec![
            "        i = (int)((float)i * f);".to_string(),
        ]);
    }

    /// All compound-op flavors should be handled identically.
    #[test]
    fn collapses_subtract_compound_op() {
        let mut v = lines(&[
            "    x = (long)x;",
            "    x -= 1;",
            "    x = (int)x;",
        ]);
        compose_cast_chain(&mut v);
        assert_eq!(v, vec!["    x = (int)((long)x - 1);".to_string()]);
    }

    #[test]
    fn collapses_shift_compound_op() {
        let mut v = lines(&[
            "    n = (long)n;",
            "    n >>>= 3;",
            "    n = (int)n;",
        ]);
        compose_cast_chain(&mut v);
        assert_eq!(v, vec!["    n = (int)((long)n >>> 3);".to_string()]);
    }

    /// The peephole runs to fixpoint: a pyramid of cast triples collapses
    /// fully in a single pass. The outer pair becomes the new line[0],
    /// which together with line[1] and line[2] forms another triple.
    #[test]
    fn chains_repeatedly_to_fixpoint() {
        // Inner: i = (float)i; i *= f; i = (int)i; → i = (int)((float)i * f);
        // Outer wrap: i = (long)i; i += 2; i = (int)i; — but the inner now
        // sits where line 2 used to be, so this can't double-chain in the
        // straightforward case. Test a sequence that DOES chain: two
        // adjacent triples sharing no register.
        let mut v = lines(&[
            "    a = (float)a;",
            "    a *= 2;",
            "    a = (int)a;",
            "    b = (long)b;",
            "    b += 1;",
            "    b = (int)b;",
        ]);
        compose_cast_chain(&mut v);
        assert_eq!(v, vec![
            "    a = (int)((float)a * 2);".to_string(),
            "    b = (int)((long)b + 1);".to_string(),
        ]);
    }

    /// Mismatched indent breaks the triple — we won't accidentally
    /// straddle block boundaries.
    #[test]
    fn rejects_mismatched_indent() {
        let mut v = lines(&[
            "    i = (float)i;",
            "        i *= f;",
            "    i = (int)i;",
        ]);
        let before = v.clone();
        compose_cast_chain(&mut v);
        assert_eq!(v, before);
    }

    /// Different variables on the lines — not a valid triple.
    #[test]
    fn rejects_mismatched_variables() {
        let mut v = lines(&[
            "    i = (float)i;",
            "    j *= f;",
            "    i = (int)i;",
        ]);
        let before = v.clone();
        compose_cast_chain(&mut v);
        assert_eq!(v, before);
    }

    /// If the variable appears in the rhs of the compound op, the inlined
    /// reference would refer to the *post-cast* value, not the pre-cast
    /// one. Bail to preserve semantics.
    #[test]
    fn rejects_self_reference_in_rhs() {
        let mut v = lines(&[
            "    i = (float)i;",
            "    i *= i + 1;",
            "    i = (int)i;",
        ]);
        let before = v.clone();
        compose_cast_chain(&mut v);
        assert_eq!(v, before);
    }

    /// Word-boundary check: `i` appearing as part of another identifier
    /// (e.g. `index`) should not be treated as a self-reference.
    #[test]
    fn allows_substring_match_that_isnt_word() {
        let mut v = lines(&[
            "    i = (float)i;",
            "    i *= index;",
            "    i = (int)i;",
        ]);
        compose_cast_chain(&mut v);
        assert_eq!(v, vec!["    i = (int)((float)i * index);".to_string()]);
    }

    /// Cast wrapped around something other than the bare variable should
    /// be rejected. We only fold the `<x> = (T) <x>` shape.
    #[test]
    fn rejects_cast_around_field_access() {
        let mut v = lines(&[
            "    i = (float)i.field;",
            "    i *= f;",
            "    i = (int)i;",
        ]);
        let before = v.clone();
        compose_cast_chain(&mut v);
        assert_eq!(v, before);
    }

    /// Plain assignment (not compound op) in the middle shouldn't match.
    #[test]
    fn rejects_plain_assignment_in_middle() {
        let mut v = lines(&[
            "    i = (float)i;",
            "    i = f;",
            "    i = (int)i;",
        ]);
        let before = v.clone();
        compose_cast_chain(&mut v);
        assert_eq!(v, before);
    }

    /// Fewer than 3 lines: never an error, never changes anything.
    #[test]
    fn short_inputs_pass_through_unchanged() {
        let mut v0: Vec<String> = lines(&[]);
        compose_cast_chain(&mut v0);
        assert!(v0.is_empty());

        let mut v1 = lines(&["    foo();"]);
        compose_cast_chain(&mut v1);
        assert_eq!(v1, vec!["    foo();".to_string()]);

        let mut v2 = lines(&["    foo();", "    bar();"]);
        compose_cast_chain(&mut v2);
        assert_eq!(v2, vec!["    foo();".to_string(), "    bar();".to_string()]);
    }

    /// Triple in the middle of a longer body should collapse without
    /// disturbing surrounding lines.
    #[test]
    fn collapse_in_middle_preserves_surroundings() {
        let mut v = lines(&[
            "    int i = a;",
            "    i = (float)i;",
            "    i *= f;",
            "    i = (int)i;",
            "    return i;",
        ]);
        compose_cast_chain(&mut v);
        assert_eq!(v, vec![
            "    int i = a;".to_string(),
            "    i = (int)((float)i * f);".to_string(),
            "    return i;".to_string(),
        ]);
    }
}

#[cfg(test)]
mod collapse_return_of_temp_tests {
    use super::collapse_return_of_temp;

    fn lines(ls: &[&str]) -> Vec<String> {
        ls.iter().map(|s| s.to_string()).collect()
    }

    /// The motivating case: the bridge method synthesised for a generic
    /// covariant return type does cast-and-call, stash, return.
    #[test]
    fn collapses_bridge_method_tail() {
        let mut v = lines(&[
            "        Rect rect2 = (Rect) obj;",
            "        Rect rect3 = (Rect) obj2;",
            "        Rect rect = this.evaluate(f, rect2, rect3);",
            "        return rect;",
        ]);
        collapse_return_of_temp(&mut v);
        assert_eq!(v, vec![
            "        Rect rect2 = (Rect) obj;".to_string(),
            "        Rect rect3 = (Rect) obj2;".to_string(),
            "        return this.evaluate(f, rect2, rect3);".to_string(),
        ]);
    }

    /// Primitive temps are inlined too — even the simple `int t = x + 1;
    /// return t;` should fold.
    #[test]
    fn collapses_primitive_temp() {
        let mut v = lines(&[
            "    int t = a + 1;",
            "    return t;",
        ]);
        collapse_return_of_temp(&mut v);
        assert_eq!(v, vec!["    return a + 1;".to_string()]);
    }

    /// Indent guard: the declaration and the return must sit at the
    /// same depth.
    #[test]
    fn rejects_indent_mismatch() {
        let mut v = lines(&[
            "    int t = 1;",
            "        return t;",
        ]);
        let before = v.clone();
        collapse_return_of_temp(&mut v);
        assert_eq!(v, before);
    }

    /// Return of a different identifier is not the same temp.
    #[test]
    fn rejects_return_of_different_name() {
        let mut v = lines(&[
            "    int t = 1;",
            "    return s;",
        ]);
        let before = v.clone();
        collapse_return_of_temp(&mut v);
        assert_eq!(v, before);
    }

    /// Bare reassignment (no type prefix) shouldn't trigger the
    /// peephole — we'd lose the original declaration.
    #[test]
    fn rejects_bare_reassignment() {
        let mut v = lines(&[
            "    int t;",
            "    t = 1;",
            "    return t;",
        ]);
        // The reassignment is not "<Type> t = expr;", so the peephole on
        // (line 2, line 3) bails. The declaration on line 1 is left alone.
        let before = v.clone();
        collapse_return_of_temp(&mut v);
        assert_eq!(v, before);
    }

    /// If the temp is referenced elsewhere in the body, the peephole
    /// must not fire — that would lose the binding.
    #[test]
    fn rejects_when_temp_referenced_elsewhere() {
        let mut v = lines(&[
            "    System.out.println(t);", // forward reference to t
            "    int t = 1;",
            "    return t;",
        ]);
        let before = v.clone();
        collapse_return_of_temp(&mut v);
        assert_eq!(v, before);
    }

    /// Substring-only match in another line (e.g. `target` containing
    /// `t`) shouldn't count as an "elsewhere" reference.
    #[test]
    fn allows_substring_in_unrelated_line() {
        let mut v = lines(&[
            "    foo(target);",
            "    int t = 1;",
            "    return t;",
        ]);
        collapse_return_of_temp(&mut v);
        assert_eq!(v, vec![
            "    foo(target);".to_string(),
            "    return 1;".to_string(),
        ]);
    }

    /// Return-of-temp in the middle of a body (e.g. inside a branch)
    /// also folds — the lifetime check still passes if the temp is
    /// scoped to just that pair.
    #[test]
    fn collapses_inside_branch() {
        let mut v = lines(&[
            "    if (cond) {",
            "        int t = compute();",
            "        return t;",
            "    }",
            "    return 0;",
        ]);
        collapse_return_of_temp(&mut v);
        assert_eq!(v, vec![
            "    if (cond) {".to_string(),
            "        return compute();".to_string(),
            "    }".to_string(),
            "    return 0;".to_string(),
        ]);
    }

    /// `return` line that returns an expression (not just an identifier)
    /// is left alone — we only collapse the bare-ident case.
    #[test]
    fn rejects_return_of_expression() {
        let mut v = lines(&[
            "    int t = 1;",
            "    return t + 1;",
        ]);
        let before = v.clone();
        collapse_return_of_temp(&mut v);
        assert_eq!(v, before);
    }

    /// Type names with dots (qualified) and generics are preserved by
    /// the split-on-final-whitespace logic.
    #[test]
    fn handles_qualified_type_name() {
        let mut v = lines(&[
            "    java.util.List<String> list = factory.make();",
            "    return list;",
        ]);
        collapse_return_of_temp(&mut v);
        assert_eq!(v, vec!["    return factory.make();".to_string()]);
    }

    /// Short bodies: never errors, never changes anything.
    #[test]
    fn short_inputs_pass_through() {
        let mut v0: Vec<String> = lines(&[]);
        collapse_return_of_temp(&mut v0);
        assert!(v0.is_empty());

        let mut v1 = lines(&["    return x;"]);
        collapse_return_of_temp(&mut v1);
        assert_eq!(v1, vec!["    return x;".to_string()]);
    }
}

#[cfg(test)]
mod binary_op_tests {
    use super::binary_op_str;

    // Regression: the previous table paired adjacent opcodes
    // (`0x90 | 0x91 => "+"`) so add-int and sub-int both became "+".
    // Every operator was off by one across the int/long ranges. We
    // now pair int with long across operators.

    #[test]
    fn int_arithmetic_ops_map_to_correct_operators() {
        assert_eq!(binary_op_str(0x90, false), "+");   // add-int
        assert_eq!(binary_op_str(0x91, false), "-");   // sub-int
        assert_eq!(binary_op_str(0x92, false), "*");   // mul-int
        assert_eq!(binary_op_str(0x93, false), "/");   // div-int
        assert_eq!(binary_op_str(0x94, false), "%");   // rem-int
    }

    #[test]
    fn long_arithmetic_ops_match_int_counterparts() {
        assert_eq!(binary_op_str(0x9b, false), "+");   // add-long
        assert_eq!(binary_op_str(0x9c, false), "-");   // sub-long
        assert_eq!(binary_op_str(0x9d, false), "*");   // mul-long
        assert_eq!(binary_op_str(0x9e, false), "/");   // div-long
        assert_eq!(binary_op_str(0x9f, false), "%");   // rem-long
    }

    #[test]
    fn int_bitwise_and_shift_ops() {
        assert_eq!(binary_op_str(0x95, false), "&");   // and-int
        assert_eq!(binary_op_str(0x96, false), "|");   // or-int
        assert_eq!(binary_op_str(0x97, false), "^");   // xor-int
        assert_eq!(binary_op_str(0x98, false), "<<");  // shl-int
        assert_eq!(binary_op_str(0x99, false), ">>");  // shr-int
        assert_eq!(binary_op_str(0x9a, false), ">>>"); // ushr-int
    }

    #[test]
    fn float_and_double_arithmetic_ops() {
        assert_eq!(binary_op_str(0xa6, false), "+");   // add-float
        assert_eq!(binary_op_str(0xa7, false), "-");   // sub-float
        assert_eq!(binary_op_str(0xa8, false), "*");   // mul-float
        assert_eq!(binary_op_str(0xa9, false), "/");   // div-float
        assert_eq!(binary_op_str(0xaa, false), "%");   // rem-float
        assert_eq!(binary_op_str(0xab, false), "+");   // add-double
        assert_eq!(binary_op_str(0xac, false), "-");   // sub-double
        assert_eq!(binary_op_str(0xad, false), "*");   // mul-double
        assert_eq!(binary_op_str(0xae, false), "/");   // div-double
        assert_eq!(binary_op_str(0xaf, false), "%");   // rem-double
    }

    #[test]
    fn two_addr_forms_match_their_three_operand_counterparts() {
        // The 2addr ops live at 0xb0-0xcf; subtracting 0x20 yields the
        // matching 3-operand opcode.
        assert_eq!(binary_op_str(0xb0, true), "+");    // add-int/2addr
        assert_eq!(binary_op_str(0xb1, true), "-");    // sub-int/2addr
        assert_eq!(binary_op_str(0xb2, true), "*");    // mul-int/2addr
        assert_eq!(binary_op_str(0xc8, true), "*");    // mul-float/2addr
        assert_eq!(binary_op_str(0xc9, true), "/");    // div-float/2addr
    }
}

#[cfg(test)]
mod ambiguous_simple_names_tests {
    use super::ambiguous_simple_names;

    #[test]
    fn flags_simple_names_shared_across_packages() {
        // Two `wfg` classes in different packages → ambiguous; `id` unique.
        let types = ["Lhivhi/wfg;", "Ldbwbi/wfg;", "Lhivhi/id;", "Ljava/lang/String;"];
        let amb = ambiguous_simple_names(types.iter().copied());
        assert!(amb.contains("wfg"), "wfg collides across hivhi/ and dbwbi/");
        assert!(!amb.contains("id"), "id appears once → not ambiguous");
        assert!(!amb.contains("String"));
    }

    #[test]
    fn unique_names_are_never_ambiguous() {
        let types = ["Lhivhi/wfg;", "Lhivhi/id;", "Lcom/x/Foo;"];
        let amb = ambiguous_simple_names(types.iter().copied());
        assert!(amb.is_empty());
    }

    #[test]
    fn duplicate_descriptor_for_same_class_is_not_ambiguous() {
        // The same fully-qualified class listed twice is NOT a collision.
        let types = ["Lhivhi/wfg;", "Lhivhi/wfg;", "[Lhivhi/wfg;"];
        let amb = ambiguous_simple_names(types.iter().copied());
        assert!(amb.is_empty());
    }

    #[test]
    fn array_prefixes_are_stripped_before_comparing() {
        // `wfg` as array in one place, plain class in another package → still
        // the same simple name, two distinct classes → ambiguous.
        let types = ["[Lhivhi/wfg;", "Ldbwbi/wfg;"];
        let amb = ambiguous_simple_names(types.iter().copied());
        assert!(amb.contains("wfg"));
    }
}

#[cfg(test)]
mod render_owned_type_tests {
    use super::render_owned_type;
    use std::collections::HashSet;

    fn amb(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn ambiguous_class_is_fully_qualified() {
        let a = amb(&["wfg"]);
        // The exact reported bug: the receiver must carry its package.
        assert_eq!(render_owned_type("Lhivhi/wfg;", &a), "hivhi.wfg");
        assert_eq!(render_owned_type("Ldbwbi/wfg;", &a), "dbwbi.wfg");
    }

    #[test]
    fn unambiguous_class_stays_simple() {
        let a = amb(&["wfg"]);
        // `id` isn't ambiguous → unchanged simple-name rendering.
        assert_eq!(render_owned_type("Lhivhi/id;", &a), "id");
    }

    #[test]
    fn primitives_and_known_types_unchanged() {
        let a = amb(&["wfg"]);
        assert_eq!(render_owned_type("I", &a), "int");
        assert_eq!(render_owned_type("Ljava/lang/String;", &a), "String");
    }

    #[test]
    fn arrays_of_ambiguous_classes_are_qualified() {
        let a = amb(&["wfg"]);
        assert_eq!(render_owned_type("[Lhivhi/wfg;", &a), "hivhi.wfg[]");
    }

    #[test]
    fn empty_ambiguous_set_matches_legacy_simple_rendering() {
        let a: HashSet<String> = HashSet::new();
        assert_eq!(render_owned_type("Lhivhi/wfg;", &a), "wfg");
        assert_eq!(render_owned_type("Lcom/foo/Outer$Inner;", &a), "Outer.Inner");
    }
}

#[cfg(test)]
mod binlit_typing_tests {
    use super::binop_result_type;

    /// Bug #2: a binary-lit destination (`v1 = i & 1`) used to leak an
    /// undeclared SSA name because nothing typed it. The fix declares it as
    /// `int`; this pins the invariant that the int arithmetic opcodes the fix
    /// relies on really are int-typed. (The end-to-end "no `v1_5` leak"
    /// behaviour is verified by the javac→d8→decompile differential harness.)
    #[test]
    fn int_arithmetic_ops_are_typed_int() {
        for op in [0x90u8, 0x95, 0x99, 0x9a] { // add/and/shr/ushr-int
            assert_eq!(binop_result_type(op), "int");
        }
    }
}

#[cfg(test)]
mod fill_array_data_tests {
    use super::{array_data_literals, default_array_elem, java_prim_width};

    #[test]
    fn byte_elements_are_signed() {
        // 0xD5 reads back as -43 for a byte[]; 0x41 as 65.
        let lits = array_data_literals("byte", 1, &[0x41, 0xD5, 0x7F, 0x80]);
        assert_eq!(lits, ["65", "-43", "127", "-128"]);
    }

    #[test]
    fn int_and_long_and_bool() {
        // 4-byte little-endian int
        assert_eq!(array_data_literals("int", 4, &[0x01, 0x00, 0x00, 0x00]), ["1"]);
        // 8-byte long gets the L suffix
        assert_eq!(array_data_literals("long", 8, &[0xFF; 8]), ["-1L"]);
        // boolean: nonzero → true, zero → false
        assert_eq!(array_data_literals("boolean", 1, &[0x00, 0x01]), ["false", "true"]);
        // char: unsigned
        assert_eq!(array_data_literals("char", 2, &[0x41, 0x00]), ["65"]);
    }

    #[test]
    fn width_to_default_type_and_prim_width_roundtrip() {
        for (w, t) in [(1, "byte"), (2, "short"), (4, "int"), (8, "long")] {
            assert_eq!(default_array_elem(w), t);
            assert_eq!(java_prim_width(t), Some(w));
        }
    }
}

#[cfg(test)]
mod unary_result_type_tests {
    use super::unary_result_type;

    /// Conversion opcodes name their *target* type — these declarations are
    /// what stop `v0_2 = (long)i;` from leaking an undeclared SSA name.
    #[test]
    fn numeric_conversions_yield_target_type() {
        assert_eq!(unary_result_type(0x81), "long");   // int-to-long
        assert_eq!(unary_result_type(0x82), "float");  // int-to-float
        assert_eq!(unary_result_type(0x83), "double"); // int-to-double
        assert_eq!(unary_result_type(0x84), "int");    // long-to-int
        assert_eq!(unary_result_type(0x87), "int");    // float-to-int
        assert_eq!(unary_result_type(0x8a), "int");    // double-to-int
        assert_eq!(unary_result_type(0x8c), "float");  // double-to-float
        assert_eq!(unary_result_type(0x8d), "byte");   // int-to-byte
        assert_eq!(unary_result_type(0x8e), "char");   // int-to-char
        assert_eq!(unary_result_type(0x8f), "short");  // int-to-short
    }

    /// neg/not preserve their operand width.
    #[test]
    fn neg_not_preserve_width() {
        assert_eq!(unary_result_type(0x7b), "int");    // neg-int
        assert_eq!(unary_result_type(0x7c), "int");    // not-int
        assert_eq!(unary_result_type(0x7d), "long");   // neg-long
        assert_eq!(unary_result_type(0x7f), "float");  // neg-float
        assert_eq!(unary_result_type(0x80), "double"); // neg-double
    }
}
