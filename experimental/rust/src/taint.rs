//! Intra-procedural register-taint analysis for Dalvik methods.
//!
//! The analysis is a linear forward dataflow pass over the instruction stream
//! (no fixpoint iteration).  This is sound for acyclic paths and gives practical
//! results for loops: taint accumulated on the first pass through a loop body
//! propagates forward.
//!
//! **Sources**: method parameters + return values of known sensitive APIs.
//! **Sinks**: calls to known dangerous APIs (logging, network, storage, …).
//! **Propagation**: union-based — if any input is tainted, the output is tainted.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::dex::access_flags::MethodAccessFlag;
use crate::dex::instructions::{Instruction, InstructionKind};
use crate::dex::method::Method;
use crate::dex::parser::DexFileWithRaw;
use crate::dex::clazz::Clazz;
use crate::dex::debug_info;

// ── Serialisable result types ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintSource {
    /// "param", "api_return", or "field_read"
    pub kind: String,
    /// Register index (Dalvik register number)
    pub register: u32,
    /// Human-readable label: "p0 (this)", "getIntent()", …
    pub label: String,
    /// Codepoint of the call that produced this source (None for parameters)
    pub codepoint: Option<u32>,
    pub instruction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintSink {
    /// "logging", "network", "storage", "database", "crypto", "file_write",
    /// "reflection", "command_exec", "webview", "ipc", "SMS"
    pub category: String,
    pub method_ref: String,
    pub codepoint: u32,
    pub instruction: String,
    /// Which argument positions (0-based) carry tainted values
    pub tainted_arg_indices: Vec<usize>,
    /// Human-readable labels of all sources flowing into this sink
    pub sources_reached: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintedField {
    pub field_ref: String,
    pub codepoint: u32,
    pub instruction: String,
    pub sources_reaching: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterTaintEntry {
    pub register: u32,
    /// "vN" or "pN" shorthand
    pub name: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintResult {
    pub method_ref: String,
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
    pub tainted_return: bool,
    /// Source labels that reach the return value (empty when !tainted_return)
    pub return_sources: Vec<String>,
    pub tainted_fields: Vec<TaintedField>,
    /// Per-register taint state at method exit (only tainted registers shown)
    pub register_summary: Vec<RegisterTaintEntry>,
}

// ── Source / sink classifiers ─────────────────────────────────────────────────

fn classify_source_api(method_ref: &str) -> Option<String> {
    // Intent / activity extras
    if method_ref.contains("getIntent") && !method_ref.contains("putExtra") {
        return Some("Intent".into());
    }
    if method_ref.contains("getStringExtra") || method_ref.contains("getIntExtra")
        || method_ref.contains("getBundleExtra") || method_ref.contains("getSerializableExtra")
        || method_ref.contains("getParcelableExtra") || method_ref.contains("getCharSequenceExtra")
    {
        return Some("Intent Extra".into());
    }
    if method_ref.contains("getAction") && method_ref.contains("Intent") {
        return Some("Intent Action".into());
    }
    if method_ref.contains("getData") && method_ref.contains("Intent") {
        return Some("Intent Data".into());
    }
    // User input / UI
    if method_ref.contains("getText") && (method_ref.contains("EditText") || method_ref.contains("TextView")) {
        return Some("UI Input".into());
    }
    if method_ref.contains("getPassword") { return Some("Password Input".into()); }
    // Network / streams
    if method_ref.contains("getInputStream") { return Some("InputStream".into()); }
    if method_ref.contains("readLine") || method_ref.contains("readFully") { return Some("Stream Read".into()); }
    // Device identifiers
    if method_ref.contains("getDeviceId") || method_ref.contains("getImei") { return Some("Device ID".into()); }
    if method_ref.contains("getSubscriberId") { return Some("IMSI".into()); }
    if method_ref.contains("getSimSerialNumber") { return Some("SIM Serial".into()); }
    if method_ref.contains("getMacAddress") { return Some("MAC Address".into()); }
    // Location
    if method_ref.contains("getLastKnownLocation") || method_ref.contains("onLocationChanged") {
        return Some("Location".into());
    }
    // Contacts / accounts
    if method_ref.contains("ContactsContract") || method_ref.contains("getAccounts") {
        return Some("Contacts / Accounts".into());
    }
    // Clipboard
    if method_ref.contains("getPrimaryClip") || method_ref.contains("getClipData") {
        return Some("Clipboard".into());
    }
    None
}

fn classify_sink(method_ref: &str) -> Option<&'static str> {
    // Logging
    if method_ref.contains("android/util/Log;->") { return Some("logging"); }
    if method_ref.contains("printStackTrace") { return Some("logging"); }
    // Network
    if (method_ref.contains("java/net/") || method_ref.contains("java/net/http/"))
        && (method_ref.contains("write") || method_ref.contains("send")
            || method_ref.contains("connect") || method_ref.contains("openConnection")
            || method_ref.contains("getOutputStream"))
    {
        return Some("network");
    }
    if method_ref.contains("okhttp3") || method_ref.contains("retrofit2") { return Some("network"); }
    if method_ref.contains("HttpURLConnection") || method_ref.contains("HttpsURLConnection") {
        return Some("network");
    }
    // SMS
    if method_ref.contains("SmsManager") && method_ref.contains("sendTextMessage") {
        return Some("SMS");
    }
    // File I/O
    if (method_ref.contains("FileOutputStream") || method_ref.contains("FileWriter")
        || method_ref.contains("openFileOutput") || method_ref.contains("java/io/OutputStream;->write")
        || method_ref.contains("java/io/Writer;->write"))
        && (method_ref.contains("<init>") || method_ref.contains("->write"))
    {
        return Some("file_write");
    }
    // Shared preferences / storage
    if method_ref.contains("SharedPreferences$Editor;->put")
        || method_ref.contains("SharedPreferences$Editor;->commit")
        || method_ref.contains("SharedPreferences$Editor;->apply")
    {
        return Some("storage");
    }
    // Database
    if method_ref.contains("ContentValues;->put") { return Some("database"); }
    if (method_ref.contains("ContentResolver;->insert") || method_ref.contains("ContentResolver;->update"))
        && method_ref.contains("android/content/")
    {
        return Some("database");
    }
    if method_ref.contains("SQLiteDatabase;->")
        && (method_ref.contains("insert") || method_ref.contains("execSQL")
            || method_ref.contains("rawQuery") || method_ref.contains("update"))
    {
        return Some("database");
    }
    // Crypto
    if (method_ref.contains("javax/crypto/") || method_ref.contains("java/security/"))
        && (method_ref.contains(";->init(") || method_ref.contains(";->doFinal(")
            || method_ref.contains(";->update(") || method_ref.contains(";->generateKey("))
    {
        return Some("crypto");
    }
    // Reflection
    if method_ref.contains("java/lang/reflect/Method;->invoke")
        || method_ref.contains("getDeclaredMethod") || method_ref.contains("getMethod(")
    {
        return Some("reflection");
    }
    // Runtime exec
    if method_ref.contains("java/lang/Runtime;->exec") || method_ref.contains("ProcessBuilder;->") {
        return Some("command_exec");
    }
    // WebView
    if method_ref.contains("android/webkit/WebView;->loadUrl")
        || method_ref.contains("android/webkit/WebView;->loadData")
        || method_ref.contains("android/webkit/WebView;->evaluateJavascript")
    {
        return Some("webview");
    }
    // IPC
    if (method_ref.contains("sendBroadcast") || method_ref.contains("startActivity")
        || method_ref.contains("startService")) && method_ref.contains("android")
    {
        return Some("ipc");
    }
    None
}

// ── Analysis state ────────────────────────────────────────────────────────────

/// Per-register taint: maps register index → list of source indices tainting it.
type RegTaint = Vec<usize>;

struct AnalysisState {
    sources:           Vec<TaintSource>,
    sinks:             Vec<TaintSink>,
    tainted_return:    bool,
    return_sources:    Vec<String>,
    tainted_fields:    Vec<TaintedField>,
    /// Current per-register taint.
    reg_taint:         HashMap<u32, RegTaint>,
    /// Taint carried by the result of the most recent invoke (used by move-result).
    last_invoke_taint: RegTaint,
}

impl AnalysisState {
    fn new() -> Self {
        AnalysisState {
            sources:           Vec::new(),
            sinks:             Vec::new(),
            tainted_return:    false,
            return_sources:    Vec::new(),
            tainted_fields:    Vec::new(),
            reg_taint:         HashMap::new(),
            last_invoke_taint: Vec::new(),
        }
    }

    fn get_taint(&self, reg: u32) -> RegTaint {
        self.reg_taint.get(&reg).cloned().unwrap_or_default()
    }

    fn set_taint(&mut self, reg: u32, taint: RegTaint) {
        if taint.is_empty() {
            self.reg_taint.remove(&reg);
        } else {
            self.reg_taint.insert(reg, taint);
        }
    }

    /// Union of taint sets for a list of registers.
    fn union_of(&self, regs: &[u32]) -> RegTaint {
        let mut result: RegTaint = Vec::new();
        for &r in regs {
            for idx in self.get_taint(r) {
                if !result.contains(&idx) {
                    result.push(idx);
                }
            }
        }
        result
    }

    fn source_labels(&self, indices: &[usize]) -> Vec<String> {
        indices.iter()
            .filter_map(|&i| self.sources.get(i))
            .map(|s| s.label.clone())
            .collect()
    }

    /// Process a single instruction with method-call overrides consulted at every invoke.
    /// Pass `&OverrideMap::default()` for the no-overrides case.
    fn process_with_overrides(&mut self, instr: &Instruction, overrides: &OverrideMap) {
        let istr = &instr.instruction_str;

        match &instr.kind {
            // ── move vA, vB ───────────────────────────────────────────────────
            InstructionKind::Move => {
                if let (Some(dst), Some(src)) = (instr.v_a, instr.v_b) {
                    let t = self.get_taint(src as u32);
                    self.set_taint(dst as u32, t);
                }
            }

            // ── move-result vA ────────────────────────────────────────────────
            InstructionKind::MoveResult => {
                if let Some(dst) = instr.v_a {
                    let t = self.last_invoke_taint.clone();
                    // If this result belongs to a pending api_return source,
                    // update its placeholder register.
                    for &src_idx in &t {
                        if let Some(src) = self.sources.get_mut(src_idx) {
                            if src.register == u32::MAX {
                                src.register = dst as u32;
                            }
                        }
                    }
                    self.set_taint(dst as u32, t);
                }
            }

            // ── return vA ─────────────────────────────────────────────────────
            InstructionKind::Return => {
                if let Some(src) = instr.v_a {
                    let t = self.get_taint(src as u32);
                    if !t.is_empty() {
                        self.tainted_return = true;
                        self.return_sources = self.source_labels(&t);
                    }
                }
            }

            // ── const* — always untainted ─────────────────────────────────────
            InstructionKind::Const => {
                if let Some(dst) = instr.v_a {
                    self.set_taint(dst as u32, vec![]);
                }
            }

            // ── new-instance — fresh untainted object ─────────────────────────
            InstructionKind::NewInstance => {
                if let Some(dst) = instr.v_a {
                    self.set_taint(dst as u32, vec![]);
                }
            }

            // ── array-length vA, vB ───────────────────────────────────────────
            InstructionKind::ArrLength => {
                if let (Some(dst), Some(src)) = (instr.v_a, instr.v_b) {
                    let t = self.get_taint(src as u32);
                    self.set_taint(dst as u32, t);
                }
            }

            // ── aget/aput ─────────────────────────────────────────────────────
            InstructionKind::ArrayOp => {
                if istr.starts_with("aget") {
                    // aget vA, vB, vC  →  taint(A) = taint(B)
                    if let (Some(dst), Some(arr)) = (instr.v_a, instr.v_b) {
                        let t = self.get_taint(arr as u32);
                        self.set_taint(dst as u32, t);
                    }
                } else if istr.starts_with("aput") {
                    // aput vA, vB, vC  →  if tainted(A), taint(B) |= taint(A)
                    if let (Some(src), Some(arr)) = (instr.v_a, instr.v_b) {
                        let st = self.get_taint(src as u32);
                        if !st.is_empty() {
                            let mut at = self.get_taint(arr as u32);
                            for idx in st { if !at.contains(&idx) { at.push(idx); } }
                            self.set_taint(arr as u32, at);
                        }
                    }
                } else if istr.starts_with("new-array") {
                    // new-array vA, vB, type  →  fresh empty array, untainted
                    if let Some(dst) = instr.v_a {
                        self.set_taint(dst as u32, vec![]);
                    }
                } else if istr.starts_with("filled-new-array") {
                    // filled-new-array {args}, type  →  result via move-result
                    let arg_regs = extract_arg_regs(instr);
                    self.last_invoke_taint = self.union_of(&arg_regs);
                }
            }

            // ── iget vA, vB, field  (conservative: field taint ← object taint)
            InstructionKind::IGet => {
                if let (Some(dst), Some(obj)) = (instr.v_a, instr.v_b) {
                    let t = self.get_taint(obj as u32);
                    self.set_taint(dst as u32, t);
                }
            }

            // ── iput vA, vB, field  →  record write if vA tainted ────────────
            InstructionKind::IPut => {
                if let Some(src) = instr.v_a {
                    let t = self.get_taint(src as u32);
                    if !t.is_empty() {
                        let field_ref = extract_iget_field_ref(istr)
                            .unwrap_or_else(|| istr.clone());
                        let labels = self.source_labels(&t);
                        self.tainted_fields.push(TaintedField {
                            field_ref,
                            codepoint: instr.codepoint,
                            instruction: istr.clone(),
                            sources_reaching: labels,
                        });
                        // Also propagate into the object register (constructor-style init)
                        if let Some(obj) = instr.v_b {
                            let mut ot = self.get_taint(obj as u32);
                            for idx in &t { if !ot.contains(idx) { ot.push(*idx); } }
                            self.set_taint(obj as u32, ot);
                        }
                    }
                }
            }

            // ── sget vA, field  →  untainted (static fields are cold by default)
            InstructionKind::SGet => {
                if let Some(dst) = instr.v_a {
                    self.set_taint(dst as u32, vec![]);
                }
            }

            // ── sput vA, field  →  record write if vA tainted ────────────────
            InstructionKind::SPut => {
                if let Some(src) = instr.v_a {
                    let t = self.get_taint(src as u32);
                    if !t.is_empty() {
                        let field_ref = extract_single_field_ref(istr)
                            .unwrap_or_else(|| istr.clone());
                        let labels = self.source_labels(&t);
                        self.tainted_fields.push(TaintedField {
                            field_ref,
                            codepoint: instr.codepoint,
                            instruction: istr.clone(),
                            sources_reaching: labels,
                        });
                    }
                }
            }

            // ── invoke-* ──────────────────────────────────────────────────────
            InstructionKind::InvokeKind
            | InstructionKind::InvokeKindRange
            | InstructionKind::InvokePolymorphic
            | InstructionKind::InvokeCustom => {
                let arg_regs = extract_arg_regs(instr);
                let method_ref = extract_invoke_method_ref(istr)
                    .unwrap_or_else(|| istr.clone());

                // Which arg positions carry tainted values?
                let mut tainted_arg_indices: Vec<usize> = Vec::new();
                let mut union_t: RegTaint = Vec::new();
                for (pos, &reg) in arg_regs.iter().enumerate() {
                    let rt = self.get_taint(reg);
                    if !rt.is_empty() {
                        tainted_arg_indices.push(pos);
                        for idx in rt {
                            if !union_t.contains(&idx) { union_t.push(idx); }
                        }
                    }
                }

                // 1. User overrides take priority over both source classification
                //    and default arg-union propagation.
                let override_outcome = overrides.return_override_for(&method_ref);
                if let Some(outcome) = override_outcome {
                    match outcome {
                        ReturnOutcome::Tainted(labels) => {
                            let mut indices = Vec::new();
                            for label in labels {
                                let idx = self.sources.len();
                                self.sources.push(TaintSource {
                                    kind: "override".into(),
                                    register: u32::MAX,
                                    label: label.clone(),
                                    codepoint: Some(instr.codepoint),
                                    instruction: Some(istr.clone()),
                                });
                                indices.push(idx);
                            }
                            self.last_invoke_taint = indices;
                        }
                        ReturnOutcome::Clean => {
                            self.last_invoke_taint = Vec::new();
                        }
                    }
                } else if let Some(source_label) = classify_source_api(&method_ref) {
                    // 2. Built-in source-API classification.
                    let idx = self.sources.len();
                    self.sources.push(TaintSource {
                        kind: "api_return".into(),
                        register: u32::MAX, // placeholder — filled on move-result
                        label: format!("{}()", short_method_name(&method_ref)),
                        codepoint: Some(instr.codepoint),
                        instruction: Some(istr.clone()),
                    });
                    self.last_invoke_taint = vec![idx];
                    let _ = source_label;
                } else {
                    // 3. Conservative: result taint = union of argument taints.
                    self.last_invoke_taint = union_t.clone();
                }

                // Is this a sink?
                if let Some(category) = classify_sink(&method_ref) {
                    if !tainted_arg_indices.is_empty() {
                        let sources_reached = self.source_labels(&union_t);
                        self.sinks.push(TaintSink {
                            category: category.into(),
                            method_ref: method_ref.clone(),
                            codepoint: instr.codepoint,
                            instruction: istr.clone(),
                            tainted_arg_indices,
                            sources_reached,
                        });
                    }
                }

                // For void constructors / void methods: if args are tainted,
                // propagate into the receiver object (arg[0] in non-static invoke).
                if !union_t.is_empty() && !arg_regs.is_empty()
                    && (method_ref.contains(";-><init>(") || method_ref.ends_with(")V"))
                    && istr.starts_with("invoke-direct")
                {
                    let obj_reg = arg_regs[0];
                    let mut ot = self.get_taint(obj_reg);
                    for idx in &union_t { if !ot.contains(idx) { ot.push(*idx); } }
                    self.set_taint(obj_reg, ot);
                }
            }

            // ── unary op vA, vB ───────────────────────────────────────────────
            InstructionKind::UnOp => {
                if let (Some(dst), Some(src)) = (instr.v_a, instr.v_b) {
                    let t = self.get_taint(src as u32);
                    self.set_taint(dst as u32, t);
                }
            }

            // ── binary op vA, vB, vC ─────────────────────────────────────────
            InstructionKind::BinOp { .. } => {
                if let Some(dst) = instr.v_a {
                    let mut srcs = Vec::new();
                    if let Some(b) = instr.v_b { srcs.push(b as u32); }
                    if let Some(c) = instr.v_c { srcs.push(c as u32); }
                    let t = self.union_of(&srcs);
                    self.set_taint(dst as u32, t);
                }
            }

            // ── binary op/2addr vA, vB ────────────────────────────────────────
            InstructionKind::BinOp2Addr { .. } => {
                if let (Some(dst), Some(src)) = (instr.v_a, instr.v_b) {
                    let t = self.union_of(&[dst as u32, src as u32]);
                    self.set_taint(dst as u32, t);
                }
            }

            // ── binary op with literal vA, vB, #lit ──────────────────────────
            InstructionKind::BinOpLit { .. } => {
                if let (Some(dst), Some(src)) = (instr.v_a, instr.v_b) {
                    let t = self.get_taint(src as u32);
                    self.set_taint(dst as u32, t);
                }
            }

            // ── cmp vA, vB, vC ────────────────────────────────────────────────
            InstructionKind::Cmp => {
                if let Some(dst) = instr.v_a {
                    let mut srcs = Vec::new();
                    if let Some(b) = instr.v_b { srcs.push(b as u32); }
                    if let Some(c) = instr.v_c { srcs.push(c as u32); }
                    let t = self.union_of(&srcs);
                    self.set_taint(dst as u32, t);
                }
            }

            // ── check-cast, monitor, instanceof — no taint change ─────────────
            InstructionKind::CheckCast | InstructionKind::Monitor => {}

            InstructionKind::InstanceOf => {
                // vA = (bool), not tainted
                if let Some(dst) = instr.v_a {
                    self.set_taint(dst as u32, vec![]);
                }
            }

            // All other instructions: no taint change
            _ => {}
        }
    }
}

// ── Instruction helpers ───────────────────────────────────────────────────────

fn extract_arg_regs(instr: &Instruction) -> Vec<u32> {
    match &instr.kind {
        InstructionKind::InvokeKind | InstructionKind::InvokePolymorphic => {
            let count = instr.v_a.unwrap_or(0) as usize;
            let regs = [instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g];
            regs[..count.min(5)].iter()
                .filter_map(|&v| v.map(|x| x as u32))
                .collect()
        }
        InstructionKind::InvokeKindRange | InstructionKind::InvokeCustom => {
            let count = instr.v_a.unwrap_or(0) as usize;
            let start = instr.v_c.unwrap_or(0) as u32;
            (0..count as u32).map(|i| start + i).collect()
        }
        _ => Vec::new(),
    }
}

/// Extract `"Lcom/Foo;->bar(...)V"` from an invoke instruction string.
fn extract_invoke_method_ref(istr: &str) -> Option<String> {
    let after = istr.find("}, ")
        .map(|p| p + 3)
        .or_else(|| istr.find("} ..").map(|p| p + 4))
        .or_else(|| istr.rfind('}').map(|p| p + 1))?;
    let rest = istr[after..].trim();
    if rest.contains("->") { Some(rest.to_string()) } else { None }
}

/// Extract field ref from `iget vA, vB, Lcom/Foo;->field:Type` style instructions.
fn extract_iget_field_ref(istr: &str) -> Option<String> {
    // Three comma-separated parts: "iget vA", "vB", "Lcom/Foo;->field:Type"
    let mut parts = istr.splitn(3, ", ");
    parts.next(); // skip "iget vA"
    parts.next(); // skip "vB"
    let rest = parts.next()?.trim();
    if rest.contains("->") { Some(rest.to_string()) } else { None }
}

/// Extract field ref from `sget vA, Lcom/Foo;->FIELD:Type` style instructions.
fn extract_single_field_ref(istr: &str) -> Option<String> {
    let comma = istr.find(", ")?;
    let rest = istr[comma + 2..].trim();
    if rest.contains("->") { Some(rest.to_string()) } else { None }
}

/// Extract just the method name part (before `(`) from a full Dalvik ref.
fn short_method_name(method_ref: &str) -> &str {
    if let Some(arrow) = method_ref.rfind("->") {
        let after = &method_ref[arrow + 2..];
        if let Some(paren) = after.find('(') { return &after[..paren]; }
        return after;
    }
    method_ref
}

/// Convert a register index to a `"vN"` or `"pN"` shorthand.
fn reg_name(reg: u32, registers_size: u16, ins_size: u16) -> String {
    let first_param = (registers_size.saturating_sub(ins_size)) as u32;
    if reg >= first_param {
        format!("p{}", reg - first_param)
    } else {
        format!("v{}", reg)
    }
}

// ── Parameter type helpers ────────────────────────────────────────────────────

/// Extract the Nth parameter type from a proto descriptor `"(Ljava/lang/String;IZ)V"`.
fn parse_param_type(proto: &str, pos: usize) -> Option<String> {
    let inner = proto.strip_prefix('(')?;
    let end = inner.rfind(')')?;
    let params_str = &inner[..end];
    split_type_list(params_str).get(pos).map(|s| shorten_type(s))
}

fn shorten_type(t: &str) -> String {
    match t {
        "V" => "void".into(),  "Z" => "boolean".into(), "B" => "byte".into(),
        "S" => "short".into(), "C" => "char".into(),    "I" => "int".into(),
        "J" => "long".into(),  "F" => "float".into(),   "D" => "double".into(),
        s if s.starts_with('L') && s.ends_with(';') => {
            let inner = &s[1..s.len() - 1];
            inner.split('/').next_back().unwrap_or(inner).to_string()
        }
        s if s.starts_with('[') => format!("{}[]", shorten_type(&s[1..])),
        other => other.into(),
    }
}

fn split_type_list(s: &str) -> Vec<String> {
    let mut types = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'L' => {
                if let Some(end) = s[i..].find(';') {
                    types.push(s[i..=i + end].to_string());
                    i += end + 1;
                } else {
                    types.push(s[i..].to_string());
                    break;
                }
            }
            b'[' => {
                let start = i;
                while i < bytes.len() && bytes[i] == b'[' { i += 1; }
                if i < bytes.len() {
                    if bytes[i] == b'L' {
                        if let Some(end) = s[i..].find(';') {
                            types.push(s[start..=i + end].to_string());
                            i += end + 1;
                            continue;
                        }
                    } else {
                        types.push(s[start..=i].to_string());
                        i += 1;
                    }
                }
            }
            _ => {
                types.push((bytes[i] as char).to_string());
                i += 1;
            }
        }
    }
    types
}

// ── Main analysis entry points ────────────────────────────────────────────────

/// Run taint analysis on `method` and return the result (no overrides).
pub fn analyze_method(method: &Method) -> TaintResult {
    analyze_method_with_overrides(method, &OverrideMap::default())
}

/// Run taint analysis on `method` with method-call overrides applied.
///
/// Overrides keyed by the **callee** method ref take effect at every invoke
/// instruction targeting that callee. Overrides keyed by the **current**
/// method's ref affect parameter seeding (force-clean / force-taint).
pub fn analyze_method_with_overrides(
    method: &Method,
    overrides: &OverrideMap,
) -> TaintResult {
    let mut state = AnalysisState::new();

    // Seed: all incoming parameters are initial taint sources, modulated by overrides.
    // In Dalvik the last `ins_size` registers are parameter registers.
    let first_param = method.registers_size.saturating_sub(method.ins_size) as u32;
    let is_static = method.access_flags.contains(&MethodAccessFlag::Static);

    let self_ref = format!(
        "L{};->{}{}",
        method.class_name, method.method_name, method.proto_desc
    );
    let param_ovs = overrides.param_overrides_for(&self_ref);

    for i in 0..method.ins_size as u32 {
        let reg = first_param + i;

        // Apply per-parameter overrides on the *current* method
        if let Some(po) = param_ovs.get(&(i as usize)) {
            match po {
                ParamOutcome::Clean => continue, // don't seed taint
                ParamOutcome::Tainted(labels) => {
                    for label in labels {
                        let idx = state.sources.len();
                        state.sources.push(TaintSource {
                            kind: "override".into(),
                            register: reg,
                            label: label.clone(),
                            codepoint: None,
                            instruction: None,
                        });
                        let mut existing = state.reg_taint.remove(&reg).unwrap_or_default();
                        existing.push(idx);
                        state.reg_taint.insert(reg, existing);
                    }
                    continue;
                }
            }
        }

        let label = if i == 0 && !is_static {
            "p0 (this)".to_string()
        } else {
            // Position in the explicit parameter list (proto_desc)
            let proto_pos = if is_static { i } else { i.saturating_sub(1) } as usize;
            let type_str = parse_param_type(&method.proto_desc, proto_pos)
                .unwrap_or_else(|| "?".into());
            format!("p{} ({})", i, type_str)
        };

        let idx = state.sources.len();
        state.sources.push(TaintSource {
            kind: "param".into(),
            register: reg,
            label,
            codepoint: None,
            instruction: None,
        });
        state.reg_taint.insert(reg, vec![idx]);
    }

    // Linear forward pass with overrides consulted on every invoke
    for instr in &method.instructions {
        state.process_with_overrides(instr, overrides);
    }

    // Build exit-state register summary (only tainted registers)
    let mut register_summary: Vec<RegisterTaintEntry> = state.reg_taint.iter()
        .filter(|(_, t)| !t.is_empty())
        .map(|(&reg, t)| {
            let sources = state.source_labels(t);
            RegisterTaintEntry {
                register: reg,
                name: reg_name(reg, method.registers_size, method.ins_size),
                sources,
            }
        })
        .collect();
    register_summary.sort_by_key(|r| r.register);

    TaintResult {
        method_ref: format!("L{};->{}{}", method.class_name, method.method_name, method.proto_desc),
        sources:           state.sources,
        sinks:             state.sinks,
        tainted_return:    state.tainted_return,
        return_sources:    state.return_sources,
        tainted_fields:    state.tainted_fields,
        register_summary,
    }
}

/// Look up `class_name::method_name` across all loaded DEX files and run taint analysis.
pub fn analyze_class_method(
    dex_files: &[DexFileWithRaw],
    class_name: &str,
    method_name: &str,
) -> Result<TaintResult, String> {
    let class_norm = class_name.trim_start_matches('L').trim_end_matches(';');
    let method_bare = method_name.split('(').next().unwrap_or(method_name).trim();

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            if def_norm != class_norm { continue; }

            let clazz = Clazz::new(class_def, dex)
                .map_err(|e| e.to_string())?;

            for method in &clazz.methods {
                if method.method_name == method_bare {
                    if method.instructions.is_empty() {
                        return Err(format!(
                            "Method '{}' has no bytecode (abstract / native / interface stub)",
                            method_bare
                        ));
                    }
                    return Ok(analyze_method(method));
                }
            }
            // Class found but method not in it
            return Err(format!("Method '{}' not found in class '{}'", method_bare, class_norm));
        }
    }

    Err(format!("Class '{}' not found in any loaded DEX file", class_norm))
}

// ═════════════════════════════════════════════════════════════════════════════
// Inter-procedural call graph
// ═════════════════════════════════════════════════════════════════════════════
//
// The intra-procedural analysis above is the building block. The graph layer
// builds a node-edge map where each node is a method (with its own analysis)
// and each edge is a call relationship. Expansion is step-at-a-time: callers
// are added by `expand_backward`, callees by `expand_forward`. A user can
// override the taint outcome of any callee, then re-run `reanalyze_with_overrides`
// to propagate the change through the graph.

// ── Override types ────────────────────────────────────────────────────────────

/// One override on a method's taint behaviour.
///
/// Overrides are keyed by method ref (`"Lcom/Foo;->bar(II)V"`) in the
/// [`OverrideMap`]. They take effect at every invoke targeting that method.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum TaintOverride {
    /// Force this method's return to be tainted with these source labels.
    /// Use case: "pretend this decryption helper is a fresh source named `decrypted`".
    ReturnTainted { sources: Vec<String> },

    /// Force this method's return to be untainted (sanitised).
    /// Use case: "this validator clears taint on its output".
    ReturnClean,

    /// Force the parameter at `index` of *this* method to be tainted.
    /// Use case: "treat parameter 1 as if it came from the network".
    ParamTainted { index: usize, sources: Vec<String> },

    /// Force the parameter at `index` of *this* method to be untainted.
    /// Use case: "ignore this parameter for the analysis".
    ParamClean { index: usize },

    /// Pin a constant return value (consumed by the VM execution path,
    /// recorded but otherwise inert in pure-taint analysis).
    /// Use case: "force `isDebug()` to always return true".
    ConstantValue { value: String, type_name: String },
}

/// Mapping from method ref → list of overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverrideMap {
    pub overrides: HashMap<String, Vec<TaintOverride>>,
}

/// Internal helper — what `OverrideMap::return_override_for` resolves to.
enum ReturnOutcome {
    Tainted(Vec<String>),
    Clean,
}

/// Internal helper — what `OverrideMap::param_overrides_for` resolves to.
enum ParamOutcome {
    Tainted(Vec<String>),
    Clean,
}

impl OverrideMap {
    pub fn new() -> Self { Self::default() }

    /// Return the effective return-value override for `method_ref`, if any.
    /// `ReturnTainted` and `ReturnClean` are honoured; later ones win on conflict.
    fn return_override_for(&self, method_ref: &str) -> Option<ReturnOutcome> {
        let entries = self.overrides.get(method_ref)?;
        let mut outcome: Option<ReturnOutcome> = None;
        for ov in entries {
            match ov {
                TaintOverride::ReturnTainted { sources } => {
                    outcome = Some(ReturnOutcome::Tainted(sources.clone()));
                }
                TaintOverride::ReturnClean => {
                    outcome = Some(ReturnOutcome::Clean);
                }
                TaintOverride::ConstantValue { .. } => {
                    // A constant value is by definition not tainted.
                    outcome = Some(ReturnOutcome::Clean);
                }
                _ => {}
            }
        }
        outcome
    }

    /// Return per-parameter overrides for `method_ref`, keyed by param index.
    fn param_overrides_for(&self, method_ref: &str) -> HashMap<usize, ParamOutcome> {
        let mut out = HashMap::new();
        if let Some(entries) = self.overrides.get(method_ref) {
            for ov in entries {
                match ov {
                    TaintOverride::ParamTainted { index, sources } => {
                        out.insert(*index, ParamOutcome::Tainted(sources.clone()));
                    }
                    TaintOverride::ParamClean { index } => {
                        out.insert(*index, ParamOutcome::Clean);
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

// ── Graph types ───────────────────────────────────────────────────────────────

/// One node in the call graph: a single Dalvik method with its taint analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintNode {
    /// Unique node id (same as `method_ref`).
    pub id: String,
    pub method_ref: String,
    pub class_name: String,
    pub method_name: String,
    pub proto_desc: String,
    /// Hop distance from the root: 0 = root, +n = forward (callee), -n = backward (caller).
    pub depth: i32,
    /// Per-method analysis result — `None` when the body is unavailable
    /// (external Android API, abstract method, or not in any loaded DEX).
    pub analysis: Option<TaintResult>,
    /// Has this node been expanded forward (callees added)?
    pub expanded_forward: bool,
    /// Has this node been expanded backward (callers added)?
    pub expanded_backward: bool,
    /// `true` if no method body was found — caller can grey out / mark "external".
    pub body_unavailable: bool,
}

/// Directed edge: caller → callee.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintEdge {
    pub from: String,         // node id (caller)
    pub to: String,           // node id (callee)
    pub codepoint: u32,
    pub instruction: String,
    pub line_number: Option<u32>,
}

/// Full graph: a root node plus the nodes/edges discovered through expansion.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintGraph {
    pub root: String,                 // root node id
    pub nodes: Vec<TaintNode>,
    pub edges: Vec<TaintEdge>,
}

impl TaintGraph {
    fn node_index(&self, id: &str) -> Option<usize> {
        self.nodes.iter().position(|n| n.id == id)
    }

    fn has_edge(&self, from: &str, to: &str, cp: u32) -> bool {
        self.edges.iter().any(|e| e.from == from && e.to == to && e.codepoint == cp)
    }

    fn add_or_get_node(&mut self, mut node: TaintNode) -> &mut TaintNode {
        if let Some(idx) = self.node_index(&node.id) {
            // Tighten depth toward zero — keep the shortest distance from root
            if node.depth.abs() < self.nodes[idx].depth.abs() {
                self.nodes[idx].depth = node.depth;
            }
            return &mut self.nodes[idx];
        }
        // Don't re-analyze on insert — analysis was already computed by the caller
        let _ = &mut node;
        self.nodes.push(node);
        self.nodes.last_mut().unwrap()
    }
}

// ── Method-ref lookup ─────────────────────────────────────────────────────────

/// Find a method by its full ref `"Lclass;->name(proto)R"` across all DEX files.
/// Falls back to a name-only match if no exact-proto match exists.
pub fn find_method_for_ref(
    dex_files: &[DexFileWithRaw],
    method_ref: &str,
) -> Option<Method> {
    let arrow = method_ref.find("->")?;
    let class_part = &method_ref[..arrow];
    let after = &method_ref[arrow + 2..];
    let class_norm = class_part.trim_start_matches('L').trim_end_matches(';');

    // Split "name(proto)R" into (name, "(proto)R")
    let (bare_name, want_proto) = match after.find('(') {
        Some(p) => (&after[..p], Some(&after[p..])),
        None    => (after, None),
    };

    // Pass 1: exact match (name + proto)
    let mut name_match: Option<Method> = None;
    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L').trim_end_matches(';');
            if def_norm != class_norm { continue; }

            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for method in clazz.methods.iter() {
                if method.method_name != bare_name { continue; }
                match want_proto {
                    Some(proto) if method.proto_desc == proto => return Some(method.clone()),
                    None => return Some(method.clone()),
                    _ => {
                        if name_match.is_none() {
                            name_match = Some(method.clone());
                        }
                    }
                }
            }
        }
    }
    name_match
}

// ── Callee extraction ─────────────────────────────────────────────────────────

/// One callee discovered inside a method.
struct Callee {
    method_ref: String,
    codepoint: u32,
    instruction: String,
    line_number: Option<u32>,
}

fn extract_callees(method: &Method) -> Vec<Callee> {
    let mut out = Vec::new();
    let mut seen_at_cp: HashSet<u32> = HashSet::new();
    for instr in &method.instructions {
        let is_invoke = matches!(
            instr.kind,
            InstructionKind::InvokeKind
                | InstructionKind::InvokeKindRange
                | InstructionKind::InvokePolymorphic
                | InstructionKind::InvokeCustom
        );
        if !is_invoke { continue; }
        if !seen_at_cp.insert(instr.codepoint) { continue; }

        let method_ref = match extract_invoke_method_ref(&instr.instruction_str) {
            Some(r) => r,
            None    => continue,
        };
        let line_number = debug_info::lookup_line(&method.line_map, instr.codepoint);
        out.push(Callee {
            method_ref,
            codepoint: instr.codepoint,
            instruction: instr.instruction_str.clone(),
            line_number,
        });
    }
    out
}

// ── Node construction ─────────────────────────────────────────────────────────

/// Build a `TaintNode` for `method_ref`, running the analysis (with overrides)
/// if the body is available, otherwise marking it as external.
fn build_node(
    dex_files: &[DexFileWithRaw],
    method_ref: &str,
    depth: i32,
    overrides: &OverrideMap,
) -> TaintNode {
    // Parse class/method/proto out of the ref
    let (class_name, method_name, proto_desc) = parse_method_ref(method_ref);

    match find_method_for_ref(dex_files, method_ref) {
        Some(method) => {
            let analysis = if method.instructions.is_empty() {
                None
            } else {
                Some(analyze_method_with_overrides(&method, overrides))
            };
            TaintNode {
                id: method_ref.to_string(),
                method_ref: method_ref.to_string(),
                class_name,
                method_name,
                proto_desc,
                depth,
                analysis,
                expanded_forward: false,
                expanded_backward: false,
                body_unavailable: method.instructions.is_empty(),
            }
        }
        None => TaintNode {
            id: method_ref.to_string(),
            method_ref: method_ref.to_string(),
            class_name,
            method_name,
            proto_desc,
            depth,
            analysis: None,
            expanded_forward: false,
            expanded_backward: false,
            body_unavailable: true,
        },
    }
}

fn parse_method_ref(method_ref: &str) -> (String, String, String) {
    let arrow = method_ref.find("->").unwrap_or(method_ref.len());
    let class_part = method_ref[..arrow]
        .trim_start_matches('L').trim_end_matches(';').to_string();
    let after = if arrow < method_ref.len() {
        &method_ref[arrow + 2..]
    } else {
        ""
    };
    let (name, proto) = match after.find('(') {
        Some(p) => (after[..p].to_string(), after[p..].to_string()),
        None    => (after.to_string(), String::new()),
    };
    (class_part, name, proto)
}

// ── Public graph entry points ─────────────────────────────────────────────────

/// Build the initial graph from a single root method.
/// Just the root node, analyzed with the supplied overrides; no edges.
pub fn build_root_graph(
    dex_files: &[DexFileWithRaw],
    class_name: &str,
    method_name: &str,
    overrides: &OverrideMap,
) -> Result<TaintGraph, String> {
    // Resolve the root method (first matching class+name across all DEX files)
    let class_norm = class_name.trim_start_matches('L').trim_end_matches(';');
    let method_bare = method_name.split('(').next().unwrap_or(method_name).trim();

    let mut found: Option<Method> = None;
    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L').trim_end_matches(';');
            if def_norm != class_norm { continue; }
            let clazz = Clazz::new(class_def, dex).map_err(|e| e.to_string())?;
            for method in clazz.methods {
                if method.method_name == method_bare {
                    found = Some(method);
                    break;
                }
            }
            if found.is_some() { break; }
        }
        if found.is_some() { break; }
    }

    let method = found.ok_or_else(|| format!(
        "Method '{}' not found in class '{}'", method_bare, class_norm
    ))?;
    if method.instructions.is_empty() {
        return Err(format!(
            "Method '{}' has no bytecode (abstract/native/interface stub)", method_bare
        ));
    }

    let method_ref = format!(
        "L{};->{}{}", method.class_name, method.method_name, method.proto_desc
    );
    let node = build_node(dex_files, &method_ref, 0, overrides);

    Ok(TaintGraph {
        root: method_ref,
        nodes: vec![node],
        edges: Vec::new(),
    })
}

/// Expand `node_id` forward — analyse and add every callee invoked by `node_id`.
/// Returns the new graph. Already-known nodes are not duplicated; new edges are added.
pub fn expand_forward(
    dex_files: &[DexFileWithRaw],
    mut graph: TaintGraph,
    node_id: &str,
    overrides: &OverrideMap,
) -> Result<TaintGraph, String> {
    let parent_idx = graph.node_index(node_id)
        .ok_or_else(|| format!("Node '{}' not in graph", node_id))?;
    let parent_depth = graph.nodes[parent_idx].depth;

    if graph.nodes[parent_idx].body_unavailable {
        // Nothing to expand — body is external. Mark as expanded so the UI stops asking.
        graph.nodes[parent_idx].expanded_forward = true;
        return Ok(graph);
    }

    // Re-find the method to walk its instructions (analysis result doesn't carry them).
    let method = find_method_for_ref(dex_files, node_id)
        .ok_or_else(|| format!("Method body for '{}' not found", node_id))?;
    let callees = extract_callees(&method);

    let new_depth = parent_depth.saturating_add(1);

    for callee in callees {
        // Add the node (if absent)
        if graph.node_index(&callee.method_ref).is_none() {
            let n = build_node(dex_files, &callee.method_ref, new_depth, overrides);
            graph.add_or_get_node(n);
        }
        // Add the edge (if absent)
        if !graph.has_edge(node_id, &callee.method_ref, callee.codepoint) {
            graph.edges.push(TaintEdge {
                from: node_id.to_string(),
                to: callee.method_ref,
                codepoint: callee.codepoint,
                instruction: callee.instruction,
                line_number: callee.line_number,
            });
        }
    }

    if let Some(idx) = graph.node_index(node_id) {
        graph.nodes[idx].expanded_forward = true;
    }
    Ok(graph)
}

/// Expand `node_id` backward — find every method that calls `node_id` and add as nodes.
pub fn expand_backward(
    dex_files: &[DexFileWithRaw],
    mut graph: TaintGraph,
    node_id: &str,
    overrides: &OverrideMap,
) -> Result<TaintGraph, String> {
    let child_idx = graph.node_index(node_id)
        .ok_or_else(|| format!("Node '{}' not in graph", node_id))?;
    let child_depth = graph.nodes[child_idx].depth;
    let new_depth = child_depth.saturating_sub(1);

    // Build the search pattern for find_calls. find_calls matches by substring,
    // so use "Lclass;->methodname" to keep it stable across overload variants.
    let arrow = node_id.find("->")
        .ok_or_else(|| format!("Malformed node id '{}'", node_id))?;
    let after = &node_id[arrow + 2..];
    let bare = match after.find('(') {
        Some(p) => &after[..p],
        None    => after,
    };
    let class_part = &node_id[..arrow]; // "Lclass;"
    let pattern = format!("{}->{}", class_part, bare);

    let mut callers_seen: HashSet<(String, u32)> = HashSet::new();
    for dex in dex_files {
        for site in crate::analysis::find_calls(dex, &pattern) {
            // Reconstruct the caller's method ref. caller_method already has proto.
            let caller_ref = format!(
                "L{};->{}", site.caller_class, site.caller_method
            );
            if !callers_seen.insert((caller_ref.clone(), site.invoke_cp)) {
                continue;
            }

            // Add the caller as a node (if absent)
            if graph.node_index(&caller_ref).is_none() {
                let n = build_node(dex_files, &caller_ref, new_depth, overrides);
                graph.add_or_get_node(n);
            }
            // Add the edge caller → child (this node)
            if !graph.has_edge(&caller_ref, node_id, site.invoke_cp) {
                graph.edges.push(TaintEdge {
                    from: caller_ref,
                    to: node_id.to_string(),
                    codepoint: site.invoke_cp,
                    instruction: site.invoke_str,
                    line_number: site.line_number,
                });
            }
        }
    }

    if let Some(idx) = graph.node_index(node_id) {
        graph.nodes[idx].expanded_backward = true;
    }
    Ok(graph)
}

/// Re-run the per-node analysis on every node in `graph` using `overrides`.
/// Edges and expansion state are preserved.
pub fn reanalyze_with_overrides(
    dex_files: &[DexFileWithRaw],
    mut graph: TaintGraph,
    overrides: &OverrideMap,
) -> Result<TaintGraph, String> {
    for node in &mut graph.nodes {
        if node.body_unavailable { continue; }
        if let Some(method) = find_method_for_ref(dex_files, &node.method_ref) {
            if !method.instructions.is_empty() {
                node.analysis = Some(analyze_method_with_overrides(&method, overrides));
            }
        }
    }
    Ok(graph)
}
