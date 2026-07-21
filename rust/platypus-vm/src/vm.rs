/// Dalvik VM interpreter — translates vm/vm.py

use std::collections::HashMap;

use platypus_dex::clazz::Clazz;
use platypus_dex::code_block::{EdgeKind, Cfg};
use platypus_dex::instructions::{Instruction, InstructionKind};
use platypus_dex::method::Method;
use platypus_dex::parser::DexFileWithRaw;

use super::debugger::{Debugger, PauseReason, StepDecision};
use super::logger::VmLogger;
use super::memory::Memory;
use super::mock_handler::MockRegistry;
use super::threading::{ThreadHandle, ThreadInfo, ThreadScheduler, ThreadStatus};
use super::value::Value;

// ── Register file ─────────────────────────────────────────────────────────────

pub type Registers = Vec<Option<Value>>;

fn make_registers(count: usize) -> Registers {
    vec![None; count]
}

// ── Interpreter return value ─────────────────────────────────────────────────

/// What an instruction returns to the dispatch loop.
#[derive(Debug)]
pub enum InstrResult {
    /// Continue to next instruction in this block.
    Continue,
    /// Jump to target codepoint.
    Goto(u32),
    /// Conditional branch — Some(cp) if taken, None if fall-through.
    Branch(Option<u32>),
    /// Method returned.
    Return(Option<Value>),
}

// ── VM ────────────────────────────────────────────────────────────────────────

pub struct Vm {
    pub dex_files:  Vec<DexFileWithRaw>,
    /// class_name → (method_name → method index within that class)
    pub lookup_map: HashMap<String, HashMap<String, usize>>,
    /// **Normalised** class name (no `L`/`;`) → `(dex_idx, class_def_idx)`.
    /// Populated by `add_dex_file`. Used to make `find_and_clone_method`
    /// O(1) per class instead of O(num_classes × num_dexes).
    pub class_index: HashMap<String, (usize, usize)>,
    /// Per-`(class_norm, method_name)` cache of fully-resolved Methods.
    /// `Clazz::new(cd, dex)` decodes *every* method in the class — for
    /// a hot deobfuscator that calls 5+ helpers per iteration, repeated
    /// Clazz::new calls dominate. We cache the resolved Method and
    /// hand back clones; the underlying CFG/instruction Vecs use Arc
    /// internally so the clone is cheap.
    method_cache: HashMap<(String, String), Option<platypus_dex::method::Method>>,
    pub memory:     Memory,
    pub mocks:      MockRegistry,
    pub mock_state: HashMap<String, Value>,
    pub call_stack: Vec<String>, // fully-qualified method names (for depth-limiting)
    pub method_denylist: Vec<String>,
    /// Optional execution logger.  None = silent.
    pub logger: Option<VmLogger>,
    /// Remaining instruction budget.  `None` = unlimited.
    /// Counts down across *all* `execute_block` calls in a single `call_method`
    /// invocation (including nested calls).  When it reaches zero the current
    /// block terminates immediately and `call_method` returns `None`.
    pub instr_budget: Option<u64>,
    /// Android resource ID → resolved string value.  Preloaded from resources.arsc
    /// and intentionally NOT cleared by `reset_for_call` (resources are static).
    pub resource_strings: HashMap<u32, String>,
    /// Cooperative-thread scheduler.  Each `spawn_method` call registers
    /// a handle here and records the eventual outcome (Completed/Failed)
    /// so the host UI can poll status without holding a live reference
    /// to the live call. See [`crate::threading`] for the model.
    pub threads: ThreadScheduler,
    /// Peak call-stack depth observed inside the currently-running
    /// `spawn_method` invocation. Reset by `spawn_method` before the
    /// run starts, sampled inside `call_method` after each push, read
    /// back by `spawn_method` once the run completes. Zero outside a
    /// spawn.
    pub(crate) peak_call_depth_during_spawn: usize,
    /// Optional debugger.  When attached, each instruction goes
    /// through [`Debugger::before_instruction`] which decides whether
    /// to execute it (and captures a register snapshot for time-travel
    /// inspection).  `None` = zero overhead — the normal case.
    pub debugger: Option<Debugger>,
    /// "Faithful" dispatch mode — when true, opcodes covered by the
    /// [`crate::opcodes`] module families are routed through that
    /// module instead of the spec-correct inline implementations
    /// below. The opcodes modules mirror the Python reference's
    /// quirks and bugs verbatim (24-bit shift mask, ushr-long
    /// shifting backwards, if-eqz never branching when val=0,
    /// if-lez `tkane` typo, BinOp2Addr None-arg path, etc.) — useful
    /// for bit-for-bit parity checks against the Python output, NOT
    /// useful for actually running real APKs (most APKs depend on
    /// the spec-correct semantics).
    ///
    /// Default is `false` (spec-correct). Flip with
    /// [`Vm::set_faithful_mode`].
    pub faithful_mode: bool,
}

impl Vm {
    pub fn new() -> Self {
        Vm {
            dex_files:       Vec::new(),
            lookup_map:      HashMap::new(),
            class_index:     HashMap::new(),
            method_cache:    HashMap::new(),
            memory:          Memory::new(),
            mocks:           MockRegistry::new(),
            mock_state:      HashMap::new(),
            call_stack:      Vec::new(),
            method_denylist: Vec::new(),
            logger:          None,
            instr_budget:    None,
            resource_strings: HashMap::new(),
            threads:         ThreadScheduler::new(),
            peak_call_depth_during_spawn: 0,
            debugger:        None,
            faithful_mode:   false,
        }
    }

    /// Toggle faithful dispatch mode. See the [`Vm::faithful_mode`]
    /// field doc for what this changes.
    pub fn set_faithful_mode(&mut self, on: bool) {
        self.faithful_mode = on;
    }

    // ── Debugger attachment ──────────────────────────────────────────

    /// Attach a debugger.  Subsequent `call_method` invocations consult
    /// it on every instruction.  Returns any previously-attached
    /// debugger so the caller can swap and inspect.
    pub fn attach_debugger(&mut self, debugger: Debugger) -> Option<Debugger> {
        self.debugger.replace(debugger)
    }

    /// Detach and return the current debugger (None if none attached).
    pub fn detach_debugger(&mut self) -> Option<Debugger> {
        self.debugger.take()
    }

    /// Cap the total number of instructions this VM will execute.
    /// Call this before `call_method` to prevent infinite loops.
    pub fn set_instr_limit(&mut self, limit: u64) {
        self.instr_budget = Some(limit);
    }

    /// Reset transient execution state so the same loaded VM can be reused
    /// for multiple independent `call_method` invocations.
    ///
    /// Resets: `call_stack`, `memory.last_return`, `mock_state`, and
    /// refills `instr_budget` to the given limit.
    /// Does *not* clear `dex_files`, `lookup_map`, `mocks`, `logger`, or
    /// `method_denylist` — those are set-once configuration.
    pub fn reset_for_call(&mut self, instr_limit: u64) {
        self.call_stack.clear();
        self.memory.last_return = None;
        self.mock_state.clear();
        self.instr_budget = Some(instr_limit);
    }

    /// Preload string resources from a parsed resources.arsc so the VM can
    /// resolve `Context.getString(int)` calls and auto-resolve resource-ID results.
    /// These entries persist across `reset_for_call`.
    pub fn load_resources(&mut self, entries: impl IntoIterator<Item = (u32, String)>) {
        for (id, value) in entries {
            self.resource_strings.insert(id, value);
        }
    }

    /// Try to resolve a resource ID to its string value.
    /// Returns None if no resource table has been loaded or the ID is unknown.
    pub fn resolve_resource_id(&self, res_id: u32) -> Option<&str> {
        self.resource_strings.get(&res_id).map(|s| s.as_str())
    }

    /// Enable execution logging at the given verbosity level (1–3).
    /// Level 0 is a no-op (logger stays None, only [result] is printed by the caller).
    pub fn enable_logging(&mut self, level: u8) {
        if level > 0 {
            self.logger = Some(VmLogger::new(level));
        }
    }

    // ── DEX loading ───────────────────────────────────────────────────────────

    pub fn add_dex_file(&mut self, dex: &DexFileWithRaw) {
        // The dex_files.push() happens at the end of this function;
        // record its index now so we can stash (dex_idx, class_def_idx)
        // pairs into class_index alongside the method lookup_map.
        let next_dex_idx = self.dex_files.len();

        // Build lookup map from class name → method name → method idx in the
        // dex file's method_ids table.  We don't persist the Method structs
        // here; they are re-built on demand via `Clazz::new`.
        for (class_def_idx, class_def) in dex.parsed.class_defs.iter().enumerate() {
            let class_name = class_def.type_name.clone();
            // class_index uses normalised names (no L… ; wrapper) so the
            // lookup matches what callers pass (which arrives in either
            // form depending on whether it came from an invoke string or
            // from a user-typed argument).
            let norm = Self::normalise_class_name(&class_name).to_string();
            self.class_index.entry(norm).or_insert((next_dex_idx, class_def_idx));

            if self.lookup_map.contains_key(&class_name) {
                continue; // first DEX wins (multidex semantics)
            }

            let mut method_map: HashMap<String, usize> = HashMap::new();
            if let Some(ref cd) = class_def.class_data {
                let mut idx = 0usize;
                for e in &cd.virtual_methods {
                    idx += e.method_idx_diff as usize;
                    if let Some(mid) = dex.parsed.method_ids.get(idx) {
                        method_map.insert(mid.method_name.clone(), idx);
                    }
                }
                idx = 0;
                for e in &cd.direct_methods {
                    idx += e.method_idx_diff as usize;
                    if let Some(mid) = dex.parsed.method_ids.get(idx) {
                        method_map.insert(mid.method_name.clone(), idx);
                    }
                }
            }
            self.lookup_map.insert(class_name, method_map);
        }

        self.dex_files.push(dex.clone());
    }

    // ── Method lookup ─────────────────────────────────────────────────────────

    /// Normalise a Dalvik class name to canonical form (L…; or stripped).
    fn normalise_class_name(name: &str) -> &str {
        name.trim_start_matches('L').trim_end_matches(';')
    }

    pub fn lookup_method(&self, class: &str, method: &str) -> Option<(usize, usize)> {
        // Returns (dex_file_index, method_id_index)
        let class = class.trim_end_matches(';');
        for (di, dex) in self.dex_files.iter().enumerate() {
            for class_def in &dex.parsed.class_defs {
                if class_def.type_name.trim_start_matches('L').trim_end_matches(';') == class.trim_start_matches('L') {
                    if let Some(ref cd) = class_def.class_data {
                        let mut idx = 0usize;
                        for e in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
                            idx += e.method_idx_diff as usize;
                            if let Some(mid) = dex.parsed.method_ids.get(idx) {
                                if mid.method_name == method {
                                    return Some((di, idx));
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    // ── Execution ─────────────────────────────────────────────────────────────

    /// Read a static field by its FQ key (`"Lcom/Foo;->BAR"`). Triggers
    /// an auto-clinit on the owning class the first time the field is
    /// touched so static initializers populate the field before we
    /// observe its (otherwise null) value.
    pub fn read_static_field(&mut self, field_key: &str) -> Value {
        // String hashed to usize so we can reuse the existing
        // HashMap<usize, Value> field storage without changing the
        // Memory struct's shape.
        let key = field_storage_key(field_key);

        // Fast path — already populated.
        if let Some(v) = self.memory.static_fields.get(&key) {
            return v.clone();
        }

        // Auto-clinit: parse the class half of `Lcom/Foo;->BAR` and
        // try to run `<clinit>` once. Mark the class as "initialized"
        // even if it has no <clinit> so we don't re-attempt every
        // sget for an uninitialized field.
        if let Some(arrow) = field_key.find(";->") {
            let class_ref = &field_key[..arrow + 1]; // include `;`
            let init_key = field_storage_key(&format!("__clinit__{}", class_ref));
            if !self.memory.static_fields.contains_key(&init_key) {
                self.memory.static_fields.insert(init_key, Value::Bool(true));
                // Try to run <clinit>. May recursively touch more fields,
                // which auto-clinits their classes too — the `init_key`
                // sentinel above prevents re-entry on this same class.
                let class_name = class_ref.trim_start_matches('L').trim_end_matches(';');
                if let Some(clinit) = self.find_and_clone_method(class_name, "<clinit>") {
                    let _ = self.call_method(&clinit, Vec::new());
                }
                // Re-read after clinit had a chance to populate.
                if let Some(v) = self.memory.static_fields.get(&key) {
                    return v.clone();
                }
            }
        }

        Value::Null
    }

    /// Write a static field by its FQ key (`"Lcom/Foo;->BAR"`).
    pub fn write_static_field(&mut self, field_key: String, value: Value) {
        let key = field_storage_key(&field_key);
        self.memory.static_fields.insert(key, value);
    }

    /// Cheap built-in stubs for JDK methods we hit constantly during
    /// crypto / encoding paths. Returning Some(_) here short-circuits
    /// the DEX-lookup fallback (which would silently fail for Java
    /// stdlib classes) and gives us a usable result instead of a None
    /// that propagates as an empty string at the call site.
    ///
    /// Format the caller passes is the FULL method ref e.g.
    /// `"Ljava/lang/String;->charAt(I)C"`. We dispatch on that.
    fn try_jdk_builtin(&self, method_ref: &str, args: &[Value]) -> Option<Value> {
        match method_ref {
            // String.charAt(I)C — receiver is the string, arg 1 is the index.
            "Ljava/lang/String;->charAt" => {
                let s = args.first()?.as_str()?;
                let idx = args.get(1)?.as_int()? as usize;
                s.chars().nth(idx).map(|c| Value::Int(c as i64))
            }
            // String.length()I
            "Ljava/lang/String;->length" => {
                let s = args.first()?.as_str()?;
                Some(Value::Int(s.chars().count() as i64))
            }
            // String([C)V or String([CII)V — receiver is sentinel,
            // arg 1 is the char[] (Value::Array of Int) and optional
            // offset/count. Return the constructed string; the
            // `<init>` path in execute_instruction writes this back
            // into the `this` register so subsequent uses see it.
            "Ljava/lang/String;-><init>" => {
                let chars_arg = args.get(1)?;
                match chars_arg {
                    Value::Array(_) => {
                        let snapshot = chars_arg.array_snapshot().unwrap_or_default();
                        let s: String = snapshot.iter()
                            .filter_map(|v| v.as_int())
                            .filter_map(|n| char::from_u32(n as u32 & 0xffff))
                            .collect();
                        // Honour the (offset, count) form when present.
                        if let (Some(off), Some(cnt)) = (args.get(2), args.get(3)) {
                            if let (Some(o), Some(c)) = (off.as_int(), cnt.as_int()) {
                                let o = o.max(0) as usize;
                                let c = c.max(0) as usize;
                                return Some(Value::Str(
                                    s.chars().skip(o).take(c).collect()
                                ));
                            }
                        }
                        Some(Value::Str(s))
                    }
                    // String(String) — copy constructor.
                    Value::Str(s) => Some(Value::Str(s.clone())),
                    // String(byte[]) — best-effort UTF-8 decode.
                    Value::Bytes(b) => Some(Value::Str(
                        String::from_utf8_lossy(b).into_owned()
                    )),
                    _ => None,
                }
            }
            // StringBuilder().toString() and friends — preserve the
            // string we've been accumulating in the sentinel.
            "Ljava/lang/StringBuilder;->toString"
            | "Ljava/lang/AbstractStringBuilder;->toString"
            | "Ljava/lang/Object;->toString" => {
                args.first().cloned()
            }
            // StringBuilder().append(...) — concatenate to receiver.
            "Ljava/lang/StringBuilder;->append" => {
                let recv = args.first()?.as_str().unwrap_or("").to_string();
                let extra = match args.get(1)? {
                    Value::Str(s) => s.clone(),
                    Value::Int(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null   => "null".to_string(),
                    _ => return None,
                };
                Some(Value::Str(format!("{recv}{extra}")))
            }
            _ => None,
        }
    }

    /// If the method being invoked is a known resource-accessor (getString, getText, etc.)
    /// AND a resource table has been loaded, return the resolved string.
    /// args[0] is `this` for instance methods, args[1] is the resource ID.
    fn try_resolve_resource_call(&self, method_name: &str, args: &[Value]) -> Option<Value> {
        if self.resource_strings.is_empty() { return None; }
        match method_name {
            "getString" | "getText" | "getQuantityString" | "getQuantityText" => {
                // Instance call: args[0] = receiver, args[1] = res_id
                // Try args[1] first, fall back to args[0] for static-like calls
                let res_id = args.get(1)
                    .or_else(|| args.first())?
                    .as_int()? as u32;
                self.resource_strings.get(&res_id).map(|s| Value::Str(s.clone()))
            }
            _ => None,
        }
    }

    /// Interpret a single instruction; returns what the dispatch loop should do.
    fn execute_instruction(
        &mut self,
        instr: &Instruction,
        registers: &mut Registers,
    ) -> InstrResult {
        let op = instr.opcode;

        if let Some(ref log) = self.logger {
            log.log_instruction(instr.codepoint, op, &instr.instruction_str);
        }

        // ── Faithful-mode dispatch shim ──────────────────────
        // When faithful_mode is on, route opcodes in the [`crate::opcodes`]
        // module's range through that module instead of the spec-correct
        // inline match below. The opcodes module mirrors Python reference
        // quirks verbatim (24-bit shift mask, ushr-long backwards, if-eqz
        // never branching when val=0, if-lez `tkane` typo, etc.) — useful
        // for bit-for-bit parity checks against the Python output, NOT
        // useful for actually running real APKs.
        if self.faithful_mode {
            use crate::opcodes;
            match op {
                // Goto family (control)
                0x28..=0x2a => return opcodes::control::execute_goto(instr, registers, &mut self.memory),
                // Switch family (control)
                0x2b..=0x2c => return opcodes::control::execute_switch(instr, registers, &mut self.memory),
                // Cmp family
                0x2d..=0x31 => return opcodes::cmp::execute(instr, registers, &mut self.memory),
                // If family (control)
                0x32..=0x37 => return opcodes::control::execute_if(instr, registers, &mut self.memory),
                // IfZ family (control)
                0x38..=0x3d => return opcodes::control::execute_ifz(instr, registers, &mut self.memory),
                // Throw (control)
                0x27 => return opcodes::control::execute_throw(instr, registers, &mut self.memory),
                // ArrayOp family
                0x44..=0x51 => return opcodes::arrayop::execute(instr, registers, &mut self.memory),
                // IGet
                0x52..=0x58 => return opcodes::iop::execute_iget(instr, registers, &mut self.memory),
                // IPut
                0x59..=0x5f => return opcodes::iop::execute_iput(instr, registers, &mut self.memory),
                // SGet
                0x60..=0x66 => return opcodes::iop::execute_sget(instr, registers, &mut self.memory),
                // SPut
                0x67..=0x6d => return opcodes::iop::execute_sput(instr, registers, &mut self.memory),
                // UnOp family
                0x7b..=0x8f => return opcodes::unop::execute(instr, registers, &mut self.memory),
                // BinOp family
                0x90..=0xaf => return opcodes::binop::execute(instr, registers, &mut self.memory),
                // BinOp2Addr family
                0xb0..=0xcf => return opcodes::binop_2addr::execute(instr, registers, &mut self.memory),
                // BinOpLit family
                0xd0..=0xe2 => return opcodes::binop_lit::execute(instr, registers, &mut self.memory),
                // Monitor / CheckCast / InstanceOf — no-op
                0x1d..=0x20 => return opcodes::misc::execute_noop(instr, registers, &mut self.memory),
                // Array (new-array, filled-new-array, fill-array-data)
                0x23..=0x26 => return opcodes::misc::execute_array(instr, registers, &mut self.memory),
                // ArrLength
                0x21 => return opcodes::misc::execute_arr_length(instr, registers, &mut self.memory),
                // NewInstance
                0x22 => return opcodes::misc::execute_new_instance(instr, registers, &mut self.memory),
                _ => {
                    // Outside the opcodes-module's covered range —
                    // fall through to the inline match. Move,
                    // MoveResult, Return, Const, Invoke variants,
                    // etc. still go through the existing path.
                }
            }
        }

        match op {
            // nop
            0x00 => InstrResult::Continue,

            // move vA, vB
            0x01..=0x09 => {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    let val = registers.get(vb as usize).cloned().flatten();
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = val;
                    }
                }
                InstrResult::Continue
            }

            // move-result / move-result-object
            0x0a..=0x0d => {
                if let Some(va) = instr.v_a {
                    let val = self.memory.last_return.clone();
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = val;
                    }
                }
                InstrResult::Continue
            }

            // return-void
            0x0e => InstrResult::Return(None),

            // return vA
            0x0f => {
                let val = instr.v_a
                    .and_then(|r| registers.get(r as usize))
                    .and_then(|v| v.clone());
                InstrResult::Return(val)
            }

            // return-wide / return-object
            0x10 | 0x11 => {
                let val = instr.v_a
                    .and_then(|r| registers.get(r as usize))
                    .and_then(|v| v.clone());
                InstrResult::Return(val)
            }

            // const/4
            0x12 => {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::Int(vb));
                    }
                }
                InstrResult::Continue
            }
            // const/16 / const / const/high16
            0x13 | 0x14 | 0x15 => {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::Int(vb));
                    }
                }
                InstrResult::Continue
            }

            // const-wide variants — store as Int (truncated)
            0x16..=0x19 => {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::Int(vb));
                    }
                }
                InstrResult::Continue
            }

            // const-string
            0x1a | 0x1b => {
                // vB = string index — resolved at parse time into instruction_str
                // We store a placeholder string; real resolution needs ParsedDex
                if let Some(va) = instr.v_a {
                    let s = instr.instruction_str
                        .splitn(3, '"')
                        .nth(1)
                        .unwrap_or("")
                        .to_string();
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::Str(s));
                    }
                }
                InstrResult::Continue
            }

            // goto / goto/16 / goto/32
            0x28 => {
                let target = (instr.codepoint as i64
                    + platypus_dex::helpers::sign_extend(instr.v_a.unwrap_or(0), 8)) as u32;
                InstrResult::Goto(target)
            }
            0x29 => {
                let target = (instr.codepoint as i64
                    + platypus_dex::helpers::sign_extend(instr.v_a.unwrap_or(0), 16)) as u32;
                InstrResult::Goto(target)
            }
            0x2a => {
                let target = (instr.codepoint as i64
                    + platypus_dex::helpers::sign_extend(instr.v_a.unwrap_or(0), 32)) as u32;
                InstrResult::Goto(target)
            }

            // if-eq / if-ne / if-lt / if-ge / if-gt / if-le
            0x32..=0x37 => {
                // Reference equality (if-eq/if-ne) treats two non-null references
                // as equal only when they have the same identity.  Since we cannot
                // compare references by identity here, we fall back to integer
                // comparison when both operands are integers/bools, and use a
                // null-aware check for eq/ne otherwise.
                let va = instr.v_a.and_then(|r| registers.get(r as usize)).and_then(|v| v.as_ref());
                let vb = instr.v_b.and_then(|r| registers.get(r as usize)).and_then(|v| v.as_ref());
                let taken = match op {
                    0x32 | 0x33 => {
                        // Equality: null == null, non-null != null, int == int
                        let eq = match (va, vb) {
                            (None, None)  => true,
                            (None, _) | (_, None) => false,
                            (Some(a), Some(b)) => {
                                let ai = a.as_int();
                                let bi = b.as_int();
                                if let (Some(an), Some(bn)) = (ai, bi) {
                                    an == bn
                                } else {
                                    false // different non-null references → not equal
                                }
                            }
                        };
                        if op == 0x32 { eq } else { !eq }
                    }
                    _ => {
                        // Integer ordering — extract as int; None → 0
                        let a = va.and_then(|v| v.as_int()).unwrap_or(0);
                        let b = vb.and_then(|v| v.as_int()).unwrap_or(0);
                        match op {
                            0x34 => a <  b,
                            0x35 => a >= b,
                            0x36 => a >  b,
                            0x37 => a <= b,
                            _ => false,
                        }
                    }
                };
                if taken {
                    let target = (instr.codepoint as i64
                        + platypus_dex::helpers::sign_extend(instr.v_c.unwrap_or(0), 16)) as u32;
                    InstrResult::Branch(Some(target))
                } else {
                    InstrResult::Branch(None)
                }
            }

            // if-eqz .. if-lez
            0x38..=0x3d => {
                let opt_val = instr.v_a
                    .and_then(|r| registers.get(r as usize))
                    .and_then(|v| v.as_ref());

                let taken = match op {
                    // if-eqz: branch if null or integer zero
                    0x38 => match opt_val {
                        None                      => true,
                        Some(Value::Int(0))       => true,
                        Some(Value::Bool(false))  => true,
                        _                         => false, // non-null reference or non-zero int
                    },
                    // if-nez: branch if non-null or non-zero
                    0x39 => match opt_val {
                        None                      => false,
                        Some(Value::Int(0))       => false,
                        Some(Value::Bool(false))  => false,
                        _                         => true,
                    },
                    // Ordered comparisons — only meaningful for integers; references → not taken
                    _ => {
                        let n = opt_val.and_then(|v| v.as_int()).unwrap_or_else(|| {
                            // Bool: treat as 0/1; null: treat as 0 for arithmetic ops
                            opt_val.and_then(|v| if let Value::Bool(b) = v {
                                Some(if *b { 1 } else { 0 })
                            } else { None }).unwrap_or(0)
                        });
                        match op {
                            0x3a => n < 0,
                            0x3b => n >= 0,
                            0x3c => n > 0,
                            0x3d => n <= 0,
                            _ => false,
                        }
                    }
                };
                if taken {
                    let target = (instr.codepoint as i64
                        + platypus_dex::helpers::sign_extend(instr.v_b.unwrap_or(0), 16)) as u32;
                    InstrResult::Branch(Some(target))
                } else {
                    InstrResult::Branch(None)
                }
            }

            // new-instance vA, type@BBBB — allocate a fresh object sentinel
            0x22 => {
                if let Some(va) = instr.v_a {
                    // Extract the type descriptor from instruction_str, e.g. "Ljavax/crypto/spec/SecretKeySpec;"
                    let type_str = instr.instruction_str
                        .split_whitespace()
                        .last()
                        .unwrap_or("object")
                        .to_string();
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::Str(type_str));
                    }
                }
                InstrResult::Continue
            }

            // invoke-virtual/super/direct/static/interface {args}, method  (35c)
            // invoke-*/range {vC..vN}, method                              (3rc)
            0x6e..=0x72 | 0x74..=0x78 => {
                // ── Collect argument register indices ──────────────────────
                let arg_regs: Vec<usize> = if op >= 0x74 {
                    // range: first = vC, count = vA
                    let first = instr.v_c.unwrap_or(0) as usize;
                    let count = instr.v_a.unwrap_or(0) as usize;
                    (first..first + count).collect()
                } else {
                    // 35c: up to 5 regs (vC..vG), count = vA
                    let count = instr.v_a.unwrap_or(0) as usize;
                    [instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g]
                        .iter()
                        .take(count.min(5))
                        .filter_map(|&r| r.map(|v| v as usize))
                        .collect()
                };

                let args: Vec<Value> = arg_regs.iter()
                    .map(|&r| registers.get(r).and_then(|v| v.clone()).unwrap_or(Value::Null))
                    .collect();

                // ── Parse method reference from instruction_str ────────────
                // Format: "invoke-xxx {v0, v1}, Lclass;->method(proto)ret"
                //      or "invoke-xxx/range {v0 .. v2}, Lclass;->method(...)"
                let after_brace = instr.instruction_str
                    .splitn(2, "}, ")
                    .nth(1)
                    .unwrap_or("");

                // Strip proto+return: "Lclass;->method(...)ret" → "Lclass;->method"
                let method_ref = after_brace.split('(').next().unwrap_or("").trim();

                // Keep class/method as borrowed slices into the instruction
                // string — `find_and_clone_method` and the `<init>` check
                // both take `&str`, so the old `.to_string()` pair was pure
                // waste on every invoke.
                let mut ref_parts = method_ref.splitn(2, "->");
                let class_name  = ref_parts.next().unwrap_or("");
                let method_name = ref_parts.next().unwrap_or("");

                // ── Try mock registry first ────────────────────────────────
                // try_execute returns Some(_) if a mock was registered (even
                // if the mock itself returns void/None), or None if no mock
                // exists.  This lets void mocks block the DEX fallback.
                //
                // Two keys are computed:
                //   short_key — class + method name only   (catches all overloads)
                //   full_key  — class + method + signature (overload-specific match)
                // Priority: exact-sig dynamic > name-only dynamic > built-in static.
                //
                // The signature-specific `full_key` is only consulted against
                // the dynamic-mock table, so when no dynamic mocks are
                // registered (the pure static-deobfuscation case) we skip
                // building it entirely — it's the single most expensive
                // string transform in the invoke path.
                let mock_key = MockRegistry::method_fqn_to_key(method_ref);
                let full_mock_key = if self.mocks.has_dynamic_mocks() {
                    MockRegistry::method_fqn_to_full_key(after_brace.trim())
                } else {
                    mock_key.clone()
                };
                let result = match self.mocks.try_execute(&mock_key, &full_mock_key, &args, &mut self.mock_state) {
                    Some(mock_result) => mock_result,   // mock hit (void or value)
                    None if !class_name.is_empty() && !method_name.is_empty() => {
                        // ── Try resource resolution before DEX lookup ──────
                        if let Some(v) = self.try_resolve_resource_call(&method_name, &args) {
                            Some(v)
                        } else if let Some(v) = self.try_jdk_builtin(method_ref, &args) {
                            // JDK stdlib — String.charAt, length, ctors, etc.
                            // These will never resolve via DEX lookup so the
                            // mini-stub layer is the only way to keep crypto
                            // / encoding chains from collapsing to null.
                            Some(v)
                        } else {
                            // ── No mock, no resource hit, no builtin —
                            //    fall back to DEX method lookup ──────────
                            let method = self.find_and_clone_method(class_name, method_name);
                            method.and_then(|m| self.call_method(&m, args))
                        }
                    }
                    None => None,
                };

                // For constructors (invoke-direct <init>), the JVM mutates the
                // `this` object in-place — there is never a move-result-object
                // after it.  Write the mock's return value back into the `this`
                // register (first arg register) so subsequent uses see the
                // constructed value instead of the raw new-instance sentinel.
                if method_name == "<init>" {
                    if let (Some(&this_reg), Some(ref val)) = (arg_regs.first(), &result) {
                        if let Some(slot) = registers.get_mut(this_reg) {
                            *slot = Some(val.clone());
                        }
                    }
                }

                self.memory.last_return = result;
                InstrResult::Continue
            }

            // throw
            0x27 => InstrResult::Return(None),

            // add-int / sub-int / mul-int / div-int / rem-int
            0x90..=0x9a => {
                if let (Some(va), Some(vb), Some(vc)) = (instr.v_a, instr.v_b, instr.v_c) {
                    let bv = registers.get(vb as usize).and_then(|v| v.as_ref()).and_then(|v| v.as_int()).unwrap_or(0);
                    let cv = registers.get(vc as usize).and_then(|v| v.as_ref()).and_then(|v| v.as_int()).unwrap_or(0);
                    let result = match op {
                        0x90 => bv.wrapping_add(cv),
                        0x91 => bv.wrapping_sub(cv),
                        0x92 => bv.wrapping_mul(cv),
                        0x93 => if cv != 0 { bv / cv } else { 0 },
                        0x94 => if cv != 0 { bv % cv } else { 0 },
                        0x95 => bv & cv,
                        0x96 => bv | cv,
                        0x97 => bv ^ cv,
                        0x98 => bv << (cv & 31),
                        0x99 => bv >> (cv & 31),
                        0x9a => ((bv as u64) >> ((cv & 31) as u64)) as i64,
                        _ => 0,
                    };
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::Int(result));
                    }
                }
                InstrResult::Continue
            }

            // ── Long binary ops (0x9b–0xa7).  Same shape as int ops
            //    but interpret the operands as i64 (which is what
            //    `Value::Int` already is — wide values fit in one
            //    register slot).  Result writes to vA only (the high
            //    half lives in vA+1 conceptually but we collapse).
            0x9b..=0xa7 => {
                if let (Some(va), Some(vb), Some(vc)) = (instr.v_a, instr.v_b, instr.v_c) {
                    let bv = registers.get(vb as usize)
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_int()).unwrap_or(0);
                    let cv = registers.get(vc as usize)
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_int()).unwrap_or(0);
                    let result = match op {
                        0x9b => bv.wrapping_add(cv),       // add-long
                        0x9c => bv.wrapping_sub(cv),       // sub-long
                        0x9d => bv.wrapping_mul(cv),       // mul-long
                        0x9e => if cv != 0 { bv / cv } else { 0 },
                        0x9f => if cv != 0 { bv % cv } else { 0 },
                        0xa0 => bv & cv,                   // and-long
                        0xa1 => bv | cv,                   // or-long
                        0xa2 => bv ^ cv,                   // xor-long
                        0xa3 => bv.wrapping_shl((cv & 63) as u32),
                        0xa4 => bv.wrapping_shr((cv & 63) as u32),
                        0xa5 => ((bv as u64) >> ((cv & 63) as u64)) as i64, // ushr-long
                        // 0xa6 add-float, 0xa7 sub-float — treat as int for now
                        _ => bv,
                    };
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::Int(result));
                    }
                }
                InstrResult::Continue
            }

            // ── 2addr binary ops (0xb0–0xcf).  vA = vA op vB.
            //    Covers add-int/2addr through ushr-long/2addr in one
            //    block — the operation is selected by the same
            //    op-number → operator table the 3-operand forms use.
            0xb0..=0xcf => {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    let av = registers.get(va as usize)
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_int()).unwrap_or(0);
                    let bv = registers.get(vb as usize)
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_int()).unwrap_or(0);
                    let result = match op {
                        // int/2addr
                        0xb0 => av.wrapping_add(bv),
                        0xb1 => av.wrapping_sub(bv),
                        0xb2 => av.wrapping_mul(bv),
                        0xb3 => if bv != 0 { av / bv } else { 0 },
                        0xb4 => if bv != 0 { av % bv } else { 0 },
                        0xb5 => av & bv,
                        0xb6 => av | bv,
                        0xb7 => av ^ bv,
                        0xb8 => av.wrapping_shl((bv & 31) as u32),
                        0xb9 => av.wrapping_shr((bv & 31) as u32),
                        0xba => ((av as i32 as u32) >> ((bv & 31) as u32)) as i64,
                        // long/2addr
                        0xbb => av.wrapping_add(bv),
                        0xbc => av.wrapping_sub(bv),
                        0xbd => av.wrapping_mul(bv),
                        0xbe => if bv != 0 { av / bv } else { 0 },
                        0xbf => if bv != 0 { av % bv } else { 0 },
                        0xc0 => av & bv,
                        0xc1 => av | bv,
                        0xc2 => av ^ bv,
                        0xc3 => av.wrapping_shl((bv & 63) as u32),
                        0xc4 => av.wrapping_shr((bv & 63) as u32),
                        0xc5 => ((av as u64) >> ((bv & 63) as u64)) as i64,
                        // float/double/2addr — treat as int. Real float
                        // support requires a Value::Float arithmetic
                        // path; out of scope here.
                        _ => av,
                    };
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::Int(result));
                    }
                }
                InstrResult::Continue
            }

            // ── Literal-arg binary ops (0xd0–0xe2).
            //    vA = vB op #literal.  Where v_a = dst, v_b = src,
            //    v_c = literal.  Shift-with-lit8 (0xe0–0xe2) is one
            //    block, lit16 (0xd0–0xd7) another, lit8 reverse-sub
            //    too.  Use the same int-op table as 0x90-0x9a.
            0xd0..=0xe2 => {
                if let (Some(va), Some(vb), Some(lit)) = (instr.v_a, instr.v_b, instr.v_c) {
                    let bv = registers.get(vb as usize)
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_int()).unwrap_or(0);
                    let result = match op {
                        // lit16
                        0xd0 => bv.wrapping_add(lit),
                        0xd1 => lit.wrapping_sub(bv),     // rsub-int (note: lit - bv)
                        0xd2 => bv.wrapping_mul(lit),
                        0xd3 => if lit != 0 { bv / lit } else { 0 },
                        0xd4 => if lit != 0 { bv % lit } else { 0 },
                        0xd5 => bv & lit,
                        0xd6 => bv | lit,
                        0xd7 => bv ^ lit,
                        // lit8
                        0xd8 => bv.wrapping_add(lit),
                        0xd9 => lit.wrapping_sub(bv),     // rsub-int/lit8 (lit - bv)
                        0xda => bv.wrapping_mul(lit),
                        0xdb => if lit != 0 { bv / lit } else { 0 },
                        0xdc => if lit != 0 { bv % lit } else { 0 },
                        0xdd => bv & lit,
                        0xde => bv | lit,
                        0xdf => bv ^ lit,
                        // shl/shr/ushr int/lit8 — only low 5 bits of lit count.
                        0xe0 => bv.wrapping_shl((lit & 31) as u32),
                        0xe1 => bv.wrapping_shr((lit & 31) as u32),
                        0xe2 => ((bv as i32 as u32) >> ((lit & 31) as u32)) as i64,
                        _ => bv,
                    };
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::Int(result));
                    }
                }
                InstrResult::Continue
            }

            // ── Type-conversion ops (0x81–0x8f).
            //    vA = (type) vB.  Since `Value::Int` is i64, most
            //    conversions are no-ops at the storage level — but
            //    int-to-short / int-to-byte / int-to-char DO truncate
            //    and we honour that for round-trip correctness in
            //    crypto-ish code paths.
            0x81..=0x8f => {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    let bv = registers.get(vb as usize)
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_int()).unwrap_or(0);
                    let result: i64 = match op {
                        0x81 => bv,                    // int-to-long  (sign-extend; bv is already i64)
                        0x82 => bv,                    // int-to-float (skip Value::Float for now)
                        0x83 => bv,                    // int-to-double
                        0x84 => bv as i32 as i64,      // long-to-int (truncate low 32 bits)
                        0x85 => bv,                    // long-to-float
                        0x86 => bv,                    // long-to-double
                        0x87 => bv,                    // float-to-int
                        0x88 => bv,                    // float-to-long
                        0x89 => bv,                    // float-to-double
                        0x8a => bv,                    // double-to-int
                        0x8b => bv,                    // double-to-long
                        0x8c => bv,                    // double-to-float
                        0x8d => bv as i8 as i64,       // int-to-byte
                        0x8e => bv as u16 as i64,      // int-to-char (zero-extend!)
                        0x8f => bv as i16 as i64,      // int-to-short
                        _ => bv,
                    };
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::Int(result));
                    }
                }
                InstrResult::Continue
            }

            // ── Array length (0x21) ──────────────────────────────────
            0x21 => {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    let len = registers.get(vb as usize)
                        .and_then(|v| v.as_ref())
                        .map(|v| match v {
                            Value::Array(_) => v.array_len().unwrap_or(0) as i64,
                            Value::Bytes(b) => b.len() as i64,
                            Value::Str(s)   => s.len() as i64,
                            _               => 0,
                        })
                        .unwrap_or(0);
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::Int(len));
                    }
                }
                InstrResult::Continue
            }

            // ── new-array vA, vB, type@CCCC ─────────────────────────
            //    vA = newly-allocated array of length vB.  We use
            //    Value::Array filled with Value::Null — primitive
            //    arrays are also Array<Null> until something writes
            //    real values into them (no per-element type metadata
            //    yet; matches our untyped-register model).
            0x23 => {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    let len = registers.get(vb as usize)
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_int()).unwrap_or(0)
                        .max(0) as usize;
                    // Cap allocations so a hostile/buggy const can't
                    // OOM the host.
                    const MAX_ARRAY: usize = 1 << 20;
                    let cap_len = len.min(MAX_ARRAY);
                    let arr = vec![Value::Null; cap_len];
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(Value::new_array(arr));
                    }
                }
                InstrResult::Continue
            }

            // ── aget vA, vB, vC ─ aget-* (0x44–0x4a) ────────────────
            //    vA = vB[vC].  All variants (aget, aget-wide, -object,
            //    -boolean, -byte, -char, -short) collapse to the same
            //    Value-typed read; the high half of wide elements is
            //    discarded (we store wide as a single Int).
            0x44..=0x4a => {
                if let (Some(va), Some(vb), Some(vc)) = (instr.v_a, instr.v_b, instr.v_c) {
                    let idx = registers.get(vc as usize)
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_int()).unwrap_or(0) as usize;
                    let val = registers.get(vb as usize)
                        .and_then(|v| v.as_ref())
                        .and_then(|v| match v {
                            Value::Array(_) => v.array_get(idx),
                            Value::Bytes(b) => b.get(idx).map(|&n| Value::Int(n as i64)),
                            Value::Str(s)   => s.chars().nth(idx)
                                                  .map(|c| Value::Int(c as i64)),
                            _               => None,
                        })
                        .unwrap_or(Value::Null);
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(val);
                    }
                }
                InstrResult::Continue
            }

            // ── Static + instance field reads (0x52–0x6d).
            //
            // Field ref lives in `instruction_str` after the registers
            // — e.g. `sget-object v0, Lcom/Foo;->BAR:[Ljava/lang/String;`.
            // We key by the full `class;->name` string and stash values
            // in `memory.static_fields` (re-using the existing
            // HashMap<usize, Value> via a string-hash bridge — see
            // `field_storage_key`).
            //
            // 0x60–0x66 = sget*, 0x67–0x6d = sput*
            // 0x52–0x58 = iget*, 0x59–0x5f = iput*
            0x60..=0x66 => {
                // sget — read static field into vA.
                if let Some(va) = instr.v_a {
                    let field_key = parse_field_ref(&instr.instruction_str);
                    let val = self.read_static_field(&field_key);
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(val);
                    }
                }
                InstrResult::Continue
            }
            0x67..=0x6d => {
                // sput — write vA to static field.
                if let Some(va) = instr.v_a {
                    let field_key = parse_field_ref(&instr.instruction_str);
                    let val = registers.get(va as usize)
                        .and_then(|v| v.clone()).unwrap_or(Value::Null);
                    self.write_static_field(field_key, val);
                }
                InstrResult::Continue
            }
            0x52..=0x58 => {
                // iget — read instance field. Without a real object
                // identity model we store per-instance fields in the
                // same static map keyed by `<class>;->name`; this is
                // wrong for multi-instance code but is enough for
                // the common case where there's a single instance
                // (singleton-style obfuscation).
                if let (Some(va), Some(_vb)) = (instr.v_a, instr.v_b) {
                    let field_key = parse_field_ref(&instr.instruction_str);
                    let val = self.read_static_field(&field_key);
                    if let Some(slot) = registers.get_mut(va as usize) {
                        *slot = Some(val);
                    }
                }
                InstrResult::Continue
            }
            0x59..=0x5f => {
                // iput — same caveat as iget above.
                if let (Some(va), Some(_vb)) = (instr.v_a, instr.v_b) {
                    let field_key = parse_field_ref(&instr.instruction_str);
                    let val = registers.get(va as usize)
                        .and_then(|v| v.clone()).unwrap_or(Value::Null);
                    self.write_static_field(field_key, val);
                }
                InstrResult::Continue
            }

            // ── aput vA, vB, vC ─ aput-* (0x4b–0x51) ────────────────
            //    vB[vC] = vA.  Mutates the array in-place inside the
            //    Value::Array; if vB doesn't hold an array (e.g. it
            //    was clobbered) we silently no-op.
            0x4b..=0x51 => {
                if let (Some(va), Some(vb), Some(vc)) = (instr.v_a, instr.v_b, instr.v_c) {
                    let value = registers.get(va as usize)
                        .and_then(|v| v.clone()).unwrap_or(Value::Null);
                    let idx = registers.get(vc as usize)
                        .and_then(|v| v.as_ref()).and_then(|v| v.as_int()).unwrap_or(0) as usize;
                    // For Arrays, mutate through the shared handle —
                    // this is what propagates aput writes back to a
                    // previously-sput'd static field.
                    let did_array = registers.get(vb as usize)
                        .and_then(|s| s.as_ref())
                        .map(|v| matches!(v, Value::Array(_)) && v.array_set(idx, value.clone()))
                        .unwrap_or(false);
                    if !did_array {
                        // Try Bytes fallback (still owned, mutate via slot).
                        if let Some(slot) = registers.get_mut(vb as usize) {
                            if let Some(Value::Bytes(ref mut b)) = slot {
                                if let Some(byte) = b.get_mut(idx) {
                                    if let Some(n) = value.as_int() {
                                        *byte = n as u8;
                                    }
                                }
                            }
                        }
                    }
                }
                InstrResult::Continue
            }

            // Anything else — treat as a no-op for now
            _ => InstrResult::Continue,
        }
    }

    /// Execute all instructions in a basic block and return the next block id.
    fn execute_block(
        &mut self,
        block_id: usize,
        cfg: &Cfg,
        instructions: &[Instruction],
        registers: &mut Registers,
    ) -> Option<usize> {
        let block = &cfg.blocks[block_id];

        for &instr_idx in &block.instr_indices {
            // Instruction budget — abort silently when exhausted
            if let Some(ref mut budget) = self.instr_budget {
                if *budget == 0 {
                    if let Some(ref log) = self.logger {
                        log.log_error("instruction budget exhausted — terminating");
                    }
                    if let Some(ref mut dbg) = self.debugger {
                        dbg.on_finished(PauseReason::BudgetExhausted);
                    }
                    self.memory.last_return = None;
                    return None;
                }
                *budget -= 1;
            }

            let instr = &instructions[instr_idx];

            // Debugger consult — captures a snapshot and decides whether
            // to run this instruction. If it returns Pause we abort the
            // whole call_method run and let the host poll the debugger
            // state. The pending instruction stays "next-to-run" so a
            // later `resume()` + repeat `call_method` will pick up here.
            if let Some(ref mut dbg) = self.debugger {
                let current_method_fqn = self.call_stack.last().cloned().unwrap_or_default();
                let depth = self.call_stack.len();
                let dec = dbg.before_instruction(
                    &current_method_fqn,
                    instr.codepoint,
                    depth,
                    registers,
                    &self.memory.last_return,
                    &instr.instruction_str,
                );
                if let StepDecision::Pause = dec {
                    return None; // surfaces to call_method which returns None
                }
            }

            // fill-array-data (0x26) needs the payload, which lives at another
            // instruction in the stream — resolve + copy it here, where we have
            // `instructions`. (`execute_instruction`/`execute_array` can't see
            // the stream and no-op it, which is why decoder byte arrays used to
            // come out zero-filled and string decryption produced garbage.)
            if instr.opcode == 0x26 {
                fill_array_data_inplace(instr, instructions, registers);
            }

            let result = self.execute_instruction(instr, registers);

            match result {
                InstrResult::Return(val) => {
                    self.memory.last_return = val;
                    return None;
                }
                InstrResult::Goto(target_cp) => {
                    if let Some(ref log) = self.logger {
                        log.log_branch(true, target_cp);
                    }
                    return cfg.addr_lookup.get(&target_cp).copied();
                }
                InstrResult::Branch(Some(target_cp)) => {
                    if let Some(ref log) = self.logger {
                        log.log_branch(true, target_cp);
                    }
                    return cfg.addr_lookup.get(&target_cp).copied();
                }
                InstrResult::Branch(None) => {
                    if let Some(ref log) = self.logger {
                        log.log_branch(false, 0);
                    }
                    return self.fall_through_block(block_id, cfg);
                }
                InstrResult::Continue => {}
            }
        }

        self.fall_through_block(block_id, cfg)
    }

    fn fall_through_block(&self, block_id: usize, cfg: &Cfg) -> Option<usize> {
        let block = &cfg.blocks[block_id];
        for &edge_idx in &block.successor_edges {
            let edge = &cfg.edges[edge_idx];
            if edge.kind == EdgeKind::FallThrough {
                return Some(edge.target_id);
            }
        }
        None
    }

    /// Run an interpreted method, returning its return value.
    pub fn call_method(
        &mut self,
        method: &Method,
        args: Vec<Value>,
    ) -> Option<Value> {
        // Safety limit
        if self.call_stack.len() >= 16 {
            if let Some(ref log) = self.logger {
                log.log_error("call stack depth limit reached");
            } else {
                eprintln!("[-] Call stack depth exceeded");
            }
            return None;
        }

        let fqn = format!("{}->{}", method.class_name, method.method_name);
        if self.method_denylist.iter().any(|d| fqn.contains(d.as_str())) {
            return None;
        }

        let cfg = method.cfg.as_ref()?;
        let reg_count   = method.registers_size as usize;

        let mut registers = make_registers(reg_count);

        // Slot layout: params occupy the *trailing* registers of the
        // callee's register file. Wide args (J/D) consume two slots —
        // the caller's invoke-* handler already split them into two
        // entries in `args` (one per slot), so we copy 1:1 here.
        //
        // Historically this loop tried to advance the cursor by the
        // per-arg width from `arg_widths`, expecting `args` to have one
        // entry per *parameter*. That was inconsistent with the invoke
        // side, which packs one entry per *register operand* — for
        // `invoke-static {v11, v13, v0, v1}` we get four entries, and
        // for a (I[String;J) callee the last two are the J halves.
        // With the old behaviour, the array argument fell off the end
        // and was silently dropped, leaving the callee with a null
        // array reference (see commit message for the SystemAndroid
        // empty-string repro).
        let arg_widths = param_slot_widths(&method.proto_desc, &method.method_type);
        let total_slots: usize = arg_widths.iter().sum();
        let param_start = reg_count.saturating_sub(total_slots.max(args.len()));

        if let Some(ref mut log) = self.logger {
            log.log_enter(&method.class_name, &method.method_name, &args);
            log.depth += 1;
        }

        for (i, val) in args.into_iter().enumerate() {
            let slot = param_start + i;
            if slot >= reg_count { break; }
            registers[slot] = Some(val);
        }

        self.call_stack.push(fqn);
        // Sample for spawn-time peak-depth tracking (no-op outside a spawn).
        if self.call_stack.len() > self.peak_call_depth_during_spawn {
            self.peak_call_depth_during_spawn = self.call_stack.len();
        }

        // Borrow the method's instructions + CFG for the whole run instead
        // of cloning them per block. `method` is owned by the caller (never
        // aliased through `self`), so these immutable borrows coexist fine
        // with the `&mut self` calls inside `execute_block` — including the
        // recursive `call_method` for nested invokes, which borrows a
        // *different* method. Previously this cloned the entire
        // `Vec<Instruction>` (each element owning a `String` + `Vec<i64>`)
        // on every basic-block transition: for a hot deobfuscation helper
        // that's the dominant cost. Borrowing makes the inner loop
        // allocation-free.
        let instructions: &[Instruction] = &method.instructions;
        let cfg: &Cfg = method.cfg.as_ref().unwrap();
        let mut current_block_id = Some(0usize);
        while let Some(bid) = current_block_id {
            current_block_id = self.execute_block(bid, cfg, instructions, &mut registers);
        }

        self.call_stack.pop();
        let result = self.memory.last_return.clone();

        if let Some(ref mut log) = self.logger {
            log.depth = log.depth.saturating_sub(1);
            log.log_exit(&method.class_name, &method.method_name, &result);
        }

        result
    }

    // ── Threading ────────────────────────────────────────────────────────────
    //
    // Cooperative model: each `spawn_method` runs the named method on a
    // *fresh* register file + isolated call stack (we save and restore
    // the VM's main call_stack across the spawn so a "thread" can't
    // accidentally see frames from its spawner). The heap (`Memory`)
    // stays shared — matches JVM semantics where instance/static
    // fields are visible across threads.
    //
    // v1 is sequential: spawn runs to completion synchronously. The
    // result lives in `self.threads` for the host UI to poll. v2 can
    // swap in real preemptive scheduling without breaking callers.

    /// Spawn `method(args)` on a new logical thread. Runs synchronously
    /// and returns a handle the caller can use to look up the result
    /// via [`Vm::thread_status`].
    ///
    /// `name` is a free-form label — the FQ method ref is a sensible
    /// default; runnable class names also work.
    pub fn spawn_method(
        &mut self,
        method: &platypus_dex::method::Method,
        args: Vec<Value>,
        name: impl Into<String>,
    ) -> ThreadHandle {
        let handle = self.threads.register(name.into());
        self.threads.mark_running(handle);

        // Save the spawner's call stack so the spawned thread runs on
        // its own. The shared heap is intentional (matches JVM).
        let saved_call_stack = std::mem::take(&mut self.call_stack);

        let mut peak_depth = 0usize;
        let result = if method.cfg.is_none() {
            ThreadStatus::Failed("method has no CFG (likely native or abstract)".into())
        } else {
            // `call_method` pushes onto `self.call_stack` and samples
            // `peak_call_depth_during_spawn` after each push — we read
            // the mirror back here once the call returns. The spawner's
            // own call stack stays empty for the duration because we
            // swapped it out above.
            let v = self.call_method(method, args);
            peak_depth = self.peak_call_depth_during_spawn;
            self.peak_call_depth_during_spawn = 0;
            match v {
                Some(val) => ThreadStatus::Completed(val),
                None      => ThreadStatus::Completed(Value::Null),
            }
        };

        // Restore the spawner's call stack.
        self.call_stack = saved_call_stack;
        self.threads.finish(handle, result, peak_depth);
        handle
    }

    /// Status of a spawned thread (or `None` if the handle is bogus).
    pub fn thread_status(&self, handle: ThreadHandle) -> Option<ThreadStatus> {
        self.threads.status(handle)
    }

    /// Full record of one thread — name, status, timing, peak depth.
    pub fn thread_info(&self, handle: ThreadHandle) -> Option<&ThreadInfo> {
        self.threads.get(handle)
    }

    /// All threads spawned in this session (newest last).
    pub fn list_threads(&self) -> &[ThreadInfo] {
        self.threads.list()
    }

    /// Wait for a thread to terminate and return its final value. In
    /// the v1 sequential scheduler `spawn_method` already ran to
    /// completion before returning the handle, so this just looks up
    /// the recorded value — but the signature is set up so v2 can
    /// actually block on a JoinHandle/oneshot without changing callers.
    pub fn join_thread(&self, handle: ThreadHandle) -> Option<Value> {
        match self.thread_status(handle)? {
            ThreadStatus::Completed(v) => Some(v),
            _ => None,
        }
    }

    /// Drop every thread that's terminal. Useful for long-running
    /// sessions where the audit trail would otherwise grow forever.
    pub fn clear_finished_threads(&mut self) {
        self.threads.clear_finished();
    }

    /// Search all loaded DEX files for a method with the given class and method name.
    /// Returns a cloned `Method` so the borrow of `self.dex_files` ends before any
    /// recursive `call_method` call.
    pub fn find_and_clone_method(&mut self, class: &str, method_name: &str) -> Option<platypus_dex::method::Method> {
        let class_norm = class.trim_start_matches('L').trim_end_matches(';');
        let cache_key = (class_norm.to_string(), method_name.to_string());

        // Fast path: cached resolution. Clone the Method out — it's
        // designed to be cheap to clone (large interior data lives
        // in Arc/Rc).
        if let Some(cached) = self.method_cache.get(&cache_key) {
            return cached.clone();
        }

        // Cache miss — resolve via class_index (O(1)) then Clazz::new
        // (decodes the class's methods; expensive once).
        let resolved: Option<platypus_dex::method::Method> = self.class_index
            .get(class_norm)
            .copied()
            .and_then(|(dex_idx, cd_idx)| {
                let dex = self.dex_files.get(dex_idx)?;
                let cd  = dex.parsed.class_defs.get(cd_idx)?;
                let clazz = Clazz::new(cd, dex).ok()?;
                clazz.methods.into_iter().find(|m| m.method_name == method_name)
            })
            .or_else(|| {
                // Fallback linear scan — only if class_index missed
                // (shouldn't happen in practice).
                for dex in &self.dex_files {
                    for cd in &dex.parsed.class_defs {
                        let cd_norm = cd.type_name.trim_start_matches('L').trim_end_matches(';');
                        if cd_norm != class_norm { continue; }
                        if let Ok(clazz) = Clazz::new(cd, dex) {
                            if let Some(m) = clazz.methods.into_iter().find(|m| m.method_name == method_name) {
                                return Some(m);
                            }
                        }
                    }
                }
                None
            });

        self.method_cache.insert(cache_key, resolved.clone());
        resolved
    }
}

impl Default for Vm {
    fn default() -> Self { Self::new() }
}

// ── Field-reference parsing helpers ──────────────────────────────────────────

/// Extract the `class;->name` portion from a sget/sput/iget/iput
/// instruction string. Format we expect:
///
/// ```text
///   sget-object v0, Lcom/Foo;->BAR: [Ljava/lang/String;
///   iput-object v1, v2, Lcom/Foo;->baz: Ljava/lang/String;
/// ```
///
/// Returns `"Lcom/Foo;->BAR"` (with no trailing type descriptor).
fn parse_field_ref(istr: &str) -> String {
    // Find the LAST `L…;->` — earlier `L…;` substrings can appear in
    // multi-register operand lists, but the field ref is always the
    // last thing on the line.
    let Some(arrow) = istr.rfind(";->") else { return String::new() };
    // class portion: walk backward from the arrow to the matching `L`.
    let Some(class_start) = istr[..arrow].rfind('L') else { return String::new() };
    let class_part = &istr[class_start..arrow + 1]; // include `;`

    let after_arrow = &istr[arrow + 3..];
    let name_end = after_arrow.find(':').unwrap_or(after_arrow.len());
    let name = after_arrow[..name_end].trim();

    format!("{class_part}->{name}")
}

/// Parse a method's proto descriptor (`"(JLjava/lang/String;)V"`) into
/// the slot width of each *user* argument — 2 for `J`/`D`, 1 for
/// everything else. Instance methods get a prepended 1-slot `this`.
///
/// The result lines up with the caller's `args: Vec<Value>` so the
/// `call_method` placement loop knows how many register slots each
/// arg consumes.
fn param_slot_widths(proto: &str, method_type: &platypus_dex::method::MethodType) -> Vec<usize> {
    use platypus_dex::method::MethodType;
    let mut widths = Vec::new();
    // Instance methods: implicit `this` is a single ref slot.
    if !matches!(method_type, MethodType::Direct) {
        // Direct = static / private / constructor — no implicit `this`
        // (except constructors, but those callers pre-place `this` as
        // args[0] like we do for instance methods). Conservatively
        // skip implicit `this` only for the unambiguous Direct case.
    }
    // Strip optional leading `(`.
    let mut chars = proto.trim_start_matches('(').chars();
    while let Some(c) = chars.next() {
        match c {
            ')' => break,
            'J' | 'D' => widths.push(2),
            'L' => {
                // Object — consume until the next ';'.
                while let Some(ch) = chars.next() {
                    if ch == ';' { break; }
                }
                widths.push(1);
            }
            '[' => {
                // Array — recurse over the element type.
                // Most array sub-elements end up 1 slot in the args; only
                // a primitive long/double array marker would matter (which
                // doesn't change the slot width of an array reference).
                // Skip subsequent `[`s, then consume the element type.
                let mut next = chars.next();
                while let Some('[') = next { next = chars.next(); }
                if let Some('L') = next {
                    while let Some(ch) = chars.next() {
                        if ch == ';' { break; }
                    }
                }
                widths.push(1);
            }
            // Single-slot primitive: B, S, C, I, F, Z (byte, short,
            // char, int, float, boolean).
            _ => widths.push(1),
        }
    }
    widths
}

/// Stable hash of a field-ref string into a `usize` for use as a key
/// in the existing `Memory::static_fields: HashMap<usize, Value>` map.
/// We can't change the map's key type (it's also used by the old
/// per-method-index path) so hash bridging is the cheapest fix.
fn field_storage_key(field_ref: &str) -> usize {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    field_ref.hash(&mut h);
    h.finish() as usize
}

/// Copy a `fill-array-data` payload into the array held in register `v_a`.
///
/// The payload (`InstructionKind::FillArrayDataPayload`) lives at a separate
/// codepoint reached via the `31t` branch offset in `v_b`. `new-array`
/// represents the array as `Value::Array` (Arc-shared), so writing through the
/// cloned handle is visible to the register — which is how a decoder's
/// `fill-array-data` + `new String(byte[], …)` recovers its plaintext.
fn fill_array_data_inplace(instr: &Instruction, instructions: &[Instruction], registers: &Registers) {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let off = (instr.v_b.unwrap_or(0) as u32 as i32) as i64;
    let target = instr.codepoint as i64 + off;

    let payload = instructions.iter().find_map(|p| match &p.kind {
        InstructionKind::FillArrayDataPayload { element_width, data, .. }
            if p.codepoint as i64 == target =>
        {
            Some((*element_width as usize, data.clone()))
        }
        _ => None,
    });
    let Some((width, data)) = payload else { return };
    if width == 0 {
        return;
    }
    let Some(arr) = crate::opcodes::read_val(registers, v_a) else { return };

    for (i, chunk) in data.chunks(width).enumerate() {
        if chunk.len() < width {
            break;
        }
        // Little-endian element. Byte arrays decode as unsigned 0..255 so the
        // `String(byte[])` path (which masks `& 0xffff`) maps each to the
        // correct character.
        let mut raw: u64 = 0;
        for (b, &byte) in chunk.iter().enumerate() {
            raw |= (byte as u64) << (8 * b);
        }
        arr.array_set(i, Value::Int(raw as i64));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_field_ref_handles_sget_object() {
        let istr = "sget-object v0, Lcom/example/Foo;->BAR: [Ljava/lang/String;";
        assert_eq!(parse_field_ref(istr), "Lcom/example/Foo;->BAR");
    }

    #[test]
    fn parse_field_ref_handles_iput_with_two_regs() {
        let istr = "iput-object v1, v2, Lcom/example/Foo;->baz: Ljava/lang/String;";
        assert_eq!(parse_field_ref(istr), "Lcom/example/Foo;->baz");
    }

    #[test]
    fn parse_field_ref_returns_empty_for_garbage() {
        assert_eq!(parse_field_ref("nop"), "");
    }

    #[test]
    fn static_field_round_trip() {
        let mut vm = Vm::new();
        vm.write_static_field("Lcom/X;->Y".to_string(), Value::Int(42));
        match vm.read_static_field("Lcom/X;->Y") {
            Value::Int(n) => assert_eq!(n, 42),
            other => panic!("expected Int(42), got {other:?}"),
        }
    }

    // ── Faithful-mode dispatch tests ────────────────────────
    //
    // Spec-correct vs Python-quirk-faithful dispatch should diverge
    // on opcodes where Python has known bugs. These tests pin both
    // sides of the divergence so a regression in either direction
    // is caught.

    use platypus_dex::instructions::{ControlFlow, InstructionKind};

    fn make_ifz(opcode: u8, v_a: i64, offset: i64, codepoint: u32) -> Instruction {
        Instruction {
            opcode, address: 0, codepoint, fmt: "21t",
            instruction_str: String::new(), width: 1,
            control_flow: ControlFlow::Branch,
            kind: InstructionKind::IfZ,
            v_a: Some(v_a), v_b: Some(offset),
            v_c: None, v_d: None, v_e: None, v_f: None,
            v_g: None, v_h: None, v_z: None,
            operands: vec![v_a, offset],
        }
    }

    #[test]
    fn faithful_mode_off_uses_spec_correct_if_eqz() {
        // Spec: if-eqz v0 with v0=0 → branch taken.
        let mut vm = Vm::new();
        // Default faithful_mode is false.
        assert!(!vm.faithful_mode);
        let mut regs: Registers = vec![Some(Value::Int(0))];
        let instr = make_ifz(0x38, 0, 50, 100);
        let result = vm.execute_instruction(&instr, &mut regs);
        match result {
            InstrResult::Branch(Some(t)) => assert_eq!(t, 150),
            other => panic!("spec mode should branch, got {:?}", other),
        }
    }

    #[test]
    fn faithful_mode_on_preserves_python_if_eqz_bug() {
        // Python bug: if-eqz v0 with v0=0 → NOT taken (gate fails).
        let mut vm = Vm::new();
        vm.set_faithful_mode(true);
        let mut regs: Registers = vec![Some(Value::Int(0))];
        let instr = make_ifz(0x38, 0, 50, 100);
        let result = vm.execute_instruction(&instr, &mut regs);
        match result {
            InstrResult::Branch(None) => {},
            other => panic!("faithful mode should NOT branch (Python bug), got {:?}", other),
        }
    }

    #[test]
    fn faithful_mode_only_affects_covered_opcodes() {
        // Move (0x01) is NOT in the opcodes-module's range — should
        // go through the inline path regardless of faithful_mode.
        let mut vm = Vm::new();
        vm.set_faithful_mode(true);
        let mut regs: Registers = vec![None, Some(Value::Int(42))];
        let instr = Instruction {
            opcode: 0x01, address: 0, codepoint: 0, fmt: "12x",
            instruction_str: String::new(), width: 1,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::Move,
            v_a: Some(0), v_b: Some(1),
            v_c: None, v_d: None, v_e: None, v_f: None,
            v_g: None, v_h: None, v_z: None,
            operands: vec![0, 1],
        };
        vm.execute_instruction(&instr, &mut regs);
        // Move should have copied reg[1] → reg[0].
        match regs[0].as_ref() {
            Some(Value::Int(42)) => {},
            other => panic!("expected Int(42), got {:?}", other),
        }
    }

    /// Regression: `fill-array-data` used to be a no-op, so decoder byte arrays
    /// stayed zero-filled and string decryption produced garbage. The payload
    /// (at a separate codepoint) must be copied into the array register.
    #[test]
    fn fill_array_data_copies_payload_into_array() {
        // new-array already produced a 4-element array in reg 0.
        let registers: Registers = vec![Some(Value::new_array(vec![Value::Int(0); 4]))];
        // fill-array-data v0, +2  (payload sits 2 code units ahead).
        let fad = Instruction {
            opcode: 0x26, address: 0, codepoint: 0, fmt: "31t",
            instruction_str: String::new(), width: 3,
            control_flow: ControlFlow::FallThrough, kind: InstructionKind::Array,
            v_a: Some(0), v_b: Some(2),
            v_c: None, v_d: None, v_e: None, v_f: None, v_g: None, v_h: None, v_z: None,
            operands: vec![0, 2],
        };
        let payload = Instruction {
            opcode: 0x00, address: 0, codepoint: 2, fmt: "10x",
            instruction_str: String::new(), width: 6,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::FillArrayDataPayload {
                element_width: 1, element_count: 4, data: vec![0x41, 0x42, 0x43, 0x44],
            },
            v_a: None, v_b: None, v_c: None, v_d: None, v_e: None, v_f: None,
            v_g: None, v_h: None, v_z: None, operands: vec![],
        };

        fill_array_data_inplace(&fad, &[fad.clone(), payload], &registers);

        let arr = registers[0].as_ref().unwrap().array_snapshot().unwrap();
        let got: Vec<i64> = arr.iter().filter_map(|v| v.as_int()).collect();
        assert_eq!(got, vec![0x41, 0x42, 0x43, 0x44]);
    }
}
