//! Post-inflation modification discovery via DEX bytecode.
//!
//! After `setContentView` runs, most non-trivial activities mutate the
//! inflated tree at runtime — `findViewById(R.id.title).setText("Hello")`,
//! `findViewById(R.id.error).setVisibility(GONE)`, and so on. Those
//! modifications are invisible if you only read the layout XML, but they
//! often carry the most interesting strings (server URLs, dynamic labels,
//! feature-flag-gated visibility).
//!
//! For each method we recognise the canonical pattern:
//!
//! ```text
//! const v0, #R.id.title
//! invoke-virtual {p0, v0}, MainActivity;->findViewById(I)Landroid/view/View;
//! move-result-object v1
//! const-string v2, "Hello"
//! invoke-virtual {v1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
//! ```
//!
//! Any `invoke-virtual` whose method name starts with `set` and whose
//! receiver register can be traced back (≤80 instructions) to a
//! `findViewById(R.id.X)` produces one [`DynModHit`]. The argument is
//! resolved when it's a `const-string` / `const`/`const-class`; otherwise
//! we record the source instruction so the inspector can show "from
//! someMethod()" with a jump-to-source link.
//!
//! False positives are possible (e.g. arbitrary classes happen to have a
//! `set*` method whose receiver came from `findViewById`), but the receiver
//! class hint in the invoke ref keeps things tight in practice.

use std::collections::HashMap;

use platypus_dex::clazz::Clazz;
use platypus_dex::instructions::{Instruction, InstructionKind};
use platypus_dex::method::Method;
use platypus_dex::parser::DexFileWithRaw;

use crate::ir::DynMod;

const FIND_VIEW_BY_ID: &str = ";->findViewById(I)";

/// One discovered post-inflation modification.
#[derive(Debug, Clone)]
pub struct DynModHit {
    /// Resource id of the view this modification targets.
    pub view_id: u32,
    /// Setter name without the package or signature — `"setText"`,
    /// `"setVisibility"`, `"setBackgroundColor"`, …
    pub setter: String,
    /// Pre-formatted value — string literal in quotes, int/bool literal,
    /// symbolic constant name (`"View.GONE"`), or method ref when derived.
    pub value: String,
    /// Method that contained the modification — useful for jump-to-source.
    /// Format: `"<class>.<methodName>"` (dot-separated).
    pub from_method: String,
    /// True iff `value` is a literal we recovered from a `const*`. Renderers
    /// can show literals confidently; non-literals get a "derived" tag.
    pub literal: bool,
}

impl DynModHit {
    pub fn into_mod(self) -> DynMod {
        DynMod {
            setter: self.setter,
            value: self.value,
            from_method: self.from_method,
            literal: self.literal,
        }
    }
}

/// Discover every post-inflation modification on a view in the activity
/// class (and its inner classes). The returned hits are keyed by view id;
/// the IR builder groups them onto the matching view nodes.
///
/// `activity_fq_name` is FQ dot-separated.
pub fn discover_dynamics(
    dex_files: &[DexFileWithRaw],
    activity_fq_name: &str,
) -> Vec<DynModHit> {
    let class_norm = activity_fq_name.replace('.', "/");
    let mut hits = Vec::new();

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            // Activity itself OR any inner class.
            let is_activity_or_inner = def_norm == class_norm
                || def_norm.starts_with(&format!("{class_norm}$"));
            if !is_activity_or_inner { continue; }

            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for method in &clazz.methods {
                scan_method(method, def_norm, &mut hits);
            }
        }
    }
    hits
}

/// Group hits by view id — the IR builder needs a `HashMap<u32, Vec<DynMod>>`
/// to attach modifications onto the matching view nodes.
pub fn group_by_view_id(hits: Vec<DynModHit>) -> HashMap<u32, Vec<DynMod>> {
    let mut out: HashMap<u32, Vec<DynMod>> = HashMap::new();
    for h in hits {
        out.entry(h.view_id).or_default().push(h.into_mod());
    }
    out
}

// ── Per-method scanner ────────────────────────────────────────────────────

fn scan_method(method: &Method, owning_class_norm: &str, hits: &mut Vec<DynModHit>) {
    for (idx, instr) in method.instructions.iter().enumerate() {
        let istr = &instr.instruction_str;
        if !istr.contains("invoke") { continue; }

        // Quick skip: setter pattern is `->set` — short string, easy reject.
        let setter_name = match extract_set_method_name(istr) {
            Some(n) => n,
            None => continue,
        };

        // Skip findViewById/setOnClickListener/setContentView — these are
        // recognised by other phases and aren't "view modifications" in the
        // dynamic-state sense.
        if matches!(setter_name.as_str(),
            "setOnClickListener" | "setOnLongClickListener" | "setOnTouchListener"
            | "setContentView") {
            continue;
        }

        let arg_regs = invoke_arg_regs(instr);
        // arg 0 = receiver, arg 1+ = setter args (we only inspect the first).
        if arg_regs.is_empty() { continue; }
        let receiver_reg = arg_regs[0];

        // Trace receiver back to findViewById(R.id.X).
        let view_id = match trace_receiver_to_view_id(method, idx, receiver_reg) {
            Some(id) => id,
            None => continue,
        };

        // Format the value. If we have a single arg, try to recover it as a
        // literal; otherwise emit "derived" placeholder. Multi-arg setters
        // (rare on Views) collapse to "derived" too.
        let (value, literal) = match arg_regs.get(1) {
            Some(&arg_reg) if arg_regs.len() == 2 => {
                resolve_value_for(method, idx, arg_reg, &setter_name, instr)
            }
            None => ("()".to_string(), true), // no-arg setter
            _ => (format!("(derived: {} args)", arg_regs.len() - 1), false),
        };

        hits.push(DynModHit {
            view_id,
            setter: setter_name,
            value,
            from_method: format!(
                "{}.{}",
                owning_class_norm.replace('/', "."),
                method.method_name,
            ),
            literal,
        });
    }
}

// ── Receiver-trace (mirror of handlers.rs but kept local for clarity) ─────

fn trace_receiver_to_view_id(
    method: &Method,
    invoke_idx: usize,
    receiver_reg: u32,
) -> Option<u32> {
    const WINDOW: usize = 80;
    let start = invoke_idx.saturating_sub(WINDOW);

    // Find the latest `move-result-object` writing receiver_reg.
    let mut move_idx: Option<usize> = None;
    for i in (start..invoke_idx).rev() {
        let earlier = &method.instructions[i];
        if matches!(earlier.kind, InstructionKind::MoveResult)
            && earlier.v_a == Some(receiver_reg as i64)
        {
            move_idx = Some(i);
            break;
        }
        if writes_register(earlier, receiver_reg) {
            return None;
        }
    }
    let move_idx = move_idx?;
    if move_idx == 0 { return None; }

    // The invoke immediately before should be findViewById.
    let invoke = &method.instructions[move_idx - 1];
    if !invoke.instruction_str.contains(FIND_VIEW_BY_ID) {
        return None;
    }
    let arg_regs = invoke_arg_regs(invoke);
    let id_reg = *arg_regs.get(1)?;
    backward_const_for(method, move_idx - 1, id_reg)
}

// ── Value resolution ─────────────────────────────────────────────────────

/// Try to recover the value passed as the setter's single argument.
/// Returns `(formatted_value, is_literal)`.
fn resolve_value_for(
    method: &Method,
    invoke_idx: usize,
    arg_reg: u32,
    setter_name: &str,
    setter_instr: &Instruction,
) -> (String, bool) {
    const WINDOW: usize = 80;
    let start = invoke_idx.saturating_sub(WINDOW);

    for i in (start..invoke_idx).rev() {
        let earlier = &method.instructions[i];
        if !writes_register(earlier, arg_reg) { continue; }
        let istr = &earlier.instruction_str;

        // const-string vN, "the value"
        if istr.contains("const-string") {
            if let Some(s) = extract_const_string_value(istr) {
                return (format!("\"{s}\""), true);
            }
        }
        // const-class vN, LCom/Foo;
        if istr.contains("const-class") {
            if let Some(c) = extract_const_class_ref(istr) {
                return (format!("class {}", dex_class_to_short(&c)), true);
            }
        }
        // const vN, #int
        if matches!(earlier.kind, InstructionKind::Const) {
            if let Some(n) = earlier.v_b {
                let formatted = format_int_for_setter(setter_name, setter_instr, n as u32);
                return (formatted, true);
            }
        }
        // move-result(-object) — value came from another invoke. Pull the
        // method ref so the inspector can jump-to-source.
        if matches!(earlier.kind, InstructionKind::MoveResult) && i > 0 {
            let prev = &method.instructions[i - 1];
            if let Some(mref) = extract_invoke_method_ref(&prev.instruction_str) {
                return (mref, false);
            }
        }
        // iget-* — value came from an instance field.
        if istr.contains("iget") {
            if let Some(field) = extract_iget_field_ref(istr) {
                return (format!("field {field}"), false);
            }
        }
        // sget-* — static field.
        if istr.contains("sget") {
            if let Some(field) = extract_iget_field_ref(istr) {
                return (format!("static {field}"), false);
            }
        }
        // We hit a write we don't recognise — bail with "derived".
        return ("(derived)".to_string(), false);
    }
    ("(derived)".to_string(), false)
}

/// Pretty-print integer values for known setters. `setVisibility(0)` →
/// `"VISIBLE"`; `setBackgroundColor(0xff112233)` → `"#ff112233"`; etc.
fn format_int_for_setter(setter: &str, setter_instr: &Instruction, value: u32) -> String {
    match setter {
        "setVisibility" => match value {
            0 => "VISIBLE".to_string(),
            4 => "INVISIBLE".to_string(),
            8 => "GONE".to_string(),
            _ => format!("{value}"),
        },
        "setBackgroundColor" | "setTextColor" | "setForegroundColor" => {
            format!("#{value:08x}")
        }
        "setBackgroundResource" | "setImageResource" | "setForegroundResource" => {
            format!("@0x{value:08x}")
        }
        "setEnabled" | "setSelected" | "setActivated" | "setChecked"
        | "setClickable" | "setLongClickable" | "setFocusable" | "setHovered"
        | "setPressed" => {
            // Boolean setters: 0 = false, anything else = true.
            if value == 0 { "false".to_string() } else { "true".to_string() }
        }
        _ => {
            // If the setter signature suggests a float, decode the bits.
            let signature = &setter_instr.instruction_str;
            if signature.contains(")V") && signature.contains("(F)") {
                let f = f32::from_bits(value);
                if f.is_finite() {
                    return format!("{f}");
                }
            }
            format!("{value}")
        }
    }
}

// ── String / instruction helpers ─────────────────────────────────────────

/// Extract the bare method name `"setText"` from an invoke whose target
/// looks like `"…->setText(Ljava/lang/CharSequence;)V"`. Returns `None` if
/// the method name doesn't start with `set` or the parse fails.
fn extract_set_method_name(istr: &str) -> Option<String> {
    let arrow = istr.find("->")?;
    let after = &istr[arrow + 2..];
    let paren = after.find('(')?;
    let name = &after[..paren];
    if !name.starts_with("set") || name.len() < 4 { return None; }
    // Filter out constructors / static initializers and anything obviously
    // not a setter (e.g. `setUp` in a test class — won't have a View receiver
    // anyway, but cheap to skip).
    if name == "setUp" { return None; }
    Some(name.to_string())
}

fn extract_invoke_method_ref(istr: &str) -> Option<String> {
    let arrow = istr.rfind("->")?;
    let class_start = istr[..arrow].rfind('L')?;
    Some(istr[class_start..].trim_end_matches(['\n', ' ', ',']).to_string())
}

fn extract_iget_field_ref(istr: &str) -> Option<String> {
    // `iget* vN, vM, LOwner;->field:LType;` — return `LOwner;->field`
    let arrow = istr.find("->")?;
    let class_start = istr[..arrow].rfind('L')?;
    let after_arrow = &istr[arrow + 2..];
    let colon = after_arrow.find(':')?;
    Some(format!("{}->{}",
        &istr[class_start..arrow],
        &after_arrow[..colon],
    ))
}

fn extract_const_string_value(istr: &str) -> Option<String> {
    let q1 = istr.find('"')?;
    let after = &istr[q1 + 1..];
    let q2 = after.find('"')?;
    Some(after[..q2].to_string())
}

fn extract_const_class_ref(istr: &str) -> Option<String> {
    let l_idx = istr.find(", L")?;
    let after = &istr[l_idx + 2..];
    let semi = after.find(';')?;
    Some(after[..=semi].to_string())
}

fn dex_class_to_short(class_ref: &str) -> String {
    let stripped = class_ref.trim_start_matches('L').trim_end_matches(';');
    stripped.rsplit('/').next().unwrap_or(stripped).to_string()
}

fn writes_register(instr: &Instruction, reg: u32) -> bool {
    instr.v_a == Some(reg as i64)
}

fn invoke_arg_regs(instr: &Instruction) -> Vec<u32> {
    match &instr.kind {
        InstructionKind::InvokeKind | InstructionKind::InvokePolymorphic => {
            let count = instr.v_a.unwrap_or(0) as usize;
            let regs  = [instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g];
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

fn backward_const_for(method: &Method, invoke_idx: usize, target_reg: u32) -> Option<u32> {
    const WINDOW: usize = 50;
    let start = invoke_idx.saturating_sub(WINDOW);
    for i in (start..invoke_idx).rev() {
        let earlier = &method.instructions[i];
        if !matches!(earlier.kind, InstructionKind::Const) { continue; }
        if earlier.v_a != Some(target_reg as i64) { continue; }
        return earlier.v_b.map(|n| n as u32);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use platypus_dex::instructions::{ControlFlow, Instruction, InstructionKind};

    /// Build a minimal Instruction for tests. Most of `format_int_for_setter`
    /// only consults `instruction_str`, so the other fields are zeroed out.
    fn empty_instr() -> Instruction {
        Instruction {
            opcode: 0, address: 0, codepoint: 0, fmt: "10x",
            instruction_str: String::new(), width: 0,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::Unknown,
            v_a: None, v_b: None, v_c: None, v_d: None,
            v_e: None, v_f: None, v_g: None, v_h: None,
            v_z: None,
            operands: Vec::new(),
        }
    }

    #[test]
    fn extract_set_method_name_only_accepts_setters() {
        let s = "invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V";
        assert_eq!(extract_set_method_name(s).as_deref(), Some("setText"));

        let s2 = "invoke-virtual {v0}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence;";
        assert_eq!(extract_set_method_name(s2), None);

        let s3 = "invoke-virtual {v0, v1}, LFooTest;->setUp()V";
        // setUp is filtered out (test scaffolding, not a setter we care about).
        assert_eq!(extract_set_method_name(s3), None);
    }

    #[test]
    fn format_int_for_setter_handles_visibility_constants() {
        let i = empty_instr();
        assert_eq!(format_int_for_setter("setVisibility", &i, 0), "VISIBLE");
        assert_eq!(format_int_for_setter("setVisibility", &i, 4), "INVISIBLE");
        assert_eq!(format_int_for_setter("setVisibility", &i, 8), "GONE");
        assert_eq!(format_int_for_setter("setVisibility", &i, 99), "99");
    }

    #[test]
    fn format_int_for_setter_renders_color() {
        let i = empty_instr();
        assert_eq!(
            format_int_for_setter("setBackgroundColor", &i, 0xff112233),
            "#ff112233",
        );
        assert_eq!(
            format_int_for_setter("setTextColor", &i, 0x80ffffff),
            "#80ffffff",
        );
    }

    #[test]
    fn format_int_for_setter_renders_resource_id() {
        let i = empty_instr();
        assert_eq!(
            format_int_for_setter("setBackgroundResource", &i, 0x7f0a0001),
            "@0x7f0a0001",
        );
        assert_eq!(
            format_int_for_setter("setImageResource", &i, 0x7f080042),
            "@0x7f080042",
        );
    }

    #[test]
    fn format_int_for_setter_handles_booleans() {
        let i = empty_instr();
        assert_eq!(format_int_for_setter("setEnabled", &i, 0), "false");
        assert_eq!(format_int_for_setter("setEnabled", &i, 1), "true");
        assert_eq!(format_int_for_setter("setChecked", &i, 1), "true");
        assert_eq!(format_int_for_setter("setSelected", &i, 0), "false");
    }

    #[test]
    fn format_int_for_setter_decodes_float_when_signature_says_F() {
        let mut i = empty_instr();
        i.instruction_str =
            "invoke-virtual {v0, v1}, Landroid/view/View;->setAlpha(F)V".to_string();
        // 0.5f = 0x3f000000.
        assert_eq!(format_int_for_setter("setAlpha", &i, 0x3f000000), "0.5");
    }

    #[test]
    fn extract_const_string_value_pulls_quoted_literal() {
        assert_eq!(
            extract_const_string_value("const-string v0, \"Hello world\"").as_deref(),
            Some("Hello world"),
        );
    }

    #[test]
    fn extract_const_class_ref_finds_l_type() {
        assert_eq!(
            extract_const_class_ref("const-class v0, Lcom/example/FooActivity;").as_deref(),
            Some("Lcom/example/FooActivity;"),
        );
    }

    #[test]
    fn dex_class_short_name_keeps_last_segment() {
        assert_eq!(dex_class_to_short("Lcom/example/Foo;"), "Foo");
        assert_eq!(dex_class_to_short("LBare;"), "Bare");
    }
}
