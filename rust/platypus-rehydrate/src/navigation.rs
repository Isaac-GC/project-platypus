//! Navigation discovery via DEX bytecode.
//!
//! For each method that may be a click target (`onClick(View)V`,
//! `onLongClick(View)Z`, or an `android:onClick`-named method on the
//! activity), we look for the standard navigation idioms:
//!
//!   * **Explicit Intent**:
//!     ```text
//!     new-instance v0, Landroid/content/Intent;
//!     const-class v1, Lcom/example/FooActivity;
//!     invoke-direct {v0, this, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
//!     invoke-virtual {this, v0}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V
//!     ```
//!
//!   * **`Intent.setClass(Context, Class)`** — same effect, different idiom
//!     (post-construction class assignment).
//!
//!   * **Fragment swap**:
//!     `FragmentTransaction.replace(int, Landroidx/fragment/app/Fragment;)`
//!     — we recover the fragment's class via the second arg's last
//!     `new-instance` write.
//!
//!   * **NavController**:
//!     `NavController.navigate(I)V` — recover the destination resource id
//!     from a backward `const` search on the int arg.
//!
//! Each match becomes a [`NavInfo`] which the IR builder maps onto an
//! [`crate::ir::NavTarget`] attached to the originating view.

use platypus_dex::clazz::Clazz;
use platypus_dex::instructions::{Instruction, InstructionKind};
use platypus_dex::method::Method;
use platypus_dex::parser::DexFileWithRaw;

use crate::ir::{NavKind, NavTarget};

const START_ACTIVITY:               &str = ";->startActivity(Landroid/content/Intent;)V";
const START_ACTIVITY_FOR_RESULT:    &str = ";->startActivityForResult(Landroid/content/Intent;I)V";
const INTENT_INIT_CONTEXT_CLASS:    &str = "Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V";
const INTENT_SET_CLASS:             &str = "Landroid/content/Intent;->setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;";
const INTENT_SET_CLASS_NAME:        &str = "Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;";
const FRAGMENT_TX_REPLACE_INT:      &str = "FragmentTransaction;->replace(ILandroidx/fragment/app/Fragment;)";
const FRAGMENT_TX_REPLACE_INT_TAG:  &str = "FragmentTransaction;->replace(ILandroidx/fragment/app/Fragment;Ljava/lang/String;)";
const FRAGMENT_TX_ADD_INT:          &str = "FragmentTransaction;->add(ILandroidx/fragment/app/Fragment;)";
const NAV_CONTROLLER_NAVIGATE_INT:  &str = "NavController;->navigate(I)V";

/// One discovered navigation transition.
#[derive(Debug, Clone)]
pub struct NavInfo {
    pub kind: NavKind,
    /// Destination — activity FQN, fragment FQN, or `R.id.X`-style nav-graph id.
    pub target: String,
    /// DEX codepoint of the navigation invoke (helpful for jump-to-source).
    pub codepoint: u32,
}

impl NavInfo {
    pub fn into_target(self) -> NavTarget {
        NavTarget { kind: self.kind, target: self.target }
    }
}

/// Scan one method (looked up by class ref + method name) for navigation
/// idioms. Returns every match in source order.
///
/// `class_ref` is in DEX form (`"Lcom/example/MainActivity$1;"`).
/// `method_name` is the bare name (`"onClick"`); the signature isn't
/// disambiguated — if a class has two methods with the same name, both
/// are scanned.
pub fn discover_navigation_in_method(
    dex_files: &[DexFileWithRaw],
    class_ref: &str,
    method_name: &str,
) -> Vec<NavInfo> {
    let class_norm = class_ref.trim_start_matches('L').trim_end_matches(';');
    let mut hits = Vec::new();

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            if def_norm != class_norm { continue; }

            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for method in &clazz.methods {
                if method.method_name != method_name { continue; }
                scan_method(method, &mut hits);
            }
        }
    }
    hits
}

/// Scan ALL methods on a class for navigation idioms — useful when you don't
/// have a single click handler to focus on (e.g. surfacing the activity-level
/// "what does this screen navigate to?" view).
pub fn discover_navigation_in_class(
    dex_files: &[DexFileWithRaw],
    class_ref: &str,
) -> Vec<NavInfo> {
    let class_norm = class_ref.trim_start_matches('L').trim_end_matches(';');
    let mut hits = Vec::new();

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            if def_norm != class_norm { continue; }

            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for method in &clazz.methods {
                scan_method(method, &mut hits);
            }
        }
    }
    hits
}

// ── Per-method scanner ────────────────────────────────────────────────────

fn scan_method(method: &Method, hits: &mut Vec<NavInfo>) {
    for (idx, instr) in method.instructions.iter().enumerate() {
        let istr = &instr.instruction_str;
        if !istr.contains("invoke") { continue; }

        // ── startActivity / startActivityForResult ──────────────────────
        let (is_start, is_for_result) = if istr.contains(START_ACTIVITY) {
            (true, false)
        } else if istr.contains(START_ACTIVITY_FOR_RESULT) {
            (true, true)
        } else {
            (false, false)
        };

        if is_start {
            let arg_regs = invoke_arg_regs(instr);
            // arg 0 = receiver (activity), arg 1 = Intent
            if let Some(&intent_reg) = arg_regs.get(1) {
                if let Some(target_class) = trace_intent_target(method, idx, intent_reg) {
                    hits.push(NavInfo {
                        kind: if is_for_result {
                            NavKind::StartActivityForResult
                        } else {
                            NavKind::StartActivity
                        },
                        target: dex_class_to_fqn(&target_class),
                        codepoint: instr.codepoint,
                    });
                    continue;
                }
            }
        }

        // ── FragmentTransaction.replace / .add ──────────────────────────
        if istr.contains(FRAGMENT_TX_REPLACE_INT)
            || istr.contains(FRAGMENT_TX_REPLACE_INT_TAG)
            || istr.contains(FRAGMENT_TX_ADD_INT)
        {
            let arg_regs = invoke_arg_regs(instr);
            // arg 0 = receiver (FragmentTransaction)
            // arg 1 = container id (int)
            // arg 2 = Fragment instance
            if let Some(&frag_reg) = arg_regs.get(2) {
                if let Some(frag_class) = trace_fragment_target(method, idx, frag_reg) {
                    hits.push(NavInfo {
                        kind: NavKind::ReplaceFragment,
                        target: dex_class_to_fqn(&frag_class),
                        codepoint: instr.codepoint,
                    });
                    continue;
                }
            }
        }

        // ── NavController.navigate(int) ─────────────────────────────────
        if istr.contains(NAV_CONTROLLER_NAVIGATE_INT) {
            let arg_regs = invoke_arg_regs(instr);
            if let Some(&id_reg) = arg_regs.get(1) {
                if let Some(id) = backward_const_for(method, idx, id_reg) {
                    hits.push(NavInfo {
                        kind: NavKind::NavController,
                        target: format!("@id/0x{:08x}", id),
                        codepoint: instr.codepoint,
                    });
                    continue;
                }
            }
        }
    }
}

// ── Intent target tracing ─────────────────────────────────────────────────

/// Walk backward from `start_idx` (a `startActivity` invoke) looking for the
/// most recent `Intent.<init>(Context, Class)` or `Intent.setClass(...)` /
/// `setClassName(...)` invoke that wrote into `intent_reg`.
///
/// Returns the target class as a DEX type ref (`"Lcom/example/FooActivity;"`)
/// or `None` if we can't recover one within the lookback window.
fn trace_intent_target(
    method: &Method,
    start_idx: usize,
    intent_reg: u32,
) -> Option<String> {
    const WINDOW: usize = 100;
    let start = start_idx.saturating_sub(WINDOW);

    for i in (start..start_idx).rev() {
        let earlier = &method.instructions[i];
        let istr = &earlier.instruction_str;

        // Pattern A — Intent.<init>(Context, Class) on intent_reg.
        if istr.contains(INTENT_INIT_CONTEXT_CLASS) {
            let arg_regs = invoke_arg_regs(earlier);
            // (this, context, class)
            if arg_regs.first().copied() == Some(intent_reg) {
                if let Some(&class_reg) = arg_regs.get(2) {
                    return backward_const_class_for(method, i, class_reg);
                }
            }
        }

        // Pattern B — Intent.setClass(Context, Class).
        if istr.contains(INTENT_SET_CLASS) {
            let arg_regs = invoke_arg_regs(earlier);
            if arg_regs.first().copied() == Some(intent_reg) {
                if let Some(&class_reg) = arg_regs.get(2) {
                    return backward_const_class_for(method, i, class_reg);
                }
            }
        }

        // Pattern C — Intent.setClassName(String, String). Recover the
        // string literal directly when it's a const-string.
        if istr.contains(INTENT_SET_CLASS_NAME) {
            let arg_regs = invoke_arg_regs(earlier);
            if arg_regs.first().copied() == Some(intent_reg) {
                if let Some(&class_str_reg) = arg_regs.get(2) {
                    if let Some(s) = backward_const_string_for(method, i, class_str_reg) {
                        // setClassName takes ("packageName", "FQ.ClassName")
                        // — surface the FQ class directly. May also be the
                        // package, but the second arg is the more common one.
                        return Some(format!("L{};", s.replace('.', "/")));
                    }
                }
            }
        }
    }
    None
}

// ── Fragment target tracing ───────────────────────────────────────────────

/// Walk backward looking for the `new-instance` that produced the fragment
/// instance, returning its class ref.
fn trace_fragment_target(
    method: &Method,
    start_idx: usize,
    frag_reg: u32,
) -> Option<String> {
    const WINDOW: usize = 100;
    let start = start_idx.saturating_sub(WINDOW);

    for i in (start..start_idx).rev() {
        let earlier = &method.instructions[i];
        // Direct: new-instance frag_reg, LFooFragment;
        if matches!(earlier.kind, InstructionKind::NewInstance)
            && earlier.v_a == Some(frag_reg as i64)
        {
            return extract_new_instance_class(&earlier.instruction_str);
        }
        // Indirect: move-result-object frag_reg after invoke (factory call).
        if matches!(earlier.kind, InstructionKind::MoveResult)
            && earlier.v_a == Some(frag_reg as i64)
            && i > 0
        {
            let prev = &method.instructions[i - 1];
            // The factory's return type is the fragment class — pull it out
            // of the invoke ref tail.
            if let Some(ret) = extract_invoke_return_class(&prev.instruction_str) {
                return Some(ret);
            }
        }
    }
    None
}

// ── Generic register-trace helpers ───────────────────────────────────────

fn backward_const_class_for(method: &Method, start_idx: usize, target_reg: u32) -> Option<String> {
    const WINDOW: usize = 60;
    let start = start_idx.saturating_sub(WINDOW);
    for i in (start..start_idx).rev() {
        let earlier = &method.instructions[i];
        let istr = &earlier.instruction_str;
        if !istr.contains("const-class") { continue; }
        if earlier.v_a != Some(target_reg as i64) { continue; }
        // const-class vN, LCom/Foo; → extract the L…; ref.
        if let Some(class_ref) = extract_const_class_ref(istr) {
            return Some(class_ref);
        }
    }
    None
}

fn backward_const_string_for(method: &Method, start_idx: usize, target_reg: u32) -> Option<String> {
    const WINDOW: usize = 60;
    let start = start_idx.saturating_sub(WINDOW);
    for i in (start..start_idx).rev() {
        let earlier = &method.instructions[i];
        let istr = &earlier.instruction_str;
        if !istr.contains("const-string") { continue; }
        if earlier.v_a != Some(target_reg as i64) { continue; }
        if let Some(s) = extract_const_string_value(istr) {
            return Some(s);
        }
    }
    None
}

fn backward_const_for(method: &Method, start_idx: usize, target_reg: u32) -> Option<u32> {
    const WINDOW: usize = 60;
    let start = start_idx.saturating_sub(WINDOW);
    for i in (start..start_idx).rev() {
        let earlier = &method.instructions[i];
        if !matches!(earlier.kind, InstructionKind::Const) { continue; }
        if earlier.v_a != Some(target_reg as i64) { continue; }
        return earlier.v_b.map(|n| n as u32);
    }
    None
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

// ── String parsing helpers ─────────────────────────────────────────────────

fn extract_new_instance_class(istr: &str) -> Option<String> {
    let l_idx = istr.find(", L")?;
    let after = &istr[l_idx + 2..];
    let semi = after.find(';')?;
    Some(after[..=semi].to_string())
}

fn extract_const_class_ref(istr: &str) -> Option<String> {
    // const-class vN, LCom/Foo;
    let l_idx = istr.find(", L")?;
    let after = &istr[l_idx + 2..];
    let semi = after.find(';')?;
    Some(after[..=semi].to_string())
}

fn extract_const_string_value(istr: &str) -> Option<String> {
    // const-string vN, "the value"
    let q1 = istr.find('"')?;
    let after = &istr[q1 + 1..];
    let q2 = after.find('"')?;
    Some(after[..q2].to_string())
}

/// Take an invoke instruction's text and return the return-type class ref.
/// `…->factory(…)Lcom/example/FooFragment;` → `"Lcom/example/FooFragment;"`.
fn extract_invoke_return_class(istr: &str) -> Option<String> {
    let close_paren = istr.rfind(')')?;
    let after = &istr[close_paren + 1..];
    // After the close paren we have either a primitive (V/I/Z/etc.), an
    // array (`[...`), or a class ref (`L...;`). We only handle class refs.
    if !after.starts_with('L') { return None; }
    let semi = after.find(';')?;
    Some(after[..=semi].to_string())
}

/// Convert a DEX class ref `"Lcom/example/FooActivity;"` to the FQ
/// dot-separated form `"com.example.FooActivity"`.
pub fn dex_class_to_fqn(class_ref: &str) -> String {
    class_ref
        .trim_start_matches('L')
        .trim_end_matches(';')
        .replace('/', ".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dex_class_to_fqn_converts_slashes_and_strips_wrapper() {
        assert_eq!(dex_class_to_fqn("Lcom/example/FooActivity;"), "com.example.FooActivity");
        assert_eq!(dex_class_to_fqn("Lapp/X;"), "app.X");
        // Nested classes preserved.
        assert_eq!(dex_class_to_fqn("Lcom/x/Outer$Inner;"), "com.x.Outer$Inner");
    }

    #[test]
    fn extract_invoke_return_class_pulls_l_type_from_signature_tail() {
        // findViewById returns Landroid/view/View;
        let s = "invoke-virtual {v0, v1}, Lcom/Foo;->findViewById(I)Landroid/view/View;";
        assert_eq!(extract_invoke_return_class(s).as_deref(), Some("Landroid/view/View;"));
    }

    #[test]
    fn extract_invoke_return_class_returns_none_for_void_or_primitive() {
        // ()V — no class return.
        let s = "invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V";
        assert_eq!(extract_invoke_return_class(s), None);
        // ()I — primitive return.
        let s2 = "invoke-virtual {v0}, Lcom/Foo;->getCount()I";
        assert_eq!(extract_invoke_return_class(s2), None);
    }

    #[test]
    fn extract_const_class_ref_finds_class_token() {
        let s = "const-class v3, Lcom/example/SecondActivity;";
        assert_eq!(extract_const_class_ref(s).as_deref(), Some("Lcom/example/SecondActivity;"));
    }

    #[test]
    fn extract_const_string_value_handles_simple_string() {
        let s = "const-string v0, \"com.example.MyService\"";
        assert_eq!(extract_const_string_value(s).as_deref(), Some("com.example.MyService"));
    }

    #[test]
    fn extract_new_instance_class_pulls_class_after_comma() {
        let s = "new-instance v0, Landroid/content/Intent;";
        assert_eq!(extract_new_instance_class(s).as_deref(), Some("Landroid/content/Intent;"));
    }
}
