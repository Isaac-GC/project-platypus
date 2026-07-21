//! Click-handler discovery via DEX bytecode.
//!
//! For each activity (and any inner classes) we look for these patterns:
//!
//! ```text
//! const v0, #R.id.my_button
//! invoke-virtual {p0, v0}, MainActivity;->findViewById(I)Landroid/view/View;
//! move-result-object v1
//! new-instance v2, MainActivity$1;
//! invoke-direct {v2, p0}, MainActivity$1;-><init>(LMainActivity;)V
//! invoke-virtual {v1, v2}, Landroid/view/View;->setOnClickListener(...)V
//! ```
//!
//! Three idioms are recognised:
//!
//!   * **inner-class listener** (`new-instance Foo$1; … <init>; setOnClickListener`)
//!     — target is `<inner-class>.onClick(View)V`.
//!   * **method-reference / lambda** (`invoke-custom` synthesizing a
//!     functional interface) — target is the method-handle's invoke target.
//!   * **`this` as listener** (`setOnClickListener(this)`) when the activity
//!     itself implements `OnClickListener` — target is `<activity>.onClick(View)V`.
//!
//! For each `setOnClickListener` invoke we trace the receiver register back
//! through the most recent `move-result-object` (≤ ~50 instructions) to the
//! `findViewById(R.id.X)` that produced it. That gives us the view id that
//! the listener was attached to; the IR builder uses that id to attach the
//! resulting [`HandlerHit`] to the matching view in the rehydrated tree.
//!
//! This is a static heuristic. False negatives are common (Kotlin lambdas
//! captured into local vars, listeners assigned via `with(...)`, listeners
//! attached in fragments / view binders). False positives are rare because
//! `setOnClickListener` is a very specific signature.

use platypus_dex::clazz::Clazz;
use platypus_dex::instructions::{Instruction, InstructionKind};
use platypus_dex::method::Method;
use platypus_dex::parser::DexFileWithRaw;

use crate::ir::HandlerKind;

const SET_ON_CLICK:        &str = ";->setOnClickListener(Landroid/view/View$OnClickListener;)V";
const SET_ON_LONG_CLICK:   &str = ";->setOnLongClickListener(Landroid/view/View$OnLongClickListener;)V";
const SET_ON_TOUCH:        &str = ";->setOnTouchListener(Landroid/view/View$OnTouchListener;)V";
const FIND_VIEW_BY_ID:     &str = ";->findViewById(I)";

/// One discovered handler attachment.
#[derive(Debug, Clone)]
pub struct HandlerHit {
    /// Resource id of the view (if we could trace the receiver back to a
    /// `findViewById(R.id.X)`). `None` means the receiver came from a
    /// view-binding field, a lambda capture, or some other path we don't
    /// yet trace — the caller can still surface the handler under the
    /// activity-level "all handlers" list.
    pub view_id: Option<u32>,
    /// `findViewById` call's source method name, for jump-to-source.
    pub from_method: String,
    /// What the handler does — see [`HandlerTarget`] for variants.
    pub target: HandlerTarget,
    pub kind: HandlerKind,
    /// DEX codepoint of the `setOnClickListener` invoke — useful for
    /// jump-to-source UIs.
    pub codepoint: u32,
}

#[derive(Debug, Clone)]
pub enum HandlerTarget {
    /// `new-instance Foo$1` then `setOnClickListener` — the listener is a
    /// dedicated class. We surface the inner class type so a "jump to
    /// source" can land in `Foo$1.onClick(View)`.
    InnerClass { class_ref: String, method: String },
    /// `setOnClickListener(this)` — the enclosing class implements the
    /// listener interface. Target is `<class>.onClick(View)V` (or
    /// `onLongClick`/`onTouch` for the other listeners).
    SelfReference { class_ref: String, method: String },
    /// `invoke-custom` synthesising the functional interface (Kotlin lambda
    /// / Java method reference). The bootstrap method handle's target is
    /// what would actually run.
    Lambda { method_ref: String },
    /// We saw `setOnClickListener` but couldn't recover the listener type.
    /// `raw_instruction` is the disassembled instruction text so a human
    /// can inspect.
    Unknown { raw_instruction: String },
}

impl HandlerTarget {
    /// Best-effort string for the IR `Handler::target` field.
    pub fn display(&self) -> String {
        match self {
            HandlerTarget::InnerClass { class_ref, method } => format!("{class_ref}->{method}"),
            HandlerTarget::SelfReference { class_ref, method } => format!("{class_ref}->{method}"),
            HandlerTarget::Lambda { method_ref } => method_ref.clone(),
            HandlerTarget::Unknown { raw_instruction } => raw_instruction.clone(),
        }
    }
}

/// Discover every click/long-click/touch handler attached inside the named
/// activity class (and its inner classes — `Outer$Inner` patterns).
///
/// `activity_class_name` is FQ dot-separated (e.g. `com.example.MainActivity`).
pub fn discover_handlers(
    dex_files: &[DexFileWithRaw],
    activity_class_name: &str,
) -> Vec<HandlerHit> {
    let class_norm = activity_class_name.replace('.', "/");
    let activity_class_ref = format!("L{class_norm};");
    let mut hits = Vec::new();

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            // Match the activity itself OR any of its inner classes
            // (`Outer$Inner`). Inner classes register their own handlers
            // when they're fragments or view-holders embedded in the
            // activity, and we want those too.
            let is_activity_or_inner = def_norm == class_norm
                || def_norm.starts_with(&format!("{class_norm}$"));
            if !is_activity_or_inner { continue; }

            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for method in &clazz.methods {
                scan_method(method, &activity_class_ref, &mut hits);
            }
        }
    }
    hits
}

// ── Per-method scanning ───────────────────────────────────────────────────

fn scan_method(
    method: &Method,
    activity_class_ref: &str,
    hits: &mut Vec<HandlerHit>,
) {
    for (idx, instr) in method.instructions.iter().enumerate() {
        let istr = &instr.instruction_str;
        if !istr.contains("invoke") { continue; }

        let kind = if istr.contains(SET_ON_CLICK) {
            HandlerKind::CodeOnClickListener
        } else if istr.contains(SET_ON_LONG_CLICK) {
            HandlerKind::CodeOnLongClickListener
        } else if istr.contains(SET_ON_TOUCH) {
            // Re-using CodeOnClickListener for now — the IR doesn't have a
            // dedicated touch variant. Touch handlers are visually less
            // important and the caller can always inspect `target` to
            // distinguish them.
            HandlerKind::CodeOnClickListener
        } else {
            continue;
        };

        let arg_regs = invoke_arg_regs(instr);
        // setOnClickListener(this, listener) → arg 0 = receiver (the View),
        // arg 1 = the OnClickListener instance.
        if arg_regs.len() < 2 { continue; }
        let receiver_reg = arg_regs[0];
        let listener_reg = arg_regs[1];

        let view_id = trace_receiver_to_view_id(method, idx, receiver_reg);
        let target  = trace_listener(method, idx, listener_reg, activity_class_ref, &kind);

        hits.push(HandlerHit {
            view_id,
            from_method: method.method_name.clone(),
            target,
            kind,
            codepoint: instr.codepoint,
        });
    }
}

// ── Receiver tracing: setOnClickListener receiver → view id ───────────────

/// Walk backward from the `setOnClickListener` invoke to find the
/// `findViewById(R.id.X)` (or compatible) that produced the receiver.
///
/// The pattern we're looking for:
///
/// ```text
/// const vN, #R.id.x          ; load id
/// invoke-virtual {…, vN}, …;->findViewById(I)…  ; call
/// move-result-object vRecv   ; copy result into the receiver register
/// …
/// invoke-virtual {vRecv, vListener}, …;->setOnClickListener(…)V
/// ```
fn trace_receiver_to_view_id(
    method: &Method,
    invoke_idx: usize,
    receiver_reg: u32,
) -> Option<u32> {
    const WINDOW: usize = 60;
    let start = invoke_idx.saturating_sub(WINDOW);

    // Step 1 — find the most recent `move-result-object` writing into receiver_reg.
    let mut move_idx: Option<usize> = None;
    for i in (start..invoke_idx).rev() {
        let earlier = &method.instructions[i];
        if matches!(earlier.kind, InstructionKind::MoveResult)
            && earlier.v_a == Some(receiver_reg as i64)
        {
            move_idx = Some(i);
            break;
        }
        // If we see a non-move-result that writes into receiver_reg, we lost
        // track — bail.
        if writes_register(earlier, receiver_reg) {
            return None;
        }
    }
    let move_idx = move_idx?;
    if move_idx == 0 { return None; }

    // Step 2 — the invoke immediately before the move-result-object should
    // be findViewById.
    let invoke = &method.instructions[move_idx - 1];
    if !invoke.instruction_str.contains(FIND_VIEW_BY_ID) {
        return None;
    }

    // Step 3 — the second arg of findViewById(I) is the id constant.
    let arg_regs = invoke_arg_regs(invoke);
    let id_reg = *arg_regs.get(1)?;

    // Step 4 — backward const search for id_reg.
    backward_const_for(method, move_idx - 1, id_reg)
}

// ── Listener tracing: setOnClickListener arg → handler target ─────────────

/// Resolve the listener register to a [`HandlerTarget`].
///
/// Looks for one of three patterns just before the invoke:
///   1. `new-instance vN, Foo$1; … invoke-direct {vN, …}, Foo$1;-><init>(…)`
///   2. `move-object/from16 vN, p0` (i.e. `this`) — the activity itself
///      implements the listener interface
///   3. `invoke-custom` (Kotlin lambda / Java method reference) — extract
///      the synthesised method ref
fn trace_listener(
    method: &Method,
    invoke_idx: usize,
    listener_reg: u32,
    activity_class_ref: &str,
    kind: &HandlerKind,
) -> HandlerTarget {
    const WINDOW: usize = 80;
    let start = invoke_idx.saturating_sub(WINDOW);

    let interface_method = match kind {
        HandlerKind::CodeOnClickListener     => "onClick(Landroid/view/View;)V",
        HandlerKind::CodeOnLongClickListener => "onLongClick(Landroid/view/View;)Z",
        HandlerKind::XmlOnClick              => "onClick(Landroid/view/View;)V",
    };

    // Last assignment to listener_reg is what we care about.
    for i in (start..invoke_idx).rev() {
        let earlier = &method.instructions[i];

        // ── Pattern 3: invoke-custom synthesising the listener ───────────
        // The result of invoke-custom lands in the next move-result-object,
        // so we look for that pattern: invoke-custom + move-result-object vN.
        if matches!(earlier.kind, InstructionKind::MoveResult)
            && earlier.v_a == Some(listener_reg as i64)
            && i > 0
        {
            let prev = &method.instructions[i - 1];
            if matches!(prev.kind, InstructionKind::InvokeCustom) {
                if let Some(mref) = extract_invoke_custom_target(&prev.instruction_str) {
                    return HandlerTarget::Lambda { method_ref: mref };
                }
                return HandlerTarget::Lambda {
                    method_ref: prev.instruction_str.clone(),
                };
            }
            // If it's just a regular invoke producing the listener (e.g.
            // a getter returning a cached instance), fall through to Unknown.
            return HandlerTarget::Unknown {
                raw_instruction: prev.instruction_str.clone(),
            };
        }

        // ── Pattern 2: move-object … listener_reg = this (p0) ────────────
        // `move-object vN, p0` or `iget-object vN, p0, ...` referencing `this`.
        if earlier.v_a == Some(listener_reg as i64) {
            let s = &earlier.instruction_str;
            // Heuristic: if the source shows `p0` (this) and the activity
            // class implements the listener interface, treat it as self-ref.
            // We don't actually verify the interface impl here; the inspector
            // can disambiguate by clicking through.
            if s.contains(", p0") || s.starts_with("move-object/from16") && s.contains("p0") {
                return HandlerTarget::SelfReference {
                    class_ref: activity_class_ref.to_string(),
                    method: interface_method.to_string(),
                };
            }
        }

        // ── Pattern 1: new-instance + <init> for listener_reg ────────────
        // `new-instance vN, Foo$1;` writes vN; the immediate next pair is
        // typically `invoke-direct {vN, …}, Foo$1;-><init>(…)V`.
        if matches!(earlier.kind, InstructionKind::NewInstance)
            && earlier.v_a == Some(listener_reg as i64)
        {
            if let Some(class_ref) = extract_new_instance_class(&earlier.instruction_str) {
                return HandlerTarget::InnerClass {
                    class_ref,
                    method: interface_method.to_string(),
                };
            }
        }

        // Anything else that writes to listener_reg invalidates the trace
        // and we keep looking back for an older write.
        if writes_register(earlier, listener_reg)
            && !matches!(earlier.kind, InstructionKind::MoveResult)
            && !matches!(earlier.kind, InstructionKind::NewInstance)
        {
            // Could be an iget-object pulling a cached listener field — note
            // it but keep searching for richer context.
            let s = &earlier.instruction_str;
            if s.contains("iget-object") {
                // Field access — best effort: extract the field type as the
                // listener class.
                if let Some(field_type) = extract_iget_field_type(s) {
                    return HandlerTarget::InnerClass {
                        class_ref: field_type,
                        method: interface_method.to_string(),
                    };
                }
            }
            // Otherwise leave the trace open — earlier writes may still be
            // the new-instance.
        }
    }

    HandlerTarget::Unknown {
        raw_instruction: method.instructions[invoke_idx].instruction_str.clone(),
    }
}

// ── Instruction helpers ───────────────────────────────────────────────────

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

/// Walk backward looking for the most recent `const` family writing the
/// requested register. Mirrors the helper in `activity_layout.rs`.
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

/// Pull the class ref out of `new-instance vN, Lcom/Foo;`.
fn extract_new_instance_class(istr: &str) -> Option<String> {
    let l_idx = istr.find(", L")?;
    let after = &istr[l_idx + 2..];
    let semi = after.find(';')?;
    Some(after[..=semi].to_string())
}

/// Pull the field *type* out of `iget-object vN, vM, LOwner;->field:LType;`.
fn extract_iget_field_type(istr: &str) -> Option<String> {
    // Look for `:L…;` at the tail.
    let colon_l = istr.rfind(":L")?;
    let after = &istr[colon_l + 1..];
    let semi = after.find(';')?;
    Some(after[..=semi].to_string())
}

/// Pull the synthesised method ref out of an `invoke-custom`'s instruction
/// text. invoke-custom's disassembly varies by toolchain but the bootstrap
/// method ref is usually the last `L…;->method(…)…` substring.
fn extract_invoke_custom_target(istr: &str) -> Option<String> {
    let arrow = istr.rfind("->")?;
    // Walk back from the arrow to the start of the class name.
    let class_start = istr[..arrow].rfind('L')?;
    Some(istr[class_start..].trim_end_matches(['\n', ' ', ',']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_new_instance_class_pulls_class_after_comma() {
        let s = "new-instance v2, Lcom/example/MainActivity$1;";
        assert_eq!(
            extract_new_instance_class(s).as_deref(),
            Some("Lcom/example/MainActivity$1;"),
        );
    }

    #[test]
    fn extract_iget_field_type_pulls_type_from_tail() {
        let s = "iget-object v1, p0, Lcom/Foo;->listener:Landroid/view/View$OnClickListener;";
        assert_eq!(
            extract_iget_field_type(s).as_deref(),
            Some("Landroid/view/View$OnClickListener;"),
        );
    }

    #[test]
    fn extract_invoke_custom_target_grabs_synthesised_method() {
        // invoke-custom disassembly varies — the trailing `L…;->m(…)…` is
        // what we recover.
        let s = "invoke-custom {v0}, call_site_42, Lcom/example/MyAppKt;->onClick$lambda$0(Landroid/view/View;)V";
        let got = extract_invoke_custom_target(s).expect("got method");
        assert!(got.contains("onClick$lambda$0"));
        assert!(got.starts_with("Lcom/example/MyAppKt;"));
    }

    #[test]
    fn handler_target_display_inner_class_format() {
        let t = HandlerTarget::InnerClass {
            class_ref: "Lcom/example/MainActivity$1;".to_string(),
            method: "onClick(Landroid/view/View;)V".to_string(),
        };
        assert_eq!(t.display(),
            "Lcom/example/MainActivity$1;->onClick(Landroid/view/View;)V");
    }

    #[test]
    fn handler_target_display_self_reference_format() {
        let t = HandlerTarget::SelfReference {
            class_ref: "Lcom/example/MainActivity;".to_string(),
            method: "onClick(Landroid/view/View;)V".to_string(),
        };
        assert_eq!(t.display(),
            "Lcom/example/MainActivity;->onClick(Landroid/view/View;)V");
    }
}
