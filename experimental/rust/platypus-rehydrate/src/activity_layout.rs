//! Activity → root layout discovery.
//!
//! For each activity, find its `setContentView(R.layout.X)` call and
//! extract `X` (the layout resource id). Three patterns are recognised:
//!
//! 1. `setContentView(int)` — direct `setContentView(R.layout.foo)`.
//!    Walk the activity's lifecycle methods, find the invoke, recover the
//!    int constant loaded into the arg register.
//!
//! 2. `setContentView(View)` with `View` from `LayoutInflater.inflate(R.layout.X, null)`.
//!    Two-step pattern; we follow the inflate call's first arg.
//!
//! 3. View-binding: `setContentView(FooBinding.inflate(...).getRoot())`.
//!    The binding class name encodes the layout (`ActivityFooBinding` →
//!    `R.layout.activity_foo`). We don't analyse the chain; we look for
//!    `*Binding.inflate(LayoutInflater)` invokes inside the activity and
//!    map the binding class name back to the layout resource name.
//!
//! All three are heuristic — false positives possible. The caller (builder)
//! returns ALL discovered layouts per activity so the inspector can show
//! ambiguity rather than picking one silently.

use platypus_dex::clazz::Clazz;
use platypus_dex::instructions::{Instruction, InstructionKind};
use platypus_dex::method::Method;
use platypus_dex::parser::DexFileWithRaw;

/// Substrings we look for in invoke instruction strings.
const SET_CONTENT_VIEW_INT: &str = "->setContentView(I)V";
const SET_CONTENT_VIEW_VIEW: &str = "->setContentView(Landroid/view/View;)V";
const LAYOUT_INFLATER_INFLATE: &str = "Landroid/view/LayoutInflater;->inflate";

/// All layout resource ids discovered for one activity. A typical activity
/// returns one id; multiple is uncommon (suggests A/B logic or multiple
/// `setContentView` calls in different lifecycle methods).
#[derive(Debug, Clone)]
pub struct ActivityLayoutHits {
    pub activity_class: String,
    /// Discovered (layout_id, source) pairs in source order.
    pub hits: Vec<LayoutHit>,
}

#[derive(Debug, Clone)]
pub struct LayoutHit {
    pub layout_id: u32,
    /// Where it was found — `"onCreate"` / `"onCreateView"` / etc.
    pub method_name: String,
    /// Codepoint of the `setContentView` invoke (or the binding inflate).
    pub codepoint: u32,
    /// "setContentView(int)" / "setContentView(View)+inflate" / "viewBinding".
    pub source: HitSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitSource {
    DirectInt,
    InflaterInflate,
    ViewBinding,
}

/// Find the root-layout id(s) for `activity_class_name` (FQ, dot-separated).
///
/// Walks every method in the activity class, looking at the lifecycle
/// methods first (`onCreate`, `onCreateView`, `onViewCreated`). Returns
/// every match — duplicates are intentional so the inspector can flag the
/// ambiguity. Empty list = activity has no `setContentView` (uses default
/// theme window, or is Compose-only, or is a base class).
pub fn discover_for_activity(
    dex_files: &[DexFileWithRaw],
    activity_class_name: &str,
) -> ActivityLayoutHits {
    let class_norm = activity_class_name.replace('.', "/");
    let mut hits = Vec::new();

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            if def_norm != class_norm {
                continue;
            }
            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for method in &clazz.methods {
                scan_method(method, &mut hits);
            }
        }
    }

    ActivityLayoutHits {
        activity_class: activity_class_name.to_string(),
        hits,
    }
}

/// Scan one method for layout-discovery patterns. Matches are appended
/// to `hits` in source order.
fn scan_method(method: &Method, hits: &mut Vec<LayoutHit>) {
    for (idx, instr) in method.instructions.iter().enumerate() {
        let istr = &instr.instruction_str;
        if !istr.contains("invoke") { continue; }

        // ── Pattern 1: setContentView(int) — direct ───────────────────────
        if istr.contains(SET_CONTENT_VIEW_INT) {
            // Args of invoke-virtual: arg 0 = `this`, arg 1 = layout int.
            let arg_regs = invoke_arg_regs(instr);
            if let Some(&data_reg) = arg_regs.get(1) {
                if let Some(id) = backward_const_for(method, idx, data_reg) {
                    hits.push(LayoutHit {
                        layout_id: id,
                        method_name: method.method_name.clone(),
                        codepoint: instr.codepoint,
                        source: HitSource::DirectInt,
                    });
                    continue;
                }
            }
        }

        // ── Pattern 2: LayoutInflater.inflate(int, …) ────────────────────
        // Whichever overload (with/without root, attachToRoot bool, …),
        // arg 1 is always the layout int. setContentView(View) often comes
        // a few instructions later but we don't require pairing — having
        // the inflate call alone is strong enough evidence.
        if istr.contains(LAYOUT_INFLATER_INFLATE) {
            let arg_regs = invoke_arg_regs(instr);
            if let Some(&data_reg) = arg_regs.get(1) {
                if let Some(id) = backward_const_for(method, idx, data_reg) {
                    hits.push(LayoutHit {
                        layout_id: id,
                        method_name: method.method_name.clone(),
                        codepoint: instr.codepoint,
                        source: HitSource::InflaterInflate,
                    });
                    continue;
                }
            }
        }

        // ── Pattern 3: ViewBinding inflate ───────────────────────────────
        // Look for `*Binding;->inflate(...)` calls. We don't try to recover
        // the layout int (these bindings call `R.layout.x` internally —
        // resolvable but indirect). Instead, the builder uses the binding
        // class name + a resource lookup for `layout/<snake_case_name>` to
        // find the matching layout. Surface the binding class here.
        if let Some(class_part) = extract_invoke_class(istr) {
            if class_part.ends_with("Binding;")
                && istr.contains(";->inflate(")
            {
                // Stash a placeholder hit; the builder resolves it later.
                // We can't compute the layout id here without resources, so
                // we encode the binding class as `0xFFFE_xxxx` — a sentinel
                // that builder.rs decodes. Actual binding-name → layout-id
                // resolution lives there.
                if let Some(layout_id) = binding_class_to_layout_sentinel(class_part) {
                    hits.push(LayoutHit {
                        layout_id,
                        method_name: method.method_name.clone(),
                        codepoint: instr.codepoint,
                        source: HitSource::ViewBinding,
                    });
                }
            }
        }
    }
}

/// Sentinel id encoding for view-binding hits. We can't know the real
/// layout id without consulting resources.arsc, so we hash the binding
/// class name into the upper bits and let the builder resolve it.
///
/// Returns `None` if the class name doesn't look like a view-binding.
/// Format: `0xFFFE_0000 | (hash & 0xFFFF)` — distinguishable from real
/// ids (which start with `0x7f`).
fn binding_class_to_layout_sentinel(class_ref: &str) -> Option<u32> {
    // class_ref format: "Lcom/example/databinding/ActivityFooBinding;"
    if !class_ref.contains("Binding;") { return None; }
    let mut h: u32 = 0;
    for b in class_ref.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    Some(0xFFFE_0000 | (h & 0xFFFF))
}

/// Try to recover the binding class name from a sentinel id. Caller passes
/// the candidate binding class refs (e.g. extracted from the activity's
/// methods); we return the one that hashes to the sentinel.
pub fn binding_class_for_sentinel(
    sentinel: u32,
    candidates: &[String],
) -> Option<String> {
    if (sentinel & 0xFFFF_0000) != 0xFFFE_0000 { return None; }
    let want_low = sentinel & 0xFFFF;
    for c in candidates {
        if let Some(s) = binding_class_to_layout_sentinel(c) {
            if (s & 0xFFFF) == want_low {
                return Some(c.clone());
            }
        }
    }
    None
}

/// Given a binding class ref like `"Lcom/example/databinding/ActivityFooBinding;"`,
/// derive the layout name `"activity_foo"` (Android's autogen convention).
pub fn binding_class_to_layout_name(class_ref: &str) -> Option<String> {
    let stripped = class_ref.trim_start_matches('L').trim_end_matches(';');
    let last = stripped.rsplit('/').next()?;
    let bare = last.strip_suffix("Binding")?;
    if bare.is_empty() { return None; }
    // CamelCase → snake_case
    let mut out = String::with_capacity(bare.len() + 4);
    for (i, ch) in bare.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_lowercase());
    }
    Some(out)
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Walk backward from `invoke_idx` looking for the most recent
/// `const` / `const/16` / `const/4` / `const/high16` instruction targeting
/// `target_reg`. Returns the loaded value as `u32`, or `None` if no const
/// load is found within a reasonable window.
fn backward_const_for(
    method: &Method,
    invoke_idx: usize,
    target_reg: u32,
) -> Option<u32> {
    // Cap the backward search — const loads are usually 1-3 instructions
    // before the invoke. Walking too far risks picking up a stale value.
    const WINDOW: usize = 50;
    let start = invoke_idx.saturating_sub(WINDOW);
    for i in (start..invoke_idx).rev() {
        let earlier = &method.instructions[i];
        // Only care about Const-family instructions.
        if !matches!(earlier.kind, InstructionKind::Const) { continue; }
        // dst register is v_a.
        if earlier.v_a != Some(target_reg as i64) { continue; }
        // The literal is in v_b for `const v0, #lit32` and similar.
        return earlier.v_b.map(|n| n as u32);
    }
    None
}

/// Extract arg registers from an invoke instruction. Mirror of the
/// helper in `dex_loader_analysis.rs` — kept local so this crate doesn't
/// depend on the main analysis module.
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

/// Pull the class portion (`"Lcom/Foo;"`) out of an invoke instruction's
/// target ref. Returns `None` for instructions that don't have one.
fn extract_invoke_class(istr: &str) -> Option<&str> {
    let after = istr.find("}, ").map(|p| p + 3)
        .or_else(|| istr.find("} ..").map(|p| p + 4))
        .or_else(|| istr.rfind('}').map(|p| p + 1))?;
    let rest = istr[after..].trim();
    let arrow = rest.find("->")?;
    // The class ref is everything up to (but not including) the `->`. The
    // class's trailing `;` already lives inside that slice — `[..arrow]`
    // gives `Landroid/app/Activity;` not `Landroid/app/Activity;-`.
    Some(&rest[..arrow])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camelcase_binding_name_to_snake_layout_name() {
        // Standard ActivityXBinding → activity_x.
        assert_eq!(
            binding_class_to_layout_name("Lcom/example/databinding/ActivityMainBinding;").as_deref(),
            Some("activity_main"),
        );
        // Multi-word: ActivityUserProfile → activity_user_profile.
        assert_eq!(
            binding_class_to_layout_name("Lcom/x/databinding/ActivityUserProfileBinding;").as_deref(),
            Some("activity_user_profile"),
        );
        // Fragment-style.
        assert_eq!(
            binding_class_to_layout_name("Lapp/databinding/FragmentSettingsBinding;").as_deref(),
            Some("fragment_settings"),
        );
    }

    #[test]
    fn binding_name_rejects_non_binding_classes() {
        assert_eq!(binding_class_to_layout_name("Lcom/example/MainActivity;"), None);
        assert_eq!(binding_class_to_layout_name("LBinding;"), None); // bare "Binding" — no name part
    }

    #[test]
    fn binding_sentinel_round_trips() {
        let class_ref = "Lcom/example/databinding/ActivityMainBinding;";
        let sentinel = binding_class_to_layout_sentinel(class_ref).expect("hash");
        assert_eq!(sentinel & 0xFFFF_0000, 0xFFFE_0000);

        // Reversing requires the candidate list — the original class must
        // be one of them for the lookup to succeed.
        let recovered = binding_class_for_sentinel(
            sentinel,
            &[class_ref.to_string(), "Lother/X;".to_string()],
        );
        assert_eq!(recovered.as_deref(), Some(class_ref));
    }

    #[test]
    fn binding_sentinel_returns_none_for_non_sentinel() {
        // A real resource id (high byte 0x7f) is not a sentinel.
        assert_eq!(binding_class_for_sentinel(0x7f0a0001, &["LFooBinding;".into()]), None);
    }

    #[test]
    fn extract_invoke_class_handles_braces() {
        // Single-arg invoke: `invoke-virtual {v0, v1}, Landroid/app/Activity;->setContentView(I)V`
        let s = "invoke-virtual {v0, v1}, Landroid/app/Activity;->setContentView(I)V";
        assert_eq!(extract_invoke_class(s), Some("Landroid/app/Activity;"));

        // Range invoke: `invoke-virtual/range {v0 .. v3}, Lcom/Foo;->bar(III)V`
        let s2 = "invoke-virtual/range {v0 .. v3}, Lcom/Foo;->bar(III)V";
        assert_eq!(extract_invoke_class(s2), Some("Lcom/Foo;"));
    }
}
