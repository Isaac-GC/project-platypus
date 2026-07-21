//! RecyclerView / ListView / GridView item-layout discovery.
//!
//! `RecyclerView` (and the older `ListView`/`GridView`) don't have static
//! children — the rows come from an adapter. Statically reconstructing the
//! adapter's item layout requires walking from the host view to the adapter
//! class to its `onCreateViewHolder` method, where the inflate call lives.
//!
//! We recognise this canonical pattern:
//!
//! ```text
//! const v0, #R.id.recycler_view
//! invoke-virtual {p0, v0}, MainActivity;->findViewById(I)Landroid/view/View;
//! move-result-object v1
//! new-instance v2, Lcom/example/MyAdapter;
//! invoke-direct {v2, …}, Lcom/example/MyAdapter;-><init>(…)V
//! invoke-virtual {v1, v2}, Landroidx/recyclerview/widget/RecyclerView;->setAdapter(…)V
//! ```
//!
//! Then in `MyAdapter`:
//!
//! ```text
//! const v0, #R.layout.item_user
//! invoke-virtual {…}, LayoutInflater;->inflate(IL…ViewGroup;Z)Landroid/view/View;
//! ```
//!
//! For each list-host view we recover the item layout id, resolve it to a
//! file path, and let the IR builder expand it the same way as the activity's
//! root layout — producing an `item_template` UnifiedView the renderer can
//! repeat to show a more accurate preview.

use std::collections::HashMap;

use platypus_dex::clazz::Clazz;
use platypus_dex::instructions::{Instruction, InstructionKind};
use platypus_dex::method::Method;
use platypus_dex::parser::DexFileWithRaw;

const SET_ADAPTER_NAMES: &[&str] = &[
    ";->setAdapter(",   // RecyclerView, ListView, GridView, ViewPager — all overload this
];
const LAYOUT_INFLATER_INFLATE: &str = "Landroid/view/LayoutInflater;->inflate";
const FIND_VIEW_BY_ID:         &str = ";->findViewById(I)";

/// One discovered (list view → adapter → item layout) chain.
#[derive(Debug, Clone)]
pub struct RecyclerHit {
    /// Resource id of the RecyclerView/ListView/GridView host.
    pub view_id: u32,
    /// Adapter class ref (`"Lcom/example/MyAdapter;"`).
    pub adapter_class: String,
    /// Item-layout resource id discovered inside the adapter's
    /// `onCreateViewHolder` (or `getView` for ListView).
    pub item_layout_id: u32,
    /// Per-row bindings from the adapter's `onBindViewHolder`. Each entry
    /// is a setter call applied to one of the holder's fields, with the
    /// view id resolved through the holder's constructor.
    /// Empty when adapter binding recovery doesn't find anything.
    pub bindings: Vec<BindingHit>,
}

/// One binding from `onBindViewHolder` — `holder.<field>.setText(...)`,
/// `setVisibility(...)`, etc. mapped through to the view id the holder
/// field references.
#[derive(Debug, Clone)]
pub struct BindingHit {
    /// View id (in the item layout) that this binding targets, recovered
    /// via the ViewHolder constructor's `findViewById(R.id.X)` mapping.
    pub view_id: u32,
    /// Setter name without signature: `"setText"`, `"setVisibility"`, …
    pub setter: String,
    /// Pre-formatted value — string literal in quotes, symbolic constant,
    /// or `"from <field>"` / `"(derived)"` when not a literal.
    pub value: String,
    /// True iff `value` is a literal we recovered confidently.
    pub literal: bool,
    /// Source method name (always `"onBindViewHolder"` or `"getView"`).
    pub from_method: String,
}

/// Discover every `(host view, adapter, item layout)` triple reachable from
/// the activity class (and its inner classes). Multiple hits per view id
/// are possible (uncommon but legal — e.g. an adapter swap on a state
/// change). The first one is generally the canonical template.
pub fn discover_recyclers(
    dex_files: &[DexFileWithRaw],
    activity_fq_name: &str,
) -> Vec<RecyclerHit> {
    let class_norm = activity_fq_name.replace('.', "/");
    let mut hits = Vec::new();

    // ── Stage 1: find every (view_id, adapter_class) pair from setAdapter
    //            invokes inside the activity class + inner classes. ──
    let adapter_pairs = collect_set_adapter_calls(dex_files, &class_norm);

    // ── Stage 2: for each adapter class, walk its onCreateViewHolder /
    //            getView body to find the inflate(R.layout.X, …) call.
    //            Wrapper adapters (ConcatAdapter, MergeAdapter — any
    //            adapter that delegates to a list of sub-adapters) won't
    //            have their own inflate; unwrap them and recurse.
    for (view_id, adapter_class) in adapter_pairs {
        let resolved = resolve_adapter_chain(dex_files, &adapter_class);
        for (effective_class, layout_id) in resolved {
            let bindings = discover_bindings_for(dex_files, &effective_class);
            hits.push(RecyclerHit {
                view_id,
                adapter_class: effective_class,
                item_layout_id: layout_id,
                bindings,
            });
        }
    }
    hits
}

/// Walk an adapter class to find its concrete inflated item layout(s).
/// For straightforward adapters this returns a single
/// `(adapter_class, layout_id)` pair — the canonical case.
///
/// For wrapper adapters that delegate to a list of sub-adapters (the
/// `ConcatAdapter([HeaderAdapter, FlowersAdapter])` pattern), this
/// recurses into each sub-adapter discovered in the wrapper's
/// constructor invocation site so the caller gets one hit per real
/// item-layout. The renderer surfaces the FIRST hit's template as the
/// list's `item_template` and reserves the rest for future per-row
/// rendering work.
fn resolve_adapter_chain(
    dex_files: &[DexFileWithRaw],
    adapter_class: &str,
) -> Vec<(String, u32)> {
    // First try to find an inflate directly on the adapter — covers the
    // 95% case where the adapter has its own onCreateViewHolder.
    if let Some(id) = inflated_layout_in_adapter(dex_files, adapter_class) {
        return vec![(adapter_class.to_string(), id)];
    }

    // No inflate on this class. If it's a known wrapper (ConcatAdapter,
    // MergeAdapter) or a custom delegator whose constructor takes an
    // adapter array, find the array's contents at the construction
    // site and recurse into each sub-adapter.
    let subs = find_wrapped_sub_adapters(dex_files, adapter_class);
    if subs.is_empty() { return Vec::new(); }

    let mut out = Vec::with_capacity(subs.len());
    for sub in subs {
        // Recurse — handles nested wrappers like ConcatAdapter(ConcatAdapter(...)).
        for hit in resolve_adapter_chain(dex_files, &sub) {
            out.push(hit);
        }
    }
    out
}

/// When the adapter's `<init>` is called somewhere, look at its args:
///   - a `[Lrecyclerview/Adapter;` array → return every type stuffed
///     into that array via `aput-object`
///   - one or more `Lrecyclerview/Adapter;` parameters → return those
///     directly (for the var-arg helper forms ConcatAdapter exposes)
///
/// Scans every method in the dex corpus for the construction site —
/// because the wrapper is created in the user's `onCreate`, not inside
/// the wrapper class itself. Returns the deduped class refs of the
/// sub-adapters in source order.
fn find_wrapped_sub_adapters(dex_files: &[DexFileWithRaw], wrapper_class: &str) -> Vec<String> {
    let wrapper_ref = format!("L{};", wrapper_class.trim_start_matches('L').trim_end_matches(';'));
    let init_marker = format!("{wrapper_ref}-><init>(");
    let mut seen = std::collections::HashSet::<String>::new();
    let mut out: Vec<String> = Vec::new();

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c, Err(_) => continue,
            };
            for method in &clazz.methods {
                for (idx, instr) in method.instructions.iter().enumerate() {
                    let istr = &instr.instruction_str;
                    if !istr.contains("invoke-direct") { continue; }
                    if !istr.contains(&init_marker) { continue; }
                    // The wrapper's ctor was called here. Args after
                    // `arg_regs[0]` (the receiver) carry the sub-adapter(s).
                    let args = invoke_arg_regs(instr);
                    for &arg_reg in args.iter().skip(1) {
                        for sub in trace_register_to_adapter_set(method, idx, arg_reg) {
                            if seen.insert(sub.clone()) { out.push(sub); }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Given a register at `at_idx`, return every adapter class that's been
/// written into it OR (if it was an array) stuffed into it via
/// `aput-object`. Resolves the array-of-adapters pattern that
/// `ConcatAdapter([HeaderAdapter, FlowersAdapter])` compiles to:
///
/// ```text
/// new-array v3, _, [Landroidx/recyclerview/widget/RecyclerView$Adapter;
/// aput-object v0, v3, 0           ; v3[0] = header
/// aput-object v1, v3, 1           ; v3[1] = flowers
/// invoke-direct {v2, v3}, ConcatAdapter;-><init>([Adapter])
/// ```
///
/// Walks backward from `at_idx` to find the matching `new-array`, then
/// in the window between the new-array and `at_idx` picks up every
/// `aput-object src, v_arr, _` write and traces `src` back to a class.
fn trace_register_to_adapter_set(method: &Method, at_idx: usize, reg: u32) -> Vec<String> {
    const WINDOW: usize = 80;
    let start = at_idx.saturating_sub(WINDOW);

    // Is `reg` an array (created via new-array)? Look for the most recent
    // new-array writing to it. If not, fall back to the single-class trace.
    let mut new_array_idx: Option<usize> = None;
    for i in (start..at_idx).rev() {
        let earlier = &method.instructions[i];
        if !writes_register(earlier, reg) { continue; }
        // new-array — `Array` instruction kind, mnemonic begins with "new-array".
        let s = &earlier.instruction_str;
        if s.starts_with("new-array") {
            new_array_idx = Some(i);
            break;
        }
        // It's some other write — fall through to single-trace.
        break;
    }

    if let Some(na_idx) = new_array_idx {
        // Collect aput-object writes into this array between na_idx and at_idx.
        let mut subs: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::<String>::new();
        for i in na_idx + 1..at_idx {
            let earlier = &method.instructions[i];
            let s = &earlier.instruction_str;
            if !s.starts_with("aput-object") { continue; }
            // Format: `aput-object vSrc, vArr, vIdx`. Decoder stores those
            // in v_a (src), v_b (array), v_c (index).
            let arr = earlier.v_b.map(|n| n as u32);
            if arr != Some(reg) { continue; }
            let src = match earlier.v_a.map(|n| n as u32) { Some(r) => r, None => continue };
            if let Some(c) = trace_register_to_class(method, i, src) {
                let bare = c.trim_start_matches('L').trim_end_matches(';').to_string();
                if seen.insert(bare.clone()) { subs.push(bare); }
            }
        }
        return subs;
    }

    // Not an array — single-class trace.
    trace_register_to_class(method, at_idx, reg)
        .map(|c| vec![c.trim_start_matches('L').trim_end_matches(';').to_string()])
        .unwrap_or_default()
}

// ── Stage 3: ViewHolder field → view id + binding scan ────────────────────

/// Recover every `holder.<field>.setText(...)` / `setVisibility(...)` etc.
/// from the adapter's `onBindViewHolder` (or `getView` for ListView).
fn discover_bindings_for(
    dex_files: &[DexFileWithRaw],
    adapter_class: &str,
) -> Vec<BindingHit> {
    let holder_class = match holder_class_for_adapter(dex_files, adapter_class) {
        Some(c) => c,
        None    => return Vec::new(),
    };
    let field_to_view_id = view_holder_field_map(dex_files, &holder_class);
    if field_to_view_id.is_empty() {
        return Vec::new();
    }
    bind_method_scan(dex_files, adapter_class, &holder_class, &field_to_view_id)
}

/// Find the ViewHolder class an adapter creates. Returns the type ref of
/// `onCreateViewHolder`'s return value (which is the holder class).
fn holder_class_for_adapter(
    dex_files: &[DexFileWithRaw],
    adapter_class: &str,
) -> Option<String> {
    let class_norm = adapter_class.trim_start_matches('L').trim_end_matches(';');

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            if def_norm != class_norm { continue; }

            let clazz = Clazz::new(class_def, dex).ok()?;
            for method in clazz.methods {
                if method.method_name != "onCreateViewHolder" { continue; }
                // Prefer "Holder" in the name; fall back to first new-instance.
                let mut fallback: Option<String> = None;
                for instr in &method.instructions {
                    if !matches!(instr.kind, InstructionKind::NewInstance) { continue; }
                    if let Some(c) = extract_class_ref_after(&instr.instruction_str, ", L") {
                        if c.contains("Holder") { return Some(c); }
                        fallback.get_or_insert(c);
                    }
                }
                if fallback.is_some() { return fallback; }
            }
        }
    }
    None
}

/// Walk a holder class's `<init>` for
/// `iput-object <field_reg>, this_reg, Holder;->field:<Type>;`
/// preceded by a `findViewById` move-result. Returns
/// `field_name → view_id` for every field assigned a `findViewById` result.
fn view_holder_field_map(
    dex_files: &[DexFileWithRaw],
    holder_class: &str,
) -> HashMap<String, u32> {
    let class_norm = holder_class.trim_start_matches('L').trim_end_matches(';');
    let mut out = HashMap::new();

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            if def_norm != class_norm { continue; }
            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c, Err(_) => continue,
            };
            for method in &clazz.methods {
                if method.method_name != "<init>" { continue; }
                scan_holder_ctor_for_fields(method, &mut out);
            }
        }
    }
    out
}

fn scan_holder_ctor_for_fields(method: &Method, out: &mut HashMap<String, u32>) {
    for (idx, instr) in method.instructions.iter().enumerate() {
        let istr = &instr.instruction_str;
        if !istr.contains("iput-object") { continue; }
        let (field_name, src_reg) = match parse_iput_field_name(instr, istr) {
            Some(t) => t, None => continue,
        };
        if let Some(view_id) = trace_field_to_view_id(method, idx, src_reg) {
            out.insert(field_name, view_id);
        }
    }
}

fn parse_iput_field_name(instr: &Instruction, istr: &str) -> Option<(String, u32)> {
    let src = instr.v_a? as u32;
    let arrow = istr.find("->")?;
    let after = &istr[arrow + 2..];
    let colon = after.find(':')?;
    let name = after[..colon].to_string();
    if name.is_empty() { return None; }
    Some((name, src))
}

fn trace_field_to_view_id(method: &Method, iput_idx: usize, target_reg: u32) -> Option<u32> {
    const WINDOW: usize = 80;
    let start = iput_idx.saturating_sub(WINDOW);
    let mut move_idx: Option<usize> = None;
    for i in (start..iput_idx).rev() {
        let earlier = &method.instructions[i];
        if matches!(earlier.kind, InstructionKind::MoveResult)
            && earlier.v_a == Some(target_reg as i64)
        {
            move_idx = Some(i);
            break;
        }
        if earlier.v_a == Some(target_reg as i64) { return None; }
    }
    let move_idx = move_idx?;
    if move_idx == 0 { return None; }
    let invoke = &method.instructions[move_idx - 1];
    if !invoke.instruction_str.contains(FIND_VIEW_BY_ID) { return None; }
    let arg_regs = invoke_arg_regs(invoke);
    let id_reg = *arg_regs.get(1)?;
    backward_const_for(method, move_idx - 1, id_reg)
}

/// Walk an adapter's `onBindViewHolder` (or `getView`) for
/// `holder.<field>.setText(<arg>)` patterns.
fn bind_method_scan(
    dex_files: &[DexFileWithRaw],
    adapter_class: &str,
    holder_class: &str,
    field_to_view_id: &HashMap<String, u32>,
) -> Vec<BindingHit> {
    let class_norm = adapter_class.trim_start_matches('L').trim_end_matches(';');
    let holder_class_norm = holder_class.trim_start_matches('L').trim_end_matches(';');
    let mut out = Vec::new();

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            if def_norm != class_norm { continue; }
            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c, Err(_) => continue,
            };
            for method in &clazz.methods {
                if method.method_name != "onBindViewHolder" && method.method_name != "getView" {
                    continue;
                }
                scan_bind_method(method, holder_class_norm, field_to_view_id, &mut out);
            }
        }
    }
    out
}

fn scan_bind_method(
    method: &Method,
    holder_class_norm: &str,
    field_to_view_id: &HashMap<String, u32>,
    out: &mut Vec<BindingHit>,
) {
    for (idx, instr) in method.instructions.iter().enumerate() {
        let istr = &instr.instruction_str;
        if !istr.contains("invoke") { continue; }

        let setter_name = match extract_set_method_name(istr) {
            Some(n) => n, None => continue,
        };
        if matches!(setter_name.as_str(),
            "setOnClickListener" | "setOnLongClickListener" | "setOnTouchListener"
            | "setContentView" | "setAdapter") { continue; }

        let arg_regs = invoke_arg_regs(instr);
        if arg_regs.is_empty() { continue; }
        let receiver_reg = arg_regs[0];

        let view_id = match trace_receiver_to_holder_field(
            method, idx, receiver_reg, holder_class_norm, field_to_view_id,
        ) {
            Some(id) => id, None => continue,
        };

        let (value, literal) = match arg_regs.get(1) {
            Some(&arg_reg) if arg_regs.len() == 2 => {
                resolve_bind_value(method, idx, arg_reg, &setter_name)
            }
            None => ("()".to_string(), true),
            _    => (format!("(derived: {} args)", arg_regs.len() - 1), false),
        };

        out.push(BindingHit {
            view_id,
            setter: setter_name,
            value,
            literal,
            from_method: method.method_name.clone(),
        });
    }
}

fn trace_receiver_to_holder_field(
    method: &Method,
    invoke_idx: usize,
    receiver_reg: u32,
    holder_class_norm: &str,
    field_to_view_id: &HashMap<String, u32>,
) -> Option<u32> {
    const WINDOW: usize = 80;
    let start = invoke_idx.saturating_sub(WINDOW);
    for i in (start..invoke_idx).rev() {
        let earlier = &method.instructions[i];
        if earlier.v_a != Some(receiver_reg as i64) { continue; }
        let istr = &earlier.instruction_str;
        if !istr.contains("iget-object") { return None; }
        if !istr.contains(&format!("L{holder_class_norm};->")) { return None; }
        let arrow = istr.find("->")?;
        let after = &istr[arrow + 2..];
        let colon = after.find(':')?;
        let field_name = &after[..colon];
        return field_to_view_id.get(field_name).copied();
    }
    None
}

fn resolve_bind_value(
    method: &Method,
    invoke_idx: usize,
    arg_reg: u32,
    setter: &str,
) -> (String, bool) {
    const WINDOW: usize = 80;
    let start = invoke_idx.saturating_sub(WINDOW);
    for i in (start..invoke_idx).rev() {
        let earlier = &method.instructions[i];
        if earlier.v_a != Some(arg_reg as i64) { continue; }
        let istr = &earlier.instruction_str;
        if istr.contains("const-string") {
            if let Some(s) = extract_const_string(istr) {
                return (format!("\"{s}\""), true);
            }
        }
        if matches!(earlier.kind, InstructionKind::Const) {
            if let Some(n) = earlier.v_b {
                return (format_int_for_setter(setter, n as u32), true);
            }
        }
        if istr.contains("iget") || istr.contains("sget") {
            if let Some(field) = extract_iget_field_name(istr) {
                return (format!("from {field}"), false);
            }
        }
        if matches!(earlier.kind, InstructionKind::MoveResult) && i > 0 {
            let prev = &method.instructions[i - 1];
            if let Some(mref) = extract_invoke_method_short(&prev.instruction_str) {
                return (mref, false);
            }
        }
        return ("(derived)".to_string(), false);
    }
    ("(derived)".to_string(), false)
}

fn format_int_for_setter(setter: &str, value: u32) -> String {
    match setter {
        "setVisibility" => match value {
            0 => "VISIBLE".to_string(),
            4 => "INVISIBLE".to_string(),
            8 => "GONE".to_string(),
            _ => format!("{value}"),
        },
        "setBackgroundColor" | "setTextColor" => format!("#{value:08x}"),
        "setBackgroundResource" | "setImageResource" => format!("@0x{value:08x}"),
        "setEnabled" | "setSelected" | "setActivated" | "setChecked"
        | "setClickable" => if value == 0 { "false".into() } else { "true".into() },
        _ => format!("{value}"),
    }
}

fn extract_set_method_name(istr: &str) -> Option<String> {
    let arrow = istr.find("->")?;
    let after = &istr[arrow + 2..];
    let paren = after.find('(')?;
    let name = &after[..paren];
    if !name.starts_with("set") || name.len() < 4 { return None; }
    Some(name.to_string())
}

fn extract_const_string(istr: &str) -> Option<String> {
    let q1 = istr.find('"')?;
    let after = &istr[q1 + 1..];
    let q2 = after.find('"')?;
    Some(after[..q2].to_string())
}

fn extract_iget_field_name(istr: &str) -> Option<String> {
    let arrow = istr.find("->")?;
    let after = &istr[arrow + 2..];
    let colon = after.find(':')?;
    Some(after[..colon].to_string())
}

fn extract_invoke_method_short(istr: &str) -> Option<String> {
    let arrow = istr.rfind("->")?;
    let after = &istr[arrow + 2..];
    let paren = after.find('(').unwrap_or(after.len());
    Some(after[..paren].to_string())
}

// ── Stage 1: setAdapter invokes inside the activity ──────────────────────

fn collect_set_adapter_calls(
    dex_files: &[DexFileWithRaw],
    class_norm: &str,
) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            let is_activity_or_inner = def_norm == class_norm
                || def_norm.starts_with(&format!("{class_norm}$"));
            if !is_activity_or_inner { continue; }

            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for method in &clazz.methods {
                scan_for_set_adapter(method, &mut out);
            }
        }
    }
    out
}

fn scan_for_set_adapter(method: &Method, out: &mut Vec<(u32, String)>) {
    for (idx, instr) in method.instructions.iter().enumerate() {
        let istr = &instr.instruction_str;
        if !istr.contains("invoke") { continue; }
        if !SET_ADAPTER_NAMES.iter().any(|s| istr.contains(s)) { continue; }

        let arg_regs = invoke_arg_regs(instr);
        if arg_regs.len() < 2 { continue; }
        let receiver_reg = arg_regs[0];
        let adapter_reg  = arg_regs[1];

        let view_id = match trace_receiver_to_view_id(method, idx, receiver_reg) {
            Some(id) => id,
            None => continue,
        };
        let adapter_class = match trace_register_to_class(method, idx, adapter_reg) {
            Some(c) => c,
            None => continue,
        };

        out.push((view_id, adapter_class));
    }
}

// ── Stage 2: walk an adapter class for the inflate call ──────────────────

fn inflated_layout_in_adapter(
    dex_files: &[DexFileWithRaw],
    adapter_class_ref: &str,
) -> Option<u32> {
    let class_norm = adapter_class_ref.trim_start_matches('L').trim_end_matches(';');

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

            // Prefer onCreateViewHolder (RecyclerView) — fallback to getView
            // (ListView) and as a last resort any method that has an
            // `inflate(int, …)` invoke.
            let preferred = ["onCreateViewHolder", "getView", "onCreateView"];
            for &target in &preferred {
                for method in &clazz.methods {
                    if method.method_name != target { continue; }
                    if let Some(id) = first_inflated_layout_id(method) {
                        return Some(id);
                    }
                }
            }

            // Last-ditch: scan every method.
            for method in &clazz.methods {
                if let Some(id) = first_inflated_layout_id(method) {
                    return Some(id);
                }
            }
        }
    }
    None
}

fn first_inflated_layout_id(method: &Method) -> Option<u32> {
    for (idx, instr) in method.instructions.iter().enumerate() {
        if !instr.instruction_str.contains("invoke") { continue; }
        if !instr.instruction_str.contains(LAYOUT_INFLATER_INFLATE) { continue; }
        let arg_regs = invoke_arg_regs(instr);
        // (this, R.layout.X, parent?, attachToRoot?)
        if let Some(&id_reg) = arg_regs.get(1) {
            if let Some(id) = backward_const_for(method, idx, id_reg) {
                return Some(id);
            }
        }
    }
    None
}

// ── Register tracing helpers ─────────────────────────────────────────────

fn trace_receiver_to_view_id(
    method: &Method,
    invoke_idx: usize,
    receiver_reg: u32,
) -> Option<u32> {
    const WINDOW: usize = 80;
    let start = invoke_idx.saturating_sub(WINDOW);

    // Walk backward, skipping passthrough writes (check-cast on the same
    // register, move-object retargets to the source register) until we
    // either find a `move-result-object` (the result of findViewById) or
    // a non-passthrough write that breaks the chain.
    let mut cur_reg = receiver_reg;
    let mut move_idx: Option<usize> = None;
    let mut i = invoke_idx;
    while i > start {
        i -= 1;
        let earlier = &method.instructions[i];
        if !writes_register(earlier, cur_reg) { continue; }

        // move-result-object — the candidate. Confirm it's downstream of
        // findViewById before accepting.
        if matches!(earlier.kind, InstructionKind::MoveResult) {
            move_idx = Some(i);
            break;
        }
        // check-cast — same register, just type-asserted. Skip past it.
        let istr = &earlier.instruction_str;
        if istr.starts_with("check-cast") { continue; }
        // move-object — retarget search to source register.
        if matches!(earlier.kind, InstructionKind::Move) && istr.starts_with("move-object") {
            if let Some(src) = earlier.v_b.map(|n| n as u32) {
                cur_reg = src;
                continue;
            }
        }
        // Any other write breaks the chain.
        return None;
    }
    let move_idx = move_idx?;
    if move_idx == 0 { return None; }

    let invoke = &method.instructions[move_idx - 1];
    if !invoke.instruction_str.contains(FIND_VIEW_BY_ID) {
        return None;
    }
    let arg_regs = invoke_arg_regs(invoke);
    let id_reg = *arg_regs.get(1)?;
    backward_const_for(method, move_idx - 1, id_reg)
}

/// Walk backward from `start_idx` looking for the most recent assignment
/// to `target_reg`, hoping to find a `new-instance` writing the adapter's
/// class ref. Falls through to `iget-object`'s field-type when the adapter
/// came from a member field.
///
/// Transparently follows three kinds of passthrough writes:
///   * `move-object vDst, vSrc`   — register copy
///   * `check-cast vDst, LType;`  — type assertion (writes vDst with same value)
///   * `move-result-object vDst`  — factory return
///
/// When we hit a pass-through that doesn't itself reveal a class, we
/// retarget the search to the source register and keep walking. This is
/// the difference between the `setAdapter(v3, v4)` pattern actually
/// resolving (because `v4` gets a `check-cast` + `move-object` from the
/// `v2 = new ConcatAdapter`) and the old behaviour of bailing on the
/// first non-recognised write.
fn trace_register_to_class(
    method: &Method,
    start_idx: usize,
    target_reg: u32,
) -> Option<String> {
    trace_register_to_class_inner(method, start_idx, target_reg, 0)
}

fn trace_register_to_class_inner(
    method: &Method,
    start_idx: usize,
    target_reg: u32,
    depth: usize,
) -> Option<String> {
    // Guard against infinite passthrough chains. 4 hops is way more than
    // real code ever uses.
    if depth > 4 { return None; }
    const WINDOW: usize = 120;
    let start = start_idx.saturating_sub(WINDOW);

    for i in (start..start_idx).rev() {
        let earlier = &method.instructions[i];
        if !writes_register(earlier, target_reg) { continue; }
        let istr = &earlier.instruction_str;

        if matches!(earlier.kind, InstructionKind::NewInstance) {
            if let Some(c) = extract_class_ref_after(istr, ", L") {
                return Some(c);
            }
        }
        if istr.contains("iget-object") || istr.contains("sget-object") {
            // Field type at `:LType;` tail.
            if let Some(c) = extract_class_ref_after(istr, ":L") {
                return Some(c);
            }
        }
        // move-result-object after a factory invoke — pull return type.
        if matches!(earlier.kind, InstructionKind::MoveResult) && i > 0 {
            let prev = &method.instructions[i - 1];
            if let Some(ret) = extract_invoke_return_class(&prev.instruction_str) {
                return Some(ret);
            }
        }
        // ── Passthrough writes — follow the source register. ──
        // `move-object vDst, vSrc` is decoded as `Move` with v_b = vSrc.
        if matches!(earlier.kind, InstructionKind::Move)
            && istr.starts_with("move-object")
        {
            if let Some(src) = earlier.v_b.map(|n| n as u32) {
                return trace_register_to_class_inner(method, i, src, depth + 1);
            }
        }
        // `check-cast vDst, LType;` — the cast's target type is what's
        // declared, but for our purposes we want the *concrete* type
        // (new-instance / sget-object source), so we retarget to the
        // SAME register and keep walking. The check-cast itself is the
        // earliest write we see, so the recursion's start_idx is `i`
        // and it'll skip past the check-cast into the actual source.
        if istr.starts_with("check-cast") {
            // Try recurse with the same register, but starting before
            // this check-cast (so we don't loop on it).
            if let Some(c) = trace_register_to_class_inner(method, i, target_reg, depth + 1) {
                return Some(c);
            }
            // If recursion found nothing, fall back to the declared
            // cast type — at least it gives the renderer *something*.
            if let Some(c) = extract_class_ref_after(istr, ", L") {
                return Some(c);
            }
        }
        // Unknown write — bail.
        return None;
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

/// True if `instr`'s execution stores a value into register `reg`.
///
/// Critical: Dalvik instructions encode the meaning of `v_a` differently
/// per opcode. For some it's the destination register (`move`, `const`,
/// `new-instance`); for others it's an arg count (`invoke-kind`),
/// a source register (`aput-object`, `iput-object`, `sput-object`,
/// `return-object`), or an unused operand. A naïve `v_a == reg` check
/// produces false positives whenever a register number happens to
/// coincide with an opcode's arg-count or source-register operand,
/// causing the register tracer to bail prematurely.
fn writes_register(instr: &Instruction, reg: u32) -> bool {
    let v_a_is_dest = matches!(instr.kind,
        // Pure register writes.
        InstructionKind::Move
        | InstructionKind::MoveResult
        | InstructionKind::Const
        | InstructionKind::NewInstance
        | InstructionKind::ArrLength
        | InstructionKind::InstanceOf
        | InstructionKind::IGet
        | InstructionKind::SGet
        | InstructionKind::Cmp
        | InstructionKind::UnOp
        | InstructionKind::BinOp { .. }
        | InstructionKind::BinOp2Addr { .. }
        | InstructionKind::BinOpLit { .. }
        // new-array — also writes v_a.
        | InstructionKind::Array
        // check-cast is a (re-)type-assert — same register, treated as a write
        // for tracing purposes so callers can decide to skip past it.
        | InstructionKind::CheckCast,
        // Excluded: InvokeKind/InvokeKindRange/InvokePolymorphic/InvokeCustom
        // (v_a is arg count), IPut/SPut (v_a is source), ArrayOp (v_a is
        // source for aput-*), Return/Throw/Goto/If/IfZ/Switch/Monitor/Nop
        // (no register write via v_a), and payload pseudo-instructions.
    );
    v_a_is_dest && instr.v_a == Some(reg as i64)
}

/// Pull a `Lcom/Foo;` class ref out of an instruction by finding the given
/// delimiter (`", L"` for new-instance, `":L"` for iget-object).
fn extract_class_ref_after(istr: &str, delim: &str) -> Option<String> {
    let pos = istr.find(delim)?;
    let after = &istr[pos + delim.len() - 1..];
    let semi = after.find(';')?;
    Some(after[..=semi].to_string())
}

fn extract_invoke_return_class(istr: &str) -> Option<String> {
    let close_paren = istr.rfind(')')?;
    let after = &istr[close_paren + 1..];
    if !after.starts_with('L') { return None; }
    let semi = after.find(';')?;
    Some(after[..=semi].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_class_ref_after_finds_l_after_delim() {
        // new-instance vN, Lfoo;
        let s = "new-instance v0, Lcom/example/Adapter;";
        assert_eq!(extract_class_ref_after(s, ", L").as_deref(),
                   Some("Lcom/example/Adapter;"));

        // iget-object vN, vM, LOwner;->field:LType; → use ":L" delim for type
        let s2 = "iget-object v1, p0, LFoo;->title:Landroid/widget/TextView;";
        assert_eq!(extract_class_ref_after(s2, ":L").as_deref(),
                   Some("Landroid/widget/TextView;"));
    }

    #[test]
    fn extract_invoke_return_class_returns_class_only_when_not_primitive() {
        let s = "invoke-virtual {v0}, Lf;->m()Lcom/Foo;";
        assert_eq!(extract_invoke_return_class(s).as_deref(), Some("Lcom/Foo;"));
        assert_eq!(extract_invoke_return_class("invoke-virtual {v0}, Lf;->m()V"), None);
        assert_eq!(extract_invoke_return_class("invoke-virtual {v0}, Lf;->m()I"), None);
    }

    #[test]
    fn binding_setter_name_filter_skips_listener_setters() {
        // These setters are recognised by other phases (handlers/recycler);
        // bindings shouldn't double-count them.
        // We can only exercise the filter via scan_bind_method, which
        // requires DEX state — but extract_set_method_name is the
        // pre-filter and we can verify it returns the name (the skip
        // happens further in).
        assert_eq!(
            extract_set_method_name("invoke-virtual {v0,v1}, LFoo;->setOnClickListener(Landroid/view/View$OnClickListener;)V").as_deref(),
            Some("setOnClickListener"),
        );
    }

    #[test]
    fn extract_const_string_handles_basic_quote() {
        assert_eq!(
            extract_const_string("const-string v0, \"Hello\"").as_deref(),
            Some("Hello"),
        );
    }

    #[test]
    fn extract_iget_field_name_pulls_field_from_get() {
        let s = "iget-object v1, p0, LFooHolder;->title:Landroid/widget/TextView;";
        assert_eq!(extract_iget_field_name(s).as_deref(), Some("title"));
    }

    #[test]
    fn extract_invoke_method_short_keeps_only_method_name() {
        let s = "invoke-virtual {v0}, Lcom/Foo;->getName()Ljava/lang/String;";
        assert_eq!(extract_invoke_method_short(s).as_deref(), Some("getName"));
    }

    #[test]
    fn format_int_for_setter_gone_visible_invisible() {
        assert_eq!(format_int_for_setter("setVisibility", 0), "VISIBLE");
        assert_eq!(format_int_for_setter("setVisibility", 4), "INVISIBLE");
        assert_eq!(format_int_for_setter("setVisibility", 8), "GONE");
    }
}
